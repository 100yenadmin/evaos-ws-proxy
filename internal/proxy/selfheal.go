package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

const (
	healthCheckInterval       = 60 * time.Second
	alertCooldownAfterRestart = 120 * time.Second
	crashLoopThreshold        = 3
	crashLoopWindow           = 10 * time.Minute
)

// HealAction describes an auto-healing action taken by the bot.
type HealAction struct {
	CustomerID string    `json:"customer_id"`
	Action     string    `json:"action"`
	Success    bool      `json:"success"`
	Error      string    `json:"error,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

// customerHealState tracks the self-healing state per customer.
type customerHealState struct {
	restartTimes []time.Time
	lastAlert    time.Time
	crashLoop    bool
}

// SelfHealBot monitors customer VMs and performs auto-healing actions.
type SelfHealBot struct {
	restarts   *RestartManager
	vms        VMRegistry
	alertFn    func(ctx context.Context, customerID, subject, body string) // M-4: accepts context

	mu         sync.Mutex
	states     map[string]*customerHealState
	customers  []string
	healLog    []HealAction
	maxLogSize int
}

// SelfHealConfig contains configuration for the self-healing bot.
type SelfHealConfig struct {
	RestartManager *RestartManager
	VMRegistry     VMRegistry
	CustomerIDs    []string
	AlertFn        func(customerID, subject, body string)
}

// NewSelfHealBot creates a new self-healing bot.
func NewSelfHealBot(cfg SelfHealConfig) *SelfHealBot {
	// Wrap the user-provided alertFn to accept context (M-4)
	var wrappedAlertFn func(ctx context.Context, customerID, subject, body string)
	if cfg.AlertFn != nil {
		userFn := cfg.AlertFn
		wrappedAlertFn = func(ctx context.Context, cid, subject, body string) {
			userFn(cid, subject, body)
		}
	} else {
		wrappedAlertFn = func(ctx context.Context, cid, subject, body string) {
			slog.Warn("self-heal alert (no handler configured)",
				"customer_id", cid, "subject", subject, "body", body)
		}
	}
	return &SelfHealBot{
		restarts:   cfg.RestartManager,
		vms:        cfg.VMRegistry,
		alertFn:    wrappedAlertFn,
		states:     make(map[string]*customerHealState),
		customers:  cfg.CustomerIDs,
		healLog:    make([]HealAction, 0, 100),
		maxLogSize: 1000,
	}
}

// SetCustomers updates the list of customer IDs to monitor.
func (b *SelfHealBot) SetCustomers(ids []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.customers = ids
}

// GetHealLog returns the recent heal actions.
func (b *SelfHealBot) GetHealLog() []HealAction {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]HealAction, len(b.healLog))
	copy(out, b.healLog)
	return out
}

// Start begins the self-healing monitoring loop.
func (b *SelfHealBot) Start(ctx context.Context) {
	slog.Info("self-heal bot started", "interval", healthCheckInterval, "customers", len(b.customers))
	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("self-heal bot stopped")
			return
		case <-ticker.C:
			b.checkAll(ctx)
		}
	}
}

func (b *SelfHealBot) checkAll(ctx context.Context) {
	b.mu.Lock()
	customers := make([]string, len(b.customers))
	copy(customers, b.customers)
	b.mu.Unlock()

	for _, cid := range customers {
		select {
		case <-ctx.Done():
			return
		default:
			b.checkCustomer(ctx, cid)
		}
	}
}

func (b *SelfHealBot) checkCustomer(ctx context.Context, customerID string) {
	vm, err := b.vms.LookupByCustomerID(customerID)
	if err != nil || vm == nil {
		return
	}

	healthy := b.pingGateway(vm.EffectiveIP(), vm.GatewayPort)
	if healthy {
		return
	}

	b.mu.Lock()
	state := b.states[customerID]
	if state == nil {
		state = &customerHealState{}
		b.states[customerID] = state
	}

	// Clean old restart times outside the crash-loop window
	now := time.Now()
	var recent []time.Time
	for _, t := range state.restartTimes {
		if now.Sub(t) < crashLoopWindow {
			recent = append(recent, t)
		}
	}
	state.restartTimes = recent

	// Check for crash-loop
	if len(state.restartTimes) >= crashLoopThreshold {
		if !state.crashLoop {
			state.crashLoop = true
			b.mu.Unlock()
			b.logAction(customerID, "crash-loop-detected", true, "")
			// M-4: Use context with timeout for alert callback
			alertCtx, alertCancel := context.WithTimeout(ctx, 10*time.Second)
			defer alertCancel()
			b.alertFn(alertCtx, customerID,
				fmt.Sprintf("evaOS ALERT: %s crash-looping", customerID),
				fmt.Sprintf("Customer %s has had %d restarts in the last 10 minutes. Auto-restart disabled. Manual intervention needed.", customerID, len(state.restartTimes)),
			)
			return
		}
		b.mu.Unlock()
		return
	}
	state.crashLoop = false

	// M-7: Check cooldown while still holding the lock to prevent race
	cooldownRemaining := b.restarts.CheckCooldown(customerID)
	b.mu.Unlock()

	if cooldownRemaining > 0 {
		return
	}

	// Attempt one auto-restart
	slog.Info("self-heal: attempting auto-restart", "customer_id", customerID)
	err = b.restarts.Restart(customerID, vm.EffectiveIP(), vm.GatewayPort)
	if err != nil {
		b.logAction(customerID, "auto-restart", false, err.Error())
		slog.Error("self-heal: auto-restart failed", "customer_id", customerID, "error", err)
	} else {
		b.logAction(customerID, "auto-restart", true, "")
	}

	b.mu.Lock()
	state.restartTimes = append(state.restartTimes, now)
	b.mu.Unlock()

	// M-4: Schedule an alert with context timeout to prevent goroutine leak
	go func() {
		// Wait for the cooldown period, but respect context cancellation
		select {
		case <-time.After(alertCooldownAfterRestart):
			// continue to check health
		case <-ctx.Done():
			return // M-4: exit cleanly on cancellation
		}

		if !b.pingGateway(vm.EffectiveIP(), vm.GatewayPort) {
			b.mu.Lock()
			lastAlert := state.lastAlert
			b.mu.Unlock()

			if time.Since(lastAlert) > 10*time.Minute {
				b.mu.Lock()
				state.lastAlert = time.Now()
				b.mu.Unlock()

				// M-4: Use context with timeout for alert callback
				alertCtx, alertCancel := context.WithTimeout(ctx, 10*time.Second)
				defer alertCancel()
				b.alertFn(alertCtx, customerID,
					fmt.Sprintf("evaOS ALERT: %s still down after restart", customerID),
					fmt.Sprintf("Customer %s gateway is still unreachable after auto-restart. Manual intervention needed.", customerID),
				)
				b.logAction(customerID, "alert-sent", true, "still down after restart")
			}
		}
	}()
}

func (b *SelfHealBot) pingGateway(ip string, port int) bool {
	healthURL := fmt.Sprintf("http://%s:%d/health", ip, port)
	resp, err := defaultHTTPClient.Get(healthURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func (b *SelfHealBot) logAction(customerID, action string, success bool, errMsg string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	entry := HealAction{
		CustomerID: customerID,
		Action:     action,
		Success:    success,
		Error:      errMsg,
		Timestamp:  time.Now(),
	}
	b.healLog = append(b.healLog, entry)

	if len(b.healLog) > b.maxLogSize {
		b.healLog = b.healLog[len(b.healLog)-b.maxLogSize:]
	}

	slog.Info("self-heal action",
		"customer_id", customerID,
		"action", action,
		"success", success,
		"error", errMsg,
	)
}

// defaultHTTPClient is the HTTP client used for health checks.
// Package-level for testability.
var defaultHTTPClient = &http.Client{Timeout: 5 * time.Second}
