package proxy

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	defaultSSHUser    = "root"
	defaultSSHKeyPath = "/root/.ssh/id_ed25519"
	restartCooldown   = 120 * time.Second
	sshTimeout        = 10 * time.Second
	restartCommand    = "systemctl restart openclaw-gateway"
)

// RestartManager handles gateway restart requests with rate limiting.
type RestartManager struct {
	sshUser    string
	sshKeyPath string
	cooldowns  sync.Map // map[customerID]time.Time
}

// NewRestartManager creates a new restart manager.
func NewRestartManager() *RestartManager {
	user := os.Getenv("SSH_USER")
	if user == "" {
		user = defaultSSHUser
	}
	keyPath := os.Getenv("SSH_KEY_PATH")
	if keyPath == "" {
		keyPath = defaultSSHKeyPath
	}
	return &RestartManager{
		sshUser:    user,
		sshKeyPath: keyPath,
	}
}

// restartResponse is the JSON response for restart requests.
type restartResponse struct {
	Status           string `json:"status"`
	CooldownSeconds  int    `json:"cooldown_seconds,omitempty"`
	RemainingSeconds int    `json:"remaining_seconds,omitempty"`
	Message          string `json:"message,omitempty"`
}

// CheckCooldown returns the remaining cooldown seconds for a customer, or 0 if ready.
func (rm *RestartManager) CheckCooldown(customerID string) int {
	if val, ok := rm.cooldowns.Load(customerID); ok {
		lastRestart := val.(time.Time)
		elapsed := time.Since(lastRestart)
		if elapsed < restartCooldown {
			return int((restartCooldown - elapsed).Seconds()) + 1
		}
	}
	return 0
}

// Restart executes a gateway restart on the customer VM via SSH.
func (rm *RestartManager) Restart(customerID, vmIP string, vmPort int) error {
	// Record restart time
	rm.cooldowns.Store(customerID, time.Now())

	signer, err := rm.loadSSHKey()
	if err != nil {
		return fmt.Errorf("load SSH key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: rm.sshUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Customer VMs — we control them
		Timeout:         sshTimeout,
	}

	addr := fmt.Sprintf("%s:22", vmIP)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("SSH dial %s: %w", addr, err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("SSH session: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(restartCommand)
	if err != nil {
		return fmt.Errorf("restart command failed: %w (output: %s)", err, string(output))
	}

	slog.Info("gateway restarted via SSH",
		"customer_id", customerID,
		"vm_ip", vmIP,
		"output", string(output),
	)
	return nil
}

func (rm *RestartManager) loadSSHKey() (ssh.Signer, error) {
	key, err := os.ReadFile(rm.sshKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", rm.sshKeyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	return signer, nil
}

// HandleRestart handles POST /vm/{customer_id}/restart requests.
func (h *Handler) HandleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	customerID := extractCustomerID(r.URL.Path)
	if customerID == "" || !customerIDPattern.MatchString(customerID) {
		http.Error(w, "invalid customer_id", http.StatusBadRequest)
		return
	}

	// Require JWT auth
	tokenStr := extractToken(r)
	if tokenStr == "" {
		writeJSON(w, http.StatusUnauthorized, restartResponse{
			Status:  "error",
			Message: "unauthorized",
		})
		return
	}

	claims, err := h.jwt.Validate(tokenStr)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, restartResponse{
			Status:  "error",
			Message: "invalid token",
		})
		return
	}

	// Look up VM
	vm, err := h.vms.LookupByCustomerID(customerID)
	if err != nil {
		slog.Error("restart: vm lookup failed", "error", err, "customer_id", customerID)
		writeJSON(w, http.StatusInternalServerError, restartResponse{
			Status:  "error",
			Message: "internal error",
		})
		return
	}
	if vm == nil {
		writeJSON(w, http.StatusNotFound, restartResponse{
			Status:  "error",
			Message: "no VM assigned",
		})
		return
	}

	// Verify ownership (unless admin)
	if vm.UserID != claims.UserID && !h.isAdmin(claims.Email) {
		writeJSON(w, http.StatusForbidden, restartResponse{
			Status:  "error",
			Message: "forbidden",
		})
		return
	}

	// Check cooldown
	if remaining := h.restarts.CheckCooldown(customerID); remaining > 0 {
		writeJSON(w, http.StatusTooManyRequests, restartResponse{
			Status:           "cooldown",
			RemainingSeconds: remaining,
		})
		return
	}

	// Execute restart (async — return immediately, restart happens in background)
	go func() {
		if err := h.restarts.Restart(customerID, vm.EffectiveIP(), vm.GatewayPort); err != nil {
			slog.Error("restart failed",
				"customer_id", customerID,
				"error", err,
			)
		}
	}()

	writeJSON(w, http.StatusOK, restartResponse{
		Status:          "restarting",
		CooldownSeconds: int(restartCooldown.Seconds()),
	})
}

// writeJSONRestart writes a JSON restart response (used internally).
func writeJSONRestart(w http.ResponseWriter, status int, resp restartResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}
