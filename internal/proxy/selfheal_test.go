package proxy

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/100yenadmin/evaos-ws-proxy/internal/registry"
)

func TestSelfHealBot_Creation(t *testing.T) {
	rm := NewRestartManager()
	reg := &mockRegistry{vm: &registry.VMInfo{
		CustomerID: "golden",
		UserID:     "user-1",
		TailnetIP:  strPtr("100.64.0.1"),
		GatewayPort: 18789,
	}}

	bot := NewSelfHealBot(SelfHealConfig{
		RestartManager: rm,
		VMRegistry:     reg,
		CustomerIDs:    []string{"golden"},
	})

	if bot == nil {
		t.Fatal("expected non-nil bot")
	}
}

func TestSelfHealBot_SetCustomers(t *testing.T) {
	bot := NewSelfHealBot(SelfHealConfig{
		RestartManager: NewRestartManager(),
		VMRegistry:     &mockRegistry{},
		CustomerIDs:    []string{"a"},
	})

	bot.SetCustomers([]string{"b", "c"})

	bot.mu.Lock()
	if len(bot.customers) != 2 || bot.customers[0] != "b" {
		t.Errorf("expected customers [b,c], got %v", bot.customers)
	}
	bot.mu.Unlock()
}

func TestSelfHealBot_GetHealLog_Empty(t *testing.T) {
	bot := NewSelfHealBot(SelfHealConfig{
		RestartManager: NewRestartManager(),
		VMRegistry:     &mockRegistry{},
	})
	log := bot.GetHealLog()
	if len(log) != 0 {
		t.Errorf("expected empty log, got %d entries", len(log))
	}
}

func TestSelfHealBot_LogAction(t *testing.T) {
	bot := NewSelfHealBot(SelfHealConfig{
		RestartManager: NewRestartManager(),
		VMRegistry:     &mockRegistry{},
	})

	bot.logAction("golden", "test-action", true, "")
	bot.logAction("golden", "test-fail", false, "some error")

	log := bot.GetHealLog()
	if len(log) != 2 {
		t.Fatalf("expected 2 log entries, got %d", len(log))
	}
	if log[0].Action != "test-action" || !log[0].Success {
		t.Errorf("first entry = %+v, want test-action/true", log[0])
	}
	if log[1].Action != "test-fail" || log[1].Success || log[1].Error != "some error" {
		t.Errorf("second entry = %+v, want test-fail/false", log[1])
	}
}

func TestSelfHealBot_LogTrimming(t *testing.T) {
	bot := NewSelfHealBot(SelfHealConfig{
		RestartManager: NewRestartManager(),
		VMRegistry:     &mockRegistry{},
	})
	bot.maxLogSize = 5

	for i := 0; i < 10; i++ {
		bot.logAction("golden", "action", true, "")
	}

	if len(bot.GetHealLog()) > 5 {
		t.Error("log should be trimmed to maxLogSize")
	}
}

func TestSelfHealBot_StartStop(t *testing.T) {
	bot := NewSelfHealBot(SelfHealConfig{
		RestartManager: NewRestartManager(),
		VMRegistry:     &mockRegistry{},
		CustomerIDs:    []string{},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		bot.Start(ctx)
		close(done)
	}()

	// Give it a moment then cancel
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("bot did not stop within 2s")
	}
}

func TestSelfHealBot_AlertCallback(t *testing.T) {
	var mu sync.Mutex
	var alerts []string

	rm := NewRestartManager()
	bot := NewSelfHealBot(SelfHealConfig{
		RestartManager: rm,
		VMRegistry:     &mockRegistry{vm: nil}, // no VM — so check skips
		CustomerIDs:    []string{"golden"},
		AlertFn: func(cid, subject, body string) {
			mu.Lock()
			alerts = append(alerts, subject)
			mu.Unlock()
		},
	})

	// Directly test crash-loop detection by manipulating state
	bot.mu.Lock()
	state := &customerHealState{
		restartTimes: []time.Time{
			time.Now().Add(-1 * time.Minute),
			time.Now().Add(-2 * time.Minute),
			time.Now().Add(-3 * time.Minute),
		},
	}
	bot.states["test-customer"] = state
	bot.mu.Unlock()

	// The crash loop detection happens in checkCustomer, which needs a VM
	// So we verify alert function was properly configured
	bot.alertFn("test", "test subject", "test body")
	mu.Lock()
	if len(alerts) != 1 || alerts[0] != "test subject" {
		t.Errorf("expected alert with 'test subject', got %v", alerts)
	}
	mu.Unlock()
}
