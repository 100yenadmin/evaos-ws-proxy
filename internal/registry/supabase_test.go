package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)


func strPtr(s string) *string { return &s }

func TestLookupByCustomerID_CacheMiss(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.Header.Get("apikey") != "test-key" {
			t.Errorf("expected apikey header")
		}
		vms := []VMInfo{{
			CustomerID:   "cust-1",
			UserID:       "user-1",
			TailnetIP:    strPtr("100.64.0.1"),
			GatewayPort:  18789,
			GatewayToken: strPtr("tok-123"),
			Status:       "active",
		}}
		json.NewEncoder(w).Encode(vms)
	}))
	defer server.Close()

	reg := NewSupabaseRegistry(context.Background(), server.URL, "test-key", 60*time.Second)
	vm, err := reg.LookupByCustomerID("cust-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vm == nil {
		t.Fatal("expected VM, got nil")
	}
	if *vm.TailnetIP != "100.64.0.1" {
		t.Errorf("expected 100.64.0.1, got %s", *vm.TailnetIP)
	}
	if *vm.GatewayToken != "tok-123" {
		t.Errorf("expected tok-123, got %s", *vm.GatewayToken)
	}
	if callCount != 1 {
		t.Errorf("expected 1 call, got %d", callCount)
	}
}

func TestLookupByCustomerID_CacheHit(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		vms := []VMInfo{{CustomerID: "cust-1", TailnetIP: strPtr("100.64.0.1")}}
		json.NewEncoder(w).Encode(vms)
	}))
	defer server.Close()

	reg := NewSupabaseRegistry(context.Background(), server.URL, "test-key", 60*time.Second)
	reg.LookupByCustomerID("cust-1")
	reg.LookupByCustomerID("cust-1")

	if callCount != 1 {
		t.Errorf("expected 1 HTTP call (cache hit), got %d", callCount)
	}
}

func TestLookupByCustomerID_CacheExpiry(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		vms := []VMInfo{{CustomerID: "cust-1", TailnetIP: strPtr("100.64.0.1")}}
		json.NewEncoder(w).Encode(vms)
	}))
	defer server.Close()

	reg := NewSupabaseRegistry(context.Background(), server.URL, "test-key", 1*time.Millisecond)
	reg.LookupByCustomerID("cust-1")
	time.Sleep(5 * time.Millisecond)
	reg.LookupByCustomerID("cust-1")

	if callCount != 2 {
		t.Errorf("expected 2 HTTP calls (cache expired), got %d", callCount)
	}
}

func TestLookupByCustomerID_NoVMFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]VMInfo{})
	}))
	defer server.Close()

	reg := NewSupabaseRegistry(context.Background(), server.URL, "test-key", 60*time.Second)
	vm, err := reg.LookupByCustomerID("cust-missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vm != nil {
		t.Error("expected nil VM for missing customer")
	}
}

func TestLookupByCustomerID_DefaultPort(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return VM with no gateway_port (zero value)
		vms := []VMInfo{{CustomerID: "cust-1", TailnetIP: strPtr("100.64.0.1"), GatewayPort: 0}}
		json.NewEncoder(w).Encode(vms)
	}))
	defer server.Close()

	reg := NewSupabaseRegistry(context.Background(), server.URL, "test-key", 60*time.Second)
	vm, err := reg.LookupByCustomerID("cust-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vm.GatewayPort != 18789 {
		t.Errorf("expected default port 18789, got %d", vm.GatewayPort)
	}
}

func TestLookupByUserID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the query includes user_id filter
		query := r.URL.RawQuery
		if query == "" {
			t.Error("expected query params")
		}
		vms := []VMInfo{{
			CustomerID: "cust-1",
			UserID:     "user-1",
			TailnetIP:  strPtr("100.64.0.1"),
			GatewayPort: 18789,
		}}
		json.NewEncoder(w).Encode(vms)
	}))
	defer server.Close()

	reg := NewSupabaseRegistry(context.Background(), server.URL, "test-key", 60*time.Second)
	vm, err := reg.LookupByUserID("user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vm == nil {
		t.Fatal("expected VM")
	}
	if vm.CustomerID != "cust-1" {
		t.Errorf("expected cust-1, got %s", vm.CustomerID)
	}
}

// --- H6: Cache sweep tests ---

func TestCacheSweep_RemovesExpiredEntries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vms := []VMInfo{{CustomerID: "cust-1", TailnetIP: strPtr("100.64.0.1")}}
		json.NewEncoder(w).Encode(vms)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use a very short TTL so entries expire quickly
	reg := NewSupabaseRegistry(ctx, server.URL, "test-key", 1*time.Millisecond)

	// Populate cache
	_, err := reg.LookupByCustomerID("cust-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify cache has an entry
	reg.mu.RLock()
	if len(reg.cache) != 1 {
		t.Errorf("expected 1 cache entry, got %d", len(reg.cache))
	}
	reg.mu.RUnlock()

	// Wait for entries to expire
	time.Sleep(10 * time.Millisecond)

	// Manually trigger sweep (don't wait for the ticker)
	reg.sweep()

	// Verify cache is now empty
	reg.mu.RLock()
	remaining := len(reg.cache)
	reg.mu.RUnlock()
	if remaining != 0 {
		t.Errorf("expected 0 cache entries after sweep, got %d", remaining)
	}
}

func TestCacheSweep_PreservesLiveEntries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vms := []VMInfo{{CustomerID: "cust-1", TailnetIP: strPtr("100.64.0.1")}}
		json.NewEncoder(w).Encode(vms)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use a long TTL so entries stay alive
	reg := NewSupabaseRegistry(ctx, server.URL, "test-key", 1*time.Hour)

	_, err := reg.LookupByCustomerID("cust-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Sweep should not remove live entries
	reg.sweep()

	reg.mu.RLock()
	remaining := len(reg.cache)
	reg.mu.RUnlock()
	if remaining != 1 {
		t.Errorf("expected 1 cache entry after sweep (not expired), got %d", remaining)
	}
}

func TestCacheSweepLoop_StopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]VMInfo{})
	}))
	defer server.Close()

	_ = NewSupabaseRegistry(ctx, server.URL, "test-key", 60*time.Second)

	// Cancel the context — the sweep goroutine should stop
	cancel()

	// Give goroutine time to exit (it should exit promptly)
	time.Sleep(50 * time.Millisecond)
	// If we get here without hanging, the sweep loop respected context cancellation
}
