package registry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

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
			TailnetIP:    "100.64.0.1",
			GatewayPort:  18789,
			GatewayToken: "tok-123",
			Status:       "active",
		}}
		json.NewEncoder(w).Encode(vms)
	}))
	defer server.Close()

	reg := NewSupabaseRegistry(server.URL, "test-key", 60*time.Second)
	vm, err := reg.LookupByCustomerID("cust-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vm == nil {
		t.Fatal("expected VM, got nil")
	}
	if vm.TailnetIP != "100.64.0.1" {
		t.Errorf("expected 100.64.0.1, got %s", vm.TailnetIP)
	}
	if vm.GatewayToken != "tok-123" {
		t.Errorf("expected tok-123, got %s", vm.GatewayToken)
	}
	if callCount != 1 {
		t.Errorf("expected 1 call, got %d", callCount)
	}
}

func TestLookupByCustomerID_CacheHit(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		vms := []VMInfo{{CustomerID: "cust-1", TailnetIP: "100.64.0.1"}}
		json.NewEncoder(w).Encode(vms)
	}))
	defer server.Close()

	reg := NewSupabaseRegistry(server.URL, "test-key", 60*time.Second)
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
		vms := []VMInfo{{CustomerID: "cust-1", TailnetIP: "100.64.0.1"}}
		json.NewEncoder(w).Encode(vms)
	}))
	defer server.Close()

	reg := NewSupabaseRegistry(server.URL, "test-key", 1*time.Millisecond)
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

	reg := NewSupabaseRegistry(server.URL, "test-key", 60*time.Second)
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
		vms := []VMInfo{{CustomerID: "cust-1", TailnetIP: "100.64.0.1", GatewayPort: 0}}
		json.NewEncoder(w).Encode(vms)
	}))
	defer server.Close()

	reg := NewSupabaseRegistry(server.URL, "test-key", 60*time.Second)
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
			TailnetIP:  "100.64.0.1",
			GatewayPort: 18789,
		}}
		json.NewEncoder(w).Encode(vms)
	}))
	defer server.Close()

	reg := NewSupabaseRegistry(server.URL, "test-key", 60*time.Second)
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
