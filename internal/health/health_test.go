package health

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleHealth(t *testing.T) {
	h := NewHandler()

	// Add some connections
	h.AddConnection()
	h.AddConnection()
	h.AddConnection()
	h.RemoveConnection()

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	h.HandleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if resp["status"] != "ok" {
		t.Errorf("expected status ok, got %v", resp["status"])
	}

	conns, ok := resp["connections"].(float64)
	if !ok || int(conns) != 2 {
		t.Errorf("expected 2 connections, got %v", resp["connections"])
	}

	if _, ok := resp["uptime_seconds"]; !ok {
		t.Error("expected uptime_seconds field")
	}
}

func TestConnectionCount(t *testing.T) {
	h := NewHandler()
	if h.ConnectionCount() != 0 {
		t.Error("expected 0 initial connections")
	}

	h.AddConnection()
	h.AddConnection()
	if h.ConnectionCount() != 2 {
		t.Errorf("expected 2, got %d", h.ConnectionCount())
	}

	h.RemoveConnection()
	if h.ConnectionCount() != 1 {
		t.Errorf("expected 1, got %d", h.ConnectionCount())
	}
}
