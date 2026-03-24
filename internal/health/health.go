package health

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"
)

// Handler tracks connection count and uptime for health checks.
type Handler struct {
	connections atomic.Int64
	startTime  time.Time
}

// NewHandler creates a new health handler.
func NewHandler() *Handler {
	return &Handler{
		startTime: time.Now(),
	}
}

// AddConnection increments the active connection count.
func (h *Handler) AddConnection() {
	h.connections.Add(1)
}

// RemoveConnection decrements the active connection count.
func (h *Handler) RemoveConnection() {
	h.connections.Add(-1)
}

// ConnectionCount returns the current number of active connections.
func (h *Handler) ConnectionCount() int64 {
	return h.connections.Load()
}

// HandleHealth serves the health check endpoint.
func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "ok",
		"connections":    h.connections.Load(),
		"uptime_seconds": int(time.Since(h.startTime).Seconds()),
	})
}
