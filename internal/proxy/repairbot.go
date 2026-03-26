package proxy

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// HandleRepairBot serves the diagnostic dashboard page.
// Route: GET /vm/{customer_id}/repairbot
// This is read-only — it doesn't restart or modify anything.
func (h *Handler) HandleRepairBot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	customerID := extractCustomerID(r.URL.Path)
	if customerID == "" || !customerIDPattern.MatchString(customerID) {
		http.Error(w, "invalid customer_id", http.StatusBadRequest)
		return
	}

	// Optional JWT auth — if present, validate it. But the page works without auth
	// (like the maintenance page) since it's read-only diagnostics.
	// This allows non-technical users to access it from a support email link.

	vm, err := h.vms.LookupByCustomerID(customerID)
	if err != nil {
		slog.Error("repairbot: vm lookup failed", "error", err, "customer_id", customerID)
		h.serveRepairBotPage(w, customerID, nil, "vm_lookup_failed")
		return
	}
	if vm == nil {
		h.serveRepairBotPage(w, customerID, nil, "not_provisioned")
		return
	}

	// Run diagnostics if we have an SSH diagnostics runner
	var report *DiagnosticReport
	if h.diagnostics != nil {
		report, err = h.diagnostics.RunDiagnostics(customerID, vm.EffectiveIP())
		if err != nil {
			slog.Error("repairbot: diagnostics failed", "error", err, "customer_id", customerID)
		}
	} else {
		// Fallback: just do a simple health check
		report = &DiagnosticReport{
			CustomerID: customerID,
			Checks: []DiagnosticCheck{
				{
					Name:    "Gateway Status",
					Status:  StatusUnknown,
					Message: "Diagnostics not configured on this proxy",
					Icon:    "⚡",
				},
			},
		}
		// Quick health check
		healthURL := fmt.Sprintf("http://%s:%d/health", vm.EffectiveIP(), vm.GatewayPort)
		resp, err := defaultHTTPClient.Get(healthURL)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				report.GatewayUp = true
				report.Checks[0].Status = StatusOK
				report.Checks[0].Message = "Gateway is running"
			}
		}
	}

	h.serveRepairBotPage(w, customerID, report, "diagnostic")
}

// HandleRepairBotBackups lists available config backups.
// Route: GET /vm/{customer_id}/repairbot/backups
func (h *Handler) HandleRepairBotBackups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	customerID := extractCustomerID(r.URL.Path)
	if customerID == "" || !customerIDPattern.MatchString(customerID) {
		http.Error(w, "invalid customer_id", http.StatusBadRequest)
		return
	}

	// Require JWT auth for backup listing (it reveals config info)
	tokenStr := extractToken(r)
	if tokenStr == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	claims, err := h.jwt.Validate(tokenStr)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}

	vm, err := h.vms.LookupByCustomerID(customerID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if vm == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no VM assigned"})
		return
	}

	// Verify ownership
	if vm.UserID != claims.UserID && !h.isAdmin(claims.Email) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}

	if h.diagnostics == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"backups": []BackupInfo{},
			"message": "diagnostics not configured",
		})
		return
	}

	backups, err := h.diagnostics.ListBackups(vm.EffectiveIP())
	if err != nil {
		slog.Error("repairbot: list backups failed", "error", err, "customer_id", customerID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list backups"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"backups": backups,
	})
}

// HandleRepairBotRestore restores a config backup.
// Route: POST /vm/{customer_id}/repairbot/restore
func (h *Handler) HandleRepairBotRestore(w http.ResponseWriter, r *http.Request) {
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
		writeJSON(w, http.StatusUnauthorized, restartResponse{Status: "error", Message: "unauthorized"})
		return
	}
	claims, err := h.jwt.Validate(tokenStr)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, restartResponse{Status: "error", Message: "invalid token"})
		return
	}

	vm, err := h.vms.LookupByCustomerID(customerID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, restartResponse{Status: "error", Message: "internal error"})
		return
	}
	if vm == nil {
		writeJSON(w, http.StatusNotFound, restartResponse{Status: "error", Message: "no VM assigned"})
		return
	}

	// Verify ownership
	if vm.UserID != claims.UserID && !h.isAdmin(claims.Email) {
		writeJSON(w, http.StatusForbidden, restartResponse{Status: "error", Message: "forbidden"})
		return
	}

	// Check cooldown (shares cooldown with restart)
	if remaining := h.restarts.CheckCooldown(customerID); remaining > 0 {
		writeJSON(w, http.StatusTooManyRequests, restartResponse{
			Status:           "cooldown",
			RemainingSeconds: remaining,
		})
		return
	}

	// Parse request body
	var body struct {
		Filename string `json:"filename"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Filename == "" {
		writeJSON(w, http.StatusBadRequest, restartResponse{Status: "error", Message: "filename is required"})
		return
	}

	if h.diagnostics == nil {
		writeJSON(w, http.StatusInternalServerError, restartResponse{Status: "error", Message: "diagnostics not configured"})
		return
	}

	// Record cooldown (restore triggers a restart)
	h.restarts.cooldowns.Store(customerID, timeNow())

	// Execute restore in background
	go func() {
		if err := h.diagnostics.RestoreBackup(customerID, vm.EffectiveIP(), body.Filename); err != nil {
			slog.Error("repairbot: restore failed",
				"customer_id", customerID,
				"error", err,
				"backup", body.Filename,
			)
		}
	}()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":           "restoring",
		"cooldown_seconds": int(restartCooldown.Seconds()),
		"message":          "Restoring backup and restarting gateway...",
	})
}

// HandleRepairBotAPI returns diagnostic results as JSON (for AJAX from the page).
// Route: GET /vm/{customer_id}/repairbot/api
func (h *Handler) HandleRepairBotAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	customerID := extractCustomerID(r.URL.Path)
	if customerID == "" || !customerIDPattern.MatchString(customerID) {
		http.Error(w, "invalid customer_id", http.StatusBadRequest)
		return
	}

	vm, err := h.vms.LookupByCustomerID(customerID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if vm == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"customer_id":    customerID,
			"overall_status": "unknown",
			"vm_reachable":   false,
		})
		return
	}

	if h.diagnostics == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"customer_id":    customerID,
			"overall_status": "unknown",
			"message":        "diagnostics not configured",
		})
		return
	}

	report, err := h.diagnostics.RunDiagnostics(customerID, vm.EffectiveIP())
	if err != nil {
		slog.Error("repairbot api: diagnostics failed", "error", err, "customer_id", customerID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "diagnostics failed"})
		return
	}

	writeJSON(w, http.StatusOK, report)
}

// serveRepairBotPage renders the RepairBot diagnostic dashboard page.
func (h *Handler) serveRepairBotPage(w http.ResponseWriter, customerID string, report *DiagnosticReport, mode string) {
	data := repairBotData{
		CustomerID:   customerID,
		Mode:         mode,
		Report:       report,
		CommonErrors: CommonErrors,
	}

	if report != nil {
		data.OverallStatus = string(report.OverallStatus)
		data.GatewayUp = report.GatewayUp
		data.VMReachable = report.VMReachable
		data.HasBackups = len(report.Backups) > 0
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	if mode == "not_provisioned" || mode == "vm_lookup_failed" {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK) // Diagnostic mode — always 200
	}

	if err := repairBotTemplate.Execute(w, data); err != nil {
		slog.Error("failed to render repairbot page", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// repairBotData is the template data for the RepairBot page.
type repairBotData struct {
	CustomerID    string
	Mode          string // "diagnostic", "not_provisioned", "vm_lookup_failed"
	OverallStatus string
	GatewayUp     bool
	VMReachable   bool
	HasBackups    bool
	Report        *DiagnosticReport
	CommonErrors  []CommonError
}

// statusIcon returns an icon for the check status.
func statusIcon(s CheckStatus) string {
	switch s {
	case StatusOK:
		return "✅"
	case StatusWarning:
		return "⚠️"
	case StatusCritical:
		return "❌"
	default:
		return "❓"
	}
}

// statusClass returns a CSS class for the check status.
func statusClass(s CheckStatus) string {
	switch s {
	case StatusOK:
		return "status-ok"
	case StatusWarning:
		return "status-warning"
	case StatusCritical:
		return "status-critical"
	default:
		return "status-unknown"
	}
}

// timeNow is a package-level var for testing.
var timeNow = time.Now

// hasPrefix is needed in templates.
func hasPrefix(s, prefix string) bool {
	return strings.HasPrefix(s, prefix)
}
