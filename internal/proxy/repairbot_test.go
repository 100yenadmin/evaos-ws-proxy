package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/100yenadmin/evaos-ws-proxy/internal/auth"
	"github.com/100yenadmin/evaos-ws-proxy/internal/registry"
)

// mockDiagnostics implements DiagnosticsRunner for testing.
type mockDiagnostics struct {
	report       *DiagnosticReport
	reportErr    error
	backups      []BackupInfo
	backupsErr   error
	restoreErr   error
	restoreCalls []string
}

func (m *mockDiagnostics) RunDiagnostics(customerID, vmIP string) (*DiagnosticReport, error) {
	if m.reportErr != nil {
		return nil, m.reportErr
	}
	if m.report != nil {
		return m.report, nil
	}
	return &DiagnosticReport{
		CustomerID:    customerID,
		OverallStatus: StatusOK,
		GatewayUp:     true,
		VMReachable:   true,
		Checks: []DiagnosticCheck{
			{Name: "Gateway Status", Status: StatusOK, Message: "Gateway is running", Icon: "⚡"},
			{Name: "Disk Space", Status: StatusOK, Message: "Disk usage normal: 42% used", Icon: "💾"},
		},
	}, nil
}

func (m *mockDiagnostics) ListBackups(vmIP string) ([]BackupInfo, error) {
	return m.backups, m.backupsErr
}

func (m *mockDiagnostics) RestoreBackup(customerID, vmIP, filename string) error {
	m.restoreCalls = append(m.restoreCalls, filename)
	return m.restoreErr
}

func newTestHandlerWithDiag(jwt JWTValidator, vms VMRegistry, diag DiagnosticsRunner, opts ...func(*HandlerConfig)) *Handler {
	cfg := HandlerConfig{
		JWTValidator:   jwt,
		VMRegistry:     vms,
		Diagnostics:    diag,
		MaxConnections: 100,
		ConnectTimeout: 5 * time.Second,
	}
	for _, o := range opts {
		o(&cfg)
	}
	return NewHandler(cfg)
}

// --- RepairBot page tests ---

func TestRepairBot_RendersDiagnosticPage(t *testing.T) {
	diag := &mockDiagnostics{}
	h := newTestHandlerWithDiag(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID:  "golden",
			UserID:      "user-1",
			TailnetIP:   strPtr("100.64.0.1"),
			GatewayPort: 18789,
		}},
		diag,
	)

	req := httptest.NewRequest("GET", "/vm/golden/repairbot", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleRepairBot(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	checks := []string{
		"evaOS RepairBot",
		"golden",
		"System Diagnostics",
		"Gateway Status",
		"Quick Actions",
		"Common Issues",
		"Electric Sheep",
	}
	for _, check := range checks {
		if !strings.Contains(body, check) {
			t.Errorf("repairbot page missing %q", check)
		}
	}

	// Should have content-type html
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html, got %q", ct)
	}
}

func TestRepairBot_NoVMShowsProvisioning(t *testing.T) {
	h := newTestHandlerWithDiag(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: nil},
		&mockDiagnostics{},
	)
	req := httptest.NewRequest("GET", "/vm/new-customer/repairbot", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleRepairBot(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "being set up") {
		t.Error("expected provisioning message")
	}
}

func TestRepairBot_MethodNotAllowed(t *testing.T) {
	h := newTestHandlerWithDiag(&mockJWT{}, &mockRegistry{}, &mockDiagnostics{})
	req := httptest.NewRequest("POST", "/vm/golden/repairbot", nil)
	w := httptest.NewRecorder()
	h.HandleRepairBot(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestRepairBot_InvalidCustomerID(t *testing.T) {
	h := newTestHandlerWithDiag(&mockJWT{}, &mockRegistry{}, &mockDiagnostics{})
	req := httptest.NewRequest("GET", "/vm/../../etc/passwd/repairbot", nil)
	w := httptest.NewRecorder()
	h.HandleRepairBot(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestRepairBot_NoDiagnosticsConfigured(t *testing.T) {
	// When diagnostics runner is nil, page should still render (with fallback)
	h := newTestHandlerWithDiag(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID:  "golden",
			UserID:      "user-1",
			TailnetIP:   strPtr("127.0.0.1"),
			GatewayPort: 59999, // not listening
		}},
		nil, // no diagnostics runner
	)

	req := httptest.NewRequest("GET", "/vm/golden/repairbot", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleRepairBot(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "evaOS RepairBot") {
		t.Error("expected repairbot branding")
	}
}

func TestRepairBot_DoesNotTriggerRestart(t *testing.T) {
	// Ensure the repairbot GET page doesn't restart anything
	rm := NewRestartManager()
	diag := &mockDiagnostics{}
	h := newTestHandlerWithDiag(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID:  "golden",
			UserID:      "user-1",
			TailnetIP:   strPtr("100.64.0.1"),
			GatewayPort: 18789,
		}},
		diag,
		func(cfg *HandlerConfig) { cfg.RestartManager = rm },
	)

	req := httptest.NewRequest("GET", "/vm/golden/repairbot", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleRepairBot(w, req)

	// No cooldown should be set (no restart triggered)
	if remaining := rm.CheckCooldown("golden"); remaining > 0 {
		t.Errorf("repairbot page should not trigger restart, but cooldown is %ds", remaining)
	}
}

func TestRepairBot_MobileResponsive(t *testing.T) {
	h := newTestHandlerWithDiag(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "golden",
			UserID:     "user-1",
			TailnetIP:  strPtr("100.64.0.1"),
		}},
		&mockDiagnostics{},
	)
	req := httptest.NewRequest("GET", "/vm/golden/repairbot", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleRepairBot(w, req)
	if !strings.Contains(w.Body.String(), "viewport") {
		t.Error("repairbot page must include viewport meta for mobile")
	}
}

// --- H-1: RepairBot page requires auth ---

func TestRepairBot_RequiresAuth(t *testing.T) {
	h := newTestHandlerWithDiag(
		&mockJWT{err: fmt.Errorf("no token")},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "golden",
			UserID:     "user-1",
			TailnetIP:  strPtr("100.64.0.1"),
		}},
		&mockDiagnostics{},
	)
	req := httptest.NewRequest("GET", "/vm/golden/repairbot", nil)
	w := httptest.NewRecorder()
	h.HandleRepairBot(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Login Required") {
		t.Error("expected unauth page with Login Required")
	}
	if !strings.Contains(body, "Contact Support") {
		t.Error("expected unauth page with Contact Support link")
	}
}

func TestRepairBot_ForbiddenForWrongUser(t *testing.T) {
	h := newTestHandlerWithDiag(
		&mockJWT{claims: &auth.Claims{UserID: "wrong-user", Email: "hacker@evil.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "golden",
			UserID:     "user-owner",
			TailnetIP:  strPtr("100.64.0.1"),
		}},
		&mockDiagnostics{},
	)
	req := httptest.NewRequest("GET", "/vm/golden/repairbot", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleRepairBot(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

// --- RepairBot API tests ---

func TestRepairBotAPI_ReturnsDiagnostics(t *testing.T) {
	diag := &mockDiagnostics{
		report: &DiagnosticReport{
			CustomerID:    "golden",
			OverallStatus: StatusWarning,
			GatewayUp:     true,
			VMReachable:   true,
			Checks: []DiagnosticCheck{
				{Name: "Disk", Status: StatusWarning, Message: "Disk 85%"},
			},
		},
	}
	h := newTestHandlerWithDiag(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "golden",
			UserID:     "user-1",
			TailnetIP:  strPtr("100.64.0.1"),
		}},
		diag,
	)

	req := httptest.NewRequest("GET", "/vm/golden/repairbot/api", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleRepairBotAPI(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var report DiagnosticReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if report.OverallStatus != StatusWarning {
		t.Errorf("expected overall_status=warning, got %s", report.OverallStatus)
	}
	if len(report.Checks) != 1 || report.Checks[0].Name != "Disk" {
		t.Error("expected disk check in response")
	}
}

func TestRepairBotAPI_NoVM(t *testing.T) {
	h := newTestHandlerWithDiag(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: nil},
		&mockDiagnostics{},
	)
	req := httptest.NewRequest("GET", "/vm/missing/repairbot/api", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleRepairBotAPI(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["vm_reachable"] != false {
		t.Error("expected vm_reachable=false")
	}
}

// H-1: RepairBot API requires auth
func TestRepairBotAPI_RequiresAuth(t *testing.T) {
	h := newTestHandlerWithDiag(
		&mockJWT{err: fmt.Errorf("no token")},
		&mockRegistry{vm: nil},
		&mockDiagnostics{},
	)
	req := httptest.NewRequest("GET", "/vm/golden/repairbot/api", nil)
	w := httptest.NewRecorder()
	h.HandleRepairBotAPI(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// --- Backups endpoint tests ---

func TestRepairBotBackups_ReturnsBackupList(t *testing.T) {
	diag := &mockDiagnostics{
		backups: []BackupInfo{
			{Filename: "/root/.openclaw/openclaw.json.backup-20260325", Size: "1234"},
			{Filename: "/root/.openclaw/openclaw.json.backup-20260324", Size: "1200"},
		},
	}
	h := newTestHandlerWithDiag(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "golden",
			UserID:     "user-1",
			TailnetIP:  strPtr("100.64.0.1"),
		}},
		diag,
	)

	req := httptest.NewRequest("GET", "/vm/golden/repairbot/backups", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleRepairBotBackups(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	backups := resp["backups"].([]interface{})
	if len(backups) != 2 {
		t.Errorf("expected 2 backups, got %d", len(backups))
	}
}

func TestRepairBotBackups_RequiresAuth(t *testing.T) {
	h := newTestHandlerWithDiag(
		&mockJWT{err: fmt.Errorf("no token")},
		&mockRegistry{},
		&mockDiagnostics{},
	)
	req := httptest.NewRequest("GET", "/vm/golden/repairbot/backups", nil)
	w := httptest.NewRecorder()
	h.HandleRepairBotBackups(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestRepairBotBackups_ForbiddenForWrongUser(t *testing.T) {
	h := newTestHandlerWithDiag(
		&mockJWT{claims: &auth.Claims{UserID: "wrong-user", Email: "hacker@evil.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "golden",
			UserID:     "user-owner",
			TailnetIP:  strPtr("100.64.0.1"),
		}},
		&mockDiagnostics{},
	)
	req := httptest.NewRequest("GET", "/vm/golden/repairbot/backups", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleRepairBotBackups(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

// --- Restore endpoint tests ---

func TestRepairBotRestore_Success(t *testing.T) {
	diag := &mockDiagnostics{}
	rm := NewRestartManager()
	h := newTestHandlerWithDiag(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "golden",
			UserID:     "user-1",
			TailnetIP:  strPtr("100.64.0.1"),
		}},
		diag,
		func(cfg *HandlerConfig) { cfg.RestartManager = rm },
	)

	body := strings.NewReader(`{"filename":"/root/.openclaw/openclaw.json.backup-20260325"}`)
	req := httptest.NewRequest("POST", "/vm/golden/repairbot/restore", body)
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandleRepairBotRestore(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "restoring" {
		t.Errorf("expected status=restoring, got %v", resp["status"])
	}

	// Wait for background goroutine
	time.Sleep(50 * time.Millisecond)

	// Verify cooldown was set
	if remaining := rm.CheckCooldown("golden"); remaining <= 0 {
		t.Error("expected cooldown after restore")
	}
}

func TestRepairBotRestore_RequiresAuth(t *testing.T) {
	h := newTestHandlerWithDiag(
		&mockJWT{err: fmt.Errorf("no token")},
		&mockRegistry{},
		&mockDiagnostics{},
	)
	body := strings.NewReader(`{"filename":"backup"}`)
	req := httptest.NewRequest("POST", "/vm/golden/repairbot/restore", body)
	w := httptest.NewRecorder()
	h.HandleRepairBotRestore(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestRepairBotRestore_Cooldown(t *testing.T) {
	rm := NewRestartManager()
	rm.SetCooldown("golden")

	h := newTestHandlerWithDiag(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "golden",
			UserID:     "user-1",
			TailnetIP:  strPtr("100.64.0.1"),
		}},
		&mockDiagnostics{},
		func(cfg *HandlerConfig) { cfg.RestartManager = rm },
	)

	body := strings.NewReader(`{"filename":"/root/.openclaw/openclaw.json.backup-20260325"}`)
	req := httptest.NewRequest("POST", "/vm/golden/repairbot/restore", body)
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandleRepairBotRestore(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
}

func TestRepairBotRestore_MissingFilename(t *testing.T) {
	h := newTestHandlerWithDiag(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "golden",
			UserID:     "user-1",
			TailnetIP:  strPtr("100.64.0.1"),
		}},
		&mockDiagnostics{},
	)

	body := strings.NewReader(`{}`)
	req := httptest.NewRequest("POST", "/vm/golden/repairbot/restore", body)
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandleRepairBotRestore(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// H-2: CSRF protection on restore endpoint
func TestRepairBotRestore_RejectsBadOrigin(t *testing.T) {
	h := newTestHandlerWithDiag(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "golden",
			UserID:     "user-1",
			TailnetIP:  strPtr("100.64.0.1"),
		}},
		&mockDiagnostics{},
	)

	body := strings.NewReader(`{"filename":"/root/.openclaw/openclaw.json.backup-20260325"}`)
	req := httptest.NewRequest("POST", "/vm/golden/repairbot/restore", body)
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("Origin", "https://evil.com")
	w := httptest.NewRecorder()
	h.HandleRepairBotRestore(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for bad origin, got %d", w.Code)
	}
}

// H-2: Restore rejects cookie-only auth
func TestRepairBotRestore_RejectsCookieOnlyAuth(t *testing.T) {
	h := newTestHandlerWithDiag(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "golden",
			UserID:     "user-1",
			TailnetIP:  strPtr("100.64.0.1"),
		}},
		&mockDiagnostics{},
	)

	body := strings.NewReader(`{"filename":"/root/.openclaw/openclaw.json.backup-20260325"}`)
	req := httptest.NewRequest("POST", "/vm/golden/repairbot/restore", body)
	// Only cookie auth, no Authorization header
	req.AddCookie(&http.Cookie{Name: "sb-abc-auth-token", Value: "cookie-jwt"})
	w := httptest.NewRecorder()
	h.HandleRepairBotRestore(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for cookie-only auth on mutating endpoint, got %d", w.Code)
	}
}

// M-3: Request body size limit on restore
func TestRepairBotRestore_RejectsLargeBody(t *testing.T) {
	h := newTestHandlerWithDiag(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "golden",
			UserID:     "user-1",
			TailnetIP:  strPtr("100.64.0.1"),
		}},
		&mockDiagnostics{},
	)

	// Create a body larger than 1KB
	largeBody := strings.Repeat("x", 2048)
	body := strings.NewReader(`{"filename":"` + largeBody + `"}`)
	req := httptest.NewRequest("POST", "/vm/golden/repairbot/restore", body)
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandleRepairBotRestore(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for oversized body, got %d", w.Code)
	}
}

// --- ServeHTTP routing tests for RepairBot ---

func TestServeHTTP_RoutesToRepairBot(t *testing.T) {
	diag := &mockDiagnostics{}
	h := newTestHandlerWithDiag(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "golden",
			UserID:     "user-1",
			TailnetIP:  strPtr("100.64.0.1"),
		}},
		diag,
	)
	server := httptest.NewServer(h)
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL+"/vm/golden/repairbot", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestServeHTTP_RoutesToRepairBotAPI(t *testing.T) {
	h := newTestHandlerWithDiag(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: nil},
		&mockDiagnostics{},
	)
	server := httptest.NewServer(h)
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL+"/vm/golden/repairbot/api", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestServeHTTP_RoutesToBackups(t *testing.T) {
	h := newTestHandlerWithDiag(
		&mockJWT{err: fmt.Errorf("no token")},
		&mockRegistry{},
		&mockDiagnostics{},
	)
	server := httptest.NewServer(h)
	defer server.Close()

	resp, err := http.Get(server.URL + "/vm/golden/repairbot/backups")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should get 401 (proves routing)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestServeHTTP_RoutesToRestore(t *testing.T) {
	h := newTestHandlerWithDiag(
		&mockJWT{err: fmt.Errorf("no token")},
		&mockRegistry{},
		&mockDiagnostics{},
	)
	server := httptest.NewServer(h)
	defer server.Close()

	req, _ := http.NewRequest("POST", server.URL+"/vm/golden/repairbot/restore", strings.NewReader(`{}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

// --- H-2: CSRF protection on restart endpoint ---

func TestRestart_RejectsBadOrigin(t *testing.T) {
	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "cust-1",
			UserID:     "user-1",
			TailnetIP:  strPtr("100.64.0.1"),
		}},
	)
	req := httptest.NewRequest("POST", "/vm/cust-1/restart", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("Origin", "https://evil.com")
	w := httptest.NewRecorder()
	h.HandleRestart(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for bad origin, got %d", w.Code)
	}
}

func TestRestart_RejectsCookieOnlyAuth(t *testing.T) {
	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "cust-1",
			UserID:     "user-1",
			TailnetIP:  strPtr("100.64.0.1"),
		}},
	)
	req := httptest.NewRequest("POST", "/vm/cust-1/restart", nil)
	// Only cookie auth, no Authorization header
	req.AddCookie(&http.Cookie{Name: "sb-abc-auth-token", Value: "cookie-jwt"})
	w := httptest.NewRecorder()
	h.HandleRestart(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for cookie-only auth on mutating endpoint, got %d", w.Code)
	}
}
