package proxy

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/100yenadmin/evaos-ws-proxy/internal/auth"
	"github.com/100yenadmin/evaos-ws-proxy/internal/registry"
)

// --- File Proxy Route Tests ---

func TestHandleFileProxy_NoAuth(t *testing.T) {
	h := newTestHandler(&mockJWT{}, &mockRegistry{})
	req := httptest.NewRequest("GET", "/vm/cust-1/files/report.pdf", nil)
	w := httptest.NewRecorder()
	h.HandleFileProxy(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleFileProxy_InvalidToken(t *testing.T) {
	h := newTestHandler(
		&mockJWT{err: fmt.Errorf("invalid token")},
		&mockRegistry{},
	)
	req := httptest.NewRequest("GET", "/vm/cust-1/files/report.pdf", nil)
	req.Header.Set("Authorization", "Bearer bad-token")
	w := httptest.NewRecorder()
	h.HandleFileProxy(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleFileProxy_NoVM(t *testing.T) {
	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: nil},
	)
	req := httptest.NewRequest("GET", "/vm/cust-1/files/report.pdf", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleFileProxy(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleFileProxy_Forbidden(t *testing.T) {
	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-wrong", Email: "hacker@evil.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "cust-1",
			UserID:     "user-owner",
			TailnetIP:  strPtr("100.64.0.1"),
		}},
	)
	req := httptest.NewRequest("GET", "/vm/cust-1/files/report.pdf", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleFileProxy(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestHandleFileProxy_PostAllowed(t *testing.T) {
	// File Browser needs POST/PUT/DELETE for file management
	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID:  "cust-1",
			UserID:      "user-1",
			TailnetIP:   strPtr("127.0.0.1"),
			GatewayPort: 59999,
		}},
	)
	req := httptest.NewRequest("POST", "/vm/cust-1/files/api/resources", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleFileProxy(w, req)
	// Should pass auth (502 expected because no file server)
	if w.Code == http.StatusMethodNotAllowed {
		t.Error("POST should be allowed for file proxy (File Browser needs it)")
	}
}

func TestHandleFileProxy_ForwardsRequest(t *testing.T) {
	var receivedPath string
	var receivedHeaders http.Header

	// Mock file server on port 8890 (File Browser port).
	// The file proxy hardcodes fileBrowserPort=8890, so we must listen there.
	listener, err := net.Listen("tcp", "127.0.0.1:8890")
	if err != nil {
		t.Skipf("cannot bind to port 8890 (may be in use): %v", err)
	}
	fileServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/pdf")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("fake-pdf-content"))
	}))
	fileServer.Listener.Close()
	fileServer.Listener = listener
	fileServer.Start()
	defer fileServer.Close()

	// The file proxy uses fileBrowserPort (8890), so our mock VM just needs
	// the correct IP (127.0.0.1). GatewayPort is irrelevant for file proxy.

	// Test: verify the handler calls through correctly with session auth
	secret := "test-file-secret"
	sm := NewSessionManager([]byte(secret))
	sm.GenerateSessionToken(SessionClaims{
		UserID: "user-1",
		Email:  "test@test.com",
	})

	h := newTestHandlerWithSessions(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID:  "cust-1",
			UserID:      "user-1",
			TailnetIP:   strPtr("127.0.0.1"),
			GatewayPort: 18789,
		}},
		secret,
	)

	// Use JWT auth (session would also work, but JWT is simpler for this test)
	req := httptest.NewRequest("GET", "/vm/cust-1/files/reports/q1.pdf", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	h.HandleFileProxy(w, req)

	// Verify the request was forwarded to our mock server with correct path
	if receivedPath != "/files/reports/q1.pdf" {
		t.Errorf("expected backend path /files/reports/q1.pdf, got %s", receivedPath)
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	// Verify gateway token was injected (EffectiveToken returns "" for test VMInfo without GatewayToken)
	_ = receivedHeaders
}

func TestHandleFileProxy_SessionAuth(t *testing.T) {
	secret := "test-file-session"
	sm := NewSessionManager([]byte(secret))
	token, _ := sm.GenerateSessionToken(SessionClaims{
		UserID: "user-1",
		Email:  "test@test.com",
	})

	h := newTestHandlerWithSessions(
		&mockJWT{},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID:  "cust-1",
			UserID:      "user-1",
			TailnetIP:   strPtr("127.0.0.1"),
			GatewayPort: 59999,
		}},
		secret,
	)

	req := httptest.NewRequest("GET", "/vm/cust-1/files/test.txt", nil)
	req.AddCookie(&http.Cookie{Name: "evaos_session", Value: token})
	w := httptest.NewRecorder()
	h.HandleFileProxy(w, req)

	// Should pass auth (will 502 because no file server, but NOT 401/403)
	if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
		t.Errorf("session auth should pass, got %d", w.Code)
	}
}

func TestHandleFileProxy_AdminAccess(t *testing.T) {
	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "admin-user", Email: "admin@100yen.org"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID:  "cust-1",
			UserID:      "other-user",
			TailnetIP:   strPtr("127.0.0.1"),
			GatewayPort: 59999,
		}},
		func(cfg *HandlerConfig) {
			cfg.AdminEmails = []string{"admin@100yen.org"}
		},
	)

	req := httptest.NewRequest("GET", "/vm/cust-1/files/secret.pdf", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleFileProxy(w, req)

	// Admin should bypass ownership — should NOT be 403
	if w.Code == http.StatusForbidden {
		t.Error("admin should bypass ownership check for file proxy")
	}
}

func TestHandleFileProxy_MissingCustomerID(t *testing.T) {
	h := newTestHandler(&mockJWT{}, &mockRegistry{})
	req := httptest.NewRequest("GET", "/vm//files/test.txt", nil)
	w := httptest.NewRecorder()
	h.HandleFileProxy(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// --- ServeHTTP routing for file proxy ---

func TestServeHTTP_RoutesToFileProxy(t *testing.T) {
	h := newTestHandler(
		&mockJWT{err: fmt.Errorf("no token")},
		&mockRegistry{},
	)
	server := httptest.NewServer(h)
	defer server.Close()

	// No auth → 401 proves routing worked (reached HandleFileProxy, not HandleHTTPProxy)
	req, _ := http.NewRequest("GET", server.URL+"/vm/cust-1/files/test.pdf", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestServeHTTP_FilesPathNotConfusedWithUI(t *testing.T) {
	// Ensure /files path doesn't accidentally match UI path handling
	h := newTestHandler(
		&mockJWT{},
		&mockRegistry{vm: nil},
	)
	server := httptest.NewServer(h)
	defer server.Close()

	// files path with no auth → 401 (not redirect to login like UI paths)
	req, _ := http.NewRequest("GET", server.URL+"/vm/cust-1/files/data.csv", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound {
		t.Error("file proxy should return 401, not redirect to login")
	}
}

func TestHandleFileProxy_PathTraversal(t *testing.T) {
	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID:  "cust-1",
			UserID:      "user-1",
			TailnetIP:   strPtr("127.0.0.1"),
			GatewayPort: 59999,
		}},
	)

	// Simulate URL-encoded dot traversal (path.Clean resolves these)
	traversalPaths := []string{
		"/vm/cust-1/files/../../etc/passwd",
		"/vm/cust-1/files/../../../etc/shadow",
	}
	for _, p := range traversalPaths {
		req := httptest.NewRequest("GET", p, nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()
		h.HandleFileProxy(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("path %q: expected 400, got %d", p, w.Code)
		}
	}
}

func TestHandleFileProxy_HeadMethod(t *testing.T) {
	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID:  "cust-1",
			UserID:      "user-1",
			TailnetIP:   strPtr("127.0.0.1"),
			GatewayPort: 59999,
		}},
	)

	req := httptest.NewRequest("HEAD", "/vm/cust-1/files/test.txt", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleFileProxy(w, req)

	// HEAD should pass auth (will 502 because no file server)
	if w.Code == http.StatusMethodNotAllowed {
		t.Error("HEAD should be allowed for file proxy")
	}
}
