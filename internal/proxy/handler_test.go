package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/100yenadmin/evaos-ws-proxy/internal/auth"
	"github.com/100yenadmin/evaos-ws-proxy/internal/health"
	"github.com/100yenadmin/evaos-ws-proxy/internal/registry"
	"github.com/gorilla/websocket"
)

// mockJWT implements JWTValidator for testing.
type mockJWT struct {
	claims *auth.Claims
	err    error
}

func (m *mockJWT) Validate(token string) (*auth.Claims, error) {
	return m.claims, m.err
}

// mockRegistry implements VMRegistry for testing.
type mockRegistry struct {
	vm  *registry.VMInfo
	err error
}

func (m *mockRegistry) LookupByCustomerID(customerID string) (*registry.VMInfo, error) {
	return m.vm, m.err
}

func (m *mockRegistry) LookupByUserID(userID string) (*registry.VMInfo, error) {
	return m.vm, m.err
}

// strPtr is a test helper for creating *string values.
func strPtr(s string) *string { return &s }



func newTestHandler(jwt JWTValidator, vms VMRegistry, opts ...func(*HandlerConfig)) *Handler {
	cfg := HandlerConfig{
		JWTValidator:   jwt,
		VMRegistry:     vms,
		Health:         health.NewHandler(),
		MaxConnections: 100,
		ConnectTimeout: 5 * time.Second,
	}
	for _, o := range opts {
		o(&cfg)
	}
	return NewHandler(cfg)
}

// --- Path extraction tests ---

func TestExtractCustomerID(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/vm/customer-123/", "customer-123"},
		{"/vm/customer-123", "customer-123"},
		{"/vm/abc-def-ghi/extra/path", "abc-def-ghi"},
		{"/vm/", ""},
		{"/vm", ""},
		{"/other/path", "other"}, // strip-prefix mode: first segment is customer_id
		{"/", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := extractCustomerID(tt.path)
		if got != tt.expected {
			t.Errorf("extractCustomerID(%q) = %q, want %q", tt.path, got, tt.expected)
		}
	}
}

// --- Token extraction tests ---

func TestExtractToken_Header(t *testing.T) {
	req := httptest.NewRequest("GET", "/vm/cust-1/", nil)
	req.Header.Set("Authorization", "Bearer my-jwt-token")
	if got := extractToken(req); got != "my-jwt-token" {
		t.Errorf("expected my-jwt-token, got %s", got)
	}
}

func TestExtractToken_QueryParam(t *testing.T) {
	req := httptest.NewRequest("GET", "/vm/cust-1/?token=query-jwt", nil)
	if got := extractToken(req); got != "query-jwt" {
		t.Errorf("expected query-jwt, got %s", got)
	}
}

func TestExtractToken_Cookie(t *testing.T) {
	req := httptest.NewRequest("GET", "/vm/cust-1/", nil)
	req.AddCookie(&http.Cookie{Name: "sb-abc-auth-token", Value: "cookie-jwt"})
	if got := extractToken(req); got != "cookie-jwt" {
		t.Errorf("expected cookie-jwt, got %s", got)
	}
}

func TestExtractToken_HeaderTakesPrecedence(t *testing.T) {
	req := httptest.NewRequest("GET", "/vm/cust-1/?token=query", nil)
	req.Header.Set("Authorization", "Bearer header")
	if got := extractToken(req); got != "header" {
		t.Errorf("expected header, got %s", got)
	}
}

// --- HTTP-level handler tests (pre-upgrade) ---

func TestHandleWebSocket_MissingCustomerID(t *testing.T) {
	h := newTestHandler(&mockJWT{}, &mockRegistry{})
	req := httptest.NewRequest("GET", "/vm/", nil)
	w := httptest.NewRecorder()
	h.HandleWebSocket(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleWebSocket_NoToken(t *testing.T) {
	h := newTestHandler(&mockJWT{}, &mockRegistry{})
	req := httptest.NewRequest("GET", "/vm/cust-1/", nil)
	w := httptest.NewRecorder()
	h.HandleWebSocket(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleWebSocket_InvalidToken(t *testing.T) {
	h := newTestHandler(
		&mockJWT{err: fmt.Errorf("invalid token")},
		&mockRegistry{},
	)
	req := httptest.NewRequest("GET", "/vm/cust-1/", nil)
	req.Header.Set("Authorization", "Bearer bad-token")
	w := httptest.NewRecorder()
	h.HandleWebSocket(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleWebSocket_NoVM(t *testing.T) {
	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: nil},
	)
	req := httptest.NewRequest("GET", "/vm/cust-1/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleWebSocket(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleWebSocket_Forbidden(t *testing.T) {
	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-wrong", Email: "hacker@evil.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "cust-1",
			UserID:     "user-owner",
			TailnetIP:  strPtr("100.64.0.1"),
		}},
	)
	req := httptest.NewRequest("GET", "/vm/cust-1/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleWebSocket(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestHandleWebSocket_AdminBypass(t *testing.T) {
	// Admin should be allowed even if they don't own the VM.
	// We can't test the full WS upgrade in httptest.NewRecorder,
	// but we can verify it passes the auth check by checking it
	// doesn't return 403. It'll fail at WS upgrade (which is fine).
	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "admin-user", Email: "admin@100yen.org"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "cust-1",
			UserID:     "other-user",
			TailnetIP:  strPtr("100.64.0.1"),
		}},
		func(cfg *HandlerConfig) {
			cfg.AdminEmails = []string{"admin@100yen.org"}
		},
	)
	req := httptest.NewRequest("GET", "/vm/cust-1/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleWebSocket(w, req)
	// Should NOT be 403 — admin bypass works.
	// Will fail at WS upgrade (not a real WS request), which returns 200 with error body.
	if w.Code == http.StatusForbidden {
		t.Error("admin should bypass ownership check")
	}
}

func TestHandleWebSocket_ConnectionLimit(t *testing.T) {
	hlth := health.NewHandler()
	hlth.AddConnection()

	h := NewHandler(HandlerConfig{
		JWTValidator:   &mockJWT{claims: &auth.Claims{UserID: "user-1"}},
		VMRegistry:     &mockRegistry{},
		Health:         hlth,
		MaxConnections: 1,
	})
	req := httptest.NewRequest("GET", "/vm/cust-1/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleWebSocket(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

// --- Admin check tests ---

func TestIsAdmin(t *testing.T) {
	h := NewHandler(HandlerConfig{
		JWTValidator:   &mockJWT{},
		VMRegistry:     &mockRegistry{},
		Health:         health.NewHandler(),
		AdminEmails:    []string{"admin@100yen.org", "Boss@Example.Com"},
		MaxConnections: 100,
	})
	tests := []struct {
		email    string
		expected bool
	}{
		{"admin@100yen.org", true},
		{"Admin@100YEN.ORG", true},
		{"boss@example.com", true},
		{"nobody@example.com", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := h.isAdmin(tt.email); got != tt.expected {
			t.Errorf("isAdmin(%q) = %v, want %v", tt.email, got, tt.expected)
		}
	}
}

// --- Full E2E proxy test with real WebSocket connections ---

func TestFullProxyCycle(t *testing.T) {
	// Mock backend gateway — records headers and echoes messages
	var receivedHeaders http.Header
	backendReceived := make(chan string, 1)

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		up := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("backend upgrade error: %v", err)
			return
		}
		defer conn.Close()

		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		backendReceived <- string(msg)
		conn.WriteMessage(websocket.TextMessage, []byte("backend-reply"))
	}))
	defer backendServer.Close()

	// Parse backend server address
	backendAddr := strings.TrimPrefix(backendServer.URL, "http://")
	parts := strings.Split(backendAddr, ":")
	backendHost := parts[0]
	var backendPort int
	fmt.Sscanf(parts[1], "%d", &backendPort)

	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID:   "cust-1",
			UserID:       "user-1",
			TailnetIP:    strPtr(backendHost),
			GatewayPort:  backendPort,
			GatewayToken: strPtr("gw-secret-token"),
		}},
	)

	proxyServer := httptest.NewServer(http.HandlerFunc(h.HandleWebSocket))
	defer proxyServer.Close()

	// Connect client to proxy at /vm/cust-1/
	wsURL := "ws" + strings.TrimPrefix(proxyServer.URL, "http") + "/vm/cust-1/"
	header := http.Header{}
	header.Set("Authorization", "Bearer valid-token")

	clientConn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("client dial error: %v", err)
	}
	defer clientConn.Close()

	// Send message through proxy
	err = clientConn.WriteMessage(websocket.TextMessage, []byte("hello-from-client"))
	if err != nil {
		t.Fatalf("client write error: %v", err)
	}

	// Verify backend received the message
	select {
	case msg := <-backendReceived:
		if msg != "hello-from-client" {
			t.Errorf("backend got %q, want 'hello-from-client'", msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for backend to receive message")
	}

	// Verify trusted-proxy headers were set on backend connection
	if got := receivedHeaders.Get("X-Forwarded-User"); got != "cust-1" {
		t.Errorf("X-Forwarded-User = %q, want 'cust-1'", got)
	}
	if got := receivedHeaders.Get("X-Forwarded-Customer"); got != "cust-1" {
		t.Errorf("X-Forwarded-Customer = %q, want 'cust-1'", got)
	}
	if got := receivedHeaders.Get("X-Openclaw-Token"); got != "gw-secret-token" {
		t.Errorf("X-OpenClaw-Token = %q, want 'gw-secret-token'", got)
	}

	// Read the backend reply through proxy
	_, reply, err := clientConn.ReadMessage()
	if err != nil {
		t.Fatalf("client read error: %v", err)
	}
	if string(reply) != "backend-reply" {
		t.Errorf("client got %q, want 'backend-reply'", string(reply))
	}
}
