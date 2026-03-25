package proxy

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// --- H2: Per-user connection limit tests ---

func TestHandleWebSocket_PerUserConnectionLimit(t *testing.T) {
	// Create a backend that accepts WS connections and holds them open
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		// Hold connection open until client disconnects
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer backendServer.Close()

	backendAddr := strings.TrimPrefix(backendServer.URL, "http://")
	parts := strings.Split(backendAddr, ":")
	backendHost := parts[0]
	var backendPort int
	fmt.Sscanf(parts[1], "%d", &backendPort)

	h := NewHandler(HandlerConfig{
		JWTValidator: &mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		VMRegistry: &mockRegistry{vm: &registry.VMInfo{
			CustomerID:   "cust-1",
			UserID:       "user-1",
			TailnetIP:    strPtr(backendHost),
			GatewayPort:  backendPort,
			GatewayToken: strPtr("tok"),
		}},
		Health:         health.NewHandler(),
		MaxConnections: 100,
		MaxPerUser:     2, // allow max 2 connections per user
		ConnectTimeout: 5 * time.Second,
	})

	proxyServer := httptest.NewServer(http.HandlerFunc(h.HandleWebSocket))
	defer proxyServer.Close()

	wsURL := "ws" + strings.TrimPrefix(proxyServer.URL, "http") + "/vm/cust-1/"
	header := http.Header{}
	header.Set("Authorization", "Bearer valid-token")

	// Open 2 connections — should succeed
	var conns []*websocket.Conn
	for i := 0; i < 2; i++ {
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
		if err != nil {
			t.Fatalf("connection %d failed: %v", i+1, err)
		}
		conns = append(conns, conn)
	}

	// 3rd connection from same user should be rejected (503)
	// Use a raw HTTP request since WS dial may not give us the status code
	req, _ := http.NewRequest("GET", proxyServer.URL+"/vm/cust-1/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("3rd request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for 3rd connection, got %d", resp.StatusCode)
	}

	// Close one connection and try again — should now succeed
	conns[0].Close()
	// Give a moment for the defer to run
	time.Sleep(50 * time.Millisecond)

	conn3, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("connection after release failed: %v", err)
	}
	conn3.Close()

	// Cleanup
	for _, c := range conns[1:] {
		c.Close()
	}
}

// --- H5: Backend reconnect with exponential backoff tests ---

func TestConnectBackend_RetryOnFailure(t *testing.T) {
	var mu sync.Mutex
	dialCount := 0
	failUntil := 2 // fail first 2, succeed on 3rd

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		dialCount++
		current := dialCount
		mu.Unlock()

		if current <= failUntil {
			// Reject the WS upgrade with a non-101 status
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}

		up := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(100 * time.Millisecond)
	}))
	defer backendServer.Close()

	backendAddr := strings.TrimPrefix(backendServer.URL, "http://")
	parts := strings.Split(backendAddr, ":")
	backendHost := parts[0]
	var backendPort int
	fmt.Sscanf(parts[1], "%d", &backendPort)

	h := NewHandler(HandlerConfig{
		JWTValidator:      &mockJWT{},
		VMRegistry:        &mockRegistry{},
		Health:            health.NewHandler(),
		MaxConnections:    100,
		ConnectTimeout:    2 * time.Second,
		ReconnectAttempts: 3,
	})

	vm := &registry.VMInfo{
		CustomerID:  "cust-1",
		TailnetIP:   strPtr(backendHost),
		GatewayPort: backendPort,
	}

	conn, err := h.connectBackend(vm, "cust-1", slog.Default())
	if err != nil {
		t.Fatalf("connectBackend should succeed on 3rd attempt, got: %v", err)
	}
	conn.Close()

	mu.Lock()
	finalCount := dialCount
	mu.Unlock()
	if finalCount < 3 {
		t.Errorf("expected at least 3 dial attempts, got %d", finalCount)
	}
}

// --- Connect frame token injection tests ---

// TestConnectFrameTokenInjection verifies that when a gateway token is present,
// the proxy injects auth.token into the first (connect) frame from client→backend,
// while passing subsequent frames through unmodified.
func TestConnectFrameTokenInjection(t *testing.T) {
	type receivedMsg struct {
		index int
		body  string
	}

	backendMsgs := make(chan receivedMsg, 10)

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("backend upgrade error: %v", err)
			return
		}
		defer conn.Close()

		for i := 0; ; i++ {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			backendMsgs <- receivedMsg{index: i, body: string(msg)}
		}
	}))
	defer backendServer.Close()

	backendAddr := strings.TrimPrefix(backendServer.URL, "http://")
	parts := strings.Split(backendAddr, ":")
	backendHost := parts[0]
	var backendPort int
	fmt.Sscanf(parts[1], "%d", &backendPort)

	gatewayToken := "gw-inject-test-token"

	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID:   "cust-1",
			UserID:       "user-1",
			TailnetIP:    strPtr(backendHost),
			GatewayPort:  backendPort,
			GatewayToken: strPtr(gatewayToken),
		}},
	)

	proxyServer := httptest.NewServer(http.HandlerFunc(h.HandleWebSocket))
	defer proxyServer.Close()

	wsURL := "ws" + strings.TrimPrefix(proxyServer.URL, "http") + "/vm/cust-1/"
	header := http.Header{}
	header.Set("Authorization", "Bearer valid-token")

	clientConn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("client dial error: %v", err)
	}
	defer clientConn.Close()

	// Send connect frame (first message) — no auth field yet
	connectFrame := `{"type":"connect","session_id":"abc123"}`
	if err := clientConn.WriteMessage(websocket.TextMessage, []byte(connectFrame)); err != nil {
		t.Fatalf("client write connect frame error: %v", err)
	}

	// Wait for backend to receive the (modified) connect frame
	var first receivedMsg
	select {
	case first = <-backendMsgs:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for connect frame at backend")
	}

	// Verify token was injected
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(first.body), &parsed); err != nil {
		t.Fatalf("backend received non-JSON: %s", first.body)
	}
	authObj, ok := parsed["auth"].(map[string]interface{})
	if !ok {
		t.Fatalf("connect frame missing 'auth' object, got: %s", first.body)
	}
	if got := authObj["token"]; got != gatewayToken {
		t.Errorf("auth.token = %q, want %q", got, gatewayToken)
	}
	// Preserve all original fields
	if got := parsed["type"]; got != "connect" {
		t.Errorf("type = %q, want 'connect'", got)
	}
	if got := parsed["session_id"]; got != "abc123" {
		t.Errorf("session_id = %q, want 'abc123'", got)
	}

	// Send a second frame — should pass through unmodified
	secondMsg := `{"type":"ping"}`
	if err := clientConn.WriteMessage(websocket.TextMessage, []byte(secondMsg)); err != nil {
		t.Fatalf("client write second frame error: %v", err)
	}

	var second receivedMsg
	select {
	case second = <-backendMsgs:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for second frame at backend")
	}
	if second.body != secondMsg {
		t.Errorf("second frame = %q, want %q (should be unmodified)", second.body, secondMsg)
	}
}

// TestConnectFrameTokenInjection_ExistingAuth verifies that if the client already
// sends an auth object, the proxy overwrites auth.token with the gateway token
// while preserving other auth fields.
func TestConnectFrameTokenInjection_ExistingAuth(t *testing.T) {
	backendMsgs := make(chan string, 1)

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		backendMsgs <- string(msg)
	}))
	defer backendServer.Close()

	backendAddr := strings.TrimPrefix(backendServer.URL, "http://")
	parts := strings.Split(backendAddr, ":")
	backendHost := parts[0]
	var backendPort int
	fmt.Sscanf(parts[1], "%d", &backendPort)

	gatewayToken := "real-gw-token"

	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID:   "cust-1",
			UserID:       "user-1",
			TailnetIP:    strPtr(backendHost),
			GatewayPort:  backendPort,
			GatewayToken: strPtr(gatewayToken),
		}},
	)

	proxyServer := httptest.NewServer(http.HandlerFunc(h.HandleWebSocket))
	defer proxyServer.Close()

	wsURL := "ws" + strings.TrimPrefix(proxyServer.URL, "http") + "/vm/cust-1/"
	header := http.Header{}
	header.Set("Authorization", "Bearer valid-token")

	clientConn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("client dial error: %v", err)
	}
	defer clientConn.Close()

	// Send connect frame with an existing (wrong) token and extra auth fields
	connectFrame := `{"type":"connect","auth":{"token":"client-wrong-token","extra":"keep-me"}}`
	if err := clientConn.WriteMessage(websocket.TextMessage, []byte(connectFrame)); err != nil {
		t.Fatalf("client write error: %v", err)
	}

	var received string
	select {
	case received = <-backendMsgs:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for message at backend")
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(received), &parsed); err != nil {
		t.Fatalf("non-JSON at backend: %s", received)
	}
	authObj, ok := parsed["auth"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing auth object, got: %s", received)
	}
	if got := authObj["token"]; got != gatewayToken {
		t.Errorf("auth.token = %q, want %q (gateway token should override)", got, gatewayToken)
	}
	// Other auth fields preserved
	if got := authObj["extra"]; got != "keep-me" {
		t.Errorf("auth.extra = %q, want 'keep-me'", got)
	}
}

// TestConnectFrameTokenInjection_NoToken verifies that when no gateway token is set,
// the first frame passes through completely unmodified.
func TestConnectFrameTokenInjection_NoToken(t *testing.T) {
	backendMsgs := make(chan string, 1)

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		backendMsgs <- string(msg)
	}))
	defer backendServer.Close()

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
			GatewayToken: nil, // no token
		}},
	)

	proxyServer := httptest.NewServer(http.HandlerFunc(h.HandleWebSocket))
	defer proxyServer.Close()

	wsURL := "ws" + strings.TrimPrefix(proxyServer.URL, "http") + "/vm/cust-1/"
	header := http.Header{}
	header.Set("Authorization", "Bearer valid-token")

	clientConn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("client dial error: %v", err)
	}
	defer clientConn.Close()

	originalMsg := `{"type":"connect","session_id":"xyz"}`
	if err := clientConn.WriteMessage(websocket.TextMessage, []byte(originalMsg)); err != nil {
		t.Fatalf("client write error: %v", err)
	}

	var received string
	select {
	case received = <-backendMsgs:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for message at backend")
	}

	if received != originalMsg {
		t.Errorf("got %q, want %q (no-token path should not modify frame)", received, originalMsg)
	}
}

func TestConnectBackend_AllRetriesFail(t *testing.T) {
	// Backend that always rejects
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "always down", http.StatusServiceUnavailable)
	}))
	defer backendServer.Close()

	backendAddr := strings.TrimPrefix(backendServer.URL, "http://")
	parts := strings.Split(backendAddr, ":")
	backendHost := parts[0]
	var backendPort int
	fmt.Sscanf(parts[1], "%d", &backendPort)

	h := NewHandler(HandlerConfig{
		JWTValidator:      &mockJWT{},
		VMRegistry:        &mockRegistry{},
		Health:            health.NewHandler(),
		MaxConnections:    100,
		ConnectTimeout:    1 * time.Second,
		ReconnectAttempts: 2, // 2 attempts, both fail
	})

	vm := &registry.VMInfo{
		CustomerID:  "cust-1",
		TailnetIP:   strPtr(backendHost),
		GatewayPort: backendPort,
	}

	_, err := h.connectBackend(vm, "cust-1", slog.Default())
	if err == nil {
		t.Fatal("expected error when all retries fail")
	}
	if !strings.Contains(err.Error(), "after 2 attempts") {
		t.Errorf("expected error to mention attempts, got: %v", err)
	}
}
