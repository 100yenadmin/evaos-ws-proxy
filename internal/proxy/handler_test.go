package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
	connectFrame := `{"type":"req","method":"connect","id":"1","params":{"session_id":"abc123"}}`
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
	params, ok := parsed["params"].(map[string]interface{})
	if !ok {
		t.Fatalf("connect frame missing 'params' object, got: %s", first.body)
	}
	authObj, ok := params["auth"].(map[string]interface{})
	if !ok {
		t.Fatalf("connect frame missing 'params.auth' object, got: %s", first.body)
	}
	if got := authObj["token"]; got != gatewayToken {
		t.Errorf("params.auth.token = %q, want %q", got, gatewayToken)
	}
	// Preserve all original fields
	if got := parsed["type"]; got != "req" {
		t.Errorf("type = %q, want 'req'", got)
	}
	if got := params["session_id"]; got != "abc123" {
		t.Errorf("params.session_id = %q, want 'abc123'", got)
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
	connectFrame := `{"type":"req","method":"connect","id":"1","params":{"auth":{"token":"client-wrong-token","extra":"keep-me"}}}`
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
	params, ok := parsed["params"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing params object, got: %s", received)
	}
	authObj, ok := params["auth"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing params.auth object, got: %s", received)
	}
	if got := authObj["token"]; got != gatewayToken {
		t.Errorf("params.auth.token = %q, want %q (gateway token should override)", got, gatewayToken)
	}
	// Other auth fields preserved
	if got := authObj["extra"]; got != "keep-me" {
		t.Errorf("params.auth.extra = %q, want 'keep-me'", got)
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

	originalMsg := `{"type":"req","method":"connect","id":"1","params":{"session_id":"xyz"}}`
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

// --- HTTP Proxy tests ---

func TestStripVMPrefix(t *testing.T) {
	tests := []struct {
		path       string
		customerID string
		expected   string
	}{
		{"/vm/cust-1/ui/index.html", "cust-1", "/ui/index.html"},
		{"/vm/cust-1/ui/", "cust-1", "/ui/"},
		{"/vm/cust-1/ui/assets/style.css", "cust-1", "/ui/assets/style.css"},
		{"/vm/cust-1/", "cust-1", "/"},
		{"/vm/cust-1", "cust-1", "/"},
		{"/cust-1/ui/index.html", "cust-1", "/ui/index.html"}, // Traefik strip mode
		{"/cust-1/", "cust-1", "/"},
		{"/cust-1", "cust-1", "/"},
	}
	for _, tt := range tests {
		got := stripVMPrefix(tt.path, tt.customerID)
		if got != tt.expected {
			t.Errorf("stripVMPrefix(%q, %q) = %q, want %q", tt.path, tt.customerID, got, tt.expected)
		}
	}
}

func TestStripTokenParam(t *testing.T) {
	tests := []struct {
		raw      string
		expected string
	}{
		{"token=abc&foo=bar", "foo=bar"},
		{"foo=bar", "foo=bar"},
		{"token=abc", ""},
		{"", ""},
		{"a=1&token=secret&b=2", "a=1&b=2"},
	}
	for _, tt := range tests {
		got := stripTokenParam(tt.raw)
		if got != tt.expected {
			t.Errorf("stripTokenParam(%q) = %q, want %q", tt.raw, got, tt.expected)
		}
	}
}

func TestIsWebSocketUpgrade(t *testing.T) {
	tests := []struct {
		name       string
		upgrade    string
		connection string
		expected   bool
	}{
		{"ws upgrade", "websocket", "Upgrade", true},
		{"ws mixed case", "WebSocket", "upgrade", true},
		{"no upgrade", "", "", false},
		{"http only", "", "keep-alive", false},
		{"upgrade no ws", "h2c", "Upgrade", false},
	}
	for _, tt := range tests {
		req := httptest.NewRequest("GET", "/vm/cust-1/", nil)
		if tt.upgrade != "" {
			req.Header.Set("Upgrade", tt.upgrade)
		}
		if tt.connection != "" {
			req.Header.Set("Connection", tt.connection)
		}
		if got := isWebSocketUpgrade(req); got != tt.expected {
			t.Errorf("isWebSocketUpgrade(%s) = %v, want %v", tt.name, got, tt.expected)
		}
	}
}

func TestHandleHTTPProxy_NoToken(t *testing.T) {
	h := newTestHandler(&mockJWT{}, &mockRegistry{})
	// Non-UI path requires auth
	req := httptest.NewRequest("GET", "/vm/cust-1/api/health", nil)
	w := httptest.NewRecorder()
	h.HandleHTTPProxy(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleHTTPProxy_InvalidToken(t *testing.T) {
	h := newTestHandler(
		&mockJWT{err: fmt.Errorf("invalid token")},
		&mockRegistry{},
	)
	// Non-UI path requires valid auth
	req := httptest.NewRequest("GET", "/vm/cust-1/api/health", nil)
	req.Header.Set("Authorization", "Bearer bad-token")
	w := httptest.NewRecorder()
	h.HandleHTTPProxy(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleHTTPProxy_UIPathRequiresAuth(t *testing.T) {
	// C-2 fix: UI paths now require auth — no session, no JWT → redirect to login
	h := newTestHandler(
		&mockJWT{}, // no valid claims
		&mockRegistry{vm: nil},
	)
	req := httptest.NewRequest("GET", "/vm/cust-1/ui/index.html", nil)
	w := httptest.NewRecorder()
	h.HandleHTTPProxy(w, req)
	// Should redirect to login page
	if w.Code != http.StatusFound {
		t.Errorf("expected 302 redirect to login, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "electricsheephq.com/login") {
		t.Errorf("expected redirect to login page, got Location=%q", loc)
	}
}

func TestHandleHTTPProxy_NoVM(t *testing.T) {
	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: nil},
	)
	// Non-UI path still returns 404
	req := httptest.NewRequest("GET", "/vm/cust-1/api/status", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleHTTPProxy(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-UI path, got %d", w.Code)
	}

	// UI path with auth returns maintenance page
	req2 := httptest.NewRequest("GET", "/vm/cust-1/ui/index.html", nil)
	req2.Header.Set("Authorization", "Bearer valid-token")
	w2 := httptest.NewRecorder()
	h.HandleHTTPProxy(w2, req2)
	if w2.Code != http.StatusNotFound {
		t.Errorf("expected 404 for UI path with auth (no VM), got %d", w2.Code)
	}
}

func TestHandleHTTPProxy_Forbidden(t *testing.T) {
	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-wrong", Email: "hacker@evil.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "cust-1",
			UserID:     "user-owner",
			TailnetIP:  strPtr("100.64.0.1"),
		}},
	)
	// Non-UI path checks ownership
	req := httptest.NewRequest("GET", "/vm/cust-1/api/health", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleHTTPProxy(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestHandleHTTPProxy_ForwardsRequest(t *testing.T) {
	// Mock backend HTTP server that records what it received
	var receivedPath string
	var receivedHeaders http.Header
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html>Hello from gateway</html>"))
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
			GatewayToken: strPtr("gw-secret"),
		}},
	)

	req := httptest.NewRequest("GET", "/vm/cust-1/ui/index.html", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleHTTPProxy(w, req)

	// Verify response
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if body != "<html>Hello from gateway</html>" {
		t.Errorf("unexpected body: %s", body)
	}

	// Verify the backend received the stripped path
	if receivedPath != "/ui/index.html" {
		t.Errorf("backend got path %q, want /ui/index.html", receivedPath)
	}

	// Verify trusted-proxy headers were set
	if got := receivedHeaders.Get("X-Forwarded-User"); got != "cust-1" {
		t.Errorf("X-Forwarded-User = %q, want 'cust-1'", got)
	}
	if got := receivedHeaders.Get("X-Forwarded-Customer"); got != "cust-1" {
		t.Errorf("X-Forwarded-Customer = %q, want 'cust-1'", got)
	}
	if got := receivedHeaders.Get("X-Openclaw-Token"); got != "gw-secret" {
		t.Errorf("X-OpenClaw-Token = %q, want 'gw-secret'", got)
	}
	// Auth header should contain the gateway token (not the browser JWT).
	// The proxy strips the browser's JWT and injects the gateway token for
	// plugins registered with auth: "gateway".
	if got := receivedHeaders.Get("Authorization"); got != "Bearer gw-secret" {
		t.Errorf("Authorization = %q, want 'Bearer gw-secret'", got)
	}
}

func TestHandleHTTPProxy_StripsTokenQueryParam(t *testing.T) {
	var receivedQuery string
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
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
			CustomerID:  "cust-1",
			UserID:      "user-1",
			TailnetIP:   strPtr(backendHost),
			GatewayPort: backendPort,
		}},
	)

	// Include token in query params — it should be stripped before forwarding
	req := httptest.NewRequest("GET", "/vm/cust-1/ui/index.html?token=supabase-jwt&theme=dark", nil)
	w := httptest.NewRecorder()
	h.HandleHTTPProxy(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if strings.Contains(receivedQuery, "token=") {
		t.Errorf("token should be stripped from query, got %q", receivedQuery)
	}
	if !strings.Contains(receivedQuery, "theme=dark") {
		t.Errorf("non-token params should be preserved, got %q", receivedQuery)
	}
}

func TestHandleHTTPProxy_CacheHeaders(t *testing.T) {
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ext := strings.ToLower(r.URL.Path)
		switch {
		case strings.HasSuffix(ext, ".html"):
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		case strings.HasSuffix(ext, ".js"):
			w.Header().Set("Content-Type", "application/javascript")
		case strings.HasSuffix(ext, ".css"):
			w.Header().Set("Content-Type", "text/css")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("content"))
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
			CustomerID:  "cust-1",
			UserID:      "user-1",
			TailnetIP:   strPtr(backendHost),
			GatewayPort: backendPort,
		}},
	)

	tests := []struct {
		path          string
		expectCache   string
	}{
		{"/vm/cust-1/ui/index.html", "no-cache, no-store, must-revalidate"},
		{"/vm/cust-1/ui/app.js", "public, max-age=86400, immutable"},
		{"/vm/cust-1/ui/style.css", "public, max-age=86400, immutable"},
	}

	for _, tt := range tests {
		req := httptest.NewRequest("GET", tt.path, nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()
		h.HandleHTTPProxy(w, req)

		got := w.Header().Get("Cache-Control")
		if got != tt.expectCache {
			t.Errorf("Cache-Control for %s = %q, want %q", tt.path, got, tt.expectCache)
		}
	}
}

func TestHandleHTTPProxy_BackendDown(t *testing.T) {
	// Point to a port that's not listening. Use session auth for UI path.
	secret := "test-bd-secret"
	sm := NewSessionManager([]byte(secret))
	token, _ := sm.GenerateSessionToken(SessionClaims{
		UserID: "user-1",
		Email:  "test@test.com",
	})

	h := newTestHandlerWithSessions(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID:  "cust-1",
			UserID:      "user-1",
			TailnetIP:   strPtr("127.0.0.1"),
			GatewayPort: 59999, // not listening
		}},
		secret,
	)

	// UI path with session auth: shows maintenance page (503) instead of raw 502
	req := httptest.NewRequest("GET", "/vm/cust-1/ui/index.html", nil)
	req.AddCookie(&http.Cookie{Name: "evaos_session", Value: token})
	w := httptest.NewRecorder()
	h.HandleHTTPProxy(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 (maintenance page), got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "evaOS") {
		t.Error("expected maintenance page with evaOS branding")
	}
	if !strings.Contains(body, "Contact Support") {
		t.Error("expected Contact Support link on maintenance page")
	}

	// Non-UI path: still returns raw 502
	req2 := httptest.NewRequest("GET", "/vm/cust-1/api/status", nil)
	req2.Header.Set("Authorization", "Bearer valid-token")
	w2 := httptest.NewRecorder()
	h.HandleHTTPProxy(w2, req2)
	if w2.Code != http.StatusBadGateway {
		t.Errorf("expected 502 for non-UI path, got %d", w2.Code)
	}
}

// TestServeHTTP_DispatchesCorrectly verifies that the combined ServeHTTP method
// routes WebSocket upgrades to HandleWebSocket and regular HTTP to HandleHTTPProxy.
func TestServeHTTP_DispatchesCorrectly(t *testing.T) {
	// Backend that serves both WS and HTTP
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			up := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
			conn, err := up.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			conn.WriteMessage(websocket.TextMessage, []byte("ws-ok"))
			time.Sleep(50 * time.Millisecond)
		} else {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("http-ok"))
		}
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
			CustomerID:  "cust-1",
			UserID:      "user-1",
			TailnetIP:   strPtr(backendHost),
			GatewayPort: backendPort,
		}},
	)

	// Use ServeHTTP (the dispatcher) via a test server
	proxyServer := httptest.NewServer(h)
	defer proxyServer.Close()

	// Test 1: Regular HTTP request → should get HTTP response from backend
	httpReq, _ := http.NewRequest("GET", proxyServer.URL+"/vm/cust-1/ui/index.html", nil)
	httpReq.Header.Set("Authorization", "Bearer valid-token")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)
	if string(bodyBytes) != "http-ok" {
		t.Errorf("HTTP dispatch: got %q, want 'http-ok'", string(bodyBytes))
	}

	// Test 2: WebSocket upgrade → should connect
	wsURL := "ws" + strings.TrimPrefix(proxyServer.URL, "http") + "/vm/cust-1/"
	header := http.Header{}
	header.Set("Authorization", "Bearer valid-token")
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("WS dial failed: %v", err)
	}
	defer wsConn.Close()
	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		t.Fatalf("WS read failed: %v", err)
	}
	if string(msg) != "ws-ok" {
		t.Errorf("WS dispatch: got %q, want 'ws-ok'", string(msg))
	}
}

// --- Maintenance page tests ---

func TestMaintenancePage_Branding(t *testing.T) {
	// Use session auth to access UI path, with nil VM → maintenance page
	secret := "test-mp-secret"
	sm := NewSessionManager([]byte(secret))
	token, _ := sm.GenerateSessionToken(SessionClaims{
		UserID: "user-1",
		Email:  "test@test.com",
	})

	h := newTestHandlerWithSessions(
		&mockJWT{},
		&mockRegistry{vm: nil},
		secret,
	)
	req := httptest.NewRequest("GET", "/vm/cust-1/ui/", nil)
	req.AddCookie(&http.Cookie{Name: "evaos_session", Value: token})
	w := httptest.NewRecorder()
	h.HandleHTTPProxy(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
	body := w.Body.String()

	// Verify branding elements
	checks := []string{
		"evaOS",
		"Electric Sheep",
		"androiddreams@electricsheephq.com",
		"Contact Support",
		"cust-1", // customer ID should be present
	}
	for _, check := range checks {
		if !strings.Contains(body, check) {
			t.Errorf("maintenance page missing %q", check)
		}
	}

	// Verify Content-Type
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html Content-Type, got %q", ct)
	}
}

func TestMaintenancePage_ProvisioningReason(t *testing.T) {
	secret := "test-mp-secret"
	sm := NewSessionManager([]byte(secret))
	token, _ := sm.GenerateSessionToken(SessionClaims{
		UserID: "user-1",
		Email:  "test@test.com",
	})

	h := newTestHandlerWithSessions(&mockJWT{}, &mockRegistry{vm: nil}, secret)
	req := httptest.NewRequest("GET", "/vm/cust-1/ui/", nil)
	req.AddCookie(&http.Cookie{Name: "evaos_session", Value: token})
	w := httptest.NewRecorder()
	h.HandleHTTPProxy(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "being set up") {
		t.Error("expected provisioning message for nil VM")
	}
	// Should NOT show restart button for provisioning
	if strings.Contains(body, `id="restartBtn"`) {
		t.Error("should not show restart button for provisioning state")
	}
}

func TestMaintenancePage_BackendDownShowsSupport(t *testing.T) {
	secret := "test-mp-secret"
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
	req := httptest.NewRequest("GET", "/vm/cust-1/ui/", nil)
	req.AddCookie(&http.Cookie{Name: "evaos_session", Value: token})
	w := httptest.NewRecorder()
	h.HandleHTTPProxy(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "Contact Support") {
		t.Error("expected Contact Support link when backend is down")
	}
	if strings.Contains(body, `id="restartBtn"`) {
		t.Error("restart button should not appear on unauthenticated maintenance page")
	}
}

func TestMaintenancePage_MobileResponsive(t *testing.T) {
	secret := "test-mp-secret"
	sm := NewSessionManager([]byte(secret))
	token, _ := sm.GenerateSessionToken(SessionClaims{
		UserID: "user-1",
		Email:  "test@test.com",
	})

	h := newTestHandlerWithSessions(&mockJWT{}, &mockRegistry{vm: nil}, secret)
	req := httptest.NewRequest("GET", "/vm/cust-1/ui/", nil)
	req.AddCookie(&http.Cookie{Name: "evaos_session", Value: token})
	w := httptest.NewRecorder()
	h.HandleHTTPProxy(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "viewport") {
		t.Error("maintenance page must include viewport meta tag for mobile responsiveness")
	}
}

// --- Health-check endpoint tests ---

func TestHealthCheck_NoAuth(t *testing.T) {
	// M-2: health-check requires auth now
	h := newTestHandlerWithSessions(
		&mockJWT{},
		&mockRegistry{vm: nil},
		"test-hc-secret",
	)

	req := httptest.NewRequest("GET", "/vm/cust-1/health-check", nil)
	w := httptest.NewRecorder()
	h.HandleHealthCheck(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthenticated health-check, got %d", w.Code)
	}
}

func TestHealthCheck_NoVM(t *testing.T) {
	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: nil},
	)

	req := httptest.NewRequest("GET", "/vm/cust-1/health-check", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleHealthCheck(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["healthy"] != false {
		t.Error("expected healthy=false for no VM")
	}
	if resp["gateway_status"] != "not_provisioned" {
		t.Errorf("expected gateway_status=not_provisioned, got %v", resp["gateway_status"])
	}
}

func TestHealthCheck_BackendHealthy(t *testing.T) {
	// Mock healthy backend
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
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
			CustomerID:  "cust-1",
			UserID:      "user-1",
			TailnetIP:   strPtr(backendHost),
			GatewayPort: backendPort,
		}},
	)

	req := httptest.NewRequest("GET", "/vm/cust-1/health-check", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleHealthCheck(w, req)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["healthy"] != true {
		t.Error("expected healthy=true for running backend")
	}
	if resp["gateway_status"] != "active" {
		t.Errorf("expected gateway_status=active, got %v", resp["gateway_status"])
	}
}

func TestHealthCheck_BackendDown(t *testing.T) {
	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID:  "cust-1",
			UserID:      "user-1",
			TailnetIP:   strPtr("127.0.0.1"),
			GatewayPort: 59999, // not listening
		}},
	)

	req := httptest.NewRequest("GET", "/vm/cust-1/health-check", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleHealthCheck(w, req)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["healthy"] != false {
		t.Error("expected healthy=false for unreachable backend")
	}
}

func TestHealthCheck_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(&mockJWT{}, &mockRegistry{})
	req := httptest.NewRequest("POST", "/vm/cust-1/health-check", nil)
	w := httptest.NewRecorder()
	h.HandleHealthCheck(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// --- Restart endpoint tests ---

func TestRestart_NoAuth(t *testing.T) {
	h := newTestHandler(&mockJWT{}, &mockRegistry{})
	req := httptest.NewRequest("POST", "/vm/cust-1/restart", nil)
	w := httptest.NewRecorder()
	h.HandleRestart(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestRestart_InvalidToken(t *testing.T) {
	h := newTestHandler(
		&mockJWT{err: fmt.Errorf("invalid token")},
		&mockRegistry{},
	)
	req := httptest.NewRequest("POST", "/vm/cust-1/restart", nil)
	req.Header.Set("Authorization", "Bearer bad-token")
	w := httptest.NewRecorder()
	h.HandleRestart(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestRestart_NoVM(t *testing.T) {
	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: nil},
	)
	req := httptest.NewRequest("POST", "/vm/cust-1/restart", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleRestart(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestRestart_Forbidden(t *testing.T) {
	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-wrong", Email: "hacker@evil.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "cust-1",
			UserID:     "user-owner",
			TailnetIP:  strPtr("100.64.0.1"),
		}},
	)
	req := httptest.NewRequest("POST", "/vm/cust-1/restart", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleRestart(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestRestart_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(&mockJWT{}, &mockRegistry{})
	req := httptest.NewRequest("GET", "/vm/cust-1/restart", nil)
	w := httptest.NewRecorder()
	h.HandleRestart(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// --- Rate limiting tests ---

func TestRestartManager_Cooldown(t *testing.T) {
	rm := NewRestartManager()

	// Initially no cooldown
	if remaining := rm.CheckCooldown("cust-1"); remaining != 0 {
		t.Errorf("expected 0 cooldown initially, got %d", remaining)
	}

	// Record a restart
	rm.SetCooldown("cust-1")

	// Should be in cooldown now
	remaining := rm.CheckCooldown("cust-1")
	if remaining <= 0 || remaining > 121 {
		t.Errorf("expected cooldown 1-121 seconds, got %d", remaining)
	}

	// Different customer should not be affected
	if r := rm.CheckCooldown("cust-2"); r != 0 {
		t.Errorf("expected 0 cooldown for different customer, got %d", r)
	}

	// Expired cooldown
	rm.mu.Lock()
	rm.cooldowns["cust-3"] = time.Now().Add(-130 * time.Second)
	rm.mu.Unlock()
	if r := rm.CheckCooldown("cust-3"); r != 0 {
		t.Errorf("expected 0 for expired cooldown, got %d", r)
	}
}

func TestRestart_Cooldown(t *testing.T) {
	rm := NewRestartManager()
	// Pre-set cooldown
	rm.SetCooldown("cust-1")

	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "cust-1",
			UserID:     "user-1",
			TailnetIP:  strPtr("100.64.0.1"),
		}},
		func(cfg *HandlerConfig) {
			cfg.RestartManager = rm
		},
	)

	req := httptest.NewRequest("POST", "/vm/cust-1/restart", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleRestart(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 for cooldown, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "cooldown" {
		t.Errorf("expected status=cooldown, got %v", resp["status"])
	}
	if resp["remaining_seconds"] == nil || resp["remaining_seconds"].(float64) <= 0 {
		t.Error("expected positive remaining_seconds")
	}
}

// --- ServeHTTP routing tests for new endpoints ---

func TestServeHTTP_RoutesToHealthCheck(t *testing.T) {
	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: nil},
	)
	server := httptest.NewServer(h)
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL+"/vm/cust-1/health-check", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	if body["healthy"] != false {
		t.Error("expected healthy=false")
	}
}

func TestServeHTTP_RoutesToRestart(t *testing.T) {
	h := newTestHandler(
		&mockJWT{err: fmt.Errorf("no token")},
		&mockRegistry{},
	)
	server := httptest.NewServer(h)
	defer server.Close()

	req, _ := http.NewRequest("POST", server.URL+"/vm/cust-1/restart", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should get 401 (no token) — proves routing worked
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

// --- Error classification tests ---

func TestClassifyBackendError(t *testing.T) {
	tests := []struct {
		errMsg   string
		expected ErrorReason
	}{
		{"connection refused", ReasonBackendDown},
		{"dial tcp: connection refused", ReasonBackendDown},
		{"no such host", ReasonNetworkError},
		{"no route to host", ReasonNetworkError},
		{"context deadline exceeded", ReasonNetworkError},
		{"timeout", ReasonNetworkError},
		{"random error", ReasonBackendDown},
	}
	for _, tt := range tests {
		got := classifyBackendError(fmt.Errorf("%s", tt.errMsg))
		if got != tt.expected {
			t.Errorf("classifyBackendError(%q) = %q, want %q", tt.errMsg, got, tt.expected)
		}
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

// --- Session auth tests ---

func newTestHandlerWithSessions(jwt JWTValidator, vms VMRegistry, secret string, opts ...func(*HandlerConfig)) *Handler {
	sm := NewSessionManager([]byte(secret))
	cfg := HandlerConfig{
		JWTValidator:   jwt,
		VMRegistry:     vms,
		Health:         health.NewHandler(),
		MaxConnections: 100,
		ConnectTimeout: 5 * time.Second,
		SessionManager: sm,
	}
	for _, o := range opts {
		o(&cfg)
	}
	return NewHandler(cfg)
}

func TestHandleHTTPProxy_SessionCookie_ValidOwner(t *testing.T) {
	secret := "test-session-secret"
	sm := NewSessionManager([]byte(secret))

	// Create a valid session token for user-1
	token, _ := sm.GenerateSessionToken(SessionClaims{
		UserID:     "user-1",
		Email:      "test@test.com",
		CustomerID: "cust-1",
	})

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer backendServer.Close()

	backendAddr := strings.TrimPrefix(backendServer.URL, "http://")
	parts := strings.Split(backendAddr, ":")
	backendHost := parts[0]
	var backendPort int
	fmt.Sscanf(parts[1], "%d", &backendPort)

	h := newTestHandlerWithSessions(
		&mockJWT{},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID:  "cust-1",
			UserID:      "user-1",
			TailnetIP:   strPtr(backendHost),
			GatewayPort: backendPort,
		}},
		secret,
	)

	req := httptest.NewRequest("GET", "/vm/cust-1/ui/index.html", nil)
	req.AddCookie(&http.Cookie{Name: "evaos_session", Value: token})
	w := httptest.NewRecorder()
	h.HandleHTTPProxy(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHandleHTTPProxy_SessionCookie_AdminAccess(t *testing.T) {
	secret := "test-session-secret"
	sm := NewSessionManager([]byte(secret))

	token, _ := sm.GenerateSessionToken(SessionClaims{
		UserID: "admin-user",
		Email:  "admin@100yen.org",
		Roles:  []string{"admin"},
	})

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer backendServer.Close()

	backendAddr := strings.TrimPrefix(backendServer.URL, "http://")
	parts := strings.Split(backendAddr, ":")
	backendHost := parts[0]
	var backendPort int
	fmt.Sscanf(parts[1], "%d", &backendPort)

	h := newTestHandlerWithSessions(
		&mockJWT{},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID:  "cust-1",
			UserID:      "other-user",
			TailnetIP:   strPtr(backendHost),
			GatewayPort: backendPort,
		}},
		secret,
		func(cfg *HandlerConfig) {
			cfg.AdminEmails = []string{"admin@100yen.org"}
		},
	)

	req := httptest.NewRequest("GET", "/vm/cust-1/ui/index.html", nil)
	req.AddCookie(&http.Cookie{Name: "evaos_session", Value: token})
	w := httptest.NewRecorder()
	h.HandleHTTPProxy(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for admin, got %d", w.Code)
	}
}

func TestHandleHTTPProxy_SessionCookie_WrongUser(t *testing.T) {
	secret := "test-session-secret"
	sm := NewSessionManager([]byte(secret))

	token, _ := sm.GenerateSessionToken(SessionClaims{
		UserID: "user-wrong",
		Email:  "wrong@example.com",
	})

	h := newTestHandlerWithSessions(
		&mockJWT{},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "cust-1",
			UserID:     "user-owner",
			TailnetIP:  strPtr("127.0.0.1"),
		}},
		secret,
	)

	req := httptest.NewRequest("GET", "/vm/cust-1/ui/index.html", nil)
	req.AddCookie(&http.Cookie{Name: "evaos_session", Value: token})
	w := httptest.NewRecorder()
	h.HandleHTTPProxy(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestHandleHTTPProxy_SessionCookie_WrongCustomer_RedirectsToLogout(t *testing.T) {
	secret := "test-session-secret"
	sm := NewSessionManager([]byte(secret))

	token, _ := sm.GenerateSessionToken(SessionClaims{
		UserID:     "admin-user",
		Email:      "admin@100yen.org",
		Roles:      []string{"admin"},
		CustomerID: "cust-other",
	})

	h := newTestHandlerWithSessions(
		&mockJWT{},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "cust-1",
			UserID:     "other-user",
			TailnetIP:  strPtr("127.0.0.1"),
		}},
		secret,
		func(cfg *HandlerConfig) {
			cfg.AdminEmails = []string{"admin@100yen.org"}
		},
	)

	req := httptest.NewRequest("GET", "/vm/cust-1/ui/index.html", nil)
	req.AddCookie(&http.Cookie{Name: "evaos_session", Value: token})
	w := httptest.NewRecorder()
	h.HandleHTTPProxy(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/vm/cust-1/auth/logout" {
		t.Fatalf("expected logout redirect, got %q", got)
	}
}

func TestHandleWSProxy_SessionCookie_WrongCustomer_Unauthorized(t *testing.T) {
	secret := "test-session-secret"
	sm := NewSessionManager([]byte(secret))

	token, _ := sm.GenerateSessionToken(SessionClaims{
		UserID:     "admin-user",
		Email:      "admin@100yen.org",
		Roles:      []string{"admin"},
		CustomerID: "cust-other",
	})

	h := newTestHandlerWithSessions(
		&mockJWT{},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "cust-1",
			UserID:     "other-user",
			TailnetIP:  strPtr("127.0.0.1"),
			GatewayPort: 9999,
		}},
		secret,
		func(cfg *HandlerConfig) {
			cfg.AdminEmails = []string{"admin@100yen.org"}
		},
	)

	req := httptest.NewRequest("GET", "/vm/cust-1/ui/ws", nil)
	req.AddCookie(&http.Cookie{Name: "evaos_session", Value: token})
	w := httptest.NewRecorder()
	h.HandleWebSocket(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHandleHTTPProxy_NoAuth_UIPath_RedirectsToLogin(t *testing.T) {
	// C-2 fix: UI paths without auth redirect to login
	h := newTestHandler(
		&mockJWT{},
		&mockRegistry{vm: nil},
	)
	req := httptest.NewRequest("GET", "/vm/cust-1/ui/index.html", nil)
	w := httptest.NewRecorder()
	h.HandleHTTPProxy(w, req)
	// Should redirect to login, not 503 maintenance page
	if w.Code != http.StatusFound {
		t.Errorf("expected 302 redirect to login, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "electricsheephq.com/login") {
		t.Errorf("expected redirect to login page, got Location=%q", loc)
	}
}

func TestHandleAuthCallback_ValidCallbackToken(t *testing.T) {
	secret := "test-session-secret"
	sm := NewSessionManager([]byte(secret))

	// H-1: Generate a callback token (not a session token directly)
	cbToken, _ := sm.GenerateCallbackToken(SessionClaims{
		UserID: "user-1",
		Email:  "test@test.com",
	})

	// Must use the SAME SessionManager instance so pending session map is shared
	h := NewHandler(HandlerConfig{
		JWTValidator:   &mockJWT{},
		VMRegistry: &mockRegistry{vm: &registry.VMInfo{
			CustomerID: "cust-1",
			UserID:     "user-1",
			TailnetIP:  strPtr("127.0.0.1"),
			GatewayToken: strPtr("test-gw-token"),
		}},
		Health:         health.NewHandler(),
		MaxConnections: 100,
		ConnectTimeout: 5 * time.Second,
		SessionManager: sm,
	})

	req := httptest.NewRequest("GET", "/vm/cust-1/auth/callback?session="+cbToken, nil)
	w := httptest.NewRecorder()
	h.HandleAuthCallback(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("expected 302 redirect, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "/vm/cust-1/ui/" {
		t.Errorf("Location = %q, want /vm/cust-1/ui/", loc)
	}
	// Verify cookies were set
	cookies := w.Result().Cookies()
	var foundSession, foundGwToken bool
	for _, c := range cookies {
		if c.Name == "evaos_session" {
			foundSession = true
		}
		if c.Name == "evaos_gw_token" {
			foundGwToken = true
			if c.HttpOnly {
				t.Error("evaos_gw_token should NOT be HttpOnly (JS needs to read it)")
			}
			if c.Path != "/vm/cust-1/" {
				t.Errorf("evaos_gw_token path = %q, want /vm/cust-1/", c.Path)
			}
		}
	}
	if !foundSession {
		t.Error("expected evaos_session cookie to be set")
	}
	if !foundGwToken {
		t.Error("expected evaos_gw_token cookie to be set")
	}
}

func TestHandleAuthCallback_CallbackTokenReplay(t *testing.T) {
	// H-1: Callback token is single-use — second use must fail
	secret := "test-session-secret"
	sm := NewSessionManager([]byte(secret))

	cbToken, _ := sm.GenerateCallbackToken(SessionClaims{
		UserID: "user-1",
		Email:  "test@test.com",
	})

	h := NewHandler(HandlerConfig{
		JWTValidator:   &mockJWT{},
		VMRegistry: &mockRegistry{vm: &registry.VMInfo{
			CustomerID: "cust-1",
			UserID:     "user-1",
			TailnetIP:  strPtr("127.0.0.1"),
		}},
		Health:         health.NewHandler(),
		MaxConnections: 100,
		ConnectTimeout: 5 * time.Second,
		SessionManager: sm,
	})

	// First use — should succeed
	req1 := httptest.NewRequest("GET", "/vm/cust-1/auth/callback?session="+cbToken, nil)
	w1 := httptest.NewRecorder()
	h.HandleAuthCallback(w1, req1)
	if w1.Code != http.StatusFound {
		t.Errorf("first use: expected 302, got %d", w1.Code)
	}

	// Second use — should fail (single-use)
	req2 := httptest.NewRequest("GET", "/vm/cust-1/auth/callback?session="+cbToken, nil)
	w2 := httptest.NewRecorder()
	h.HandleAuthCallback(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("replay: expected 401, got %d", w2.Code)
	}
}

func TestHandleAuthCallback_CallbackTokenExpired(t *testing.T) {
	// H-1: Callback tokens expire after 30 seconds
	secret := "test-session-secret"
	sm := NewSessionManager([]byte(secret))

	// Manually create an expired callback token
	cbClaims := CallbackTokenClaims{
		Type: "callback",
		Ref:  "expired-ref",
		Exp:  time.Now().Add(-1 * time.Minute).Unix(), // already expired
	}
	payload, _ := json.Marshal(cbClaims)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := sessionHeader + "." + payloadB64
	mac := hmac.New(sha256.New, sm.secret)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	expiredToken := signingInput + "." + sig

	h := newTestHandlerWithSessions(
		&mockJWT{},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "cust-1",
			UserID:     "user-1",
		}},
		secret,
	)

	req := httptest.NewRequest("GET", "/vm/cust-1/auth/callback?session="+expiredToken, nil)
	w := httptest.NewRecorder()
	h.HandleAuthCallback(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired callback token, got %d", w.Code)
	}
}

func TestHandleAuthCallback_InvalidSession(t *testing.T) {
	h := newTestHandlerWithSessions(
		&mockJWT{},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "cust-1",
			UserID:     "user-1",
		}},
		"test-secret",
	)

	req := httptest.NewRequest("GET", "/vm/cust-1/auth/callback?session=invalid.token.here", nil)
	w := httptest.NewRecorder()
	h.HandleAuthCallback(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleAuthCallback_MissingSession(t *testing.T) {
	h := newTestHandlerWithSessions(
		&mockJWT{},
		&mockRegistry{},
		"test-secret",
	)

	req := httptest.NewRequest("GET", "/vm/cust-1/auth/callback", nil)
	w := httptest.NewRecorder()
	h.HandleAuthCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleAuthCallback_Forbidden(t *testing.T) {
	secret := "test-session-secret"
	sm := NewSessionManager([]byte(secret))

	cbToken, _ := sm.GenerateCallbackToken(SessionClaims{
		UserID: "user-wrong",
		Email:  "wrong@example.com",
	})

	h := NewHandler(HandlerConfig{
		JWTValidator:   &mockJWT{},
		VMRegistry: &mockRegistry{vm: &registry.VMInfo{
			CustomerID: "cust-1",
			UserID:     "user-owner",
			TailnetIP:  strPtr("127.0.0.1"),
		}},
		Health:         health.NewHandler(),
		MaxConnections: 100,
		ConnectTimeout: 5 * time.Second,
		SessionManager: sm,
	})

	req := httptest.NewRequest("GET", "/vm/cust-1/auth/callback?session="+cbToken, nil)
	w := httptest.NewRecorder()
	h.HandleAuthCallback(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestHandleAuthSession_ValidJWT(t *testing.T) {
	h := newTestHandlerWithSessions(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "cust-1",
			UserID:     "user-1",
			TailnetIP:  strPtr("127.0.0.1"),
		}},
		"test-session-secret",
	)

	req := httptest.NewRequest("POST", "/vm/cust-1/auth/session", nil)
	req.Header.Set("Authorization", "Bearer valid-jwt")
	w := httptest.NewRecorder()
	h.HandleAuthSession(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	// H-1: session_token is no longer returned in the response (security fix)
	if resp["session_token"] != "" {
		t.Error("session_token should not be in response (H-1 fix)")
	}
	if resp["redirect_url"] == "" {
		t.Error("expected non-empty redirect_url")
	}
	if !strings.Contains(resp["redirect_url"], "/auth/callback") {
		t.Errorf("redirect_url should contain /auth/callback, got %q", resp["redirect_url"])
	}

	// Verify CORS headers
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://www.electricsheephq.com" {
		t.Errorf("CORS origin = %q, want https://www.electricsheephq.com", got)
	}
}

func TestHandleAuthSession_NoJWT(t *testing.T) {
	h := newTestHandlerWithSessions(
		&mockJWT{},
		&mockRegistry{},
		"test-secret",
	)

	req := httptest.NewRequest("POST", "/vm/cust-1/auth/session", nil)
	w := httptest.NewRecorder()
	h.HandleAuthSession(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleAuthSession_Forbidden(t *testing.T) {
	h := newTestHandlerWithSessions(
		&mockJWT{claims: &auth.Claims{UserID: "user-wrong", Email: "hacker@evil.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "cust-1",
			UserID:     "user-owner",
			TailnetIP:  strPtr("127.0.0.1"),
		}},
		"test-secret",
	)

	req := httptest.NewRequest("POST", "/vm/cust-1/auth/session", nil)
	req.Header.Set("Authorization", "Bearer valid-jwt")
	w := httptest.NewRecorder()
	h.HandleAuthSession(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestHandleAuthSessionCORS_Preflight(t *testing.T) {
	h := newTestHandlerWithSessions(
		&mockJWT{},
		&mockRegistry{},
		"test-secret",
	)

	server := httptest.NewServer(h)
	defer server.Close()

	req, _ := http.NewRequest("OPTIONS", server.URL+"/vm/cust-1/auth/session", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("expected 204, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://www.electricsheephq.com" {
		t.Errorf("CORS origin = %q, want https://www.electricsheephq.com", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Methods"); !strings.Contains(got, "POST") {
		t.Errorf("CORS methods = %q, want POST", got)
	}
}

func TestServeHTTP_RoutesToAuthCallback(t *testing.T) {
	secret := "test-session-secret"
	sm := NewSessionManager([]byte(secret))
	// Use callback token now (H-1)
	cbToken, _ := sm.GenerateCallbackToken(SessionClaims{
		UserID: "user-1",
		Email:  "test@test.com",
	})

	h := NewHandler(HandlerConfig{
		JWTValidator:   &mockJWT{},
		VMRegistry: &mockRegistry{vm: &registry.VMInfo{
			CustomerID: "cust-1",
			UserID:     "user-1",
			TailnetIP:  strPtr("127.0.0.1"),
		}},
		Health:         health.NewHandler(),
		MaxConnections: 100,
		ConnectTimeout: 5 * time.Second,
		SessionManager: sm,
	})

	server := httptest.NewServer(h)
	defer server.Close()

	// Don't follow redirects
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.Get(server.URL + "/vm/cust-1/auth/callback?session=" + cbToken)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("expected 302, got %d", resp.StatusCode)
	}
}

// --- Audit fix tests ---

// C-1: WS connection with no auth → 401
func TestHandleWebSocket_UIPath_NoAuth(t *testing.T) {
	h := newTestHandler(
		&mockJWT{},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "cust-1",
			UserID:     "user-1",
			TailnetIP:  strPtr("127.0.0.1"),
		}},
	)
	// UI WS path with NO auth at all
	req := httptest.NewRequest("GET", "/vm/cust-1/ui/", nil)
	w := httptest.NewRecorder()
	h.HandleWebSocket(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("C-1: UI WS with no auth: expected 401, got %d", w.Code)
	}
}

// H-3: Logout endpoint clears cookie
func TestHandleLogout(t *testing.T) {
	h := newTestHandlerWithSessions(
		&mockJWT{},
		&mockRegistry{},
		"test-logout-secret",
	)

	req := httptest.NewRequest("GET", "/vm/cust-1/auth/logout", nil)
	w := httptest.NewRecorder()
	h.HandleLogout(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("expected 302 redirect, got %d", w.Code)
	}

	// Verify cookie is cleared (MaxAge=-1)
	cookies := w.Result().Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == "evaos_session" {
			found = true
			if c.MaxAge != -1 {
				t.Errorf("expected MaxAge=-1 for cookie clear, got %d", c.MaxAge)
			}
			if c.Value != "" {
				t.Errorf("expected empty cookie value, got %q", c.Value)
			}
			break
		}
	}
	if !found {
		t.Error("expected evaos_session cookie to be set (cleared)")
	}

	// Verify redirect to login page
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "electricsheephq.com/login") {
		t.Errorf("expected redirect to login page, got Location=%q", loc)
	}
}

// H-3: Logout routed via ServeHTTP
func TestServeHTTP_RoutesToLogout(t *testing.T) {
	h := newTestHandlerWithSessions(
		&mockJWT{},
		&mockRegistry{},
		"test-logout-secret",
	)

	server := httptest.NewServer(h)
	defer server.Close()

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.Get(server.URL + "/vm/cust-1/auth/logout")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("expected 302, got %d", resp.StatusCode)
	}
}

// L-3: CORS multi-origin support
func TestCORS_MultiOrigin(t *testing.T) {
	h := newTestHandlerWithSessions(
		&mockJWT{},
		&mockRegistry{},
		"test-cors-secret",
	)

	server := httptest.NewServer(h)
	defer server.Close()

	// Test with non-www origin
	req, _ := http.NewRequest("OPTIONS", server.URL+"/vm/cust-1/auth/session", nil)
	req.Header.Set("Origin", "https://electricsheephq.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	got := resp.Header.Get("Access-Control-Allow-Origin")
	if got != "https://electricsheephq.com" {
		t.Errorf("CORS origin = %q, want https://electricsheephq.com", got)
	}

	// Test with localhost dev origin
	req2, _ := http.NewRequest("OPTIONS", server.URL+"/vm/cust-1/auth/session", nil)
	req2.Header.Set("Origin", "http://localhost:5173")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp2.Body.Close()

	got2 := resp2.Header.Get("Access-Control-Allow-Origin")
	if got2 != "http://localhost:5173" {
		t.Errorf("CORS origin = %q, want http://localhost:5173", got2)
	}
}

// M-1: Cookie domain scoped to ecs.electricsheephq.com
func TestSessionCookieDomain(t *testing.T) {
	sm := NewSessionManager([]byte("test-domain-secret"))
	token, _ := sm.GenerateSessionToken(SessionClaims{
		UserID: "user-1",
		Email:  "test@test.com",
	})

	w := httptest.NewRecorder()
	sm.SetSessionCookie(w, token)

	cookies := w.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "evaos_session" {
			// Go normalizes by stripping leading dot, so we check for the ecs prefix
			if !strings.Contains(c.Domain, "ecs") {
				t.Errorf("M-1: cookie domain = %q, should contain 'ecs'", c.Domain)
			}
			return
		}
	}
	t.Error("evaos_session cookie not found")
}

// H-2: Derived key differs from raw secret
func TestDeriveKey(t *testing.T) {
	baseSecret := "test-secret"
	derived := DeriveKey(baseSecret, "evaos-proxy-session-v1")

	// Derived key should NOT equal the raw secret bytes
	if string(derived) == baseSecret {
		t.Error("derived key should differ from base secret")
	}

	// Same purpose → same key (deterministic)
	derived2 := DeriveKey(baseSecret, "evaos-proxy-session-v1")
	if string(derived) != string(derived2) {
		t.Error("same base+purpose should produce same derived key")
	}

	// Different purpose → different key
	derived3 := DeriveKey(baseSecret, "different-purpose")
	if string(derived) == string(derived3) {
		t.Error("different purpose should produce different derived key")
	}
}

// H-1: Full auth session flow with callback tokens
func TestHandleAuthSession_ReturnsCallbackToken(t *testing.T) {
	secret := "test-cb-flow-secret"
	h := newTestHandlerWithSessions(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "cust-1",
			UserID:     "user-1",
			TailnetIP:  strPtr("127.0.0.1"),
		}},
		secret,
	)

	req := httptest.NewRequest("POST", "/vm/cust-1/auth/session", nil)
	req.Header.Set("Authorization", "Bearer valid-jwt")
	w := httptest.NewRecorder()
	h.HandleAuthSession(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)

	// session_token should NOT be in response anymore
	if resp["session_token"] != "" {
		t.Error("H-1: session_token should not be exposed in response")
	}

	// redirect_url should contain callback token
	redirectURL := resp["redirect_url"]
	if !strings.Contains(redirectURL, "/auth/callback?session=") {
		t.Errorf("expected redirect_url with callback token, got %q", redirectURL)
	}
}

// H-3: Session TTL reduced to 4h
func TestSessionMaxAge_FourHours(t *testing.T) {
	sm := NewSessionManager([]byte("test-ttl"))
	token, _ := sm.GenerateSessionToken(SessionClaims{
		UserID: "user-1",
		Email:  "test@test.com",
	})

	claims, err := sm.ValidateSessionToken(token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}

	remaining := time.Until(time.Unix(claims.Exp, 0))
	// Should be ~4h, not 24h
	if remaining > 5*time.Hour {
		t.Errorf("session TTL too long: %v (expected ~4h)", remaining)
	}
	if remaining < 3*time.Hour {
		t.Errorf("session TTL too short: %v (expected ~4h)", remaining)
	}
}
