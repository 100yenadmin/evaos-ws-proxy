package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/100yenadmin/evaos-ws-proxy/internal/auth"
	"github.com/100yenadmin/evaos-ws-proxy/internal/health"
	"github.com/100yenadmin/evaos-ws-proxy/internal/registry"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin:    func(r *http.Request) bool { return true }, // CORS handled by Caddy
	ReadBufferSize: 4096,
	WriteBufferSize: 4096,
}

// VMRegistry is the interface the handler needs for VM lookups.
type VMRegistry interface {
	LookupByCustomerID(customerID string) (*registry.VMInfo, error)
	LookupByUserID(userID string) (*registry.VMInfo, error)
}

// JWTValidator is the interface for JWT validation.
type JWTValidator interface {
	Validate(tokenStr string) (*auth.Claims, error)
}

// HandlerConfig holds all dependencies for the proxy handler.
type HandlerConfig struct {
	JWTValidator      JWTValidator
	VMRegistry        VMRegistry
	Health            *health.Handler
	AdminEmails       []string
	ConnectTimeout    time.Duration
	ReconnectAttempts int
	MaxConnections    int
}

// Handler manages WebSocket proxy connections.
type Handler struct {
	jwt               JWTValidator
	vms               VMRegistry
	health            *health.Handler
	adminEmails       map[string]bool
	connectTimeout    time.Duration
	reconnectAttempts int
	maxConnections    int
}

// NewHandler creates a new proxy handler.
func NewHandler(cfg HandlerConfig) *Handler {
	adminSet := make(map[string]bool, len(cfg.AdminEmails))
	for _, e := range cfg.AdminEmails {
		adminSet[strings.ToLower(e)] = true
	}
	return &Handler{
		jwt:               cfg.JWTValidator,
		vms:               cfg.VMRegistry,
		health:            cfg.Health,
		adminEmails:       adminSet,
		connectTimeout:    cfg.ConnectTimeout,
		reconnectAttempts: cfg.ReconnectAttempts,
		maxConnections:    cfg.MaxConnections,
	}
}

// HandleWebSocket upgrades the connection and starts bidirectional proxying.
// Route: /vm/{customer_id}/ (with optional trailing path segments)
func (h *Handler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Check connection limit
	if h.health.ConnectionCount() >= int64(h.maxConnections) {
		slog.Warn("connection limit reached", "max", h.maxConnections)
		http.Error(w, "too many connections", http.StatusServiceUnavailable)
		return
	}

	// Extract customer_id from path: /vm/{customer_id}/...
	customerID := extractCustomerID(r.URL.Path)
	if customerID == "" {
		slog.Info("missing customer_id in path", "path", r.URL.Path, "remote_addr", r.RemoteAddr)
		http.Error(w, "missing customer_id", http.StatusBadRequest)
		return
	}

	// Extract and validate Supabase JWT
	tokenStr := extractToken(r)
	if tokenStr == "" {
		slog.Info("auth failed: no token provided",
			"remote_addr", r.RemoteAddr, "customer_id", customerID)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	claims, err := h.jwt.Validate(tokenStr)
	if err != nil {
		slog.Info("auth failed: invalid token",
			"error", err, "remote_addr", r.RemoteAddr, "customer_id", customerID)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	logger := slog.With(
		"user_id", claims.UserID,
		"customer_id", customerID,
		"remote_addr", r.RemoteAddr,
	)

	// Look up VM by customer_id
	vm, err := h.vms.LookupByCustomerID(customerID)
	if err != nil {
		logger.Error("vm lookup failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if vm == nil {
		logger.Info("no active VM for customer")
		http.Error(w, "no VM assigned", http.StatusNotFound)
		return
	}

	// Authorization: verify the user owns this VM (unless admin)
	if vm.UserID != claims.UserID && !h.isAdmin(claims.Email) {
		logger.Warn("user does not own this VM",
			"vm_user_id", vm.UserID, "email", claims.Email)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	logger = logger.With("ip", vm.EffectiveIP(), "gateway_port", vm.GatewayPort)

	// Upgrade client connection
	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Error("websocket upgrade failed", "error", err)
		return
	}

	h.health.AddConnection()
	logger.Info("client connected")

	defer func() {
		clientConn.Close()
		h.health.RemoveConnection()
		logger.Info("client disconnected")
	}()

	// Connect to backend VM gateway as trusted proxy
	backendConn, err := h.connectBackend(vm, customerID, logger)
	if err != nil {
		logger.Error("backend connection failed", "error", err)
		closeMsg := websocket.FormatCloseMessage(4002, "backend unavailable")
		clientConn.WriteMessage(websocket.CloseMessage, closeMsg)
		return
	}
	defer backendConn.Close()

	logger.Info("backend connected")

	// Bidirectional proxy — pass all frames through transparently.
	// The OpenClaw connect handshake (challenge → connect → hello-ok)
	// happens over the WS frames between client and backend.
	// The proxy is transparent to the protocol.
	h.proxyBidirectional(clientConn, backendConn, vm, logger)
}

func (h *Handler) isAdmin(email string) bool {
	if email == "" {
		return false
	}
	return h.adminEmails[strings.ToLower(email)]
}

// connectBackend dials the backend gateway WebSocket.
// It injects the gateway token via query param and sets X-Forwarded-User
// so the gateway recognizes this as a trusted-proxy connection.
func (h *Handler) connectBackend(vm *registry.VMInfo, customerID string, logger *slog.Logger) (*websocket.Conn, error) {
	// Build backend URL — prefer tailnet_ip, fall back to public_ip
	ip := vm.EffectiveIP()
	backendURL := fmt.Sprintf("ws://%s:%d", ip, vm.GatewayPort)

	// If we have a gateway token, pass it as query param for auth
	token := vm.EffectiveToken()
	if token != "" {
		backendURL += "?token=" + token
	}

	// Set trusted-proxy headers so the gateway identifies the customer
	header := http.Header{}
	header.Set("X-Forwarded-User", customerID)
	header.Set("X-Forwarded-Customer", customerID)

	// Also pass gateway token as header for compatibility
	if token != "" {
		header.Set("X-OpenClaw-Token", token)
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: h.connectTimeout,
	}

	conn, _, err := dialer.Dial(backendURL, header)
	if err != nil {
		return nil, fmt.Errorf("dial backend: %w", err)
	}

	return conn, nil
}

func (h *Handler) proxyBidirectional(client, backend *websocket.Conn, vm *registry.VMInfo, logger *slog.Logger) {
	var once sync.Once
	done := make(chan struct{})
	closeDone := func() { once.Do(func() { close(done) }) }

	// Client → Backend
	go func() {
		defer closeDone()
		h.forwardFrames(client, backend, "client→backend", logger)
	}()

	// Backend → Client
	go func() {
		defer closeDone()
		h.forwardFrames(backend, client, "backend→client", logger)
	}()

	// Wait for either direction to finish
	<-done

	// Close both sides
	closeMsg := websocket.FormatCloseMessage(websocket.CloseGoingAway, "peer disconnected")
	client.WriteControl(websocket.CloseMessage, closeMsg, time.Now().Add(time.Second))
	backend.WriteControl(websocket.CloseMessage, closeMsg, time.Now().Add(time.Second))
}

func (h *Handler) forwardFrames(src, dst *websocket.Conn, direction string, logger *slog.Logger) {
	for {
		msgType, msg, err := src.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				logger.Warn("read error", "direction", direction, "error", err)
			}
			return
		}

		if err := dst.WriteMessage(msgType, msg); err != nil {
			logger.Warn("write error", "direction", direction, "error", err)
			return
		}
	}
}

// extractCustomerID extracts the customer_id from a path.
// Supports both /vm/{customer_id}/... (direct) and /{customer_id}/... (after Traefik strip-prefix).
func extractCustomerID(path string) string {
	path = strings.TrimPrefix(path, "/")
	parts := strings.SplitN(path, "/", 3)
	if len(parts) == 0 || parts[0] == "" {
		return ""
	}
	// If first segment is "vm", customer_id is second segment
	if parts[0] == "vm" {
		if len(parts) < 2 || parts[1] == "" {
			return ""
		}
		return parts[1]
	}
	// Otherwise first segment IS the customer_id (Traefik stripped /vm)
	return parts[0]
}

// extractToken gets the JWT from Authorization header, token query param, or cookie.
func extractToken(r *http.Request) string {
	// 1. Authorization: Bearer <token>
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	// 2. Query param ?token=<jwt>
	if token := r.URL.Query().Get("token"); token != "" {
		return token
	}

	// 3. Cookie (Supabase stores session in sb-*-auth-token cookie)
	for _, cookie := range r.Cookies() {
		if strings.HasPrefix(cookie.Name, "sb-") && strings.HasSuffix(cookie.Name, "-auth-token") {
			return cookie.Value
		}
	}

	return ""
}
