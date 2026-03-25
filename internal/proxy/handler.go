package proxy

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/100yenadmin/evaos-ws-proxy/internal/auth"
	"github.com/100yenadmin/evaos-ws-proxy/internal/health"
	"github.com/100yenadmin/evaos-ws-proxy/internal/registry"
	"github.com/gorilla/websocket"
)

// customerIDPattern validates customer_id format: alphanumeric, hyphens, underscores (slug or UUID).
var customerIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

// allowedOrigins for WebSocket CORS check.
var allowedOrigins = map[string]bool{
	"https://electricsheephq.com":     true,
	"https://www.electricsheephq.com": true,
	"http://localhost:5173":           true, // Vite dev
	"http://localhost:3000":           true,
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true // Non-browser clients (curl, etc.)
		}
		return allowedOrigins[origin]
	},
	ReadBufferSize:  4096,
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
	MaxPerUser        int
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
	maxPerUser        int
	userConns         sync.Map // map[string]*atomic.Int64
}

// NewHandler creates a new proxy handler.
func NewHandler(cfg HandlerConfig) *Handler {
	adminSet := make(map[string]bool, len(cfg.AdminEmails))
	for _, e := range cfg.AdminEmails {
		adminSet[strings.ToLower(e)] = true
	}
	maxPerUser := cfg.MaxPerUser
	if maxPerUser <= 0 {
		maxPerUser = 10 // default
	}
	return &Handler{
		jwt:               cfg.JWTValidator,
		vms:               cfg.VMRegistry,
		health:            cfg.Health,
		adminEmails:       adminSet,
		connectTimeout:    cfg.ConnectTimeout,
		reconnectAttempts: cfg.ReconnectAttempts,
		maxConnections:    cfg.MaxConnections,
		maxPerUser:        maxPerUser,
	}
}

// acquireUserConn increments the per-user connection counter and returns true if allowed.
func (h *Handler) acquireUserConn(userID string) bool {
	val, _ := h.userConns.LoadOrStore(userID, &atomic.Int64{})
	counter := val.(*atomic.Int64)
	for {
		cur := counter.Load()
		if cur >= int64(h.maxPerUser) {
			return false
		}
		if counter.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// releaseUserConn decrements the per-user connection counter.
func (h *Handler) releaseUserConn(userID string) {
	if val, ok := h.userConns.Load(userID); ok {
		counter := val.(*atomic.Int64)
		counter.Add(-1)
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

	// Extract and validate customer_id from path: /vm/{customer_id}/...
	customerID := extractCustomerID(r.URL.Path)
	if customerID == "" {
		slog.Info("missing customer_id in path", "path", r.URL.Path, "remote_addr", r.RemoteAddr)
		http.Error(w, "missing customer_id", http.StatusBadRequest)
		return
	}
	if !customerIDPattern.MatchString(customerID) {
		slog.Warn("invalid customer_id format", "customer_id", customerID, "remote_addr", r.RemoteAddr)
		http.Error(w, "invalid customer_id", http.StatusBadRequest)
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

	// Check per-user connection limit
	if !h.acquireUserConn(claims.UserID) {
		slog.Warn("per-user connection limit reached",
			"user_id", claims.UserID, "max_per_user", h.maxPerUser)
		http.Error(w, "too many connections for user", http.StatusServiceUnavailable)
		return
	}
	// Will be released in the defer after WS upgrade succeeds.
	// If we return early (before upgrade), release here.
	userConnAcquired := true
	defer func() {
		if userConnAcquired {
			h.releaseUserConn(claims.UserID)
		}
	}()

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
		// userConnAcquired release is handled by the earlier defer
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

// connectBackend dials the backend gateway WebSocket with retry and exponential backoff.
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
	// Set Origin to match the proxy's own origin so the gateway's
	// allowedOrigins check passes (browser Origin is not forwarded).
	header.Set("Origin", "https://ecs.electricsheephq.com")

	// Also pass gateway token as header for compatibility
	if token != "" {
		header.Set("X-OpenClaw-Token", token)
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: h.connectTimeout,
	}

	var lastErr error
	maxAttempts := h.reconnectAttempts
	if maxAttempts <= 0 {
		maxAttempts = 1 // at least one attempt
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			backoff := time.Second * time.Duration(1<<(attempt-1)) // 1s, 2s, 4s, ...
			logger.Warn("retrying backend connection",
				"attempt", attempt+1, "max_attempts", maxAttempts, "backoff", backoff)
			time.Sleep(backoff)
		}

		conn, _, err := dialer.Dial(backendURL, header)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		logger.Warn("backend dial failed",
			"attempt", attempt+1, "max_attempts", maxAttempts, "error", err)
	}

	return nil, fmt.Errorf("dial backend after %d attempts: %w", maxAttempts, lastErr)
}

func (h *Handler) proxyBidirectional(client, backend *websocket.Conn, vm *registry.VMInfo, logger *slog.Logger) {
	var once sync.Once
	done := make(chan struct{})
	closeDone := func() { once.Do(func() { close(done) }) }

	// Client → Backend
	go func() {
		defer closeDone()
		// If we have a gateway token, intercept the first client message (connect frame)
		// and inject auth.token before forwarding. All subsequent frames pass through as-is.
		if token := vm.EffectiveToken(); token != "" {
			if err := h.injectTokenInConnectFrame(client, backend, token, logger); err != nil {
				logger.Warn("connect frame injection failed", "error", err)
				return
			}
		}
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

// injectTokenInConnectFrame reads the first message from the client, injects the
// gateway token into the auth.token field, and sends the modified frame to the backend.
// If the message is not valid JSON, it is forwarded unmodified.
func (h *Handler) injectTokenInConnectFrame(client, backend *websocket.Conn, token string, logger *slog.Logger) error {
	msgType, msg, err := client.ReadMessage()
	if err != nil {
		if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
			logger.Warn("read error", "direction", "client→backend (connect frame)", "error", err)
		}
		return err
	}

	// Only attempt JSON injection for text frames
	if msgType == websocket.TextMessage {
		var frame map[string]interface{}
		if jsonErr := json.Unmarshal(msg, &frame); jsonErr == nil {
			// OpenClaw connect frame format: {"type":"req","method":"connect","id":"...","params":{"auth":{"token":"..."},...}}
			// Inject token into params.auth.token (not top-level auth)
			params, hasParams := frame["params"].(map[string]interface{})
			if !hasParams {
				params = make(map[string]interface{})
			}
			authObj, ok := params["auth"].(map[string]interface{})
			if !ok {
				authObj = make(map[string]interface{})
			}
			authObj["token"] = token
			params["auth"] = authObj
			frame["params"] = params

			if modified, marshalErr := json.Marshal(frame); marshalErr == nil {
				msg = modified
				logger.Debug("injected gateway token into connect frame")
			} else {
				logger.Warn("failed to marshal modified connect frame, forwarding original", "error", marshalErr)
			}
		} else {
			logger.Debug("connect frame is not valid JSON, forwarding unmodified")
		}
	}

	if err := backend.WriteMessage(msgType, msg); err != nil {
		logger.Warn("write error", "direction", "client→backend (connect frame)", "error", err)
		return err
	}
	return nil
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

// isWebSocketUpgrade returns true if the request is a WebSocket upgrade.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// ServeHTTP dispatches between WebSocket upgrades and regular HTTP proxy requests.
// Register this on the mux instead of HandleWebSocket directly.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if isWebSocketUpgrade(r) {
		h.HandleWebSocket(w, r)
		return
	}
	h.HandleHTTPProxy(w, r)
}

// HandleHTTPProxy forwards regular HTTP requests to the backend VM gateway.
// It performs the same auth + VM lookup as HandleWebSocket, then reverse-proxies
// the request with the /vm/{customer_id} prefix stripped.
func (h *Handler) HandleHTTPProxy(w http.ResponseWriter, r *http.Request) {
	// Extract and validate customer_id from path
	customerID := extractCustomerID(r.URL.Path)
	if customerID == "" {
		http.Error(w, "missing customer_id", http.StatusBadRequest)
		return
	}
	if !customerIDPattern.MatchString(customerID) {
		http.Error(w, "invalid customer_id", http.StatusBadRequest)
		return
	}

	// Extract and validate Supabase JWT
	tokenStr := extractToken(r)
	if tokenStr == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	claims, err := h.jwt.Validate(tokenStr)
	if err != nil {
		slog.Info("http proxy auth failed",
			"error", err, "remote_addr", r.RemoteAddr, "customer_id", customerID)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	logger := slog.With(
		"user_id", claims.UserID,
		"customer_id", customerID,
		"remote_addr", r.RemoteAddr,
		"method", r.Method,
		"path", r.URL.Path,
	)

	// Look up VM by customer_id
	vm, err := h.vms.LookupByCustomerID(customerID)
	if err != nil {
		logger.Error("vm lookup failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if vm == nil {
		http.Error(w, "no VM assigned", http.StatusNotFound)
		return
	}

	// Authorization: verify the user owns this VM (unless admin)
	if vm.UserID != claims.UserID && !h.isAdmin(claims.Email) {
		logger.Warn("http proxy forbidden",
			"vm_user_id", vm.UserID, "email", claims.Email)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Strip /vm/{customer_id} prefix from the path to get the backend path.
	// e.g. /vm/cust-1/ui/index.html → /ui/index.html
	backendPath := stripVMPrefix(r.URL.Path, customerID)

	// Build backend target URL
	backendURL := fmt.Sprintf("http://%s:%d", vm.EffectiveIP(), vm.GatewayPort)
	target, err := url.Parse(backendURL)
	if err != nil {
		logger.Error("invalid backend URL", "url", backendURL, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	logger.Debug("proxying HTTP request",
		"backend", backendURL,
		"backend_path", backendPath,
	)

	// Use httputil.ReverseProxy for robust proxying
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = backendPath
			req.URL.RawQuery = stripTokenParam(r.URL.RawQuery)
			req.Host = target.Host

			// Set trusted-proxy headers
			req.Header.Set("X-Forwarded-User", customerID)
			req.Header.Set("X-Forwarded-Customer", customerID)
			req.Header.Set("X-Forwarded-For", r.RemoteAddr)
			req.Header.Set("X-Forwarded-Proto", "https")

			// Inject gateway token if available
			if token := vm.EffectiveToken(); token != "" {
				req.Header.Set("X-OpenClaw-Token", token)
			}

			// Remove hop-by-hop headers
			req.Header.Del("Authorization")
		},
		ModifyResponse: func(resp *http.Response) error {
			// Add cache headers based on content type
			addCacheHeaders(resp)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("http proxy backend error", "error", err)
			http.Error(w, "backend unavailable", http.StatusBadGateway)
		},
		Transport: &http.Transport{
			ResponseHeaderTimeout: h.connectTimeout,
		},
	}

	proxy.ServeHTTP(w, r)
}

// stripVMPrefix removes the /vm/{customer_id} prefix from a URL path.
// If path doesn't have the /vm/ prefix (Traefik strip mode), strips /{customer_id}.
// Returns at least "/" if the result would be empty.
func stripVMPrefix(urlPath, customerID string) string {
	// Try /vm/{customer_id}/... first
	prefix := "/vm/" + customerID
	if strings.HasPrefix(urlPath, prefix) {
		result := strings.TrimPrefix(urlPath, prefix)
		if result == "" || result[0] != '/' {
			result = "/" + result
		}
		return path.Clean(result)
	}

	// Try /{customer_id}/... (Traefik strip-prefix mode)
	prefix = "/" + customerID
	if strings.HasPrefix(urlPath, prefix) {
		result := strings.TrimPrefix(urlPath, prefix)
		if result == "" || result[0] != '/' {
			result = "/" + result
		}
		return path.Clean(result)
	}

	return urlPath
}

// stripTokenParam removes the "token" query parameter from raw query string
// to avoid leaking Supabase JWTs to the backend.
func stripTokenParam(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return rawQuery
	}
	values.Del("token")
	return values.Encode()
}

// addCacheHeaders sets appropriate Cache-Control headers based on content type.
// Static assets (JS, CSS, fonts, images) get long cache; HTML gets no-cache.
func addCacheHeaders(resp *http.Response) {
	ct := resp.Header.Get("Content-Type")

	// Don't override if backend already set Cache-Control
	if resp.Header.Get("Cache-Control") != "" {
		return
	}

	switch {
	case strings.Contains(ct, "text/html"):
		resp.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	case strings.Contains(ct, "javascript"),
		strings.Contains(ct, "text/css"),
		strings.Contains(ct, "font/"),
		strings.Contains(ct, "image/"):
		resp.Header.Set("Cache-Control", "public, max-age=86400, immutable")
	default:
		// Other types: short cache
		resp.Header.Set("Cache-Control", "public, max-age=300")
	}
}

// Ensure Handler implements http.Handler (used for the combined WS+HTTP route).
var _ http.Handler = (*Handler)(nil)

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
