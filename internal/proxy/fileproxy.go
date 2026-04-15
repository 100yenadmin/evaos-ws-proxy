package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

// maxFileBodySize limits file uploads through the proxy to 100MB.
const maxFileBodySize = 100 << 20 // 100 MiB

// filegatorPort is the port where Filegator runs on each VM.
const filegatorPort = 8891

type filegatorSession struct {
	Cookie    string
	CSRFToken string
	ExpiresAt time.Time
}

type filegatorSessionStore struct {
	mu       sync.Mutex
	sessions map[string]*filegatorSession // key: customer_id
}

var globalFilegatorSessions = &filegatorSessionStore{
	sessions: make(map[string]*filegatorSession),
}

func (s *filegatorSessionStore) get(customerID string) *filegatorSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[customerID]
	if sess == nil || time.Now().After(sess.ExpiresAt) {
		return nil
	}
	return sess
}

func (s *filegatorSessionStore) set(customerID string, sess *filegatorSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[customerID] = sess
}

func bootstrapFilegatorSession(vmIP, customerID string) (*filegatorSession, error) {
	base := fmt.Sprintf("http://%s:%d", vmIP, filegatorPort)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 15 * time.Second}

	resp, err := client.Get(base + "/")
	if err != nil {
		return nil, fmt.Errorf("filegator init GET failed: %w", err)
	}
	resp.Body.Close()
	csrf := resp.Header.Get("X-CSRF-Token")

	loginBody := `{"username":"customer","password":"customer123456"}`
	req, _ := http.NewRequest("POST", base+"/?r=/login", strings.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err = client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("filegator login failed: %w", err)
	}
	resp.Body.Close()
	newCSRF := resp.Header.Get("X-CSRF-Token")
	if newCSRF != "" {
		csrf = newCSRF
	}

	baseURL, _ := url.Parse(base)
	cookies := jar.Cookies(baseURL)
	var sessionCookie string
	for _, c := range cookies {
		if c.Name == "filegator" {
			sessionCookie = c.Value
			break
		}
	}
	if sessionCookie == "" {
		return nil, fmt.Errorf("filegator session cookie not found after login")
	}

	return &filegatorSession{
		Cookie:    sessionCookie,
		CSRFToken: csrf,
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}, nil
}

func mapFilegatorPath(fullPath, customerID string) string {
	// Try /vm/{customerID}/files... first (direct access, no Traefik strip)
	prefix := "/vm/" + customerID + "/files"
	if strings.HasPrefix(fullPath, prefix) {
		stripped := strings.TrimPrefix(fullPath, prefix)
		if stripped == "" || stripped == "/" {
			return "/"
		}
		return stripped
	}
	// Try /{customerID}/files... (Traefik stripped /vm prefix before forwarding)
	prefix = "/" + customerID + "/files"
	if strings.HasPrefix(fullPath, prefix) {
		stripped := strings.TrimPrefix(fullPath, prefix)
		if stripped == "" || stripped == "/" {
			return "/"
		}
		return stripped
	}
	return fullPath
}

// HandleFileProxy serves files from a customer's VM via File Browser (filebrowser.org).
// Route: /vm/{customer_id}/files/{path...}
// Auth: Supabase JWT or session cookie (proxy handles all authentication).
// File Browser runs on port 8890 with --noauth, so the proxy is the only auth layer.
// The /vm/{customer_id} prefix is stripped; /files/* is passed through as-is
// since File Browser is configured with baseURL=/files.
func (h *Handler) HandleFileProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
		r.Body = http.MaxBytesReader(w, r.Body, maxFileBodySize)
	}

	customerID := extractCustomerID(r.URL.Path)
	if customerID == "" || !customerIDPattern.MatchString(customerID) {
		slog.Info("file proxy: invalid customer_id", "path", r.URL.Path, "customer_id", customerID)
		http.Error(w, "invalid customer_id", http.StatusBadRequest)
		return
	}

	var userID string
	var authedViaSession bool

	if h.sessions != nil {
		sessionToken := GetSessionCookie(r)
		slog.Info("file proxy: auth check",
			"customer_id", customerID,
			"path", r.URL.Path,
			"has_session_cookie", sessionToken != "",
			"remote_addr", r.RemoteAddr)
		if sessionToken != "" {
			sessionClaims, err := h.sessions.ValidateSessionToken(sessionToken)
			if err != nil {
				slog.Info("file proxy: session cookie invalid", "error", err, "customer_id", customerID)
			} else if !h.sessionCustomerMatches(sessionClaims, customerID) {
				slog.Info("file proxy: session customer mismatch",
					"session_customer_id", sessionClaims.CustomerID,
					"route_customer_id", customerID,
					"remote_addr", r.RemoteAddr)
			} else {
				vm, err := h.vms.LookupByCustomerID(customerID)
				slog.Info("file proxy: vm lookup",
					"customer_id", customerID,
					"vm_found", vm != nil,
					"lookup_err", err,
					"session_user_id", sessionClaims.UserID)
				if err == nil && vm != nil {
					if sessionClaims.UserID == vm.UserID || h.isAdmin(sessionClaims.Email) {
						userID = sessionClaims.UserID
						authedViaSession = true
					} else {
						slog.Warn("file proxy: ownership mismatch",
							"session_user", sessionClaims.UserID,
							"vm_user", vm.UserID,
							"customer_id", customerID)
						http.Error(w, "forbidden", http.StatusForbidden)
						return
					}
				}
				if authedViaSession && h.sessions.ShouldRenew(sessionClaims) {
					if renewed, err := h.sessions.RenewSessionToken(sessionClaims); err == nil {
						h.sessions.SetSessionCookie(w, renewed)
					}
				}
			}
		}
	} else {
		slog.Warn("file proxy: no session manager")
	}

	if !authedViaSession {
		tokenStr := extractToken(r)
		slog.Info("file proxy: fallback to token", "has_token", tokenStr != "", "customer_id", customerID)
		if tokenStr == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		claims, err := h.jwt.Validate(tokenStr)
		if err != nil {
			slog.Info("file proxy auth failed",
				"error", err, "remote_addr", r.RemoteAddr, "customer_id", customerID)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		userID = claims.UserID

		vm, err := h.vms.LookupByCustomerID(customerID)
		if err != nil {
			slog.Error("file proxy vm lookup failed", "error", err, "customer_id", customerID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if vm == nil {
			http.Error(w, "no VM assigned", http.StatusNotFound)
			return
		}
		if vm.UserID != claims.UserID && !h.isAdmin(claims.Email) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}

	vm, err := h.vms.LookupByCustomerID(customerID)
	if err != nil {
		slog.Error("file proxy vm lookup failed", "error", err, "customer_id", customerID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if vm == nil {
		http.Error(w, "no VM assigned", http.StatusNotFound)
		return
	}

	session := globalFilegatorSessions.get(customerID)
	if session == nil {
		session, err = bootstrapFilegatorSession(vm.EffectiveIP(), customerID)
		if err != nil {
			slog.Error("filegator session bootstrap failed", "error", err, "customer_id", customerID, "vm_ip", vm.EffectiveIP())
			http.Error(w, "file server unavailable", http.StatusBadGateway)
			return
		}
		globalFilegatorSessions.set(customerID, session)
	}

	mappedPath := mapFilegatorPath(r.URL.Path, customerID)
	if strings.Contains(mappedPath, "..") {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	filePath := path.Clean(mappedPath)
	if filePath == "." || filePath == "" {
		filePath = "/"
	}
	if !strings.HasPrefix(filePath, "/") {
		filePath = "/" + filePath
	}

	logger := slog.With(
		"user_id", userID,
		"customer_id", customerID,
		"remote_addr", r.RemoteAddr,
		"file_path", filePath,
	)

	backendURL := fmt.Sprintf("http://%s:%d", vm.EffectiveIP(), filegatorPort)
	target, err := url.Parse(backendURL)
	if err != nil {
		logger.Error("invalid file server URL", "url", backendURL, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	logger.Debug("proxying filegator request", "backend", backendURL, "file_path", filePath)

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = filePath
			req.URL.RawPath = filePath
			req.URL.RawQuery = r.URL.RawQuery
			req.Host = target.Host
			req.RequestURI = ""

			req.Header.Set("X-Forwarded-For", r.RemoteAddr)
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Del("Authorization")
			req.Header.Del("Cookie")
			req.Header.Set("Cookie", "filegator="+session.Cookie)
			if session.CSRFToken != "" {
				req.Header.Set("X-CSRF-Token", session.CSRFToken)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("X-Frame-Options")
			resp.Header.Del("Set-Cookie")
			resp.Header.Set("Content-Security-Policy", "frame-ancestors 'self' https://ecs.electricsheephq.com")

			origin := r.Header.Get("Origin")
			if origin != "" && allowedOrigins[origin] {
				resp.Header.Set("Access-Control-Allow-Origin", origin)
			}
			if resp.Header.Get("Cache-Control") == "" {
				resp.Header.Set("Cache-Control", "private, max-age=300")
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("file proxy backend error", "error", err)
			http.Error(w, "file server unavailable", http.StatusBadGateway)
		},
		Transport: h.httpTransport,
	}

	proxy.ServeHTTP(w, r)
}

// HandleBareFileProxy handles bare /files/... requests (no /vm/{cid} prefix).
// File Browser's JS makes absolute-path requests like /files/api/resources/
// because its baseURL is "/files". We look up the customer_id from the session
// cookie and proxy directly to File Browser on the correct VM.
//
// This handler only supports session cookie auth (not JWT), because these
// requests come from File Browser's JS running in an already-authenticated
// browser session.
func (h *Handler) HandleBareFileProxy(w http.ResponseWriter, r *http.Request) {
	// Limit uploads
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
		r.Body = http.MaxBytesReader(w, r.Body, maxFileBodySize)
	}

	// Auth: session cookie only (these are JS-initiated requests from File Browser UI)
	if h.sessions == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	sessionToken := GetSessionCookie(r)
	if sessionToken == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	sessionClaims, err := h.sessions.ValidateSessionToken(sessionToken)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Look up VM by customer_id from session
	customerID := sessionClaims.CustomerID
	if customerID == "" {
		// Fallback: look up by user_id
		vm, err := h.vms.LookupByUserID(sessionClaims.UserID)
		if err != nil || vm == nil {
			http.Error(w, "no VM found", http.StatusNotFound)
			return
		}
		customerID = vm.CustomerID
	}

	vm, err := h.vms.LookupByCustomerID(customerID)
	if err != nil || vm == nil {
		http.Error(w, "VM not found", http.StatusNotFound)
		return
	}
	if sessionClaims.UserID != vm.UserID && !h.isAdmin(sessionClaims.Email) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Renew session if needed
	if h.sessions.ShouldRenew(sessionClaims) {
		if renewed, err := h.sessions.RenewSessionToken(sessionClaims); err == nil {
			h.sessions.SetSessionCookie(w, renewed)
		}
	}

	// Clean the path
	filePath := path.Clean(r.URL.Path)
	if !strings.HasPrefix(filePath, "/files") {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	logger := slog.With(
		"user_id", sessionClaims.UserID,
		"customer_id", customerID,
		"remote_addr", r.RemoteAddr,
		"file_path", filePath,
		"bare_file_proxy", true,
	)

	// Proxy to File Browser on port 8890
	backendURL := fmt.Sprintf("http://%s:%d", vm.EffectiveIP(), filegatorPort)
	target, err := url.Parse(backendURL)
	if err != nil {
		logger.Error("invalid file server URL", "url", backendURL, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	logger.Debug("proxying bare file request", "backend", backendURL)

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = filePath
			req.URL.RawQuery = r.URL.RawQuery
			req.Host = target.Host
			req.Header.Set("X-Forwarded-For", r.RemoteAddr)
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Del("Authorization")
			req.Header.Del("Cookie")
		},
		ModifyResponse: func(resp *http.Response) error {
			origin := r.Header.Get("Origin")
			if origin != "" && allowedOrigins[origin] {
				resp.Header.Set("Access-Control-Allow-Origin", origin)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("bare file proxy backend error", "error", err)
			http.Error(w, "file server unavailable", http.StatusBadGateway)
		},
		Transport: h.httpTransport,
	}

	proxy.ServeHTTP(w, r)
}
