package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
)

// maxFileBodySize limits file uploads through the proxy to 100MB.
const maxFileBodySize = 100 << 20 // 100 MiB

// fileBrowserPort is the port where File Browser (filebrowser.org) runs on each VM.
// File Browser runs in noauth mode — the proxy is the sole auth layer.
const fileBrowserPort = 8890

// HandleFileProxy serves files from a customer's VM via File Browser (filebrowser.org).
// Route: /vm/{customer_id}/files/{path...}
// Auth: Supabase JWT or session cookie (proxy handles all authentication).
// File Browser runs on port 8890 with --noauth, so the proxy is the only auth layer.
// The /vm/{customer_id} prefix is stripped; /files/* is passed through as-is
// since File Browser is configured with baseURL=/files.
func (h *Handler) HandleFileProxy(w http.ResponseWriter, r *http.Request) {
	// File Browser uses GET, HEAD, POST, PUT, PATCH, DELETE for its full UI.
	// Allow all standard methods.

	// Limit request body size for mutating methods to prevent abuse
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
		r.Body = http.MaxBytesReader(w, r.Body, maxFileBodySize)
	}

	customerID := extractCustomerID(r.URL.Path)
	if customerID == "" || !customerIDPattern.MatchString(customerID) {
		http.Error(w, "invalid customer_id", http.StatusBadRequest)
		return
	}

	// --- Auth (identical to HandleHTTPProxy non-UI path) ---
	var userID string
	var authedViaSession bool

	// 1. Check session cookie
	if h.sessions != nil {
		if sessionToken := GetSessionCookie(r); sessionToken != "" {
			if sessionClaims, err := h.sessions.ValidateSessionToken(sessionToken); err == nil {
				vm, err := h.vms.LookupByCustomerID(customerID)
				if err == nil && vm != nil {
					if sessionClaims.UserID == vm.UserID || h.isAdmin(sessionClaims.Email) {
						userID = sessionClaims.UserID
						authedViaSession = true
					} else {
						http.Error(w, "forbidden", http.StatusForbidden)
						return
					}
				}
				// Renew cookie if close to expiry
				if authedViaSession && h.sessions.ShouldRenew(sessionClaims) {
					if renewed, err := h.sessions.RenewSessionToken(sessionClaims); err == nil {
						h.sessions.SetSessionCookie(w, renewed)
					}
				}
			}
		}
	}

	// 2. Fall back to JWT
	if !authedViaSession {
		tokenStr := extractToken(r)
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

		// Verify ownership
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

	// --- VM lookup ---
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

	// --- Build file path ---
	// Strip /vm/{customer_id} prefix, keep /files/* intact.
	// File Browser is configured with baseurl=/files, so it expects /files/... paths.
	backendPath := stripVMPrefix(r.URL.Path, customerID)
	// Clean the path to prevent traversal via encoded dots (%2e%2e)
	backendPath = path.Clean(backendPath)
	// backendPath is now "/files/..." — pass it through as-is.
	filePath := backendPath
	if filePath == "" || filePath == "." {
		filePath = "/files/"
	}
	// Verify the cleaned path still starts with /files to prevent traversal escape
	if !strings.HasPrefix(filePath, "/files") {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	logger := slog.With(
		"user_id", userID,
		"customer_id", customerID,
		"remote_addr", r.RemoteAddr,
		"file_path", filePath,
	)

	// --- Reverse proxy to File Browser (port 8890, noauth) ---
	// File Browser runs standalone on the VM, NOT behind the OpenClaw gateway.
	// Auth is handled entirely by the proxy (Supabase JWT/session above).
	backendURL := fmt.Sprintf("http://%s:%d", vm.EffectiveIP(), fileBrowserPort)
	target, err := url.Parse(backendURL)
	if err != nil {
		logger.Error("invalid file server URL", "url", backendURL, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	logger.Debug("proxying file request", "backend", backendURL, "file_path", filePath)

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = filePath
			req.URL.RawQuery = stripTokenParam(r.URL.RawQuery)
			req.Host = target.Host

			// Set forwarding headers
			req.Header.Set("X-Forwarded-For", r.RemoteAddr)
			req.Header.Set("X-Forwarded-Proto", "https")

			// Remove browser auth headers — File Browser runs noauth,
			// no credentials needed. Stripping prevents accidental leaks.
			req.Header.Del("Authorization")
			req.Header.Del("Cookie")
		},
		ModifyResponse: func(resp *http.Response) error {
			// Set CORS headers for file downloads
			origin := r.Header.Get("Origin")
			if origin != "" && allowedOrigins[origin] {
				resp.Header.Set("Access-Control-Allow-Origin", origin)
			}

			// Cache shared files for 5 minutes
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
