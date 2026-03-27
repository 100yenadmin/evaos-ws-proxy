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

// maxAudioBodySize limits multipart STT uploads to 25MB (matches OpenAI's limit).
const maxAudioBodySize = 25 << 20 // 25 MiB

const speachesPort = 8000

// isAllowedAudioOrigin returns true for known dashboard origins and Chrome extension origins.
func isAllowedAudioOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	if allowedOrigins[origin] {
		return true
	}
	return strings.HasPrefix(origin, "chrome-extension://")
}

// HandleAudioProxy proxies OpenAI-compatible audio API requests to Speaches on the VM.
// Route: /vm/{customer_id}/v1/audio/{endpoint}
// Supported endpoints:
//   - POST /v1/audio/transcriptions (STT — multipart/form-data with audio file)
//   - POST /v1/audio/speech (TTS — JSON body, returns audio bytes)
//
// Auth: session cookie, gateway token, or Supabase JWT.
// The /vm/{customer_id} prefix is stripped; /v1/audio/* is kept intact.
func (h *Handler) HandleAudioProxy(w http.ResponseWriter, r *http.Request) {
	// Allow POST (main usage) and OPTIONS (CORS preflight)
	if r.Method != http.MethodPost && r.Method != http.MethodOptions {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Limit request body size to prevent abuse (25MB matches OpenAI's audio upload limit)
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxAudioBodySize)
	}

	customerID := extractCustomerID(r.URL.Path)
	if customerID == "" || !customerIDPattern.MatchString(customerID) {
		http.Error(w, "invalid customer_id", http.StatusBadRequest)
		return
	}

	// Handle CORS preflight
	if r.Method == http.MethodOptions {
		origin := r.Header.Get("Origin")
		if isAllowedAudioOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Max-Age", "3600")
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Resolve the VM up front so we can validate either JWT ownership or direct gateway-token auth.
	vm, err := h.vms.LookupByCustomerID(customerID)
	if err != nil {
		slog.Error("audio proxy vm lookup failed", "error", err, "customer_id", customerID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if vm == nil {
		http.Error(w, "no VM assigned", http.StatusNotFound)
		return
	}

	// --- Auth ---
	var userID string
	var authedViaSession bool

	// 1. Check session cookie
	if h.sessions != nil {
		if sessionToken := GetSessionCookie(r); sessionToken != "" {
			if sessionClaims, err := h.sessions.ValidateSessionToken(sessionToken); err == nil {
				if sessionClaims.UserID == vm.UserID || h.isAdmin(sessionClaims.Email) {
					userID = sessionClaims.UserID
					authedViaSession = true
				} else {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
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

	// 2. Fall back to Authorization/query token.
	if !authedViaSession {
		tokenStr := extractToken(r)
		if tokenStr == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Chrome extension / direct API usage: accept the VM's gateway token directly.
		if vm.EffectiveToken() != "" && tokenStr == vm.EffectiveToken() {
			userID = "gateway:" + customerID
		} else {
			claims, err := h.jwt.Validate(tokenStr)
			if err != nil {
				slog.Info("audio proxy auth failed",
					"error", err, "remote_addr", r.RemoteAddr, "customer_id", customerID)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			userID = claims.UserID

			if vm.UserID != claims.UserID && !h.isAdmin(claims.Email) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
	}

	// --- Build backend path ---
	// Strip /vm/{customer_id}, keep /v1/audio/* intact
	backendPath := path.Clean(stripVMPrefix(r.URL.Path, customerID))
	// Verify the cleaned path still starts with /v1/audio/ to prevent traversal escape
	if !strings.HasPrefix(backendPath, "/v1/audio/") {
		http.Error(w, "invalid audio path", http.StatusBadRequest)
		return
	}

	logger := slog.With(
		"user_id", userID,
		"customer_id", customerID,
		"remote_addr", r.RemoteAddr,
		"audio_path", backendPath,
	)

	// --- Reverse proxy to Speaches on VM ---
	backendURL := fmt.Sprintf("http://%s:%d", vm.EffectiveIP(), speachesPort)
	target, err := url.Parse(backendURL)
	if err != nil {
		logger.Error("invalid speaches URL", "url", backendURL, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	logger.Debug("proxying audio request", "backend", backendURL, "path", backendPath)

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = backendPath
			req.URL.RawQuery = stripTokenParam(r.URL.RawQuery)
			req.Host = target.Host

			// Forwarding metadata + VM-scoped backend auth.
			req.Header.Set("X-Forwarded-For", r.RemoteAddr)
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Del("Cookie")
			if token := vm.EffectiveToken(); token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("X-OpenClaw-Token", token)
			} else {
				req.Header.Del("Authorization")
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			origin := r.Header.Get("Origin")
			if isAllowedAudioOrigin(origin) {
				resp.Header.Set("Access-Control-Allow-Origin", origin)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("audio proxy backend error", "error", err)
			http.Error(w, "audio service unavailable", http.StatusBadGateway)
		},
		Transport: h.httpTransport,
	}

	proxy.ServeHTTP(w, r)
}
