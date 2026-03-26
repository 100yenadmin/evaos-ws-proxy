package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
)

const speachesPort = 8000

// HandleAudioProxy proxies OpenAI-compatible audio API requests to Speaches on the VM.
// Route: /vm/{customer_id}/v1/audio/{endpoint}
// Supported endpoints:
//   - POST /v1/audio/transcriptions (STT — multipart/form-data with audio file)
//   - POST /v1/audio/speech (TTS — JSON body, returns audio bytes)
//
// Auth: Supabase JWT or session cookie (same as other authenticated routes).
// The /vm/{customer_id} prefix is stripped; /v1/audio/* is kept intact.
func (h *Handler) HandleAudioProxy(w http.ResponseWriter, r *http.Request) {
	// Allow POST (main usage) and OPTIONS (CORS preflight)
	if r.Method != http.MethodPost && r.Method != http.MethodOptions {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	customerID := extractCustomerID(r.URL.Path)
	if customerID == "" || !customerIDPattern.MatchString(customerID) {
		http.Error(w, "invalid customer_id", http.StatusBadRequest)
		return
	}

	// Handle CORS preflight
	if r.Method == http.MethodOptions {
		origin := r.Header.Get("Origin")
		if origin != "" && allowedOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Max-Age", "3600")
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// --- Auth (identical to file proxy) ---
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
			slog.Info("audio proxy auth failed",
				"error", err, "remote_addr", r.RemoteAddr, "customer_id", customerID)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		userID = claims.UserID

		// Verify ownership
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
		if vm.UserID != claims.UserID && !h.isAdmin(claims.Email) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}

	// --- VM lookup ---
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

	// --- Build backend path ---
	// Strip /vm/{customer_id}, keep /v1/audio/* intact
	backendPath := stripVMPrefix(r.URL.Path, customerID)

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

			// Don't forward auth headers to the backend
			req.Header.Del("Authorization")
			req.Header.Del("Cookie")
		},
		ModifyResponse: func(resp *http.Response) error {
			// Set CORS headers
			origin := r.Header.Get("Origin")
			if origin != "" && allowedOrigins[origin] {
				resp.Header.Set("Access-Control-Allow-Origin", origin)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("audio proxy backend error", "error", err)
			http.Error(w, "audio service unavailable", http.StatusBadGateway)
		},
		// No FlushInterval needed — audio responses are typically complete before sending.
		// For streaming TTS, we'd add FlushInterval: -1, but Speaches buffers.
		Transport: &http.Transport{
			ResponseHeaderTimeout: h.connectTimeout,
		},
	}

	proxy.ServeHTTP(w, r)
}
