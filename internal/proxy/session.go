package proxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	sessionCookieName   = "evaos_session"
	sessionCookieDomain = "ecs.electricsheephq.com"
	sessionMaxAge       = 4 * time.Hour
	sessionRenewWindow  = 1 * time.Hour // renew if less than this remaining

	callbackTokenMaxAge = 30 * time.Second
)

// SessionClaims are the claims embedded in the proxy session token.
type SessionClaims struct {
	UserID     string   `json:"user_id"`
	Email      string   `json:"email"`
	Roles      []string `json:"roles,omitempty"`
	CustomerID string   `json:"customer_id,omitempty"`
	Exp        int64    `json:"exp"`
}

// CallbackTokenClaims are the claims for the short-lived callback token.
type CallbackTokenClaims struct {
	Type string `json:"type"` // always "callback"
	Ref  string `json:"ref"`  // reference to pending session data
	Exp  int64  `json:"exp"`
}

// pendingSession holds session data waiting for callback exchange.
type pendingSession struct {
	claims    SessionClaims
	createdAt time.Time
}

// sessionHeader is the fixed JWT header for proxy session tokens.
var sessionHeader = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

// DeriveKey creates a purpose-specific HMAC key from a base secret.
func DeriveKey(base, purpose string) []byte {
	h := hmac.New(sha256.New, []byte(base))
	h.Write([]byte(purpose))
	return h.Sum(nil)
}

// SessionManager handles proxy session token generation and validation.
type SessionManager struct {
	secret []byte

	// Pending callback sessions (H-1: short-lived callback tokens)
	pendingMu       sync.Mutex
	pendingSessions map[string]*pendingSession // keyed by callback ref hash
}

// NewSessionManager creates a session manager with the given HMAC secret.
func NewSessionManager(secret []byte) *SessionManager {
	sm := &SessionManager{
		secret:          secret,
		pendingSessions: make(map[string]*pendingSession),
	}
	// Start cleanup goroutine for expired pending sessions
	go sm.cleanupPendingSessions()
	return sm
}

// cleanupPendingSessions periodically removes expired pending session entries.
func (sm *SessionManager) cleanupPendingSessions() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		sm.pendingMu.Lock()
		now := time.Now()
		for key, ps := range sm.pendingSessions {
			if now.Sub(ps.createdAt) > callbackTokenMaxAge+10*time.Second {
				delete(sm.pendingSessions, key)
			}
		}
		sm.pendingMu.Unlock()
	}
}

// GenerateSessionToken creates a signed proxy session JWT.
func (sm *SessionManager) GenerateSessionToken(claims SessionClaims) (string, error) {
	if claims.Exp == 0 {
		claims.Exp = time.Now().Add(sessionMaxAge).Unix()
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := sessionHeader + "." + payloadB64

	mac := hmac.New(sha256.New, sm.secret)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig, nil
}

// ValidateSessionToken validates a proxy session JWT and returns the claims.
func (sm *SessionManager) ValidateSessionToken(tokenStr string) (*SessionClaims, error) {
	// Split into 3 parts
	parts := splitToken(tokenStr)
	if parts == nil {
		return nil, fmt.Errorf("invalid token format")
	}

	// Verify signature
	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, sm.secret)
	mac.Write([]byte(signingInput))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	var claims SessionClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}

	// Check expiry
	if time.Now().Unix() > claims.Exp {
		return nil, fmt.Errorf("token expired")
	}

	return &claims, nil
}

// GenerateCallbackToken creates a short-lived callback token (30s TTL, single-use)
// and stores the real session data in memory for later exchange.
func (sm *SessionManager) GenerateCallbackToken(sessionClaims SessionClaims) (string, error) {
	// Generate random ref
	refBytes := make([]byte, 16)
	if _, err := rand.Read(refBytes); err != nil {
		return "", fmt.Errorf("generate ref: %w", err)
	}
	ref := hex.EncodeToString(refBytes)

	// Store pending session data keyed by ref hash
	refHash := sha256Hash(ref)
	sm.pendingMu.Lock()
	sm.pendingSessions[refHash] = &pendingSession{
		claims:    sessionClaims,
		createdAt: time.Now(),
	}
	sm.pendingMu.Unlock()

	// Build callback token JWT
	cbClaims := CallbackTokenClaims{
		Type: "callback",
		Ref:  ref,
		Exp:  time.Now().Add(callbackTokenMaxAge).Unix(),
	}

	payload, err := json.Marshal(cbClaims)
	if err != nil {
		return "", fmt.Errorf("marshal callback claims: %w", err)
	}

	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := sessionHeader + "." + payloadB64

	mac := hmac.New(sha256.New, sm.secret)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig, nil
}

// ExchangeCallbackToken validates a callback token, looks up and removes the pending
// session data, then generates the real session token. Returns empty if invalid/expired/replayed.
func (sm *SessionManager) ExchangeCallbackToken(callbackTokenStr string) (string, *SessionClaims, error) {
	// Parse and validate callback token
	parts := splitToken(callbackTokenStr)
	if parts == nil {
		return "", nil, fmt.Errorf("invalid token format")
	}

	// Verify signature
	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, sm.secret)
	mac.Write([]byte(signingInput))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return "", nil, fmt.Errorf("invalid signature")
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil, fmt.Errorf("decode payload: %w", err)
	}

	var cbClaims CallbackTokenClaims
	if err := json.Unmarshal(payloadBytes, &cbClaims); err != nil {
		return "", nil, fmt.Errorf("unmarshal claims: %w", err)
	}

	// Check type
	if cbClaims.Type != "callback" {
		return "", nil, fmt.Errorf("not a callback token")
	}

	// Check expiry
	if time.Now().Unix() > cbClaims.Exp {
		return "", nil, fmt.Errorf("callback token expired")
	}

	// Look up and delete pending session (single-use)
	refHash := sha256Hash(cbClaims.Ref)
	sm.pendingMu.Lock()
	ps, ok := sm.pendingSessions[refHash]
	if ok {
		delete(sm.pendingSessions, refHash)
	}
	sm.pendingMu.Unlock()

	if !ok {
		return "", nil, fmt.Errorf("callback token already used or invalid")
	}

	// Check pending session TTL as extra safety
	if time.Since(ps.createdAt) > callbackTokenMaxAge+5*time.Second {
		return "", nil, fmt.Errorf("pending session expired")
	}

	// Generate the real session token
	sessionToken, err := sm.GenerateSessionToken(ps.claims)
	if err != nil {
		return "", nil, fmt.Errorf("generate session token: %w", err)
	}

	return sessionToken, &ps.claims, nil
}

// sha256Hash returns hex-encoded SHA-256 hash of input.
func sha256Hash(input string) string {
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:])
}

// SetSessionCookie sets the evaos_session cookie on the response.
func (sm *SessionManager) SetSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Domain:   sessionCookieDomain,
		Path:     "/",
		MaxAge:   int(sessionMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie clears the evaos_session cookie (H-3: logout).
func (sm *SessionManager) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Domain:   sessionCookieDomain,
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// GetSessionCookie reads the evaos_session cookie from the request.
func GetSessionCookie(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// ShouldRenew returns true if the session token is close to expiry and should be renewed.
func (sm *SessionManager) ShouldRenew(claims *SessionClaims) bool {
	remaining := time.Until(time.Unix(claims.Exp, 0))
	return remaining < sessionRenewWindow
}

// RenewSessionToken generates a new token with the same claims but a fresh expiry.
func (sm *SessionManager) RenewSessionToken(claims *SessionClaims) (string, error) {
	renewed := *claims
	renewed.Exp = time.Now().Add(sessionMaxAge).Unix()
	return sm.GenerateSessionToken(renewed)
}

// splitToken splits a JWT into its 3 parts. Returns nil if invalid format.
func splitToken(token string) []string {
	var parts [3]string
	start := 0
	partIdx := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			if partIdx >= 2 {
				return nil
			}
			parts[partIdx] = token[start:i]
			partIdx++
			start = i + 1
		}
	}
	if partIdx != 2 {
		return nil
	}
	parts[2] = token[start:]
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil
	}
	return parts[:]
}
