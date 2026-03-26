package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	sessionCookieName   = "evaos_session"
	sessionCookieDomain = ".electricsheephq.com"
	sessionMaxAge       = 24 * time.Hour
	sessionRenewWindow  = 6 * time.Hour // renew if less than this remaining
)

// SessionClaims are the claims embedded in the proxy session token.
type SessionClaims struct {
	UserID     string   `json:"user_id"`
	Email      string   `json:"email"`
	Roles      []string `json:"roles,omitempty"`
	CustomerID string   `json:"customer_id,omitempty"`
	Exp        int64    `json:"exp"`
}

// sessionHeader is the fixed JWT header for proxy session tokens.
var sessionHeader = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

// SessionManager handles proxy session token generation and validation.
type SessionManager struct {
	secret []byte
}

// NewSessionManager creates a session manager with the given HMAC secret.
func NewSessionManager(secret []byte) *SessionManager {
	return &SessionManager{secret: secret}
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
