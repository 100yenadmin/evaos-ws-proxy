package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents the relevant JWT claims from a Supabase token.
type Claims struct {
	UserID string // sub claim
	Email  string // email claim (optional)
}

// jwksKey represents a single key from the JWKS endpoint.
type jwksKey struct {
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// jwksResponse represents the JWKS endpoint response.
type jwksResponse struct {
	Keys []jwksKey `json:"keys"`
}

// JWTValidator validates Supabase JWTs using JWKS (ES256) with HMAC (HS256) fallback.
type JWTValidator struct {
	jwksURL    string
	hmacSecret []byte // fallback for HS256 tokens

	mu       sync.RWMutex
	keys     map[string]*ecdsa.PublicKey
	fetchedAt time.Time
	cacheTTL  time.Duration
}

// NewJWTValidator creates a validator that fetches keys from the Supabase JWKS endpoint.
// The secret parameter is kept as HMAC fallback (legacy tokens).
// jwksURL example: "https://PROJECT.supabase.co/auth/v1/.well-known/jwks.json"
func NewJWTValidator(secret string, jwksURL string) *JWTValidator {
	var hmacSecret []byte
	if secret != "" {
		decoded, err := base64.StdEncoding.DecodeString(secret)
		if err != nil {
			decoded = []byte(secret)
		}
		hmacSecret = decoded
	}

	v := &JWTValidator{
		jwksURL:    jwksURL,
		hmacSecret: hmacSecret,
		keys:       make(map[string]*ecdsa.PublicKey),
		cacheTTL:   10 * time.Minute,
	}

	// Pre-fetch keys at startup (best-effort)
	_ = v.refreshKeys()

	return v
}

// refreshKeys fetches the JWKS endpoint and caches the public keys.
func (v *JWTValidator) refreshKeys() error {
	if v.jwksURL == "" {
		return fmt.Errorf("no JWKS URL configured")
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(v.jwksURL)
	if err != nil {
		return fmt.Errorf("JWKS fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("JWKS fetch returned %d", resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("JWKS parse failed: %w", err)
	}

	newKeys := make(map[string]*ecdsa.PublicKey)
	for _, k := range jwks.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" {
			continue
		}
		pubKey, err := parseECPublicKey(k)
		if err != nil {
			continue
		}
		newKeys[k.Kid] = pubKey
	}

	v.mu.Lock()
	v.keys = newKeys
	v.fetchedAt = time.Now()
	v.mu.Unlock()

	return nil
}

// getKey returns the public key for the given kid, refreshing if stale or missing.
func (v *JWTValidator) getKey(kid string) (*ecdsa.PublicKey, error) {
	v.mu.RLock()
	key, ok := v.keys[kid]
	stale := time.Since(v.fetchedAt) > v.cacheTTL
	v.mu.RUnlock()

	if ok && !stale {
		return key, nil
	}

	// Refresh and retry
	if err := v.refreshKeys(); err != nil {
		// If we had a cached key, use it even if stale
		if ok {
			return key, nil
		}
		return nil, err
	}

	v.mu.RLock()
	key, ok = v.keys[kid]
	v.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("key %s not found in JWKS", kid)
	}
	return key, nil
}

// Validate parses and validates a JWT string, returning the extracted claims.
func (v *JWTValidator) Validate(tokenStr string) (*Claims, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		switch t.Method.(type) {
		case *jwt.SigningMethodECDSA:
			kid, _ := t.Header["kid"].(string)
			if kid == "" {
				return nil, fmt.Errorf("ES256 token missing kid header")
			}
			return v.getKey(kid)
		case *jwt.SigningMethodHMAC:
			if len(v.hmacSecret) == 0 {
				return nil, fmt.Errorf("no HMAC secret configured")
			}
			return v.hmacSecret, nil
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
	}, jwt.WithValidMethods([]string{"ES256", "HS256"}))
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	sub, err := mapClaims.GetSubject()
	if err != nil || sub == "" {
		return nil, fmt.Errorf("missing sub claim")
	}

	claims := &Claims{UserID: sub}

	if email, ok := mapClaims["email"].(string); ok {
		claims.Email = email
	}

	return claims, nil
}

// parseECPublicKey converts a JWK EC key to an *ecdsa.PublicKey.
func parseECPublicKey(k jwksKey) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("decode x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("decode y: %w", err)
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}
