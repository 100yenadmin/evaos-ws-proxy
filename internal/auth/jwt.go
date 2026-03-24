package auth

import (
	"encoding/base64"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents the relevant JWT claims from a Supabase token.
type Claims struct {
	UserID string // sub claim
	Email  string // email claim (optional)
}

// JWTValidator validates Supabase JWTs using HS256.
type JWTValidator struct {
	secret []byte
}

// NewJWTValidator creates a validator with the given HMAC secret.
// The secret may be base64-encoded (as Supabase provides it) or raw.
func NewJWTValidator(secret string) *JWTValidator {
	// Try base64 decode first (Supabase JWT secrets are base64-encoded)
	decoded, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		// Not valid base64 — use as raw bytes
		decoded = []byte(secret)
	}
	return &JWTValidator{secret: decoded}
}

// Validate parses and validates a JWT string, returning the extracted claims.
func (v *JWTValidator) Validate(tokenStr string) (*Claims, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return v.secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
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
