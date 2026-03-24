package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testSecret = "test-secret-key-for-jwt-validation"

func makeToken(claims jwt.MapClaims, secret string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, _ := token.SignedString([]byte(secret))
	return s
}

func TestValidate_ValidToken(t *testing.T) {
	tokenStr := makeToken(jwt.MapClaims{
		"sub":   "user-123",
		"email": "test@example.com",
		"exp":   float64(time.Now().Add(time.Hour).Unix()),
	}, testSecret)

	v := NewJWTValidator(testSecret)
	claims, err := v.Validate(tokenStr)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if claims.UserID != "user-123" {
		t.Errorf("expected user-123, got %s", claims.UserID)
	}
	if claims.Email != "test@example.com" {
		t.Errorf("expected test@example.com, got %s", claims.Email)
	}
}

func TestValidate_ExpiredToken(t *testing.T) {
	tokenStr := makeToken(jwt.MapClaims{
		"sub": "user-123",
		"exp": float64(time.Now().Add(-time.Hour).Unix()),
	}, testSecret)

	v := NewJWTValidator(testSecret)
	_, err := v.Validate(tokenStr)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestValidate_WrongSecret(t *testing.T) {
	tokenStr := makeToken(jwt.MapClaims{
		"sub": "user-123",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}, "wrong-secret")

	v := NewJWTValidator(testSecret)
	_, err := v.Validate(tokenStr)
	if err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

func TestValidate_MissingSub(t *testing.T) {
	tokenStr := makeToken(jwt.MapClaims{
		"email": "test@example.com",
		"exp":   float64(time.Now().Add(time.Hour).Unix()),
	}, testSecret)

	v := NewJWTValidator(testSecret)
	_, err := v.Validate(tokenStr)
	if err == nil {
		t.Fatal("expected error for missing sub")
	}
}

func TestValidate_NoEmail(t *testing.T) {
	tokenStr := makeToken(jwt.MapClaims{
		"sub": "user-456",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}, testSecret)

	v := NewJWTValidator(testSecret)
	claims, err := v.Validate(tokenStr)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if claims.Email != "" {
		t.Errorf("expected empty email, got %s", claims.Email)
	}
}
