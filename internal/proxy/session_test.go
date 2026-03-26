package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionManager_GenerateAndValidate(t *testing.T) {
	sm := NewSessionManager([]byte("test-secret-key-for-hmac"))

	claims := SessionClaims{
		UserID:     "user-123",
		Email:      "test@example.com",
		Roles:      []string{"customer"},
		CustomerID: "cust-abc",
	}

	token, err := sm.GenerateSessionToken(claims)
	if err != nil {
		t.Fatalf("GenerateSessionToken failed: %v", err)
	}

	if token == "" {
		t.Fatal("expected non-empty token")
	}

	// Validate
	got, err := sm.ValidateSessionToken(token)
	if err != nil {
		t.Fatalf("ValidateSessionToken failed: %v", err)
	}

	if got.UserID != "user-123" {
		t.Errorf("UserID = %q, want %q", got.UserID, "user-123")
	}
	if got.Email != "test@example.com" {
		t.Errorf("Email = %q, want %q", got.Email, "test@example.com")
	}
	if got.CustomerID != "cust-abc" {
		t.Errorf("CustomerID = %q, want %q", got.CustomerID, "cust-abc")
	}
	if len(got.Roles) != 1 || got.Roles[0] != "customer" {
		t.Errorf("Roles = %v, want [customer]", got.Roles)
	}
}

func TestSessionManager_ExpiredToken(t *testing.T) {
	sm := NewSessionManager([]byte("test-secret"))

	claims := SessionClaims{
		UserID: "user-123",
		Email:  "test@example.com",
		Exp:    time.Now().Add(-1 * time.Hour).Unix(), // expired
	}

	token, err := sm.GenerateSessionToken(claims)
	if err != nil {
		t.Fatalf("GenerateSessionToken failed: %v", err)
	}

	_, err = sm.ValidateSessionToken(token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if err.Error() != "token expired" {
		t.Errorf("expected 'token expired' error, got: %v", err)
	}
}

func TestSessionManager_InvalidSignature(t *testing.T) {
	sm1 := NewSessionManager([]byte("secret-1"))
	sm2 := NewSessionManager([]byte("secret-2"))

	claims := SessionClaims{
		UserID: "user-123",
		Email:  "test@example.com",
	}

	token, err := sm1.GenerateSessionToken(claims)
	if err != nil {
		t.Fatalf("GenerateSessionToken failed: %v", err)
	}

	_, err = sm2.ValidateSessionToken(token)
	if err == nil {
		t.Fatal("expected error for wrong secret")
	}
	if err.Error() != "invalid signature" {
		t.Errorf("expected 'invalid signature' error, got: %v", err)
	}
}

func TestSessionManager_InvalidFormat(t *testing.T) {
	sm := NewSessionManager([]byte("test-secret"))

	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"no dots", "abcdef"},
		{"one dot", "abc.def"},
		{"four parts", "a.b.c.d"},
		{"empty parts", ".."},
	}

	for _, tt := range tests {
		_, err := sm.ValidateSessionToken(tt.token)
		if err == nil {
			t.Errorf("%s: expected error, got nil", tt.name)
		}
	}
}

func TestSessionManager_SetAndGetCookie(t *testing.T) {
	sm := NewSessionManager([]byte("test-secret"))

	claims := SessionClaims{
		UserID: "user-123",
		Email:  "test@example.com",
	}

	token, _ := sm.GenerateSessionToken(claims)

	// Set cookie on response
	w := httptest.NewRecorder()
	sm.SetSessionCookie(w, token)

	// Extract cookie from response
	resp := w.Result()
	cookies := resp.Cookies()
	var found *http.Cookie
	for _, c := range cookies {
		if c.Name == sessionCookieName {
			found = c
			break
		}
	}

	if found == nil {
		t.Fatal("session cookie not set")
	}
	if found.Value != token {
		t.Errorf("cookie value = %q, want token", found.Value)
	}
	if !found.HttpOnly {
		t.Error("cookie should be HttpOnly")
	}
	if !found.Secure {
		t.Error("cookie should be Secure")
	}
	if found.SameSite != http.SameSiteLaxMode {
		t.Error("cookie should be SameSite=Lax")
	}
	// Go's net/http normalizes cookie domains by stripping the leading dot
	expectedDomain := "electricsheephq.com"
	if found.Domain != expectedDomain {
		t.Errorf("cookie domain = %q, want %q", found.Domain, expectedDomain)
	}

	// Now read it back from a request
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(found)
	gotToken := GetSessionCookie(req)
	if gotToken != token {
		t.Errorf("GetSessionCookie = %q, want token", gotToken)
	}
}

func TestSessionManager_GetSessionCookie_Missing(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	got := GetSessionCookie(req)
	if got != "" {
		t.Errorf("expected empty string for missing cookie, got %q", got)
	}
}

func TestSessionManager_ShouldRenew(t *testing.T) {
	sm := NewSessionManager([]byte("test-secret"))

	// Token with plenty of time left — should NOT renew
	freshClaims := &SessionClaims{
		UserID: "user-123",
		Exp:    time.Now().Add(20 * time.Hour).Unix(),
	}
	if sm.ShouldRenew(freshClaims) {
		t.Error("should not renew token with 20h remaining")
	}

	// Token close to expiry — SHOULD renew
	staleClaims := &SessionClaims{
		UserID: "user-123",
		Exp:    time.Now().Add(2 * time.Hour).Unix(),
	}
	if !sm.ShouldRenew(staleClaims) {
		t.Error("should renew token with 2h remaining")
	}
}

func TestSessionManager_RenewSessionToken(t *testing.T) {
	sm := NewSessionManager([]byte("test-secret"))

	original := &SessionClaims{
		UserID:     "user-123",
		Email:      "test@example.com",
		CustomerID: "cust-abc",
		Exp:        time.Now().Add(1 * time.Hour).Unix(),
	}

	token, err := sm.RenewSessionToken(original)
	if err != nil {
		t.Fatalf("RenewSessionToken failed: %v", err)
	}

	renewed, err := sm.ValidateSessionToken(token)
	if err != nil {
		t.Fatalf("ValidateSessionToken failed: %v", err)
	}

	if renewed.UserID != original.UserID {
		t.Errorf("UserID changed: %q vs %q", renewed.UserID, original.UserID)
	}
	if renewed.Email != original.Email {
		t.Errorf("Email changed: %q vs %q", renewed.Email, original.Email)
	}

	// New expiry should be ~24h from now, not 1h
	remaining := time.Until(time.Unix(renewed.Exp, 0))
	if remaining < 23*time.Hour {
		t.Errorf("renewed expiry too soon: %v remaining", remaining)
	}
}

func TestSplitToken(t *testing.T) {
	tests := []struct {
		input    string
		wantNil  bool
		wantLen  int
	}{
		{"a.b.c", false, 3},
		{"header.payload.sig", false, 3},
		{"", true, 0},
		{"nodots", true, 0},
		{"one.dot", true, 0},
		{"a.b.c.d", true, 0},
		{"..", true, 0},
		{"a..c", true, 0},
		{".b.c", true, 0},
		{"a.b.", true, 0},
	}
	for _, tt := range tests {
		got := splitToken(tt.input)
		if tt.wantNil && got != nil {
			t.Errorf("splitToken(%q) = %v, want nil", tt.input, got)
		}
		if !tt.wantNil && got == nil {
			t.Errorf("splitToken(%q) = nil, want non-nil", tt.input)
		}
		if !tt.wantNil && len(got) != tt.wantLen {
			t.Errorf("splitToken(%q) len = %d, want %d", tt.input, len(got), tt.wantLen)
		}
	}
}
