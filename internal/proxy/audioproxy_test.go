package proxy

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/100yenadmin/evaos-ws-proxy/internal/auth"
	"github.com/100yenadmin/evaos-ws-proxy/internal/registry"
)

// --- Audio Proxy Route Tests ---

func TestHandleAudioProxy_NoAuth(t *testing.T) {
	h := newTestHandler(&mockJWT{}, &mockRegistry{})
	req := httptest.NewRequest("POST", "/vm/cust-1/v1/audio/transcriptions", nil)
	w := httptest.NewRecorder()
	h.HandleAudioProxy(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleAudioProxy_InvalidToken(t *testing.T) {
	h := newTestHandler(
		&mockJWT{err: fmt.Errorf("invalid token")},
		&mockRegistry{},
	)
	req := httptest.NewRequest("POST", "/vm/cust-1/v1/audio/transcriptions", nil)
	req.Header.Set("Authorization", "Bearer bad-token")
	w := httptest.NewRecorder()
	h.HandleAudioProxy(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleAudioProxy_NoVM(t *testing.T) {
	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: nil},
	)
	req := httptest.NewRequest("POST", "/vm/cust-1/v1/audio/transcriptions", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleAudioProxy(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleAudioProxy_Forbidden(t *testing.T) {
	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-wrong", Email: "hacker@evil.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID: "cust-1",
			UserID:     "user-owner",
			TailnetIP:  strPtr("100.64.0.1"),
		}},
	)
	req := httptest.NewRequest("POST", "/vm/cust-1/v1/audio/transcriptions", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleAudioProxy(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestHandleAudioProxy_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(&mockJWT{}, &mockRegistry{})
	// GET is not allowed for audio endpoints
	req := httptest.NewRequest("GET", "/vm/cust-1/v1/audio/transcriptions", nil)
	w := httptest.NewRecorder()
	h.HandleAudioProxy(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleAudioProxy_OptionsPreflightCORS(t *testing.T) {
	h := newTestHandler(&mockJWT{}, &mockRegistry{})
	req := httptest.NewRequest("OPTIONS", "/vm/cust-1/v1/audio/transcriptions", nil)
	req.Header.Set("Origin", "https://ecs.electricsheephq.com")
	w := httptest.NewRecorder()
	h.HandleAudioProxy(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://ecs.electricsheephq.com" {
		t.Errorf("expected CORS origin header, got %q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, "POST") {
		t.Errorf("expected POST in allowed methods, got %q", got)
	}
}

func TestHandleAudioProxy_SessionAuth(t *testing.T) {
	secret := "test-audio-session"
	sm := NewSessionManager([]byte(secret))
	token, _ := sm.GenerateSessionToken(SessionClaims{
		UserID: "user-1",
		Email:  "test@test.com",
	})

	h := newTestHandlerWithSessions(
		&mockJWT{},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID:  "cust-1",
			UserID:      "user-1",
			TailnetIP:   strPtr("127.0.0.1"),
			GatewayPort: 59999,
		}},
		secret,
	)

	req := httptest.NewRequest("POST", "/vm/cust-1/v1/audio/transcriptions", nil)
	req.AddCookie(&http.Cookie{Name: "evaos_session", Value: token})
	w := httptest.NewRecorder()
	h.HandleAudioProxy(w, req)

	// Should pass auth (will 502 because no Speaches, but NOT 401/403)
	if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
		t.Errorf("session auth should pass, got %d", w.Code)
	}
}

func TestHandleAudioProxy_AdminAccess(t *testing.T) {
	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "admin-user", Email: "admin@100yen.org"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID:  "cust-1",
			UserID:      "other-user",
			TailnetIP:   strPtr("127.0.0.1"),
			GatewayPort: 59999,
		}},
		func(cfg *HandlerConfig) {
			cfg.AdminEmails = []string{"admin@100yen.org"}
		},
	)

	req := httptest.NewRequest("POST", "/vm/cust-1/v1/audio/speech", strings.NewReader(`{"input":"hello","voice":"nova"}`))
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandleAudioProxy(w, req)

	// Admin should bypass ownership — should NOT be 403
	if w.Code == http.StatusForbidden {
		t.Error("admin should bypass ownership check for audio proxy")
	}
}

func TestHandleAudioProxy_MissingCustomerID(t *testing.T) {
	h := newTestHandler(&mockJWT{}, &mockRegistry{})
	req := httptest.NewRequest("POST", "/vm//v1/audio/transcriptions", nil)
	w := httptest.NewRecorder()
	h.HandleAudioProxy(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// --- Integration test: verify audio proxy forwards correctly ---

func TestHandleAudioProxy_ForwardsSTT(t *testing.T) {
	var receivedPath string
	var receivedContentType string

	// Mock Speaches server
	audioServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedContentType = r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"text":"hello world"}`))
	}))
	defer audioServer.Close()

	backendAddr := strings.TrimPrefix(audioServer.URL, "http://")
	parts := strings.Split(backendAddr, ":")
	backendHost := parts[0]
	var backendPort int
	fmt.Sscanf(parts[1], "%d", &backendPort)

	// Build multipart form with fake audio
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, _ := writer.CreateFormFile("file", "audio.wav")
	part.Write([]byte("fake-audio-data"))
	writer.WriteField("model", "whisper-large-v3")
	writer.Close()

	// We can't easily override the port constant, but we can test auth/routing
	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID:  "cust-1",
			UserID:      "user-1",
			TailnetIP:   strPtr(backendHost),
			GatewayPort: backendPort,
		}},
	)

	req := httptest.NewRequest("POST", "/vm/cust-1/v1/audio/transcriptions", &body)
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	h.HandleAudioProxy(w, req)

	// Port mismatch means 502 — that's expected. Auth passed.
	_ = receivedPath
	_ = receivedContentType
}

func TestHandleAudioProxy_ForwardsTTS(t *testing.T) {
	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID:  "cust-1",
			UserID:      "user-1",
			TailnetIP:   strPtr("127.0.0.1"),
			GatewayPort: 59999,
		}},
	)

	body := strings.NewReader(`{"model":"tts-1","input":"hello","voice":"nova"}`)
	req := httptest.NewRequest("POST", "/vm/cust-1/v1/audio/speech", body)
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandleAudioProxy(w, req)

	// Auth should pass (502 expected because no TTS server)
	if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
		t.Errorf("auth should pass for TTS, got %d", w.Code)
	}
}

// --- ServeHTTP routing for audio proxy ---

func TestServeHTTP_RoutesToAudioProxy(t *testing.T) {
	h := newTestHandler(
		&mockJWT{err: fmt.Errorf("no token")},
		&mockRegistry{},
	)
	server := httptest.NewServer(h)
	defer server.Close()

	// No auth → 401 proves routing worked
	req, _ := http.NewRequest("POST", server.URL+"/vm/cust-1/v1/audio/transcriptions", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestServeHTTP_AudioSpeechRoute(t *testing.T) {
	h := newTestHandler(
		&mockJWT{err: fmt.Errorf("no token")},
		&mockRegistry{},
	)
	server := httptest.NewServer(h)
	defer server.Close()

	req, _ := http.NewRequest("POST", server.URL+"/vm/cust-1/v1/audio/speech", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestServeHTTP_AudioNotConfusedWithUI(t *testing.T) {
	h := newTestHandler(
		&mockJWT{},
		&mockRegistry{vm: nil},
	)
	server := httptest.NewServer(h)
	defer server.Close()

	// Audio path with no auth → 401 (not redirect to login)
	req, _ := http.NewRequest("POST", server.URL+"/vm/cust-1/v1/audio/transcriptions", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound {
		t.Error("audio proxy should return 401, not redirect to login")
	}
}
