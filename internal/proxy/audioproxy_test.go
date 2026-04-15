package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/100yenadmin/evaos-ws-proxy/internal/auth"
	"github.com/100yenadmin/evaos-ws-proxy/internal/registry"
)

// --- Audio Proxy Route Tests ---

func TestHandleAudioProxy_NoAuth(t *testing.T) {
	h := newTestHandler(&mockJWT{}, &mockRegistry{vm: &registry.VMInfo{CustomerID: "cust-1", UserID: "user-1", TailnetIP: strPtr("127.0.0.1")}})
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
		&mockRegistry{vm: &registry.VMInfo{CustomerID: "cust-1", UserID: "user-1", TailnetIP: strPtr("127.0.0.1")}},
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
	req.Header.Set("Origin", "chrome-extension://abcdefghijklmnop")
	w := httptest.NewRecorder()
	h.HandleAudioProxy(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "chrome-extension://abcdefghijklmnop" {
		t.Errorf("expected chrome extension CORS origin header, got %q", got)
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

	if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
		t.Errorf("session auth should pass, got %d", w.Code)
	}
}

func TestHandleAudioProxy_SessionWrongCustomer_Unauthorized(t *testing.T) {
	secret := "test-audio-session"
	sm := NewSessionManager([]byte(secret))
	token, _ := sm.GenerateSessionToken(SessionClaims{
		UserID:     "user-1",
		Email:      "test@test.com",
		CustomerID: "cust-other",
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

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong-customer session, got %d", w.Code)
	}
}

func TestHandleAudioProxy_GatewayTokenAuth(t *testing.T) {
	h := newTestHandler(
		&mockJWT{err: fmt.Errorf("should not validate JWT for gateway token")},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID:   "golden",
			UserID:       "user-owner",
			TailnetIP:    strPtr("127.0.0.1"),
			GatewayToken: strPtr("gw-direct-token"),
		}},
	)

	req := httptest.NewRequest("POST", "/vm/golden/v1/audio/speech", strings.NewReader(`{"input":"hello","voice":"nova"}`))
	req.Header.Set("Authorization", "Bearer gw-direct-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandleAudioProxy(w, req)

	if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
		t.Fatalf("gateway token auth should pass, got %d", w.Code)
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

func TestHandleAudioProxy_CustomerIsolation(t *testing.T) {
	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-A", Email: "a@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID:  "cust-B",
			UserID:      "user-B",
			TailnetIP:   strPtr("100.64.0.2"),
			GatewayPort: 59999,
		}},
	)
	req := httptest.NewRequest("POST", "/vm/cust-B/v1/audio/transcriptions", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	h.HandleAudioProxy(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for cross-customer access, got %d", w.Code)
	}
}

func TestHandleAudioProxy_PathTraversal(t *testing.T) {
	h := newTestHandler(
		&mockJWT{claims: &auth.Claims{UserID: "user-1", Email: "test@test.com"}},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID:  "cust-1",
			UserID:      "user-1",
			TailnetIP:   strPtr("127.0.0.1"),
			GatewayPort: 59999,
		}},
	)

	traversalPaths := []string{
		"/vm/cust-1/v1/audio/../../etc/passwd",
		"/vm/cust-1/v1/audio/../../../etc/shadow",
	}
	for _, p := range traversalPaths {
		req := httptest.NewRequest("POST", p, nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()
		h.HandleAudioProxy(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("path %q: expected 400, got %d", p, w.Code)
		}
	}
}

func startSpeachesTestServer(t *testing.T, handler http.HandlerFunc) func() {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:8000")
	if err != nil {
		t.Fatalf("listen 127.0.0.1:8000: %v", err)
	}
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(ln) }()
	return func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}
}

// --- Integration tests: verify audio proxy forwards correctly ---

func TestHandleAudioProxy_ForwardsSTTMultipart(t *testing.T) {
	var receivedPath string
	var receivedContentType string
	var receivedBody []byte
	var receivedAuth string

	cleanup := startSpeachesTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedContentType = r.Header.Get("Content-Type")
		receivedAuth = r.Header.Get("Authorization")
		receivedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"hello world"}`))
	}))
	defer cleanup()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, _ := writer.CreateFormFile("file", "audio.wav")
	_, _ = part.Write([]byte("fake-audio-data"))
	_ = writer.WriteField("model", "whisper-large-v3")
	_ = writer.Close()

	h := newTestHandler(
		&mockJWT{err: fmt.Errorf("should not validate JWT for gateway token")},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID:   "cust-1",
			UserID:       "user-1",
			TailnetIP:    strPtr("127.0.0.1"),
			GatewayToken: strPtr("gw-direct-token"),
		}},
	)

	req := httptest.NewRequest("POST", "/vm/cust-1/v1/audio/transcriptions", &body)
	req.Header.Set("Authorization", "Bearer gw-direct-token")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	h.HandleAudioProxy(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%q", w.Code, w.Body.String())
	}
	if receivedPath != "/v1/audio/transcriptions" {
		t.Fatalf("received path = %q, want /v1/audio/transcriptions", receivedPath)
	}
	if !strings.HasPrefix(receivedContentType, "multipart/form-data; boundary=") {
		t.Fatalf("content-type = %q, want multipart/form-data with boundary", receivedContentType)
	}
	if !bytes.Contains(receivedBody, []byte("fake-audio-data")) {
		t.Fatal("backend did not receive multipart audio payload")
	}
	if receivedAuth != "Bearer gw-direct-token" {
		t.Fatalf("authorization header = %q, want backend gateway token", receivedAuth)
	}
}

func TestHandleAudioProxy_ForwardsTTSSuccess(t *testing.T) {
	var receivedPath string
	var receivedBody []byte

	cleanup := startSpeachesTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "audio/mpeg")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ID3fake-mp3"))
	}))
	defer cleanup()

	h := newTestHandler(
		&mockJWT{err: fmt.Errorf("should not validate JWT for gateway token")},
		&mockRegistry{vm: &registry.VMInfo{
			CustomerID:   "cust-1",
			UserID:       "user-1",
			TailnetIP:    strPtr("127.0.0.1"),
			GatewayToken: strPtr("gw-direct-token"),
		}},
	)

	body := strings.NewReader(`{"model":"tts-1","input":"hello","voice":"nova"}`)
	req := httptest.NewRequest("POST", "/vm/cust-1/v1/audio/speech", body)
	req.Header.Set("Authorization", "Bearer gw-direct-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandleAudioProxy(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%q", w.Code, w.Body.String())
	}
	if receivedPath != "/v1/audio/speech" {
		t.Fatalf("received path = %q, want /v1/audio/speech", receivedPath)
	}
	if !bytes.Equal(w.Body.Bytes(), []byte("ID3fake-mp3")) {
		t.Fatalf("response body = %q, want fake mp3 bytes", w.Body.Bytes())
	}
	if !bytes.Contains(receivedBody, []byte(`"input":"hello"`)) {
		t.Fatalf("backend did not receive TTS JSON body: %q", receivedBody)
	}
}

// --- ServeHTTP routing for audio proxy ---

func TestServeHTTP_RoutesToAudioProxy(t *testing.T) {
	h := newTestHandler(
		&mockJWT{err: fmt.Errorf("no token")},
		&mockRegistry{vm: &registry.VMInfo{CustomerID: "cust-1", UserID: "user-1", TailnetIP: strPtr("127.0.0.1")}},
	)
	server := httptest.NewServer(h)
	defer server.Close()

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
		&mockRegistry{vm: &registry.VMInfo{CustomerID: "cust-1", UserID: "user-1", TailnetIP: strPtr("127.0.0.1")}},
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
		&mockRegistry{vm: &registry.VMInfo{CustomerID: "cust-1", UserID: "user-1", TailnetIP: strPtr("127.0.0.1")}},
	)
	server := httptest.NewServer(h)
	defer server.Close()

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
