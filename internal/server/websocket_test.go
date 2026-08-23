package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebSocketOrigin_DefaultDeny(t *testing.T) {
	// No configured origins: cross-origin handshakes must be denied
	// (regression: previously defaulted to allowing all origins).
	SetupWebSocketOrigins(nil)

	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Origin", "https://evil.example")

	if upgrader.CheckOrigin(req) {
		t.Error("expected cross-origin request to be denied when no origins configured")
	}

	// Same-origin (no Origin header) is always allowed
	sameOrigin := httptest.NewRequest(http.MethodGet, "/ws", nil)
	if !upgrader.CheckOrigin(sameOrigin) {
		t.Error("expected request without Origin header to be allowed")
	}
}

func TestWebSocketOrigin_ExplicitAllowlist(t *testing.T) {
	SetupWebSocketOrigins([]string{"https://app.example"})
	defer SetupWebSocketOrigins(nil)

	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Origin", "https://app.example")
	if !upgrader.CheckOrigin(req) {
		t.Error("expected allowlisted origin to be accepted")
	}

	req.Header.Set("Origin", "https://other.example")
	if upgrader.CheckOrigin(req) {
		t.Error("expected non-allowlisted origin to be denied")
	}
}
