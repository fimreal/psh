package mcp

import (
	"testing"
	"time"
)

func TestRateLimiter_AllowWithinLimit(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute, 0)
	defer rl.Close()

	for i := 0; i < 3; i++ {
		if !rl.Allow("client-a") {
			t.Fatalf("expected call %d to be allowed", i+1)
		}
	}
}

func TestRateLimiter_BlocksOverLimit(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute, 0)
	defer rl.Close()

	if !rl.Allow("client-a") {
		t.Fatal("expected first call allowed")
	}
	if !rl.Allow("client-a") {
		t.Fatal("expected second call allowed")
	}
	if rl.Allow("client-a") {
		t.Fatal("expected third call to be blocked")
	}
}

func TestRateLimiter_PerClientIsolation(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute, 0)
	defer rl.Close()

	if !rl.Allow("client-a") {
		t.Fatal("expected client-a first call allowed")
	}
	if rl.Allow("client-a") {
		t.Fatal("expected client-a second call blocked")
	}
	// Different client has its own window.
	if !rl.Allow("client-b") {
		t.Fatal("expected client-b first call allowed (independent window)")
	}
}

func TestRateLimiter_WindowReset(t *testing.T) {
	rl := NewRateLimiter(1, 20*time.Millisecond, 0)
	defer rl.Close()

	if !rl.Allow("client-a") {
		t.Fatal("expected first call allowed")
	}
	if rl.Allow("client-a") {
		t.Fatal("expected second call blocked within window")
	}

	// Wait for the window to expire.
	time.Sleep(30 * time.Millisecond)

	if !rl.Allow("client-a") {
		t.Fatal("expected call allowed after window reset")
	}
}

func TestRateLimiter_DefaultWindow(t *testing.T) {
	// A non-positive window should fall back to one minute.
	rl := NewRateLimiter(5, 0, 0)
	defer rl.Close()

	if rl.window != time.Minute {
		t.Errorf("expected default window of 1m, got %v", rl.window)
	}
}

func TestRateLimiter_AllowSessionCap(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute, 2)
	defer rl.Close()

	if !rl.AllowSession(0) {
		t.Fatal("expected session allowed at 0 current")
	}
	if !rl.AllowSession(1) {
		t.Fatal("expected session allowed at 1 current")
	}
	if rl.AllowSession(2) {
		t.Fatal("expected session blocked at cap (2)")
	}
	if rl.AllowSession(3) {
		t.Fatal("expected session blocked above cap")
	}
}

func TestRateLimiter_AllowSessionUnlimited(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute, 0)
	defer rl.Close()

	if !rl.AllowSession(1000) {
		t.Fatal("expected unlimited sessions when cap is 0")
	}
}

func TestRateLimiter_MaxSessionsAccessor(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute, 7)
	defer rl.Close()

	if rl.MaxSessions() != 7 {
		t.Errorf("expected MaxSessions 7, got %d", rl.MaxSessions())
	}
}

func TestRateLimiter_CloseIdempotent(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute, 0)
	// Closing twice must not panic.
	rl.Close()
	rl.Close()
}

func TestNewServer_AppliesRateLimitDefaults(t *testing.T) {
	srv, err := NewServer(Config{
		AuditLogPath: "", // disabled
		AuditLevel:   "off",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer srv.Close()

	if srv.limiter == nil {
		t.Fatal("expected limiter to be initialized")
	}
	if srv.limiter.limit != DefaultRateLimit {
		t.Errorf("expected default rate limit %d, got %d", DefaultRateLimit, srv.limiter.limit)
	}
	if srv.limiter.window != DefaultRateWindow {
		t.Errorf("expected default rate window %v, got %v", DefaultRateWindow, srv.limiter.window)
	}
	if srv.limiter.maxSessions != DefaultMaxSessions {
		t.Errorf("expected default max sessions %d, got %d", DefaultMaxSessions, srv.limiter.maxSessions)
	}
}

func TestNewServer_CustomRateLimitConfig(t *testing.T) {
	srv, err := NewServer(Config{
		AuditLogPath: "",
		AuditLevel:   "off",
		RateLimit:    42,
		RateWindow:   5 * time.Second,
		MaxSessions:  9,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer srv.Close()

	if srv.limiter.limit != 42 {
		t.Errorf("expected rate limit 42, got %d", srv.limiter.limit)
	}
	if srv.limiter.window != 5*time.Second {
		t.Errorf("expected rate window 5s, got %v", srv.limiter.window)
	}
	if srv.limiter.maxSessions != 9 {
		t.Errorf("expected max sessions 9, got %d", srv.limiter.maxSessions)
	}
}
