package auth

import (
	"testing"
	"time"
)

func TestLoginLimiter_CleanupRemovesStaleEntries(t *testing.T) {
	l := NewLoginLimiter(5, 15)
	defer l.Close()

	now := time.Now()

	// Entry that was never locked out and is stale: must be removed.
	// (Regression for the unbounded-map DoS: previously Cleanup only
	// deleted entries that had been locked out, so an attacker rotating
	// spoofed IPs grew the map forever.)
	l.mu.Lock()
	l.attempts["1.2.3.4"] = &LoginAttempt{Count: 1, FirstSeen: now, LastAttempt: now.Add(-time.Hour)}
	l.attempts["5.6.7.8"] = &LoginAttempt{Count: 9, FirstSeen: now.Add(-time.Hour), LastAttempt: now.Add(-31 * time.Minute), LockedUntil: now.Add(-30 * time.Minute)} // lockout long expired, stale
	l.attempts["9.9.9.9"] = &LoginAttempt{Count: 9, FirstSeen: now.Add(-time.Hour), LastAttempt: now.Add(-time.Hour), LockedUntil: now.Add(10 * time.Minute)}         // still locked: keep
	l.attempts["7.7.7.7"] = &LoginAttempt{Count: 1, FirstSeen: now, LastAttempt: now}                                                                                 // fresh: keep
	l.mu.Unlock()

	l.Cleanup()

	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.attempts["1.2.3.4"]; ok {
		t.Error("expected never-locked stale entry to be removed")
	}
	if _, ok := l.attempts["5.6.7.8"]; ok {
		t.Error("expected expired-lockout stale entry to be removed")
	}
	if _, ok := l.attempts["9.9.9.9"]; !ok {
		t.Error("expected actively locked entry to be retained")
	}
	if _, ok := l.attempts["7.7.7.7"]; !ok {
		t.Error("expected recently active entry to be retained")
	}
}

func TestLoginLimiter_RecordFailureSetsLastAttempt(t *testing.T) {
	l := NewLoginLimiter(5, 15)
	defer l.Close()

	before := time.Now().Add(-time.Second)
	l.RecordFailure("10.0.0.1")

	l.mu.RLock()
	attempt, ok := l.attempts["10.0.0.1"]
	l.mu.RUnlock()
	if !ok {
		t.Fatal("expected entry after RecordFailure")
	}
	if attempt.LastAttempt.Before(before) {
		t.Errorf("expected LastAttempt >= test start, got %v", attempt.LastAttempt)
	}
}

func TestLoginLimiter_LockoutStillWorks(t *testing.T) {
	l := NewLoginLimiter(3, 15)
	defer l.Close()

	for i := 0; i < 3; i++ {
		if l.IsLocked("10.1.1.1") {
			t.Fatalf("unexpectedly locked after %d failures", i)
		}
		l.RecordFailure("10.1.1.1")
	}
	if !l.IsLocked("10.1.1.1") {
		t.Error("expected lockout after max attempts")
	}
}
