package api

import (
	"bytes"
	"testing"
	"time"

	"github.com/fimreal/psh/internal/netguard"
)

func TestGenerateRandomHex(t *testing.T) {
	hex1, err := generateRandomHex(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hex1) != 64 {
		t.Errorf("expected 64 chars, got %d", len(hex1))
	}

	hex2, err := generateRandomHex(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hex1 == hex2 {
		t.Error("two random hex strings should not be equal")
	}
}

func TestSessionManager_CreateAndList(t *testing.T) {
	sm := NewSessionManager(10*time.Minute, 1*time.Hour)
	defer sm.Close()

	sessions := sm.ListSessions()
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessions))
	}
}

func TestSessionManager_GetNonExistent(t *testing.T) {
	sm := NewSessionManager(10*time.Minute, 1*time.Hour)
	defer sm.Close()

	_, ok := sm.GetSession("nonexistent")
	if ok {
		t.Error("expected session not found")
	}
}

func TestSessionManager_CleanupExpired(t *testing.T) {
	sm := NewSessionManager(1*time.Millisecond, 1*time.Millisecond)
	defer sm.Close()

	sess := &APISession{
		ID:          "test-expired",
		Host:        "testhost",
		CreatedAt:   time.Now().Add(-1 * time.Hour),
		sessionKey:  "test-key",
		observers:   make(map[chan []byte]struct{}),
		closed:      make(chan struct{}),
		idleTimeout: 1 * time.Millisecond,
		maxLifetime: 1 * time.Millisecond,
	}
	sm.mu.Lock()
	sm.sessions["test-expired"] = sess
	sm.mu.Unlock()

	sm.cleanupExpired()

	_, ok := sm.GetSession("test-expired")
	if ok {
		t.Error("expected expired session to be cleaned up")
	}
}

func TestSessionManager_RemoveSession(t *testing.T) {
	sm := NewSessionManager(10*time.Minute, 1*time.Hour)
	defer sm.Close()

	sess := &APISession{
		ID:          "test-remove",
		Host:        "testhost",
		CreatedAt:   time.Now(),
		sessionKey:  "test-key",
		observers:   make(map[chan []byte]struct{}),
		closed:      make(chan struct{}),
		idleTimeout: 10 * time.Minute,
		maxLifetime: 1 * time.Hour,
	}
	sm.mu.Lock()
	sm.sessions["test-remove"] = sess
	sm.mu.Unlock()

	sm.RemoveSession("test-remove")

	_, ok := sm.GetSession("test-remove")
	if ok {
		t.Error("expected session to be removed")
	}
	if sess.State() != StateClosed {
		t.Errorf("expected session state to be closed, got %s", sess.State())
	}
}

func TestAPISession_ValidateSessionKey(t *testing.T) {
	sess := &APISession{sessionKey: "correct-key"}

	if !sess.ValidateSessionKey("correct-key") {
		t.Error("expected valid key to pass")
	}
	if sess.ValidateSessionKey("wrong-key") {
		t.Error("expected wrong key to fail")
	}
	if sess.ValidateSessionKey("") {
		t.Error("expected empty key to fail")
	}
}

func TestAPISession_AttachDetach(t *testing.T) {
	sess := &APISession{
		ID:        "test-attach",
		observers: make(map[chan []byte]struct{}),
		closed:    make(chan struct{}),
		outputBuf: bytes.NewBuffer(nil),
	}
	sess.setState(StateConnected)

	ch, err := sess.Attach()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sess.broadcastOutput([]byte("hello"))

	select {
	case data := <-ch:
		if string(data) != "hello" {
			t.Errorf("expected 'hello', got %q", string(data))
		}
	case <-time.After(time.Second):
		t.Error("timed out waiting for output")
	}

	sess.Detach(ch)

	sess.broadcastOutput([]byte("world"))
	select {
	case <-ch:
		t.Error("expected no message after detach")
	case <-time.After(50 * time.Millisecond):
		// OK
	}
}

func TestAPISession_AttachClosedSession(t *testing.T) {
	sess := &APISession{
		ID:        "test-closed",
		observers: make(map[chan []byte]struct{}),
		closed:    make(chan struct{}),
	}
	sess.setState(StateClosed)
	close(sess.closed)

	_, err := sess.Attach()
	if err == nil {
		t.Error("expected error attaching to closed session")
	}
}

func TestAPISession_CloseNotifiesObservers(t *testing.T) {
	sess := &APISession{
		ID:        "test-close-notify",
		observers: make(map[chan []byte]struct{}),
		closed:    make(chan struct{}),
	}
	sess.setState(StateConnected)

	ch, err := sess.Attach()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sess.Close()

	_, ok := <-ch
	if ok {
		t.Error("expected observer channel to be closed")
	}
}

func TestAPISession_Touch(t *testing.T) {
	sess := &APISession{}
	old := sess.LastActive()
	time.Sleep(time.Millisecond)
	sess.Touch()
	if !sess.LastActive().After(old) {
		t.Error("expected LastActive to be updated")
	}
}

func TestResolveSSHConfig_Defaults(t *testing.T) {
	cfg, err := ResolveSSHConfig("somehost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Hostname != "somehost" {
		t.Errorf("expected hostname 'somehost', got %q", cfg.Hostname)
	}
	if cfg.Port != 22 {
		t.Errorf("expected port 22, got %d", cfg.Port)
	}
}

func TestAddrBlocked(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:22", "[::1]:22", "169.254.169.254:80"} {
		if !addrBlocked(addr) {
			t.Errorf("expected %s to be blacklisted", addr)
		}
	}
	if addrBlocked("8.8.8.8:22") {
		t.Error("expected public IP to not be blacklisted")
	}
}

func TestSessionManager_OwnershipFiltering(t *testing.T) {
	sm := NewSessionManager(10*time.Minute, 1*time.Hour)
	defer sm.Close()

	mk := func(id, owner string) {
		sess := &APISession{
			ID:        id,
			ownerID:   owner,
			observers: make(map[chan []byte]struct{}),
			closed:    make(chan struct{}),
		}
		sm.mu.Lock()
		sm.sessions[id] = sess
		sm.mu.Unlock()
	}
	mk("s-alice", "key-alice")
	mk("s-bob", "key-bob")

	if _, ok := sm.GetSessionOwned("s-alice", "key-bob"); ok {
		t.Error("expected cross-owner access to be denied")
	}
	if _, ok := sm.GetSessionOwned("s-alice", "key-alice"); !ok {
		t.Error("expected owner to access own session")
	}

	if got := len(sm.ListSessionsByOwner("key-bob")); got != 1 {
		t.Errorf("expected 1 session for key-bob, got %d", got)
	}
}

func TestNetguardControl(t *testing.T) {
	ctrl := netguard.ControlFunc(nil)
	if err := ctrl("tcp", "127.0.0.1:22", nil); err == nil {
		t.Error("expected loopback dial control to be rejected")
	}
	if err := ctrl("tcp", "[::1]:22", nil); err == nil {
		t.Error("expected IPv6 loopback dial control to be rejected")
	}
	if err := ctrl("tcp", "169.254.169.254:80", nil); err == nil {
		t.Error("expected metadata endpoint dial control to be rejected")
	}
	if err := ctrl("tcp", "8.8.8.8:22", nil); err != nil {
		t.Errorf("expected public address to be allowed, got %v", err)
	}
}
