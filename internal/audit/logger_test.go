package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAsyncWriter_TimerResetFlushesLowTraffic verifies the batch timer is
// re-armed after each flush: a single event written to an otherwise idle
// logger must hit the file within ~batchWindow, not sit in the buffer until
// the process exits (regression for the missing timer.Reset).
func TestAsyncWriter_TimerResetFlushesLowTraffic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := NewLogger(path, LevelCommand)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	if err := l.LogConnection("sess-1", "host-1", "user-1"); err != nil {
		t.Fatalf("LogConnection: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil && strings.Contains(string(data), "sess-1") {
			return // flushed by the periodic timer
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("single low-traffic event was not flushed within 2s; periodic timer is not being re-armed")
}

// TestLogger_LevelFiltering ensures events below the configured level are dropped.
func TestLogger_LevelFiltering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := NewLogger(path, LevelConnection)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	_ = l.LogCommand("sess-1", "host-1", "ls") // below LevelConnection
	_ = l.LogConnection("sess-1", "host-1", "user-1")

	defer l.Close() // ensure eventual flush

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			s := string(data)
			if strings.Contains(s, "\"command\"") {
				t.Fatal("command event should have been filtered at LevelConnection")
			}
			if strings.Contains(s, "sess-1") {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("connection event was not flushed within 2s")
}

// TestLogger_Disabled ensures empty path/off level yields a no-op logger.
func TestLogger_Disabled(t *testing.T) {
	for _, tc := range []struct {
		path  string
		level Level
	}{
		{"", LevelCommand},
		{"/tmp/unused-audit.jsonl", LevelOff},
	} {
		l, err := NewLogger(tc.path, tc.level)
		if err != nil {
			t.Fatalf("NewLogger(%q,%v): %v", tc.path, tc.level, err)
		}
		if err := l.LogConnection("s", "h", "u"); err != nil {
			t.Errorf("expected nil error on disabled logger, got %v", err)
		}
		if err := l.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}
}
