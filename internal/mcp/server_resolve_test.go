package mcp

import (
	"testing"
	"time"
)

func TestServer_ResolveTimeout(t *testing.T) {
	srv := newTestServer(t, nil)

	cases := []struct {
		name    string
		seconds int
		want    time.Duration
	}{
		{"zero defaults to 30s", 0, 30 * time.Second},
		{"negative defaults to 30s", -5, 30 * time.Second},
		{"explicit value", 10, 10 * time.Second},
		{"capped at default max", 9999, defaultMaxExecTimeout},
	}
	for _, tc := range cases {
		if got := srv.resolveTimeout(tc.seconds); got != tc.want {
			t.Errorf("%s: resolveTimeout(%d) = %v, want %v", tc.name, tc.seconds, got, tc.want)
		}
	}
}

func TestServer_ResolveTimeoutHonorsConfiguredMax(t *testing.T) {
	srv := newTestServer(t, func(cfg *Config) {
		cfg.ExecTimeout = 60 * time.Second
	})

	if got := srv.resolveTimeout(120); got != 60*time.Second {
		t.Errorf("resolveTimeout(120) = %v, want cap at configured 60s", got)
	}
	if got := srv.resolveTimeout(10); got != 10*time.Second {
		t.Errorf("resolveTimeout(10) = %v, want 10s", got)
	}
}

func TestNewServer_ExecTimeoutDefault(t *testing.T) {
	srv := newTestServer(t, nil)
	if srv.maxExecTimeout != defaultMaxExecTimeout {
		t.Errorf("maxExecTimeout = %v, want %v", srv.maxExecTimeout, defaultMaxExecTimeout)
	}
}
