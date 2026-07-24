package mcp

import (
	"sync"
	"time"
)

// RateLimiter implements a sliding-window rate limiter for MCP tool calls.
// It tracks the number of tool invocations per client within a time window
// and enforces a maximum number of concurrent SSH sessions.
//
// The implementation mirrors the sliding-window approach used by the HTTP
// layer (internal/server/middleware_ratelimit.go) so behaviour stays
// consistent across the codebase.
type RateLimiter struct {
	requests map[string]*clientWindow
	mu       sync.Mutex

	limit  int           // max tool calls per window per client
	window time.Duration // sliding window duration

	maxSessions int // max concurrent SSH sessions across the server

	stopCleanup chan struct{}
}

// clientWindow tracks tool-call timestamps for a single client within the
// current window.
type clientWindow struct {
	count     int
	windowEnd time.Time
}

// NewRateLimiter creates a rate limiter.
//
//	limit       - max tool calls allowed per client per window
//	window      - sliding window duration (e.g. time.Minute)
//	maxSessions - max concurrent SSH sessions (0 disables the session cap)
func NewRateLimiter(limit int, window time.Duration, maxSessions int) *RateLimiter {
	if window <= 0 {
		window = time.Minute
	}
	rl := &RateLimiter{
		requests:    make(map[string]*clientWindow),
		limit:       limit,
		window:      window,
		maxSessions: maxSessions,
		stopCleanup: make(chan struct{}),
	}
	go rl.cleanup()
	return rl
}

// Close stops the background cleanup goroutine.
func (rl *RateLimiter) Close() {
	select {
	case <-rl.stopCleanup:
		// already closed
	default:
		close(rl.stopCleanup)
	}
}

// Allow reports whether a tool call from the given client is permitted under
// the per-client rate limit. When allowed, the call is counted.
func (rl *RateLimiter) Allow(client string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	info, exists := rl.requests[client]
	if !exists || now.After(info.windowEnd) {
		// Start a new window for this client.
		rl.requests[client] = &clientWindow{
			count:     1,
			windowEnd: now.Add(rl.window),
		}
		return true
	}

	if info.count >= rl.limit {
		return false
	}
	info.count++
	return true
}

// AllowSession reports whether a new SSH session may be created given the
// configured concurrent-session cap. currentSessions is the number of
// currently active sessions.
func (rl *RateLimiter) AllowSession(currentSessions int) bool {
	if rl.maxSessions <= 0 {
		return true // cap disabled
	}
	return currentSessions < rl.maxSessions
}

// MaxSessions returns the configured concurrent-session cap (0 = unlimited).
func (rl *RateLimiter) MaxSessions() int {
	return rl.maxSessions
}

// cleanup periodically removes expired client windows to bound memory usage.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-rl.stopCleanup:
			return
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for client, info := range rl.requests {
				if now.After(info.windowEnd) {
					delete(rl.requests, client)
				}
			}
			rl.mu.Unlock()
		}
	}
}
