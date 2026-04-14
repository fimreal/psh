package server

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimiter implements a sliding window rate limiter
type RateLimiter struct {
	requests map[string]*clientInfo
	mu       sync.RWMutex
	limit    int           // max requests per window
	window   time.Duration // time window
}

type clientInfo struct {
	count     int
	windowEnd time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(limit int) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string]*clientInfo),
		limit:    limit,
		window:   time.Minute,
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// Allow checks if a request from the given IP should be allowed
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	info, exists := rl.requests[ip]
	if !exists || now.After(info.windowEnd) {
		// New window
		rl.requests[ip] = &clientInfo{
			count:     1,
			windowEnd: now.Add(rl.window),
		}
		return true
	}

	// Within window
	if info.count >= rl.limit {
		return false
	}

	info.count++
	return true
}

// cleanup periodically removes expired entries
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, info := range rl.requests {
			if now.After(info.windowEnd) {
				delete(rl.requests, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// RateLimitMiddleware returns a rate limiting middleware
func RateLimitMiddleware(limit int) gin.HandlerFunc {
	limiter := NewRateLimiter(limit)

	return func(c *gin.Context) {
		ip := c.ClientIP()

		if !limiter.Allow(ip) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many requests, please try again later",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// WSConnTracker tracks active WebSocket connections per IP
type WSConnTracker struct {
	connections map[string]int // IP -> connection count
	mu          sync.RWMutex
	maxConns    int
}

// NewWSConnTracker creates a new WebSocket connection tracker
func NewWSConnTracker(maxConns int) *WSConnTracker {
	return &WSConnTracker{
		connections: make(map[string]int),
		maxConns:    maxConns,
	}
}

// Acquire attempts to acquire a connection slot. Returns true if allowed.
func (t *WSConnTracker) Acquire(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.connections[ip] >= t.maxConns {
		return false
	}
	t.connections[ip]++
	return true
}

// Release releases a connection slot
func (t *WSConnTracker) Release(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.connections[ip] > 0 {
		t.connections[ip]--
		if t.connections[ip] == 0 {
			delete(t.connections, ip)
		}
	}
}

// wsConnTracker is the global WebSocket connection tracker
var wsConnTracker *WSConnTracker

// InitWSConnTracker initializes the global WebSocket connection tracker
func InitWSConnTracker(maxConns int) {
	wsConnTracker = NewWSConnTracker(maxConns)
}

// GetWSConnTracker returns the global WebSocket connection tracker
func GetWSConnTracker() *WSConnTracker {
	return wsConnTracker
}

// WSRateLimitMiddleware returns a middleware that limits concurrent WebSocket connections per IP
func WSRateLimitMiddleware(limit int) gin.HandlerFunc {
	// Initialize the global tracker if not already done
	if wsConnTracker == nil {
		InitWSConnTracker(limit)
	}

	return func(c *gin.Context) {
		ip := c.ClientIP()

		if !wsConnTracker.Acquire(ip) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Maximum concurrent WebSocket connections reached",
			})
			c.Abort()
			return
		}

		// Store IP in context so websocket handler can release it
		c.Set("ws-client-ip", ip)

		c.Next()
	}
}
