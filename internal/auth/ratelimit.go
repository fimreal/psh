package auth

import (
	"sync"
	"time"
)

// LoginAttempt tracks failed login attempts per IP
type LoginAttempt struct {
	Count     int
	FirstSeen time.Time
	LockedUntil time.Time
}

// LoginLimiter manages login attempt tracking
type LoginLimiter struct {
	attempts    map[string]*LoginAttempt
	mu          sync.RWMutex
	maxAttempts int
	lockoutDur  time.Duration
}

// NewLoginLimiter creates a new login limiter
func NewLoginLimiter(maxAttempts int, lockoutMinutes int) *LoginLimiter {
	return &LoginLimiter{
		attempts:    make(map[string]*LoginAttempt),
		maxAttempts: maxAttempts,
		lockoutDur:  time.Duration(lockoutMinutes) * time.Minute,
	}
}

// IsLocked returns true if the IP is currently locked out
func (l *LoginLimiter) IsLocked(ip string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()

	attempt, exists := l.attempts[ip]
	if !exists {
		return false
	}

	if attempt.LockedUntil.IsZero() {
		return false
	}

	if time.Now().Before(attempt.LockedUntil) {
		return true
	}

	// Lockout expired
	return false
}

// RecordFailure records a failed login attempt
// Returns true if this failure triggered a lockout
func (l *LoginLimiter) RecordFailure(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()

	attempt, exists := l.attempts[ip]
	if !exists {
		l.attempts[ip] = &LoginAttempt{
			Count:     1,
			FirstSeen: now,
		}
		return false
	}

	// Reset if lockout has expired
	if !attempt.LockedUntil.IsZero() && now.After(attempt.LockedUntil) {
		attempt.Count = 0
		attempt.LockedUntil = time.Time{}
	}

	attempt.Count++

	// Check if we should lock out
	if attempt.Count >= l.maxAttempts {
		attempt.LockedUntil = now.Add(l.lockoutDur)
		return true
	}

	return false
}

// RecordSuccess clears the attempt history for an IP
func (l *LoginLimiter) RecordSuccess(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	delete(l.attempts, ip)
}

// GetRemainingAttempts returns how many attempts are left before lockout
func (l *LoginLimiter) GetRemainingAttempts(ip string) int {
	l.mu.RLock()
	defer l.mu.RUnlock()

	attempt, exists := l.attempts[ip]
	if !exists {
		return l.maxAttempts
	}

	remaining := l.maxAttempts - attempt.Count
	if remaining < 0 {
		return 0
	}
	return remaining
}

// GetLockoutRemaining returns the remaining lockout duration
func (l *LoginLimiter) GetLockoutRemaining(ip string) time.Duration {
	l.mu.RLock()
	defer l.mu.RUnlock()

	attempt, exists := l.attempts[ip]
	if !exists || attempt.LockedUntil.IsZero() {
		return 0
	}

	remaining := time.Until(attempt.LockedUntil)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// Cleanup removes expired entries (call periodically)
func (l *LoginLimiter) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	for ip, attempt := range l.attempts {
		// Remove if lockout expired and no recent attempts
		if !attempt.LockedUntil.IsZero() && now.After(attempt.LockedUntil) {
			delete(l.attempts, ip)
		}
	}
}
