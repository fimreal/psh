package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// LoginAttempt tracks failed login attempts per IP
type LoginAttempt struct {
	Count           int
	FirstSeen       time.Time
	LockedUntil     time.Time
	CaptchaKey      string    // Key for the current captcha challenge
	CaptchaLevel    int       // Number of captcha failures
	CaptchaExpires  time.Time // Rate limit for captcha generation
}

// CaptchaChallenge represents a captcha challenge
type CaptchaChallenge struct {
	Question string
	Answer   int
	Expires  time.Time
}

// LoginLimiter manages login attempt tracking
type LoginLimiter struct {
	attempts         map[string]*LoginAttempt
	captchas         map[string]*CaptchaChallenge // captcha key -> challenge
	mu               sync.RWMutex
	maxAttempts      int
	lockoutDur       time.Duration
	captchaThreshold int           // Number of failures before requiring captcha
	captchaExpiry    time.Duration // Captcha expiration time
	stopCleanup      chan struct{} // Signal to stop cleanup goroutine
}

// NewLoginLimiter creates a new login limiter
func NewLoginLimiter(maxAttempts int, lockoutMinutes int) *LoginLimiter {
	l := &LoginLimiter{
		attempts:         make(map[string]*LoginAttempt),
		captchas:         make(map[string]*CaptchaChallenge),
		maxAttempts:      maxAttempts,
		lockoutDur:       time.Duration(lockoutMinutes) * time.Minute,
		captchaThreshold: 2, // Require captcha after 2 failed attempts
		captchaExpiry:    5 * time.Minute,
		stopCleanup:      make(chan struct{}),
	}

	// Start cleanup goroutine
	go l.cleanupLoop()

	return l
}

// Close stops the cleanup goroutine
func (l *LoginLimiter) Close() {
	close(l.stopCleanup)
}

// cleanupLoop periodically cleans up expired entries
func (l *LoginLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-l.stopCleanup:
			return
		case <-ticker.C:
			l.Cleanup()
		}
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
		attempt.CaptchaLevel = 0
	}

	attempt.Count++
	attempt.CaptchaKey = "" // Invalidate existing captcha

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

// RequiresCaptcha returns true if captcha is required for this IP
func (l *LoginLimiter) RequiresCaptcha(ip string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()

	attempt, exists := l.attempts[ip]
	if !exists {
		return false
	}

	return attempt.Count >= l.captchaThreshold
}

// GenerateCaptcha creates a new captcha challenge for the IP
// Returns the captcha key (to be sent back) and question
func (l *LoginLimiter) GenerateCaptcha(ip string) (key string, question string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	attempt, exists := l.attempts[ip]
	if !exists {
		attempt = &LoginAttempt{
			Count:     l.captchaThreshold, // Ensure we stay in captcha mode
			FirstSeen: time.Now(),
		}
		l.attempts[ip] = attempt
	}

	// Limit captcha generation rate (max 1 per 3 seconds)
	if !attempt.CaptchaExpires.IsZero() && time.Now().Before(attempt.CaptchaExpires) {
		// Return existing challenge
		if challenge, ok := l.captchas[attempt.CaptchaKey]; ok {
			return attempt.CaptchaKey, challenge.Question
		}
	}

	// Generate random numbers using crypto/rand (larger range for harder brute-force)
	a, _ := rand.Int(rand.Reader, big.NewInt(50))
	b, _ := rand.Int(rand.Reader, big.NewInt(50))
	aVal := int(a.Int64()) + 10  // 10-59
	bVal := int(b.Int64()) + 10  // 10-59
	answer := aVal + bVal        // 20-118

	// Generate random key
	keyBytes := make([]byte, 16)
	_, _ = rand.Read(keyBytes)
	captchaKey := hex.EncodeToString(keyBytes)

	challenge := &CaptchaChallenge{
		Question: fmt.Sprintf("What is %d + %d?", aVal, bVal),
		Answer:   answer,
		Expires:  time.Now().Add(l.captchaExpiry),
	}

	attempt.CaptchaKey = captchaKey
	attempt.CaptchaExpires = time.Now().Add(3 * time.Second) // Rate limit
	l.captchas[captchaKey] = challenge

	return captchaKey, challenge.Question
}

// VerifyCaptcha checks if the captcha answer is correct
func (l *LoginLimiter) VerifyCaptcha(ip string, captchaKey string, answer int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	attempt, exists := l.attempts[ip]
	if !exists || attempt.CaptchaKey == "" || attempt.CaptchaKey != captchaKey {
		return false
	}

	challenge, exists := l.captchas[captchaKey]
	if !exists {
		return false
	}

	// Check expiry
	if time.Now().After(challenge.Expires) {
		delete(l.captchas, captchaKey)
		attempt.CaptchaKey = ""
		return false
	}

	// Clean up captcha after use
	delete(l.captchas, captchaKey)
	attempt.CaptchaKey = ""

	if challenge.Answer == answer {
		// Reset captcha level on success
		attempt.CaptchaLevel = 0
		return true
	}

	// Increment captcha failure count
	attempt.CaptchaLevel++

	// After 3 wrong captcha answers, lock out
	if attempt.CaptchaLevel >= 3 {
		attempt.LockedUntil = time.Now().Add(l.lockoutDur)
	}

	return false
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

	// Clean up expired captchas
	for key, challenge := range l.captchas {
		if now.After(challenge.Expires) {
			delete(l.captchas, key)
		}
	}
}
