package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	jwt.RegisteredClaims
	TokenID string `json:"jti,omitempty"`
}

type Service struct {
	jwtSecret   []byte
	jwtExpire   int
	passwords   [][]byte
	blacklist   map[string]time.Time // tokenID -> expiry time
	blacklistMu sync.RWMutex
	stopCleanup chan struct{} // signal to stop cleanup goroutine
}

func NewService(jwtSecret string, jwtExpire int, passwords []string) *Service {
	secret := jwtSecret
	if secret == "" {
		// Generate cryptographically secure random secret
		bytes := make([]byte, 32)
		if _, err := rand.Read(bytes); err != nil {
			panic("failed to generate random secret: " + err.Error())
		}
		secret = hex.EncodeToString(bytes)
	}

	// Convert passwords to byte slices for constant-time comparison
	pwBytes := make([][]byte, len(passwords))
	for i, pw := range passwords {
		pwBytes[i] = []byte(pw)
	}

	s := &Service{
		jwtSecret:   []byte(secret),
		jwtExpire:   jwtExpire,
		passwords:   pwBytes,
		blacklist:   make(map[string]time.Time),
		stopCleanup: make(chan struct{}),
	}

	// Start automatic blacklist cleanup
	go s.cleanupLoop()

	return s
}

// Close stops the cleanup goroutine
func (s *Service) Close() {
	close(s.stopCleanup)
}

// cleanupLoop periodically cleans up expired blacklist entries
func (s *Service) cleanupLoop() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCleanup:
			return
		case <-ticker.C:
			s.CleanupBlacklist()
		}
	}
}

// VerifyPassword checks if the provided password matches any of the configured passwords
func (s *Service) VerifyPassword(password string) bool {
	pwBytes := []byte(password)
	for _, pw := range s.passwords {
		if subtle.ConstantTimeCompare(pwBytes, pw) == 1 {
			return true
		}
	}
	return false
}

// GenerateToken creates a new JWT token
func (s *Service) GenerateToken() (string, error) {
	now := time.Now()
	tokenIDBytes := make([]byte, 16)
	if _, err := rand.Read(tokenIDBytes); err != nil {
		return "", err
	}
	tokenID := hex.EncodeToString(tokenIDBytes)

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(s.jwtExpire) * time.Second)),
		},
		TokenID: tokenID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

// ValidateToken validates a JWT token and returns the claims
func (s *Service) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		// Check if token is blacklisted
		if claims.TokenID != "" && s.isBlacklisted(claims.TokenID) {
			return nil, errors.New("token has been revoked")
		}
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// RevokeToken adds a token to the blacklist
func (s *Service) RevokeToken(tokenString string) error {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return err
	}

	if claims.TokenID == "" {
		return errors.New("token has no ID")
	}

	s.blacklistMu.Lock()
	defer s.blacklistMu.Unlock()

	// Store with expiry time so we can clean up later
	s.blacklist[claims.TokenID] = time.Now().Add(time.Duration(s.jwtExpire) * time.Second)
	return nil
}

// isBlacklisted checks if a token ID is in the blacklist
func (s *Service) isBlacklisted(tokenID string) bool {
	s.blacklistMu.RLock()
	defer s.blacklistMu.RUnlock()

	_, exists := s.blacklist[tokenID]
	return exists
}

// CleanupBlacklist removes expired entries from the blacklist
func (s *Service) CleanupBlacklist() {
	s.blacklistMu.Lock()
	defer s.blacklistMu.Unlock()

	now := time.Now()
	for tokenID, expiry := range s.blacklist {
		if now.After(expiry) {
			delete(s.blacklist, tokenID)
		}
	}
}
