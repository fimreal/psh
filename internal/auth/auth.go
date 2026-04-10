package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	jwt.RegisteredClaims
}

type Service struct {
	jwtSecret []byte
	jwtExpire int
	password  []byte
}

func NewService(jwtSecret string, jwtExpire int, password string) *Service {
	secret := jwtSecret
	if secret == "" {
		// Generate cryptographically secure random secret
		bytes := make([]byte, 32)
		if _, err := rand.Read(bytes); err != nil {
			panic("failed to generate random secret: " + err.Error())
		}
		secret = hex.EncodeToString(bytes)
	}

	return &Service{
		jwtSecret: []byte(secret),
		jwtExpire: jwtExpire,
		password:  []byte(password),
	}
}

// VerifyPassword checks if the provided password matches using constant-time comparison
func (s *Service) VerifyPassword(password string) bool {
	return subtle.ConstantTimeCompare([]byte(password), s.password) == 1
}

// GenerateToken creates a new JWT token
func (s *Service) GenerateToken() (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(s.jwtExpire) * time.Second)),
		},
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
		return claims, nil
	}

	return nil, errors.New("invalid token")
}
