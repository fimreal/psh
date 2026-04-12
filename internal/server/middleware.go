package server

import (
	"net/http"
	"slices"
	"strings"

	"github.com/fimreal/psh/internal/auth"
	"github.com/gin-gonic/gin"
)

// SecurityMiddleware adds security-related headers
func SecurityMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prevent clickjacking
		c.Header("X-Frame-Options", "DENY")
		// Prevent MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")
		// XSS protection (legacy browsers)
		c.Header("X-XSS-Protection", "1; mode=block")
		// Referrer policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		// Content Security Policy
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; font-src 'self' data:; img-src 'self' data:;")
		// HSTS - only for HTTPS
		if c.Request.TLS != nil {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		c.Next()
	}
}

// CORSMiddleware creates a CORS middleware with the specified allowed origins
func CORSMiddleware(allowedOrigins []string) gin.HandlerFunc {
	allowAll := slices.Contains(allowedOrigins, "*")

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" {
			c.Next()
			return
		}

		// Determine if origin is allowed
		allowed := allowAll || slices.Contains(allowedOrigins, origin)

		if allowed {
			if allowAll {
				c.Header("Access-Control-Allow-Origin", "*")
			} else {
				c.Header("Access-Control-Allow-Origin", origin)
				c.Header("Access-Control-Allow-Credentials", "true")
			}
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
			c.Header("Access-Control-Max-Age", "86400")
		}

		// Handle preflight request
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func AuthMiddleware(authService *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check cookie first
		token, err := c.Cookie("psh_token")
		if err != nil || token == "" {
			// Check Authorization header
			authHeader := c.GetHeader("Authorization")
			if token, _ = strings.CutPrefix(authHeader, "Bearer "); token == "" {
				// Check query parameter
				token = c.Query("token")
			}
		}

		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "No token provided"})
			return
		}

		claims, err := authService.ValidateToken(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		// Store claims in context
		c.Set("claims", claims)
		c.Next()
	}
}
