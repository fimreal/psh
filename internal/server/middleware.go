package server

import (
	"net/http"
	"strings"

	"github.com/fimreal/psh/internal/auth"
	"github.com/gin-gonic/gin"
)

func AuthMiddleware(authService *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check cookie first
		token, err := c.Cookie("psh_token")
		if err != nil || token == "" {
			// Check Authorization header
			authHeader := c.GetHeader("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			} else {
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
