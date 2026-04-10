package server

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/fimreal/psh/internal/audit"
	"github.com/fimreal/psh/internal/auth"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

type Handler struct {
	authService *auth.Service
	auditLogger *audit.Logger
	jwtExpire   int
}

func NewHandler(authService *auth.Service, auditLogger *audit.Logger, jwtExpire int) *Handler {
	return &Handler{
		authService: authService,
		auditLogger: auditLogger,
		jwtExpire:   jwtExpire,
	}
}

// IndexHandler serves the main page
func (h *Handler) IndexHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", nil)
}

// StaticHandler serves static files
func (h *Handler) StaticHandler(c *gin.Context) {
	path := c.Param("path")

	// Remove leading slash if present (Gin wildcard includes it)
	path = strings.TrimPrefix(path, "/")

	// Security: prevent path traversal
	if strings.Contains(path, "..") || strings.Contains(path, "\\") {
		c.Status(http.StatusBadRequest)
		return
	}

	// Normalize path
	path = strings.ReplaceAll(path, "./", "")
	if path == "" {
		c.Status(http.StatusBadRequest)
		return
	}

	filePath := "static/" + path

	// Set MIME type based on extension
	ext := ""
	if idx := strings.LastIndex(path, "."); idx >= 0 {
		ext = path[idx+1:]
	}

	mimeType := "application/octet-stream"
	switch ext {
	case "js":
		mimeType = "application/javascript"
	case "css":
		mimeType = "text/css"
	case "html":
		mimeType = "text/html"
	case "json":
		mimeType = "application/json"
	case "png":
		mimeType = "image/png"
	case "jpg", "jpeg":
		mimeType = "image/jpeg"
	case "svg":
		mimeType = "image/svg+xml"
	case "woff", "woff2":
		mimeType = "font/woff2"
	}

	c.Header("Content-Type", mimeType)
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Cache-Control", "public, max-age=3600")
	c.File(filePath)
}

type LoginRequest struct {
	Password string `json:"password" binding:"required"`
}

// LoginHandler handles authentication
func (h *Handler) LoginHandler(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if !h.authService.VerifyPassword(req.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
		return
	}

	token, err := h.authService.GenerateToken()
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// Set HttpOnly cookie
	c.SetCookie("psh_token", token, h.jwtExpire, "/", "", true, true)

	c.JSON(http.StatusOK, gin.H{
		"expires_in": h.jwtExpire,
	})
}

// WSMessage represents a WebSocket message
type WSMessage struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

// WSResponse represents a WebSocket response
type WSResponse struct {
	Type      string `json:"type"`
	SessionID string `json:"session_id,omitempty"`
	Data      string `json:"data,omitempty"`
	Message   string `json:"message,omitempty"`
}

// encodeBase64 encodes data to base64
func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// decodeBase64 decodes base64 data
func decodeBase64(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

// getMaxAge returns the max age for cookie in seconds
func getMaxAge(expire int) int {
	return int(time.Duration(expire) * time.Second / time.Second)
}
