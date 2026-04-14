package server

import (
	"encoding/base64"
	"io"
	"net/http"
	"strings"

	log "github.com/fimreal/goutils/ezap"

	"github.com/fimreal/psh/internal/audit"
	"github.com/fimreal/psh/internal/auth"
	"github.com/fimreal/psh/static"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	authService       *auth.Service
	auditLogger       *audit.Logger
	jwtExpire         int
	loginLimiter      *auth.LoginLimiter
	sessionManager    *auth.SessionManager
	sshBlacklist      []string
	strictHostKey     bool
	showHostKeyDigest bool
	devMode           bool
}

func NewHandler(authService *auth.Service, auditLogger *audit.Logger, jwtExpire int, loginLimiter *auth.LoginLimiter, sessionManager *auth.SessionManager, sshBlacklist []string, strictHostKey, showHostKeyDigest bool, devMode bool) *Handler {
	return &Handler{
		authService:       authService,
		auditLogger:       auditLogger,
		jwtExpire:         jwtExpire,
		loginLimiter:      loginLimiter,
		sessionManager:    sessionManager,
		sshBlacklist:      sshBlacklist,
		strictHostKey:     strictHostKey,
		showHostKeyDigest: showHostKeyDigest,
		devMode:           devMode,
	}
}

// IndexHandler serves the main page
func (h *Handler) IndexHandler(c *gin.Context) {
	// Get CSP nonce from context
	nonce, exists := c.Get("csp-nonce")
	if !exists {
		nonce = ""
	}

	c.HTML(http.StatusOK, "index.html", gin.H{
		"nonce": nonce,
	})
}

// StaticHandler serves static files from embedded FS
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

	// Read file from embedded FS
	file, err := static.Files.Open(path)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	defer file.Close()

	c.Header("Content-Type", mimeType)
	c.Header("X-Content-Type-Options", "nosniff")

	// Long cache for versioned static assets (xterm.js, etc.)
	if strings.HasPrefix(path, "xterm/") {
		c.Header("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		c.Header("Cache-Control", "public, max-age=3600")
	}

	data, err := io.ReadAll(file)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	c.Data(http.StatusOK, mimeType, data)
}

type LoginRequest struct {
	Password      string `json:"password" binding:"required,min=1,max=256"`
	CaptchaKey    string `json:"captcha_key,omitempty"`
	CaptchaAnswer int    `json:"captcha_answer,omitempty"`
}

// LoginHandler handles authentication
func (h *Handler) LoginHandler(c *gin.Context) {
	clientIP := c.ClientIP()

	// Check if IP is locked out
	if h.loginLimiter.IsLocked(clientIP) {
		remaining := h.loginLimiter.GetLockoutRemaining(clientIP)
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":           "Too many failed attempts, please try again later",
			"retry_after_sec": int(remaining.Seconds()),
		})
		return
	}

	// Check if captcha is required
	if h.loginLimiter.RequiresCaptcha(clientIP) {
		// Limit request body size to prevent DoS
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1024)

		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		// Verify captcha if provided
		if req.CaptchaKey == "" || req.CaptchaAnswer == 0 {
			// Generate new captcha challenge
			key, question := h.loginLimiter.GenerateCaptcha(clientIP)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":          "Captcha required",
				"captcha_key":    key,
				"captcha_question": question,
				"captcha_needed": true,
			})
			return
		}

		// Verify captcha answer
		if !h.loginLimiter.VerifyCaptcha(clientIP, req.CaptchaKey, req.CaptchaAnswer) {
			key, question := h.loginLimiter.GenerateCaptcha(clientIP)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":            "Invalid captcha",
				"captcha_key":      key,
				"captcha_question": question,
				"captcha_needed":   true,
			})
			return
		}
	}

	// Limit request body size to prevent DoS
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1024)

	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if !h.authService.VerifyPassword(req.Password) {
		// Record failed attempt
		locked := h.loginLimiter.RecordFailure(clientIP)
		if locked {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many failed attempts, please try again later",
			})
			return
		}

		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authentication failed",
		})
		return
	}

	// Clear failed attempts on successful login
	h.loginLimiter.RecordSuccess(clientIP)

	token, err := h.authService.GenerateToken()
	if err != nil {
		log.Errorw("Failed to generate token", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// Set HttpOnly cookie
	c.SetCookie("psh_token", token, h.jwtExpire, "/", "", true, true)

	c.JSON(http.StatusOK, gin.H{
		"expires_in": h.jwtExpire,
	})
}

// LogoutHandler handles logout (revokes token)
func (h *Handler) LogoutHandler(c *gin.Context) {
	token, err := c.Cookie("psh_token")
	if err != nil || token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No token found"})
		return
	}

	if err := h.authService.RevokeToken(token); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to revoke token"})
		return
	}

	// Clear cookie
	c.SetCookie("psh_token", "", -1, "/", "", true, true)

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// VerifyHandler checks if the user is authenticated
func (h *Handler) VerifyHandler(c *gin.Context) {
	// In dev mode, always return authenticated
	if h.devMode {
		c.JSON(http.StatusOK, gin.H{"authenticated": true})
		return
	}

	token, err := c.Cookie("psh_token")
	if err != nil || token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"authenticated": false})
		return
	}

	_, err = h.authService.ValidateToken(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"authenticated": false})
		return
	}

	c.JSON(http.StatusOK, gin.H{"authenticated": true})
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
	Host      string `json:"host,omitempty"`
}

// encodeBase64 encodes data to base64
func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// decodeBase64 decodes base64 data
func decodeBase64(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}
