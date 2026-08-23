package api

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"time"

	log "github.com/fimreal/goutils/ezap"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"github.com/fimreal/psh/internal/audit"
)

const (
	maxCommandLength   = 64 * 1024 // 64KB
	defaultExecTimeout = 30        // seconds
	// fallbackMaxExecTimeout is used only when the handler has no configured
	// maximum (0), so a missing config cannot disable the cap entirely.
	fallbackMaxExecTimeout = 300 // seconds
)

// Handler holds dependencies for API endpoints.
type Handler struct {
	sessionMgr     *SessionManager
	auditLogger    *audit.Logger
	apiKeys        map[string]APIKeyConfig // key -> config
	allowedHosts   map[string]bool
	maxExecTimeout time.Duration
}

// APIKeyConfig holds per-key configuration.
type APIKeyConfig struct {
	Key          string
	AllowedHosts []string // empty means use global whitelist
	Identifier   string   // human-readable identifier for audit
}

// NewHandler creates a new API handler.
func NewHandler(sessionMgr *SessionManager, auditLogger *audit.Logger, apiKeys map[string]APIKeyConfig, allowedHosts []string, maxExecTimeout time.Duration) *Handler {
	hostSet := make(map[string]bool, len(allowedHosts))
	for _, h := range allowedHosts {
		hostSet[strings.TrimSpace(h)] = true
	}
	return &Handler{
		sessionMgr:     sessionMgr,
		auditLogger:    auditLogger,
		apiKeys:        apiKeys,
		allowedHosts:   hostSet,
		maxExecTimeout: maxExecTimeout,
	}
}

// --- Request/Response types ---

type CreateSessionRequest struct {
	Host string `json:"host" binding:"required"`
}

type CreateSessionResponse struct {
	SessionID  string `json:"session_id"`
	SessionKey string `json:"session_key"`
	Host       string `json:"host"`
	State      string `json:"state"`
	CreatedAt  string `json:"created_at"`
}

type ExecRequest struct {
	Command string `json:"command" binding:"required"`
	Timeout int    `json:"timeout"` // seconds, optional
}

type ExecResponse struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

type SessionInfo struct {
	ID         string `json:"id"`
	Host       string `json:"host"`
	State      string `json:"state"`
	CreatedAt  string `json:"created_at"`
	LastActive string `json:"last_active"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

// --- Middleware ---

// APIKeyAuthMiddleware validates the Bearer API key.
func (h *Handler) APIKeyAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse{Error: "missing Authorization header"})
			return
		}

		key, found := strings.CutPrefix(authHeader, "Bearer ")
		if !found || key == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse{Error: "invalid Authorization format, expected: Bearer <key>"})
			return
		}

		keyCfg, ok := h.lookupKey(key)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse{Error: "invalid API key"})
			return
		}

		// Store key config in context for downstream handlers
		c.Set("api_key_config", keyCfg)
		c.Set("api_key_id", keyCfg.Identifier)
		c.Next()
	}
}

// lookupKey finds the API key config using constant-time comparison so the
// validity of a candidate key cannot be measured via map-lookup timing.
func (h *Handler) lookupKey(candidate string) (APIKeyConfig, bool) {
	for key, cfg := range h.apiKeys {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(key)) == 1 {
			return cfg, true
		}
	}
	return APIKeyConfig{}, false
}

// sessionKeyMiddleware validates the X-Session-Key header against the session.
func (h *Handler) sessionKeyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID := c.Param("id")
		sess, ok := h.sessionMgr.GetSession(sessionID)
		if !ok {
			c.AbortWithStatusJSON(http.StatusNotFound, ErrorResponse{Error: "session not found"})
			return
		}

		sessionKey := c.GetHeader("X-Session-Key")
		if sessionKey == "" {
			// Also check query param for WebSocket compatibility
			sessionKey = c.Query("session_key")
		}
		if sessionKey == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse{Error: "missing X-Session-Key header"})
			return
		}

		if !sess.ValidateSessionKey(sessionKey) {
			c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse{Error: "invalid session key"})
			return
		}

		c.Set("api_session", sess)
		c.Next()
	}
}

// --- Handlers ---

// CreateSession handles POST /api/v1/sessions
func (h *Handler) CreateSession(c *gin.Context) {
	var req CreateSessionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request: " + err.Error()})
		return
	}

	host := strings.TrimSpace(req.Host)
	if host == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "host is required"})
		return
	}

	// Validate host format
	if !isValidHost(host) {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid host format"})
		return
	}

	// Check host whitelist (per-key or global)
	keyCfg, _ := c.Get("api_key_config")
	if !h.isHostAllowed(host, keyCfg.(APIKeyConfig)) {
		c.JSON(http.StatusForbidden, ErrorResponse{Error: "host not in whitelist"})
		return
	}

	// Resolve SSH config
	sshCfg, err := ResolveSSHConfig(host)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to resolve SSH config"})
		return
	}

	// Create session (owned by the calling API key)
	sess, err := h.sessionMgr.CreateSession(host, sshCfg, c.GetString("api_key_id"))
	if err != nil {
		log.Warnw("API session creation failed", "host", host, "error", err)
		c.JSON(http.StatusBadGateway, ErrorResponse{Error: "SSH connection failed: " + err.Error()})
		return
	}

	// Audit log
	keyID, _ := c.Get("api_key_id")
	_ = h.auditLogger.LogAPIEvent(audit.EventAPISessionCreate, sess.ID, host, keyID.(string), "")

	c.JSON(http.StatusCreated, CreateSessionResponse{
		SessionID:  sess.ID,
		SessionKey: sess.SessionKey(),
		Host:       sess.Host,
		State:      string(sess.State()),
		CreatedAt:  sess.CreatedAt.UTC().Format(time.RFC3339),
	})
}

// ExecCommand handles POST /api/v1/sessions/:id/exec
func (h *Handler) ExecCommand(c *gin.Context) {
	sess := c.MustGet("api_session").(*APISession)

	var req ExecRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request: " + err.Error()})
		return
	}

	command := req.Command
	if len(command) > maxCommandLength {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "command exceeds maximum length of 64KB"})
		return
	}

	// Determine timeout (cap honors --api-exec-timeout, not a constant)
	timeout := time.Duration(defaultExecTimeout) * time.Second
	maxExec := h.maxExecTimeout
	if maxExec <= 0 {
		maxExec = fallbackMaxExecTimeout * time.Second
	}
	if req.Timeout > 0 {
		if time.Duration(req.Timeout)*time.Second > maxExec {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Error: fmt.Sprintf("timeout exceeds maximum of %ds", int(maxExec.Seconds())),
			})
			return
		}
		timeout = time.Duration(req.Timeout) * time.Second
	}

	// Check session state
	if sess.State() != StateConnected {
		c.JSON(http.StatusConflict, ErrorResponse{Error: "session is not connected"})
		return
	}

	startTime := time.Now()
	stdout, stderr, exitCode, err := sess.Exec(command, timeout)
	duration := time.Since(startTime)

	if err != nil {
		if strings.Contains(err.Error(), "timed out") {
			c.JSON(http.StatusGatewayTimeout, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	// Audit log (metadata only, no stdout/stderr content)
	keyID, _ := c.Get("api_key_id")
	_ = h.auditLogger.LogAPIEvent(audit.EventAPIExec, sess.ID, sess.Host, keyID.(string), command)
	// Log exit code and duration separately
	log.Infow("API exec completed",
		"session_id", sess.ID,
		"exit_code", exitCode,
		"duration_ms", duration.Milliseconds(),
	)

	c.JSON(http.StatusOK, ExecResponse{
		ExitCode: exitCode,
		Stdout:   stdout,
		Stderr:   stderr,
	})
}

// ListSessions handles GET /api/v1/sessions
func (h *Handler) ListSessions(c *gin.Context) {
	sessions := h.sessionMgr.ListSessionsByOwner(c.GetString("api_key_id"))
	result := make([]SessionInfo, 0, len(sessions))
	for _, sess := range sessions {
		result = append(result, SessionInfo{
			ID:         sess.ID,
			Host:       sess.Host,
			State:      string(sess.State()),
			CreatedAt:  sess.CreatedAt.UTC().Format(time.RFC3339),
			LastActive: sess.LastActive().UTC().Format(time.RFC3339),
		})
	}
	c.JSON(http.StatusOK, gin.H{"sessions": result, "count": len(result)})
}

// GetSession handles GET /api/v1/sessions/:id
func (h *Handler) GetSession(c *gin.Context) {
	sess := c.MustGet("api_session").(*APISession)
	c.JSON(http.StatusOK, SessionInfo{
		ID:         sess.ID,
		Host:       sess.Host,
		State:      string(sess.State()),
		CreatedAt:  sess.CreatedAt.UTC().Format(time.RFC3339),
		LastActive: sess.LastActive().UTC().Format(time.RFC3339),
	})
}

// CloseSession handles DELETE /api/v1/sessions/:id
func (h *Handler) CloseSession(c *gin.Context) {
	sess := c.MustGet("api_session").(*APISession)
	sessionID := sess.ID

	h.sessionMgr.RemoveSession(sessionID)

	// Audit log
	keyID, _ := c.Get("api_key_id")
	_ = h.auditLogger.LogAPIEvent(audit.EventAPISessionClose, sessionID, sess.Host, keyID.(string), "")

	c.JSON(http.StatusOK, gin.H{"message": "session closed", "session_id": sessionID})
}

// AttachSession handles GET /api/v1/sessions/:id/attach (WebSocket, read-only)
var attachUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // API clients are not browser-bound
	},
}

func (h *Handler) AttachSession(c *gin.Context) {
	sess := c.MustGet("api_session").(*APISession)

	conn, err := attachUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Warnw("Attach WebSocket upgrade failed", "error", err)
		return
	}
	defer conn.Close()

	// Subscribe to output
	outputCh, err := sess.Attach()
	if err != nil {
		conn.WriteJSON(ErrorResponse{Error: "session already closed"})
		return
	}
	defer sess.Detach(outputCh)

	// Read pump: discard all input (read-only observer)
	go func() {
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				return
			}
			// Ignore all incoming messages — observers cannot send commands
		}
	}()

	// Write pump: forward session output to observer
	for {
		select {
		case data, ok := <-outputCh:
			if !ok {
				// Session closed
				conn.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, "session closed"))
				return
			}
			if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
				return
			}
		case <-sess.closed:
			conn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, "session closed"))
			return
		}
	}
}

// --- Helpers ---

func (h *Handler) isHostAllowed(host string, keyCfg APIKeyConfig) bool {
	// Per-key whitelist takes precedence
	if len(keyCfg.AllowedHosts) > 0 {
		for _, allowed := range keyCfg.AllowedHosts {
			if strings.TrimSpace(allowed) == host {
				return true
			}
		}
		return false
	}
	// Fall back to global whitelist
	return h.allowedHosts[host]
}

func isValidHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	// Allow hostname, IP, or user@host format
	if strings.Contains(host, " ") || strings.Contains(host, ";") ||
		strings.Contains(host, "|") || strings.Contains(host, "&") ||
		strings.Contains(host, "$") || strings.Contains(host, "`") {
		return false
	}
	return true
}
