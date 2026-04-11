package server

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	log "github.com/fimreal/goutils/ezap"

	"github.com/fimreal/psh/internal/audit"
	"github.com/fimreal/psh/internal/auth"
	"github.com/fimreal/psh/internal/shell"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

const (
	// Time allowed to write a message to the peer
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer
	pongWait = 60 * time.Second

	// Send pings to peer with this period
	pingPeriod = 30 * time.Second

	// Maximum message size allowed from peer
	maxMessageSize = 64 * 1024 // 64KB
)

type WSClient struct {
	conn           *websocket.Conn
	session        *shell.Session
	sessionID      string
	host           string
	commandBuf     []byte
	mu             sync.Mutex
	auditLogger    *audit.Logger
	done           chan struct{}
	sessionManager *auth.SessionManager
	tokenID        string
	sshBlacklist   []string
}

// TerminalWSHandler handles WebSocket connections for terminal
func (h *Handler) TerminalWSHandler(c *gin.Context) {
	// Get token from cookie or query
	token, err := c.Cookie("psh_token")
	if err != nil || token == "" {
		token = c.Query("token")
	}

	if token == "" {
		c.Status(http.StatusUnauthorized)
		return
	}

	// Validate token
	claims, err := h.authService.ValidateToken(token)
	if err != nil {
		log.Warnw("Invalid token for WebSocket", "error", err)
		c.Status(http.StatusUnauthorized)
		return
	}

	// Check session limit
	if !h.sessionManager.CanCreateSession(claims.TokenID) {
		log.Warnw("Session limit reached", "token_id", claims.TokenID)
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "Maximum concurrent sessions reached"})
		return
	}

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Errorw("WebSocket upgrade failed", "error", err)
		return
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Warnw("Failed to close WebSocket connection", "error", err)
		}
	}()

	// Set read deadline and pong handler
	conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetReadLimit(maxMessageSize)
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	sessionID := uuid.New().String()
	host := c.Query("host")
	log.Infow("New WebSocket session", "session", sessionID, "host", host, "remote", c.ClientIP())

	client := &WSClient{
		conn:           conn,
		sessionID:      sessionID,
		host:           host,
		auditLogger:    h.auditLogger,
		done:           make(chan struct{}),
		sessionManager: h.sessionManager,
		tokenID:        claims.TokenID,
		sshBlacklist:   h.sshBlacklist,
	}

	client.handleMessages()
}

func (c *WSClient) handleMessages() {
	// Register session
	c.sessionManager.AddSession(c.tokenID)

	// Start shell session
	sess := shell.NewSession(c.sshBlacklist)
	sess.Start()
	c.session = sess

	// Send connected message
	c.sendMessage(WSResponse{
		Type:      "connected",
		SessionID: c.sessionID,
	})

	// Log connection
	if err := c.auditLogger.LogConnection(c.sessionID, c.host, ""); err != nil {
		log.Warnw("Failed to log connection", "error", err)
	}

	// Start output reader goroutine
	go c.readOutput()

	// Start ping ticker for keepalive
	go c.pingLoop()

	// Handle messages
	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Errorw("WebSocket read error", "error", err)
			}
			break
		}

		var msg WSMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			// If not JSON, send as raw input
			if c.session != nil {
				if writeErr := c.session.Write(message); writeErr != nil {
					log.Warnw("Failed to write to session", "error", writeErr)
				}
			}
			continue
		}

		switch msg.Type {
		case "input":
			c.handleInput(msg)
		case "resize":
			c.handleResize(msg)
		}
	}

	// Cleanup
	close(c.done)
	c.sessionManager.RemoveSession(c.tokenID)
	if err := c.session.Close(); err != nil {
		log.Debugw("Failed to close session", "error", err)
	}
	if err := c.auditLogger.LogDisconnection(c.sessionID, c.host); err != nil {
		log.Warnw("Failed to log disconnection", "error", err)
	}
	log.Infow("WebSocket session ended", "session", c.sessionID)
}

func (c *WSClient) handleInput(msg WSMessage) {
	if c.session == nil {
		return
	}

	data, err := decodeBase64(msg.Data)
	if err != nil {
		log.Errorw("Failed to decode base64 input", "error", err)
		return
	}

	// Buffer input and detect commands (Enter key)
	c.processInput(data)

	if err := c.session.Write(data); err != nil {
		log.Errorw("Failed to write to shell session", "error", err)
	}
}

// processInput buffers input and logs complete commands on Enter
func (c *WSClient) processInput(data []byte) {
	for _, b := range data {
		switch b {
		case '\r', '\n': // Enter key
			if len(c.commandBuf) > 0 {
				cmd := string(c.commandBuf)
				// Trim leading/trailing whitespace
				cmd = trimCommand(cmd)
				if cmd != "" {
					c.auditLogger.LogCommand(c.sessionID, c.host, cmd)
				}
				c.commandBuf = c.commandBuf[:0] // Reset buffer
			}
		case 127, 8: // Backspace / Delete
			if len(c.commandBuf) > 0 {
				c.commandBuf = c.commandBuf[:len(c.commandBuf)-1]
			}
		case 0x03: // Ctrl+C
			c.commandBuf = c.commandBuf[:0] // Clear buffer
		default:
			// Only buffer printable ASCII (ignore control sequences)
			if b >= 32 && b < 127 {
				c.commandBuf = append(c.commandBuf, b)
			}
		}
	}
}

// trimCommand removes leading/trailing whitespace and common prompt artifacts
func trimCommand(cmd string) string {
	// Simple trim for now
	for len(cmd) > 0 && (cmd[0] == ' ' || cmd[0] == '\t') {
		cmd = cmd[1:]
	}
	for len(cmd) > 0 && (cmd[len(cmd)-1] == ' ' || cmd[len(cmd)-1] == '\t') {
		cmd = cmd[:len(cmd)-1]
	}
	return cmd
}

func (c *WSClient) handleResize(msg WSMessage) {
	if c.session == nil {
		return
	}

	cols, rows := msg.Cols, msg.Rows
	log.Debugw("Terminal resize", "cols", cols, "rows", rows)
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}

	if err := c.session.Resize(cols, rows); err != nil {
		log.Debugw("Failed to resize terminal", "error", err)
	}
}

func (c *WSClient) readOutput() {
	buf := make([]byte, 4096)

	for {
		select {
		case <-c.session.Done():
			return
		default:
			n, err := c.session.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Errorw("Shell output read error", "error", err)
				}
				return
			}

			if n > 0 {
				c.sendMessage(WSResponse{
					Type: "output",
					Data: encodeBase64(buf[:n]),
				})
			}
		}
	}
}

func (c *WSClient) sendMessage(msg WSResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := json.Marshal(msg)
	if err != nil {
		log.Errorw("Failed to marshal WebSocket message", "error", err)
		return
	}

	c.conn.SetWriteDeadline(time.Now().Add(writeWait))
	if err := c.conn.WriteMessage(websocket.TextMessage, data); err != nil {
		log.Warnw("Failed to send WebSocket message", "error", err)
	}
}

// pingLoop sends periodic ping messages to keep the connection alive
func (c *WSClient) pingLoop() {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			c.mu.Lock()
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			err := c.conn.WriteMessage(websocket.PingMessage, nil)
			c.mu.Unlock()
			if err != nil {
				log.Debugw("Ping failed, connection likely closed", "error", err)
				return
			}
		}
	}
}
