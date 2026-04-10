package server

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"

	log "github.com/fimreal/goutils/ezap"

	"github.com/fimreal/psh/internal/audit"
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

type WSClient struct {
	conn      *websocket.Conn
	session   *shell.Session
	sessionID string
	mu        sync.Mutex
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
	_, err = h.authService.ValidateToken(token)
	if err != nil {
		log.Warnw("Invalid token for WebSocket", "error", err)
		c.Status(http.StatusUnauthorized)
		return
	}

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Errorw("WebSocket upgrade failed", "error", err)
		return
	}
	defer conn.Close()

	sessionID := uuid.New().String()
	log.Infow("New WebSocket session", "session", sessionID, "remote", c.ClientIP())

	client := &WSClient{
		conn:      conn,
		sessionID: sessionID,
	}

	client.handleMessages(h.auditLogger)
}

func (c *WSClient) handleMessages(auditLogger *audit.Logger) {
	// Start shell session
	sess := shell.NewSession()
	sess.Start()
	c.session = sess

	// Send connected message
	c.sendMessage(WSResponse{
		Type:      "connected",
		SessionID: c.sessionID,
	})

	// Log connection
	if err := auditLogger.LogConnection(c.sessionID, "webshell", ""); err != nil {
		log.Warnw("Failed to log connection", "error", err)
	}

	// Start output reader goroutine
	go c.readOutput()

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
	c.session.Close()
	if err := auditLogger.LogDisconnection(c.sessionID, "webshell"); err != nil {
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

	if err := c.session.Write(data); err != nil {
		log.Errorw("Failed to write to shell session", "error", err)
	}
}

func (c *WSClient) handleResize(msg WSMessage) {
	if c.session == nil {
		return
	}

	cols := msg.Cols
	rows := msg.Rows
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

	if err := c.conn.WriteMessage(websocket.TextMessage, data); err != nil {
		log.Warnw("Failed to send WebSocket message", "error", err)
	}
}
