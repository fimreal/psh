package server

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	log "github.com/fimreal/goutils/ezap"

	"github.com/fimreal/psh/internal/mcp"
	"github.com/fimreal/psh/internal/audit"
	"github.com/fimreal/psh/internal/config"
	"github.com/gin-gonic/gin"
)

// initMCP builds the embedded MCP server (SSE transport) sharing the web
// process and the web login passwords. It returns nil when MCP is disabled
// or no passwords are configured (fail-closed: without a shared secret the
// endpoints would be unreachable anyway).
func initMCP(cfg *config.Config, auditLogger *audit.Logger) (*mcp.Server, *mcp.SSEServer, error) {
	if !cfg.MCPEnabled {
		return nil, nil, nil
	}
	if len(cfg.Passwords) == 0 {
		log.Warn("MCP requested but no web passwords configured; MCP endpoints stay disabled")
		return nil, nil, nil
	}

	mcpCfg := mcp.Config{
		AllowedHosts:      cfg.MCPAllowedHosts,
		AuditLevel:        cfg.AuditLevel,
		ExecTimeout:       cfg.MCPExecTimeout,
		SharedAuditLogger: auditLogger,
	}
	mcpSrv, err := mcp.NewServer(mcpCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create MCP server: %w", err)
	}

	// The SSE layer authenticates every request against these keys; they are
	// exactly the web login passwords, so one credential works everywhere.
	keys := make(map[string]string, len(cfg.Passwords))
	for i, p := range cfg.Passwords {
		keys[p] = fmt.Sprintf("web-password-%d", i+1)
	}
	sseSrv, err := mcp.NewSSEServer(mcpSrv, keys, mcp.SSEOptions{BasePath: "/mcp"})
	if err != nil {
		mcpSrv.Close()
		return nil, nil, fmt.Errorf("failed to create MCP SSE server: %w", err)
	}
	log.Infow("Embedded MCP enabled",
		"endpoint", "/mcp/sse",
		"allowed_hosts", cfg.MCPAllowedHosts,
		"exec_timeout", cfg.MCPExecTimeout,
	)
	return mcpSrv, sseSrv, nil
}

// mcpCredentialMiddleware authenticates MCP requests with the same
// credentials as the webshell login:
//
//   - Authorization: Bearer <password>
//   - Authorization: Basic base64(user:password)  (user part is ignored;
//     psh has no usernames, the password is the credential)
//
// Basic headers are rewritten to Bearer so the inner SSE server (which
// validates the same password set) sees a uniform scheme.
func (s *Server) mcpCredentialMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		scheme, value, _ := strings.Cut(header, " ")
		value = strings.TrimSpace(value)

		var candidate string
		switch strings.ToLower(scheme) {
		case "bearer":
			candidate = value
		case "basic":
			raw, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid Basic encoding"})
				return
			}
			_, pass, ok := strings.Cut(string(raw), ":")
			if !ok {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid Basic credentials, expected user:password"})
				return
			}
			candidate = pass
		default:
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing credentials: use 'Authorization: Bearer <webshell-password>' or Basic user:password",
			})
			return
		}

		// Compare against every configured password without early exit so
		// timing does not reveal which (or whether any) entry matched.
		ok := false
		for _, p := range s.cfg.Passwords {
			if subtle.ConstantTimeCompare([]byte(candidate), []byte(p)) == 1 {
				ok = true
			}
		}
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}

		// Normalize to Bearer for the inner SSE server authentication.
		c.Request.Header.Set("Authorization", "Bearer "+candidate)
		c.Next()
	}
}

// handleAuditRecent serves the latest audit events (webshell commands and
// MCP tool calls) from the in-memory ring, newest first.
func (s *Server) handleAuditRecent(c *gin.Context) {
	n := audit.RecentCap
	if raw := c.Query("limit"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 && v <= audit.RecentCap {
			n = v
		}
	}
	c.JSON(http.StatusOK, gin.H{"events": s.auditLogger.Recent(n)})
}
