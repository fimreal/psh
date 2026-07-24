package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/fimreal/goutils/ezap"

	"github.com/fimreal/psh/internal/mcp"
)

func main() {
	// Read configuration from environment variables
	sessionTimeout := parseDuration("PSH_API_SESSION_TIMEOUT", 10*time.Minute)
	sessionMaxLife := parseDuration("PSH_API_SESSION_MAX_LIFE", 1*time.Hour)
	execTimeout := parseDuration("PSH_API_EXEC_TIMEOUT", 300*time.Second)
	auditLogPath := getEnv("PSH_AUDIT_LOG", "-")
	auditLevel := getEnv("PSH_AUDIT_LEVEL", "command")
	apiKeyID := getEnv("PSH_API_KEY_ID", "mcp-server")

	// Parse allowed hosts from comma-separated env var
	var allowedHosts []string
	if raw := os.Getenv("PSH_API_ALLOWED_HOSTS"); raw != "" {
		for _, h := range strings.Split(raw, ",") {
			h = strings.TrimSpace(h)
			if h != "" {
				allowedHosts = append(allowedHosts, h)
			}
		}
	}

	// Rate limiting configuration
	rateLimit := parseInt("PSH_MCP_RATE_LIMIT", mcp.DefaultRateLimit)
	rateWindow := parseDuration("PSH_MCP_RATE_WINDOW", mcp.DefaultRateWindow)
	maxSessions := parseInt("PSH_MCP_MAX_SESSIONS", mcp.DefaultMaxSessions)

	cfg := mcp.Config{
		SessionTimeout: sessionTimeout,
		SessionMaxLife: sessionMaxLife,
		ExecTimeout:    execTimeout,
		AllowedHosts:   allowedHosts,
		AuditLogPath:   auditLogPath,
		AuditLevel:     auditLevel,
		APIKeyID:       apiKeyID,
		RateLimit:      rateLimit,
		RateWindow:     rateWindow,
		MaxSessions:    maxSessions,
	}

	srv, err := mcp.NewServer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create MCP server: %v\n", err)
		os.Exit(1)
	}
	defer srv.Close()

	log.Infow("psh-mcp server starting (stdio mode)",
		"rate_limit", rateLimit,
		"rate_window", rateWindow.String(),
		"max_sessions", maxSessions,
	)

	if err := srv.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "MCP server error: %v\n", err)
		os.Exit(1)
	}
}

func parseDuration(envKey string, defaultVal time.Duration) time.Duration {
	val := os.Getenv(envKey)
	if val == "" {
		return defaultVal
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		return defaultVal
	}
	return d
}

func getEnv(key, defaultVal string) string {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	return val
}

func parseInt(envKey string, defaultVal int) int {
	val := os.Getenv(envKey)
	if val == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return defaultVal
	}
	return n
}
