package main

import (
	"fmt"
	"os"
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

	cfg := mcp.Config{
		SessionTimeout: sessionTimeout,
		SessionMaxLife: sessionMaxLife,
		ExecTimeout:    execTimeout,
		AuditLogPath:   auditLogPath,
		AuditLevel:     auditLevel,
		APIKeyID:       apiKeyID,
	}

	srv, err := mcp.NewServer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create MCP server: %v\n", err)
		os.Exit(1)
	}
	defer srv.Close()

	log.Info("psh-mcp server starting (stdio mode)")

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
