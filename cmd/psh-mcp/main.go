package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	log "github.com/fimreal/goutils/ezap"

	"github.com/fimreal/psh/internal/mcp"
	tlspkg "github.com/fimreal/psh/pkg/tls"
)

func main() {
	// CLI flags; defaults can be supplied via environment variables so both
	// styles keep working. Flags: --transport stdio|sse, --listen, TLS options.
	transport := flag.String("transport", getEnv("PSH_MCP_TRANSPORT", "stdio"),
		"transport mode: stdio (default, local) or sse (remote HTTP/SSE)")
	listen := flag.String("listen", getEnv("PSH_MCP_LISTEN", ":18080"),
		"listen address for the sse transport")
	tlsCert := flag.String("tls-cert", getEnv("PSH_TLS_CERT", ""),
		"TLS certificate path (sse transport)")
	tlsKey := flag.String("tls-key", getEnv("PSH_TLS_KEY", ""),
		"TLS private key path (sse transport)")
	autoCerts := flag.Bool("auto-certs", getEnv("PSH_AUTO_CERTS", "") == "true",
		"auto-generate a self-signed TLS certificate when no cert is provided (sse transport)")
	flag.Parse()

	mode := strings.ToLower(strings.TrimSpace(*transport))
	if mode != "stdio" && mode != "sse" {
		fmt.Fprintf(os.Stderr, "Unsupported transport %q (expected: stdio or sse)\n", *transport)
		os.Exit(1)
	}

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
	maxConnections := parseInt("PSH_MCP_MAX_CONNECTIONS", mcp.DefaultMaxConnections)

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

	if mode == "stdio" {
		log.Infow("psh-mcp server starting (stdio mode)",
			"rate_limit", rateLimit,
			"rate_window", rateWindow.String(),
			"max_sessions", maxSessions,
		)

		if err := srv.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "MCP server error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := runSSE(srv, *listen, *tlsCert, *tlsKey, *autoCerts, maxConnections, rateLimit, rateWindow, maxSessions); err != nil {
		fmt.Fprintf(os.Stderr, "MCP server error: %v\n", err)
		os.Exit(1)
	}
}

// runSSE runs the MCP server as a resident remote service using the HTTP/SSE
// transport (MCP spec 2024-11-05 "HTTP with SSE").
func runSSE(srv *mcp.Server, listen, tlsCertPath, tlsKeyPath string, autoCerts bool, maxConnections, rateLimit int, rateWindow time.Duration, maxSessions int) error {
	apiKeys := loadMCPAPIKeys(os.Getenv("PSH_MCP_API_KEYS"))
	sseSrv, err := mcp.NewSSEServer(srv, apiKeys)
	if err != nil {
		return err
	}
	sseSrv.SetMaxConnections(maxConnections)

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", listen, err)
	}

	// Resolve TLS configuration.
	tlsConfig, err := buildTLSConfig(tlsCertPath, tlsKeyPath, autoCerts)
	if err != nil {
		return err
	}
	if tlsConfig != nil {
		ln = tls.NewListener(ln, tlsConfig)
	} else {
		log.Warn("sse transport running WITHOUT TLS; commands travel in plaintext - " +
			"provide --tls-cert/--tls-key, set --auto-certs, or terminate TLS in front of psh-mcp")
	}

	log.Infow("psh-mcp server starting (sse mode)",
		"listen", listen,
		"tls", tlsConfig != nil,
		"api_keys", len(apiKeys),
		"max_connections", sseSrv.MaxConnections(),
		"rate_limit", rateLimit,
		"rate_window", rateWindow.String(),
		"max_sessions", maxSessions,
	)

	errCh := make(chan error, 1)
	go func() { errCh <- sseSrv.Serve(ln) }()

	// Graceful shutdown on SIGINT/SIGTERM so docker/systemd can supervise it.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	log.Info("Shutting down psh-mcp sse server...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sseSrv.Shutdown(shutdownCtx); err != nil {
		// A shutdown timeout (e.g. a stalled SSE client) must not turn a
		// normal SIGTERM into a failure exit code: docker/systemd would
		// treat it as a crash and may trigger restart storms.
		if errors.Is(err, context.DeadlineExceeded) {
			log.Warnw("Shutdown timed out, some connections were not drained", "error", err)
			return nil
		}
		return err
	}
	return nil
}

// buildTLSConfig resolves the TLS configuration for the sse transport:
// explicit cert/key paths win; otherwise a self-signed certificate is
// generated when autoCerts is enabled; otherwise nil (plaintext HTTP).
func buildTLSConfig(certPath, keyPath string, autoCerts bool) (*tls.Config, error) {
	if certPath != "" && keyPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		log.Info("sse transport TLS enabled with custom certificates")
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
	}
	if certPath != "" || keyPath != "" {
		return nil, fmt.Errorf("both --tls-cert and --tls-key must be provided")
	}
	if !autoCerts {
		return nil, nil
	}

	cert, err := tlspkg.GenerateSelfSigned()
	if err != nil {
		return nil, fmt.Errorf("failed to generate self-signed certificate: %w", err)
	}
	keyPair, err := tls.X509KeyPair(cert.CertPEM, cert.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create key pair: %w", err)
	}
	log.Warn("sse transport TLS enabled with a self-signed certificate")
	return &tls.Config{Certificates: []tls.Certificate{keyPair}}, nil
}

// loadMCPAPIKeys parses PSH_MCP_API_KEYS: a comma-separated list of bearer
// tokens. An entry that is a path to an existing file is treated as a key
// file containing one token per line ('#' comments allowed), mirroring the
// web server's PSH_API_KEYS behaviour. Returns token -> identifier.
func loadMCPAPIKeys(raw string) map[string]string {
	keys := make(map[string]string)
	idx := 0
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		tokens := []string{entry}
		if info, err := os.Stat(entry); err == nil && !info.IsDir() {
			data, err := os.ReadFile(entry)
			if err != nil {
				log.Warnw("Failed to read MCP API key file, treating as literal token",
					"path", entry, "error", err)
			} else {
				tokens = nil
				for _, line := range strings.Split(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					tokens = append(tokens, line)
				}
			}
		}

		for _, token := range tokens {
			if token == "" {
				continue
			}
			if _, exists := keys[token]; exists {
				continue // duplicate token: keep the first identifier
			}
			idx++
			keys[token] = fmt.Sprintf("mcp-key-%d", idx)
		}
	}
	return keys
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
