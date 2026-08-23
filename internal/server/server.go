package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	log "github.com/fimreal/goutils/ezap"

	"github.com/fimreal/psh/internal/api"
	"github.com/fimreal/psh/internal/audit"
	"github.com/fimreal/psh/internal/auth"
	"github.com/fimreal/psh/internal/config"
	tlspkg "github.com/fimreal/psh/pkg/tls"
	"github.com/fimreal/psh/static"
	"github.com/gin-gonic/gin"
)

type Server struct {
	cfg            *config.Config
	authService    *auth.Service
	auditLogger    *audit.Logger
	handler        *Handler
	loginLimiter   *auth.LoginLimiter
	sessionManager *auth.SessionManager

	// API (optional)
	apiHandler    *api.Handler
	apiSessionMgr *api.SessionManager
}

func New(cfg *config.Config) (*Server, error) {
	// Initialize auth service
	authService := auth.NewService(cfg.JWTSecret, cfg.JWTExpire, cfg.Passwords)
	log.Info("Auth service initialized")

	// Initialize login limiter
	loginLimiter := auth.NewLoginLimiter(cfg.MaxLoginAttempts, cfg.LoginLockoutMins)

	// Initialize session manager
	sessionManager := auth.NewSessionManager(cfg.MaxSessions)

	// Initialize audit logger
	auditLogger, err := audit.NewLogger(cfg.AuditLogPath, audit.Level(cfg.AuditLevel))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize audit logger: %w", err)
	}

	// Create handler
	handler := NewHandler(authService, auditLogger, cfg.JWTExpire, loginLimiter, sessionManager, cfg.SSHBlacklist, cfg.StrictHostKey, cfg.ShowHostKeyDigest, cfg.DevMode)

	srv := &Server{
		cfg:            cfg,
		authService:    authService,
		auditLogger:    auditLogger,
		handler:        handler,
		loginLimiter:   loginLimiter,
		sessionManager: sessionManager,
	}

	// Initialize API if enabled
	if cfg.APIEnabled {
		apiKeys, err := loadAPIKeys(cfg.APIKeys)
		if err != nil {
			return nil, fmt.Errorf("failed to load API keys: %w", err)
		}
		if len(apiKeys) == 0 {
			return nil, fmt.Errorf("API enabled but no API keys configured (set PSH_API_KEYS or --api-keys)")
		}
		apiSessionMgr := api.NewSessionManager(cfg.APISessionTimeout, cfg.APISessionMaxLife)
		apiHandler := api.NewHandler(apiSessionMgr, auditLogger, apiKeys, cfg.APIAllowedHosts, cfg.APIExecTimeout)
		srv.apiHandler = apiHandler
		srv.apiSessionMgr = apiSessionMgr
		log.Infow("REST API enabled", "allowed_hosts", cfg.APIAllowedHosts, "api_keys", len(apiKeys))
	}

	return srv, nil
}

func (s *Server) Run() error {
	// Set Gin mode
	if !s.cfg.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create router
	r := gin.New()

	// Only trust X-Forwarded-* headers from explicitly configured proxies.
	// gin's default trusts every peer, letting any client spoof its IP via
	// X-Forwarded-For and bypass login lockout / rate limiting (fail-closed).
	if len(s.cfg.TrustedProxies) == 0 {
		if err := r.SetTrustedProxies(nil); err != nil {
			return fmt.Errorf("failed to configure trusted proxies: %w", err)
		}
		log.Info("Trusted proxies: none (ClientIP = direct TCP peer)")
	} else {
		if err := r.SetTrustedProxies(s.cfg.TrustedProxies); err != nil {
			return fmt.Errorf("invalid trusted proxies configuration: %w", err)
		}
		log.Infow("Trusted proxies configured", "proxies", s.cfg.TrustedProxies)
	}

	r.Use(gin.Recovery())

	// Apply security headers
	r.Use(SecurityMiddleware())

	// Apply CORS middleware. Backwards-compatible default: an empty
	// configuration allows all origins, but this weakens the WebSocket origin
	// check (any page can attempt authenticated handshakes) and disables CSRF
	// protection for cookie-based auth, so warn loudly at startup.
	origins := s.cfg.AllowedOrigins
	if len(origins) == 0 {
		origins = []string{"*"}
		log.Warnw("PSH_ALLOWED_ORIGINS is not configured: allowing all origins. " +
			"For production use, set it to the exact origin(s) serving the web UI " +
			"(e.g. https://shell.example.com)")
	}
	r.Use(CORSMiddleware(origins))

	// Setup WebSocket origin validation (same policy as CORS)
	SetupWebSocketOrigins(origins)

	// Load HTML templates from embedded FS
	tmpl, err := template.ParseFS(static.Files, "index.html")
	if err != nil {
		return fmt.Errorf("failed to load template: %w", err)
	}
	r.SetHTMLTemplate(tmpl)

	// Public routes
	r.GET("/", s.handler.IndexHandler)
	r.GET("/api/auth/verify", RateLimitMiddleware(s.cfg.MaxRequestPerMin), s.handler.VerifyHandler)
	r.POST("/api/auth/login", RateLimitMiddleware(s.cfg.MaxRequestPerMin), s.handler.LoginHandler)
	r.POST("/api/auth/logout", s.handler.LogoutHandler)

	// Static files
	r.GET("/static/*path", s.handler.StaticHandler)

	// Protected routes
	protected := r.Group("")
	if !s.cfg.DevMode {
		protected.Use(AuthMiddleware(s.authService))
	} else {
		log.Warn("DEV MODE: Authentication disabled")
	}
	protected.GET("/ws/terminal", WSRateLimitMiddleware(s.cfg.MaxWSConnsPerMin), s.handler.TerminalWSHandler)

	// API routes (separate auth, does not touch web auth)
	if s.cfg.APIEnabled && s.apiHandler != nil {
		s.apiHandler.RegisterRoutes(r, RateLimitMiddleware(s.cfg.MaxRequestPerMin))
		log.Info("API v1 routes registered at /api/v1/sessions")
	}

	// Create HTTP server
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	srv := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	// Setup TLS
	var tlsConfig *tls.Config
	if s.cfg.DevMode {
		log.Warn("DEV MODE: TLS disabled")
	} else if s.cfg.TLSCertPath != "" && s.cfg.TLSKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(s.cfg.TLSCertPath, s.cfg.TLSKeyPath)
		if err != nil {
			return fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		log.Info("TLS enabled with custom certificates")
	} else if s.cfg.AutoGenerateCerts {
		cert, err := tlspkg.GenerateSelfSigned()
		if err != nil {
			return fmt.Errorf("failed to generate self-signed certificate: %w", err)
		}

		keyPair, err := tls.X509KeyPair(cert.CertPEM, cert.KeyPEM)
		if err != nil {
			return fmt.Errorf("failed to create key pair: %w", err)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{keyPair}}
		log.Info("TLS enabled with self-signed certificates")
	} else {
		log.Warn("TLS not configured - running in HTTP mode (not recommended)")
	}

	// Start server in goroutine
	go func() {
		var err error
		if tlsConfig != nil {
			srv.TLSConfig = tlsConfig
			log.Infow("Starting HTTPS server", "addr", addr)
			err = srv.ListenAndServeTLS("", "")
		} else {
			log.Infow("Starting HTTP server", "addr", addr)
			err = srv.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown error: %w", err)
	}

	// Close audit logger
	if err := s.auditLogger.Close(); err != nil {
		log.Warnw("Failed to close audit logger", "error", err)
	}

	// Close auth service (stop cleanup goroutine)
	s.authService.Close()

	// Close login limiter (stop cleanup goroutine)
	s.loginLimiter.Close()

	// Close API session manager (closes all SSH sessions)
	if s.apiSessionMgr != nil {
		s.apiSessionMgr.Close()
	}

	log.Info("Server stopped")
	return nil
}

// loadAPIKeys loads API keys from a list of values. Each value is either a
// literal key or a path to a file containing one key per line.
// Returns a map of key -> APIKeyConfig.
func loadAPIKeys(raw []string) (map[string]api.APIKeyConfig, error) {
	keys := make(map[string]api.APIKeyConfig)
	idx := 0
	for _, entry := range raw {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// If the entry is a path to an existing file, read keys from it
		if info, err := os.Stat(entry); err == nil && !info.IsDir() {
			data, err := os.ReadFile(entry)
			if err != nil {
				return nil, fmt.Errorf("failed to read API key file %s: %w", entry, err)
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				idx++
				keys[line] = api.APIKeyConfig{
					Key:        line,
					Identifier: fmt.Sprintf("apikey-%d", idx),
				}
			}
			continue
		}
		// Otherwise treat as a literal key
		idx++
		keys[entry] = api.APIKeyConfig{
			Key:        entry,
			Identifier: fmt.Sprintf("apikey-%d", idx),
		}
	}
	return keys, nil
}
