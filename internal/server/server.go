package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/fimreal/goutils/ezap"

	"github.com/fimreal/psh/internal/audit"
	"github.com/fimreal/psh/internal/auth"
	"github.com/fimreal/psh/internal/config"
	tlspkg "github.com/fimreal/psh/pkg/tls"
	"github.com/gin-gonic/gin"
)

type Server struct {
	cfg         *config.Config
	authService *auth.Service
	auditLogger *audit.Logger
	handler     *Handler
}

func New(cfg *config.Config) (*Server, error) {
	// Initialize auth service
	authService := auth.NewService(cfg.JWTSecret, cfg.JWTExpire, cfg.Password)
	log.Info("Auth service initialized")

	// Initialize audit logger
	auditLogger, err := audit.NewLogger(cfg.AuditLogPath, audit.Level(cfg.AuditLevel))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize audit logger: %w", err)
	}

	// Create handler
	handler := NewHandler(authService, auditLogger, cfg.JWTExpire)

	return &Server{
		cfg:         cfg,
		authService: authService,
		auditLogger: auditLogger,
		handler:     handler,
	}, nil
}

func (s *Server) Run() error {
	// Set Gin mode
	if !s.cfg.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create router
	r := gin.New()
	r.Use(gin.Recovery())

	// Load HTML templates
	r.LoadHTMLFiles("static/index.html")

	// Public routes
	r.GET("/", s.handler.IndexHandler)
	r.POST("/api/auth/login", s.handler.LoginHandler)

	// Static files
	r.GET("/static/*path", s.handler.StaticHandler)

	// Protected routes
	protected := r.Group("")
	protected.Use(AuthMiddleware(s.authService))
	protected.GET("/ws/terminal", s.handler.TerminalWSHandler)

	// Create HTTP server
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	srv := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	// Setup TLS
	var tlsConfig *tls.Config
	if s.cfg.TLSCertPath != "" && s.cfg.TLSKeyPath != "" {
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

	log.Info("Server stopped")
	return nil
}
