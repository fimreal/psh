package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type Config struct {
	Host              string
	Port              int
	AuditLogPath      string
	AuditLevel        string
	TLSCertPath       string
	TLSKeyPath        string
	AutoGenerateCerts bool
	JWTSecret         string
	JWTExpire         int
	Passwords         []string
	PasswordFile      string // Path to file containing passwords (one per line)
	Debug             bool
	DevMode           bool // Development mode: disable TLS and password auth

	// Security settings
	MaxLoginAttempts int // Max failed login attempts before lockout (default: 5)
	LoginLockoutMins int // Lockout duration in minutes (default: 15)
	MaxSessions      int // Max concurrent sessions per user (default: 10)
	MaxRequestPerMin int // Max requests per minute per IP (default: 100)
	MaxWSConnsPerMin int // Max WebSocket connections per minute per IP (default: 10)

	// SSH security settings
	SSHBlacklist      []string // CIDR ranges blocked from SSH (default: 127.0.0.0/8)
	StrictHostKey     bool     // Reject unknown SSH host keys instead of auto-accepting (default: false)
	ShowHostKeyDigest bool     // Show host key fingerprint when connecting (default: true)

	// CORS settings
	AllowedOrigins []string // Allowed CORS origins
}

// RunFunc is the function to run after config is loaded
type RunFunc func(*Config) error

func Load(run RunFunc) error {
	var cfg Config

	rootCmd := &cobra.Command{
		Use:   "psh",
		Short: "WebSSH Proxy Server",
		Run: func(cmd *cobra.Command, args []string) {
			// Apply viper overrides
			if viper.IsSet("HOST") {
				cfg.Host = viper.GetString("HOST")
			}
			if viper.IsSet("PORT") {
				cfg.Port = viper.GetInt("PORT")
			}
			if viper.IsSet("AUDIT_LOG") {
				cfg.AuditLogPath = viper.GetString("AUDIT_LOG")
			}
			if viper.IsSet("AUDIT_LEVEL") {
				cfg.AuditLevel = viper.GetString("AUDIT_LEVEL")
			}
			if viper.IsSet("TLS_CERT") {
				cfg.TLSCertPath = viper.GetString("TLS_CERT")
			}
			if viper.IsSet("TLS_KEY") {
				cfg.TLSKeyPath = viper.GetString("TLS_KEY")
			}
			if viper.IsSet("AUTO_CERTS") {
				cfg.AutoGenerateCerts = viper.GetBool("AUTO_CERTS")
			}
			if viper.IsSet("JWT_SECRET") {
				cfg.JWTSecret = viper.GetString("JWT_SECRET")
			}
			if viper.IsSet("JWT_EXPIRE") {
				cfg.JWTExpire = viper.GetInt("JWT_EXPIRE")
			}
			if viper.IsSet("PASSWORD") {
				cfg.Passwords = viper.GetStringSlice("PASSWORD")
			}

			// Load passwords from file if specified
			if cfg.PasswordFile != "" {
				passwords, err := loadPasswordsFromFile(cfg.PasswordFile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error loading password file: %v\n", err)
					os.Exit(1)
				}
				cfg.Passwords = append(cfg.Passwords, passwords...)
			}

			if len(cfg.Passwords) == 0 && !cfg.DevMode {
				fmt.Fprintln(os.Stderr, "Error: password is required.")
				fmt.Fprintln(os.Stderr, "Secure options:")
				fmt.Fprintln(os.Stderr, "  --password-file FILE   Read password from file (recommended)")
				fmt.Fprintln(os.Stderr, "  PSH_PASSWORD env       Set environment variable")
				fmt.Fprintln(os.Stderr, "  -P PASSWORD            Command line (visible in ps, not recommended)")
				os.Exit(1)
			}

			// Dev mode: use HTTP port 8080 by default
			if cfg.DevMode && !cmd.Flags().Changed("port") {
				cfg.Port = 8080
			}

			// Dev mode safety check: warn if binding to public interface
			if cfg.DevMode && (cfg.Host == "0.0.0.0" || cfg.Host == "") {
				fmt.Fprintln(os.Stderr, "WARNING: Dev mode with public binding (0.0.0.0) is insecure!")
				fmt.Fprintln(os.Stderr, "         Anyone on your network can access this server without authentication.")
				fmt.Fprintln(os.Stderr, "         Use -H 127.0.0.1 for local development only.")
			}

			// Set security defaults
			if cfg.MaxLoginAttempts == 0 {
				cfg.MaxLoginAttempts = 5
			}
			if cfg.LoginLockoutMins == 0 {
				cfg.LoginLockoutMins = 15
			}
			if cfg.MaxSessions == 0 {
				cfg.MaxSessions = 10
			}
			if cfg.MaxRequestPerMin == 0 {
				cfg.MaxRequestPerMin = 100
			}
			if cfg.MaxWSConnsPerMin == 0 {
				cfg.MaxWSConnsPerMin = 10
			}
			// Default SSH blacklist: block localhost (disabled in dev mode)
			if len(cfg.SSHBlacklist) == 0 && !cfg.DevMode {
				cfg.SSHBlacklist = []string{"127.0.0.0/8"}
			}
			// Default ShowHostKeyDigest to true
			if !cmd.Flags().Changed("show-host-key") {
				cfg.ShowHostKeyDigest = true
			}

			cfg.AuditLogPath = expandTilde(cfg.AuditLogPath)
			cfg.TLSCertPath = expandTilde(cfg.TLSCertPath)
			cfg.TLSKeyPath = expandTilde(cfg.TLSKeyPath)

			if err := run(&cfg); err != nil {
				os.Exit(1)
			}
		},
	}

	flags := rootCmd.Flags()
	flags.StringVarP(&cfg.Host, "host", "H", "0.0.0.0", "Host address to bind to")
	flags.IntVarP(&cfg.Port, "port", "p", 8443, "Port to listen on (default: 8443, dev mode: 8080)")
	flags.StringVarP(&cfg.AuditLogPath, "audit-log", "a", "-", "Path to audit log file ('-' for stdout, empty to disable)")
	flags.StringVar(&cfg.AuditLevel, "audit-level", "command", "Audit level: off, connection, command, command-full")
	flags.StringVar(&cfg.TLSCertPath, "tls-cert", "", "Path to TLS certificate file")
	flags.StringVar(&cfg.TLSKeyPath, "tls-key", "", "Path to TLS private key file")
	flags.BoolVar(&cfg.AutoGenerateCerts, "auto-certs", true, "Auto-generate self-signed TLS certificates")
	flags.StringVar(&cfg.JWTSecret, "jwt-secret", "", "JWT secret key (auto-generated if not provided)")
	flags.IntVar(&cfg.JWTExpire, "jwt-expire", 14400, "JWT token expiration time in seconds (default: 4 hours)")
	flags.StringVar(&cfg.PasswordFile, "password-file", "", "Path to file containing passwords (one per line)")
	flags.StringSliceVarP(&cfg.Passwords, "password", "P", nil, "Password(s) for auth (WARNING: visible in ps, prefer --password-file or PSH_PASSWORD)")
	flags.BoolVar(&cfg.Debug, "debug", false, "Enable debug logging")
	flags.BoolVar(&cfg.DevMode, "dev", false, "Development mode: disable TLS, password auth, and SSH blacklist")

	// Security flags
	flags.IntVar(&cfg.MaxLoginAttempts, "max-login-attempts", 5, "Max failed login attempts before lockout")
	flags.IntVar(&cfg.LoginLockoutMins, "login-lockout-mins", 15, "Lockout duration in minutes")
	flags.IntVar(&cfg.MaxSessions, "max-sessions", 10, "Max concurrent sessions")
	flags.IntVar(&cfg.MaxRequestPerMin, "max-requests", 100, "Max requests per minute per IP")
	flags.IntVar(&cfg.MaxWSConnsPerMin, "max-ws-conns", 10, "Max WebSocket connections per minute per IP")

	// SSH security flags
	flags.StringSliceVar(&cfg.SSHBlacklist, "ssh-blacklist", []string{"127.0.0.0/8"}, "CIDR ranges blocked from SSH (default: 127.0.0.0/8, use empty string to disable)")
	flags.BoolVar(&cfg.StrictHostKey, "strict-host-key", false, "Reject unknown SSH host keys instead of auto-accepting")
	flags.BoolVar(&cfg.ShowHostKeyDigest, "show-host-key", true, "Show host key fingerprint when connecting")

	// CORS flags
	flags.StringSliceVar(&cfg.AllowedOrigins, "allowed-origins", []string{}, "Allowed CORS origins (e.g., https://example.com)")

	viper.AutomaticEnv()
	viper.SetEnvPrefix("PSH")

	return rootCmd.Execute()
}

func expandTilde(path string) string {
	if len(path) > 0 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[1:])
	}
	return path
}

// loadPasswordsFromFile reads passwords from a file (one per line)
func loadPasswordsFromFile(path string) ([]string, error) {
	path = expandTilde(path)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read password file: %w", err)
	}

	var passwords []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			passwords = append(passwords, line)
		}
	}

	return passwords, nil
}
