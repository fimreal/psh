package config

import (
	"os"
	"path/filepath"

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
	Password          string
	Debug             bool
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
				cfg.Password = viper.GetString("PASSWORD")
			}

			if cfg.Password == "" {
				cfg.Password = "psh" // Default password for convenience
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
	flags.IntVarP(&cfg.Port, "port", "p", 8443, "Port to listen on")
	flags.StringVarP(&cfg.AuditLogPath, "audit-log", "a", "-", "Path to audit log file ('-' for stdout, empty to disable)")
	flags.StringVar(&cfg.AuditLevel, "audit-level", "command", "Audit level: off, connection, command, command-full")
	flags.StringVar(&cfg.TLSCertPath, "tls-cert", "", "Path to TLS certificate file")
	flags.StringVar(&cfg.TLSKeyPath, "tls-key", "", "Path to TLS private key file")
	flags.BoolVar(&cfg.AutoGenerateCerts, "auto-certs", true, "Auto-generate self-signed TLS certificates")
	flags.StringVar(&cfg.JWTSecret, "jwt-secret", "", "JWT secret key (auto-generated if not provided)")
	flags.IntVar(&cfg.JWTExpire, "jwt-expire", 86400, "JWT token expiration time in seconds")
	flags.StringVarP(&cfg.Password, "password", "P", "", "Password for authentication (required)")
	flags.BoolVar(&cfg.Debug, "debug", false, "Enable debug logging")

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
