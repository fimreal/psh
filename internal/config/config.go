package config

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type Config struct {
	Host             string
	Port             int
	AuditLogPath     string
	TLSCertPath      string
	TLSKeyPath       string
	AutoGenerateCerts bool
	JWTSecret        string
	JWTExpire        int
	Password         string
	Debug            bool
}

func Load() (*Config, error) {
	var cfg Config

	// Define root command
	rootCmd := &cobra.Command{
		Use:   "psh",
		Short: "WebSSH Proxy Server",
		Run: func(cmd *cobra.Command, args []string) {
			// Command just parses flags, actual work is in main
		},
	}

	// Define flags
	flags := rootCmd.Flags()
	flags.StringVarP(&cfg.Host, "host", "H", "0.0.0.0", "Host address to bind to")
	flags.IntVarP(&cfg.Port, "port", "p", 8443, "Port to listen on")
	flags.StringVarP(&cfg.AuditLogPath, "audit-log", "a", "/var/log/psh/audit.jsonl", "Path to audit log file")
	flags.StringVar(&cfg.TLSCertPath, "tls-cert", "", "Path to TLS certificate file")
	flags.StringVar(&cfg.TLSKeyPath, "tls-key", "", "Path to TLS private key file")
	flags.BoolVar(&cfg.AutoGenerateCerts, "auto-certs", true, "Auto-generate self-signed TLS certificates")
	flags.StringVar(&cfg.JWTSecret, "jwt-secret", "", "JWT secret key (auto-generated if not provided)")
	flags.IntVar(&cfg.JWTExpire, "jwt-expire", 86400, "JWT token expiration time in seconds")
	flags.StringVarP(&cfg.Password, "password", "P", "", "Password for authentication (required)")
	flags.BoolVar(&cfg.Debug, "debug", false, "Enable debug logging")

	// Bind environment variables
	viper.BindEnv("host", "PSH_HOST")
	viper.BindEnv("port", "PSH_PORT")
	viper.BindEnv("audit-log", "PSH_AUDIT_LOG")
	viper.BindEnv("tls-cert", "PSH_TLS_CERT")
	viper.BindEnv("tls-key", "PSH_TLS_KEY")
	viper.BindEnv("auto-certs", "PSH_AUTO_CERTS")
	viper.BindEnv("jwt-secret", "PSH_JWT_SECRET")
	viper.BindEnv("jwt-expire", "PSH_JWT_EXPIRE")
	viper.BindEnv("password", "PSH_PASSWORD")

	// Parse flags
	if err := rootCmd.Execute(); err != nil {
		return nil, err
	}

	// Override with environment variables if set
	if h := viper.GetString("host"); h != "" {
		cfg.Host = h
	}
	if p := viper.GetInt("port"); p != 0 {
		cfg.Port = p
	}
	if a := viper.GetString("audit-log"); a != "" {
		cfg.AuditLogPath = a
	}
	if tc := viper.GetString("tls-cert"); tc != "" {
		cfg.TLSCertPath = tc
	}
	if tk := viper.GetString("tls-key"); tk != "" {
		cfg.TLSKeyPath = tk
	}
	if viper.IsSet("auto-certs") {
		cfg.AutoGenerateCerts = viper.GetBool("auto-certs")
	}
	if js := viper.GetString("jwt-secret"); js != "" {
		cfg.JWTSecret = js
	}
	if je := viper.GetInt("jwt-expire"); je != 0 {
		cfg.JWTExpire = je
	}
	if pw := viper.GetString("password"); pw != "" {
		cfg.Password = pw
	}

	// Validate required fields
	if cfg.Password == "" {
		rootCmd.Help()
		os.Exit(1)
	}

	// Expand tilde in paths
	cfg.AuditLogPath = expandTilde(cfg.AuditLogPath)
	cfg.TLSCertPath = expandTilde(cfg.TLSCertPath)
	cfg.TLSKeyPath = expandTilde(cfg.TLSKeyPath)

	return &cfg, nil
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
