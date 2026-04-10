package main

import (
	"github.com/fimreal/psh/internal/config"
	"github.com/fimreal/psh/internal/server"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Setup logging
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if cfg.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	log.Info().
		Str("host", cfg.Host).
		Int("port", cfg.Port).
		Msg("Starting psh (proxy shell) - WebSSH server")

	// Create and run server
	srv, err := server.New(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create server")
	}

	if err := srv.Run(); err != nil {
		log.Fatal().Err(err).Msg("Server error")
	}
}
