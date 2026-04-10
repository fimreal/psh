package main

import (
	log "github.com/fimreal/goutils/ezap"

	"github.com/fimreal/psh/internal/config"
	"github.com/fimreal/psh/internal/server"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	// Setup logging
	if cfg.Debug {
		log.SetLevel("debug")
	}

	log.Infof("Starting psh (proxy shell) - WebSSH server on %s:%d", cfg.Host, cfg.Port)

	// Create and run server
	srv, err := server.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	if err := srv.Run(); err != nil {
		log.Fatal(err)
	}
}
