package main

import (
	"os"

	log "github.com/fimreal/goutils/ezap"

	"github.com/fimreal/psh/internal/config"
	"github.com/fimreal/psh/internal/server"
)

func main() {
	err := config.Load(func(cfg *config.Config) error {
		// Setup logging
		if cfg.Debug {
			log.SetLevel("debug")
		}

		log.Infof("Starting psh (proxy shell) - WebSSH server on %s:%d", cfg.Host, cfg.Port)

		// Create and run server
		srv, err := server.New(cfg)
		if err != nil {
			log.Fatal(err)
			return err
		}

		if err := srv.Run(); err != nil {
			log.Fatal(err)
			return err
		}
		return nil
	})
	if err != nil {
		os.Exit(1)
	}
}
