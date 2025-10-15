package main

import (
	"log"

	"github.com/BetterCallFirewall/Hackerecon/internal/broker"
	"github.com/BetterCallFirewall/Hackerecon/internal/config"
	"github.com/BetterCallFirewall/Hackerecon/internal/driven"
	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/BetterCallFirewall/Hackerecon/internal/web"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	customBroker := broker.New[models.SecurityAnalysisResponse](10000)
	server := web.NewServer(cfg, customBroker)
	go func() {
		if err := server.Start(); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	genkitProxy, err := driven.NewSecurityProxyWithGenkit(cfg.LLM, customBroker)
	if err != nil {
		log.Fatalf("Failed to initialize genkit proxy: %v", err)
	}

	log.Fatal(genkitProxy.Start())
}
