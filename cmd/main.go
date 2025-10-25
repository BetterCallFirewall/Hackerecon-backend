package main

import (
	"log"

	"github.com/BetterCallFirewall/Hackerecon/internal/config"
	"github.com/BetterCallFirewall/Hackerecon/internal/driven"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	genkitProxy, err := driven.NewSecurityProxyWithGenkit(cfg.LLM)
	if err != nil {
		log.Fatalf("Failed to initialize genkit proxy: %v", err)
	}
	go startGenkitReportServer(genkitProxy.Analyzer)

	log.Fatal(genkitProxy.Start())
}
