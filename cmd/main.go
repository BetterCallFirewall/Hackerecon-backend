package main

import (
	"log"

	"github.com/BetterCallFirewall/Hackerecon/internal/config"
	"github.com/BetterCallFirewall/Hackerecon/internal/driven"
	"github.com/BetterCallFirewall/Hackerecon/internal/websocket"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	wsHub := websocket.NewWebsocketManager()

	genkitProxy, err := driven.NewSecurityProxyWithGenkit(cfg.LLM, wsHub)
	if err != nil {
		log.Fatalf("Failed to initialize genkit proxy: %v", err)
	}
	go startGenkitReportServer(genkitProxy.Analyzer)

	log.Fatal(genkitProxy.Start())
}
