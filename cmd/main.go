package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/BetterCallFirewall/Hackerecon/internal/config"
	"github.com/BetterCallFirewall/Hackerecon/internal/proxy"
	"github.com/BetterCallFirewall/Hackerecon/internal/storage"
	"github.com/BetterCallFirewall/Hackerecon/internal/web"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to config file")
	flag.Parse()

	// Загружаем конфигурацию
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Инициализируем хранилище в памяти
	store := storage.NewMemoryStorage()

	// Запускаем прокси сервер
	proxyServer := proxy.NewServer(cfg, store)
	go func() {
		log.Printf("Starting proxy server on %s", cfg.Proxy.ListenAddr)
		if err := proxyServer.Start(); err != nil {
			log.Fatalf("Proxy server failed: %v", err)
		}
	}()

	// Запускаем веб-интерфейс
	webServer := web.NewServer(cfg, store)
	go func() {
		log.Printf("Starting web interface on %s", cfg.Web.ListenAddr)
		if err := webServer.Start(); err != nil {
			log.Fatalf("Web server failed: %v", err)
		}
	}()

	// Graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	log.Println("Shutting down...")
	proxyServer.Stop()
	webServer.Stop()
}