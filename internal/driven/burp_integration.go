package driven

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"
)

// BurpIntegration - упрощенная интеграция с Burp Suite
// Простой переключатель: либо через Burp, либо напрямую
type BurpIntegration struct {
	host    string
	port    string
	enabled bool
	client  *http.Client
}

// NewBurpIntegration создает интеграцию с Burp
func NewBurpIntegration(host, port string) *BurpIntegration {
	if host == "" || port == "" {
		log.Printf("📡 Burp Suite: выключен (адрес не указан)")
		return &BurpIntegration{enabled: false}
	}

	integration := &BurpIntegration{
		host:    host,
		port:    port,
		enabled: true,
	}

	integration.setupClient()
	log.Printf("📡 Burp Suite: включен (%s:%s)", host, port)

	return integration
}

// setupClient настраивает HTTP клиент для проксирования через Burp
func (bi *BurpIntegration) setupClient() {
	proxyURL, _ := url.Parse(fmt.Sprintf("http://%s:%s", bi.host, bi.port))

	bi.client = &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Для работы с Burp CA
			},
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		Timeout: 30 * time.Second,
	}
}

// GetClient возвращает HTTP клиент (через Burp или напрямую)
func (bi *BurpIntegration) GetClient() *http.Client {
	if bi.enabled {
		return bi.client
	}
	return http.DefaultClient
}

// GetRouteInfo возвращает информацию о маршруте для логирования
func (bi *BurpIntegration) GetRouteInfo() string {
	if bi.enabled {
		return fmt.Sprintf("через Burp (%s:%s)", bi.host, bi.port)
	}
	return "напрямую"
}

// IsEnabled возвращает статус включения Burp
func (bi *BurpIntegration) IsEnabled() bool {
	return bi.enabled
}
