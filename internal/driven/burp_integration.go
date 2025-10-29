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

type BurpIntegration struct {
	host        string
	port        string
	enabled     bool
	client      *http.Client
	healthCheck bool
}

// NewBurpIntegration создает новую интеграцию с Burp
func NewBurpIntegration(host, port string) *BurpIntegration {
	if host == "" || port == "" {
		return &BurpIntegration{enabled: false}
	}

	integration := &BurpIntegration{
		host:    host,
		port:    port,
		enabled: true,
	}

	// Создаем HTTP клиент для работы с Burp
	integration.setupClient()

	// Проверяем доступность Burp
	integration.healthCheck = integration.checkBurpHealth()

	return integration
}

// setupClient настраивает HTTP клиент для Burp
func (bi *BurpIntegration) setupClient() {
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%s", bi.host, bi.port))
	if err != nil {
		log.Printf("❌ Ошибка парсинга Burp URL: %v", err)
		bi.enabled = false
		return
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Для работы с Burp CA
		},
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 0,
		}).DialContext,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	bi.client = &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

// GetClient возвращает HTTP клиент для запросов через Burp
func (bi *BurpIntegration) GetClient() *http.Client {
	if bi.IsHealthy() {
		return bi.client
	}
	return http.DefaultClient
}

// IsHealthy возвращает состояние здоровья Burp интеграции
func (bi *BurpIntegration) IsHealthy() bool {
	return bi.enabled && bi.healthCheck
}

// Периодическая проверка здоровья Burp
func (ps *SecurityProxyWithGenkit) startHealthChecker() {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for range ticker.C {
			if ps.fallbackMode && ps.burpIntegration.enabled {
				// Пробуем восстановить подключение к Burp
				if ps.burpIntegration.checkBurpHealth() {
					log.Printf("✅ Burp Suite восстановлен, выходим из fallback режима")
					ps.fallbackMode = false
					ps.burpIntegration.healthCheck = true
				}
			}
		}
	}()
}

// checkBurpHealth проверяет доступность Burp Suite
func (bi *BurpIntegration) checkBurpHealth() bool {
	if !bi.enabled {
		return false
	}

	log.Printf("🔍 Проверка подключения к Burp Suite %s:%s...", bi.host, bi.port)

	conn, err := net.DialTimeout("tcp", bi.host+":"+bi.port, 5*time.Second)
	if err != nil {
		log.Printf("❌ Burp Suite недоступен: %v", err)
		log.Printf("💡 Убедитесь что Burp запущен и слушает на %s:%s", bi.host, bi.port)
		return false
	}
	conn.Close()

	// Дополнительная проверка через HTTP запрос
	testReq, _ := http.NewRequest("GET", "http://httpbin.org/get", nil)
	testReq.Header.Set("User-Agent", "SecurityProxy-HealthCheck")

	resp, err := bi.client.Do(testReq)
	if err != nil {
		log.Printf("⚠️ Burp доступен, но HTTP запросы не проходят: %v", err)
		return false
	}
	resp.Body.Close()

	log.Printf("✅ Burp Suite подключен успешно")
	return true
}
