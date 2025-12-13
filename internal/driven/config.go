package driven

import (
	"log"
	"net/http"
	"time"
)

// SecurityProxyWithGenkit расширенный прокси с интеграцией Genkit

// HTTP прокси функции (упрощенная версия для демонстрации)
func (ps *SecurityProxyWithGenkit) Start() error {
	ps.server = &http.Server{
		Addr: ":" + ps.port,
		Handler: http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodConnect {
					ps.handleTunneling(w, r)
				} else {
					ps.handleHTTP(w, r)
				}
			},
		),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Printf("🚀 Security Proxy запущен на порту %s", ps.port)
	if ps.burpIntegration.enabled {
		log.Printf("📡 Upstream Burp Suite: %s:%s", ps.burpIntegration.host, ps.burpIntegration.port)
	}
	log.Printf("🤖 LLM анализ: Включен")

	return ps.server.ListenAndServe()
}
