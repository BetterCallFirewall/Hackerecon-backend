package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/BetterCallFirewall/Hackerecon/internal/driven"
	"github.com/BetterCallFirewall/Hackerecon/internal/models"
)

// StartAPIServer запускает REST API сервер для взаимодействия с анализатором
func StartAPIServer(analyzer *driven.GenkitSecurityAnalyzer) {
	// CORS middleware для разрешения cross-origin запросов с фронтенда
	corsMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

			// Обработка preflight запросов
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next(w, r)
		}
	}

	// Единственная REST API ручка: генерация гипотезы с tech stack
	// POST /api/hypothesis/{host} - принудительно сгенерировать новую гипотезу
	http.HandleFunc("/api/hypothesis/", corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		if r.Method != "POST" {
			http.Error(w, `{"error": "only POST method allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		// Извлекаем host из пути: /api/hypothesis/{host}
		pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(pathParts) < 3 {
			http.Error(w, `{"error": "host parameter is required"}`, http.StatusBadRequest)
			return
		}

		host := pathParts[2]

		// Принудительно сгенерировать новую гипотезу (синхронный вызов LLM)
		hypothesisResp, err := analyzer.GenerateHypothesisForHost(host)
		if err != nil {
			log.Printf("❌ Failed to generate hypothesis for %s: %v", host, err)
			http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		// Получаем tech stack из контекста
		siteContext := analyzer.GetSiteContext(host)
		var techStack *models.TechStack
		if siteContext != nil {
			techStack = siteContext.TechStack
		}

		// Формируем DTO с гипотезой и tech stack
		dto := models.HypothesisDTO{
			Type: "hypothesis",
			Data: &models.HypothesisData{
				Hypothesis: hypothesisResp.Hypothesis,
				TechStack:  techStack,
			},
		}

		json.NewEncoder(w).Encode(dto)
	}))

	// WebSocket endpoint для live-обновлений результатов анализа
	http.HandleFunc("/ws", analyzer.WsHub.ServeHTTP)

	// Health check endpoint
	http.HandleFunc("/health", corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"service": "hackerecon-api",
		})
	}))

	// Запуск сервера
	log.Println("📊 API Server запущен на http://localhost:8081")
	log.Println("📡 Доступные endpoints:")
	log.Println("   POST /api/hypothesis/{host}        - Сгенерировать гипотезу с tech stack")
	log.Println("   WS   /ws                           - WebSocket для live обновлений анализа")
	log.Println("   GET  /health                       - Health check")

	log.Fatal(http.ListenAndServe(":8081", nil))
}
