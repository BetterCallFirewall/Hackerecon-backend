package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/BetterCallFirewall/Hackerecon/internal/driven"
)

// StartAPIServer запускает REST API сервер для взаимодействия с анализатором
// Detective flow simplified version - removed /api/hypothesis endpoint
// Hypotheses are now automatically generated as Leads during analysis
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

	// WebSocket endpoint для live-обновлений результатов анализа
	// detective_analysis_complete messages are sent automatically
	http.HandleFunc("/ws", analyzer.GetWsHub().ServeHTTP)

	// Health check endpoint
	http.HandleFunc("/health", corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"service": "hackerecon-api",
			"flow":    "detective", // Indicate we're using detective flow
		})
	}))

	// Запуск сервера
	log.Println("📊 API Server запущен на http://localhost:8081")
	log.Println("📡 Доступные endpoints:")
	log.Println("   WS   /ws                           - WebSocket для live обновлений анализа (detective flow)")
	log.Println("   GET  /health                       - Health check")

	log.Fatal(http.ListenAndServe(":8081", nil))
}
