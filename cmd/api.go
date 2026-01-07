package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

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
			"flow":    "3-phase", // 3-phase agent flow
		})
	}))

	// Deep analysis endpoint - triggers Strategist + Tactician pipeline
	http.HandleFunc("/api/analyze-deep", corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		log.Printf("📨 Received deep analysis request")

		// Run deep analysis asynchronously with independent context (don't block HTTP response)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			if err := analyzer.RunDeepAnalysis(ctx); err != nil {
				log.Printf("❌ Deep analysis failed: %v", err)
			}
		}()

		// Return immediately
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "started",
		})
	}))

	// Запуск сервера
	log.Println("📊 API Server запущен на http://localhost:8081")
	log.Println("📡 Доступные endpoints:")
	log.Println("   WS   /ws                           - WebSocket для live обновлений анализа (3-phase flow)")
	log.Println("   GET  /health                       - Health check")
	log.Println("   POST /api/analyze-deep             - Trigger deep analysis (Strategist + Tactician)")

	log.Fatal(http.ListenAndServe(":8081", nil))
}
