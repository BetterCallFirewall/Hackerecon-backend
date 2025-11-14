package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/BetterCallFirewall/Hackerecon/internal/driven"
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

	// 1. Получить все отчёты об уязвимостях
	http.HandleFunc("/api/reports", corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		reports := analyzer.GetReports()
		json.NewEncoder(w).Encode(reports)
	}))

	// 2. Получить только высокорисковые отчёты (CRITICAL/HIGH)
	http.HandleFunc("/api/high-risk", corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		highRiskReports := analyzer.GetHighRiskReports()
		json.NewEncoder(w).Encode(highRiskReports)
	}))

	// 3. Общая статистика анализа
	http.HandleFunc("/api/stats", corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		stats := analyzer.GetSummaryStats()
		json.NewEncoder(w).Encode(stats)
	}))

	// 4. Статистика оптимизации (кэширование, фильтрация)
	http.HandleFunc("/api/optimization-stats", corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		stats := analyzer.GetOptimizationStats()
		json.NewEncoder(w).Encode(stats)
	}))

	// 5. 🆕 Работа с гипотезами для конкретного хоста
	// GET  /api/hypothesis/{host} - получить текущую гипотезу
	// POST /api/hypothesis/{host} - принудительно сгенерировать новую гипотезу
	http.HandleFunc("/api/hypothesis/", corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		// Извлекаем host из пути: /api/hypothesis/{host}
		pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(pathParts) < 3 {
			http.Error(w, `{"error": "host parameter is required"}`, http.StatusBadRequest)
			return
		}

		host := pathParts[2]

		switch r.Method {
		case "GET":
			// Получить текущую гипотезу для хоста
			hypothesis := analyzer.GetCurrentHypothesis(host)
			if hypothesis == nil {
				http.Error(w, `{"error": "no hypothesis found for this host"}`, http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(hypothesis)

		case "POST":
			// Принудительно сгенерировать новую гипотезу (синхронный вызов LLM)
			hypothesis, err := analyzer.GenerateHypothesisForHost(host)
			if err != nil {
				log.Printf("❌ Failed to generate hypothesis for %s: %v", host, err)
				http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(hypothesis)

		default:
			http.Error(w, `{"error": "method not allowed"}`, http.StatusMethodNotAllowed)
		}
	}))

	// 6. 🆕 Получить все гипотезы по всем хостам
	http.HandleFunc("/api/hypotheses", corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		hypotheses := analyzer.GetAllHypotheses()
		json.NewEncoder(w).Encode(hypotheses)
	}))

	// 7. 🆕 Получить полный контекст сайта (для отладки)
	// Возвращает все URL паттерны, заметки, технологии, гипотезу
	http.HandleFunc("/api/context/", corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		// Извлекаем host из пути: /api/context/{host}
		pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(pathParts) < 3 {
			http.Error(w, `{"error": "host parameter is required"}`, http.StatusBadRequest)
			return
		}

		host := pathParts[2]
		context := analyzer.GetSiteContext(host)

		if context == nil {
			http.Error(w, `{"error": "no context found for this host"}`, http.StatusNotFound)
			return
		}

		json.NewEncoder(w).Encode(context)
	}))

	// 8. WebSocket endpoint для live-обновлений
	http.HandleFunc("/ws", analyzer.WsHub.ServeHTTP)

	// 9. Health check endpoint
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
	log.Println("   GET  /api/reports                  - Все отчеты об уязвимостях")
	log.Println("   GET  /api/high-risk                - Критические уязвимости")
	log.Println("   GET  /api/stats                    - Общая статистика анализа")
	log.Println("   GET  /api/optimization-stats       - Статистика оптимизации")
	log.Println("   GET  /api/hypothesis/{host}        - Текущая гипотеза для хоста")
	log.Println("   POST /api/hypothesis/{host}        - Сгенерировать новую гипотезу")
	log.Println("   GET  /api/hypotheses               - Все гипотезы")
	log.Println("   GET  /api/context/{host}           - Полный контекст сайта (debug)")
	log.Println("   WS   /ws                           - WebSocket для live обновлений")
	log.Println("   GET  /health                       - Health check")

	log.Fatal(http.ListenAndServe(":8081", nil))
}
