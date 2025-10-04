package web

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/config"
	"github.com/BetterCallFirewall/Hackerecon/internal/storage"
	"github.com/BetterCallFirewall/Hackerecon/internal/websocket"
)

type Server struct {
	config  *config.Config
	storage *storage.MemoryStorage
	server  *http.Server
	hub     *websocket.Hub
}

func NewServer(cfg *config.Config, store *storage.MemoryStorage) *Server {
	hub := websocket.NewHub()
	go hub.Run()

	return &Server{
		config:  cfg,
		storage: store,
		hub:     hub,
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/requests", s.handleGetRequests)
	mux.HandleFunc("/api/requests/", s.handleGetRequest)

	// WebSocket endpoint
	mux.HandleFunc("/ws", s.hub.ServeWS)

	// Static files (для фронтенда)
	mux.Handle("/", http.FileServer(http.Dir("./web/static")))

	s.server = &http.Server{
		Addr:    s.config.Web.ListenAddr,
		Handler: s.enableCORS(mux),
	}

	return s.server.ListenAndServe()
}

func (s *Server) Stop() error {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.server.Shutdown(ctx)
	}
	return nil
}

func (s *Server) handleGetRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	requests := s.storage.GetAllRequests()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(requests)
}

func (s *Server) handleGetRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Path[len("/api/requests/"):]
	req, ok := s.storage.GetRequest(id)
	if !ok {
		http.Error(w, "Request not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(req)
}

func (s *Server) enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) BroadcastAnalysis(analysis interface{}) {
	s.hub.BroadcastAnalysis(analysis)
}
