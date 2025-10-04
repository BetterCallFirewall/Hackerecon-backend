package web

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/config"
	"github.com/BetterCallFirewall/Hackerecon/internal/middlewares"
	proxymodels "github.com/BetterCallFirewall/Hackerecon/internal/models/proxy"
	"github.com/BetterCallFirewall/Hackerecon/internal/websocket"
)

type storageI interface {
	GetAllRequests() []*proxymodels.RequestData
	GetRequest(id string) (*proxymodels.RequestData, bool)
}

type Server struct {
	config  *config.Config
	storage storageI
	server  *http.Server
	hub     *websocket.Hub
}

func NewServer(cfg *config.Config, store storageI) *Server {
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

	// Health check
	mux.HandleFunc(
		"/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		},
	)

	s.server = &http.Server{
		Addr:         s.config.Web.ListenAddr,
		Handler:      middlewares.CORS(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
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

func (s *Server) Broadcast(data interface{}) {
	s.hub.Broadcast(data)
}
