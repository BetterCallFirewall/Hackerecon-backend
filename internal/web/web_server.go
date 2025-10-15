package web

import (
	"context"
	"net/http"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/config"
	"github.com/BetterCallFirewall/Hackerecon/internal/middlewares"
	"github.com/BetterCallFirewall/Hackerecon/internal/models"
	"github.com/BetterCallFirewall/Hackerecon/internal/websocket"
)

type broker interface {
	Subscribe(topic string) chan models.SecurityAnalysisResponse
}

type Server struct {
	server *http.Server
	broker broker
	hub    *websocket.Hub
}

func NewServer(cfg *config.Config, broker broker) *Server {
	hub := websocket.NewHub()

	server := &http.Server{
		Addr:         cfg.Web.ListenAddr,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	go hub.Run()

	return &Server{
		server: server,
		hub:    hub,
		broker: broker,
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.hub.ServeWS)
	mux.HandleFunc("/api/analysis", s.GetAnalysis)

	mux.HandleFunc(
		"/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		},
	)

	s.server.Handler = middlewares.CORS(mux)
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

// подумать чо как дальше
func (s *Server) Broadcast() {
	ch := s.broker.Subscribe(models.LLMTopic)

	for msg := range ch {
		s.hub.Broadcast(msg)
	}
}
