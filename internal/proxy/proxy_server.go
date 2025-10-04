package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/analyzer"
	"github.com/BetterCallFirewall/Hackerecon/internal/config"
	"github.com/BetterCallFirewall/Hackerecon/internal/storage"
	"github.com/google/uuid"
)

type Server struct {
	config   *config.Config
	analyzer *analyzer.LLMAnalyzer
	storage  *storage.MemoryStorage
	server   *http.Server
}

func NewServer(cfg *config.Config, store *storage.MemoryStorage) *Server {
	return &Server{
		config:   cfg,
		analyzer: analyzer.NewLLMAnalyzer(cfg),
		storage:  store,
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRequest)

	s.server = &http.Server{
		Addr:    s.config.Proxy.ListenAddr,
		Handler: mux,
		TLSConfig: &tls.Config{
			GetCertificate: s.getCertificate,
		},
	}

	// Для простоты MVP - используем HTTP
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

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Перехватываем запрос
	requestData := s.captureRequest(r)

	// Пересылаем запрос к целевому серверу
	response, err := s.forwardRequest(r)
	if err != nil {
		http.Error(w, "Proxy error", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()

	// Захватываем ответ
	responseData := s.captureResponse(response)

	// Отправляем на анализ в LLM (асинхронно)
	go s.analyzeTraffic(requestData, responseData)

	// Возвращаем ответ клиенту
	s.copyResponse(w, response)
}

func (s *Server) captureRequest(r *http.Request) *storage.RequestData {
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(strings.NewReader(string(body)))

	return &storage.RequestData{
		ID:        uuid.New().String(),
		URL:       r.URL.String(),
		Method:    r.Method,
		Headers:   r.Header,
		Body:      string(body),
		Timestamp: time.Now(),
	}
}

func (s *Server) captureResponse(resp *http.Response) *storage.ResponseData {
	body, _ := io.ReadAll(resp.Body)
	resp.Body = io.NopCloser(strings.NewReader(string(body)))

	return &storage.ResponseData{
		Status:  resp.StatusCode,
		Headers: resp.Header,
		Body:    string(body),
	}
}

func (s *Server) forwardRequest(r *http.Request) (*http.Response, error) {
	// Простая реализация пересылки запроса
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		return nil, err
	}

	// Копируем заголовки
	for name, values := range r.Header {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	return client.Do(req)
}

func (s *Server) analyzeTraffic(req *storage.RequestData, resp *storage.ResponseData) {
	// Анализируем трафик с помощью LLM
	analysis, err := s.analyzer.Analyze(req, resp)
	if err != nil {
		log.Printf("Analysis failed: %v", err)
		return
	}

	// Сохраняем результаты
	req.Analysis = analysis
	s.storage.StoreRequest(req)
}

func (s *Server) copyResponse(w http.ResponseWriter, resp *http.Response) {
	// Копируем заголовки ответа
	for name, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (s *Server) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// Простая генерация самоподписанного сертификата
	// В продакшене нужно использовать более сложную логику
	// Пока возвращаем nil для HTTP-only режима
	return nil, nil
}