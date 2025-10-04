package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/config"
	"github.com/BetterCallFirewall/Hackerecon/internal/storage"
	"github.com/google/uuid"
)

type Server struct {
	config  *config.Config
	storage *storage.MemoryStorage
	server  *http.Server
}

func NewServer(cfg *config.Config, store *storage.MemoryStorage) *Server {
	return &Server{
		config:  cfg,
		storage: store,
	}
}

func (s *Server) Start() error {
	s.server = &http.Server{
		Addr:    s.config.Proxy.ListenAddr,
		Handler: http.HandlerFunc(s.handleRequest),
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
	// Обрабатываем CONNECT для HTTPS
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}

	// Получаем полный URL из запроса
	targetURL := r.URL.String()

	// Если URL не абсолютный, формируем его из Host
	if !r.URL.IsAbs() {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		targetURL = scheme + "://" + r.Host + r.RequestURI
	}

	// Перехватываем запрос
	requestData := s.captureRequest(r, targetURL)

	// Пересылаем запрос к целевому серверу
	response, err := s.forwardRequest(r, targetURL)
	if err != nil {
		http.Error(w, "Proxy error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer response.Body.Close()

	// Захватываем ответ
	responseData := s.captureResponse(response)

	// Сохраняем запрос с ответом
	requestData.Response = responseData
	s.storage.StoreRequest(requestData)

	// Возвращаем ответ клиенту
	s.copyResponse(w, response)
}

func (s *Server) captureRequest(r *http.Request, targetURL string) *storage.RequestData {
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(strings.NewReader(string(body)))

	return &storage.RequestData{
		ID:        uuid.New().String(),
		URL:       targetURL,
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

func (s *Server) forwardRequest(r *http.Request, targetURL string) (*http.Response, error) {
	// Создаем HTTP клиент
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Не следуем за редиректами автоматически
		},
	}

	// Создаем новый запрос
	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		return nil, err
	}

	// Копируем заголовки, кроме Proxy-Connection
	for name, values := range r.Header {
		if name == "Proxy-Connection" {
			continue
		}
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	return client.Do(req)
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

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	// CONNECT используется для HTTPS туннелирования
	// Мы просто создаём TCP туннель между клиентом и целевым сервером

	// Получаем доступ к underlying connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Cannot hijack connection", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Подключаемся к целевому серверу
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 503 Service Unavailable\r\n\r\n"))
		return
	}
	defer destConn.Close()

	// Сообщаем клиенту что туннель установлен
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Логируем HTTPS туннель (без содержимого, т.к. он зашифрован)
	requestData := &storage.RequestData{
		ID:        uuid.New().String(),
		URL:       "https://" + r.Host,
		Method:    "CONNECT",
		Headers:   r.Header,
		Body:      "[HTTPS tunnel - encrypted]",
		Timestamp: time.Now(),
		Response: &storage.ResponseData{
			Status:  200,
			Headers: http.Header{},
			Body:    "[HTTPS tunnel - encrypted]",
		},
	}
	s.storage.StoreRequest(requestData)

	// Копируем данные в обе стороны
	go io.Copy(destConn, clientConn)
	io.Copy(clientConn, destConn)
}

func (s *Server) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// Простая генерация самоподписанного сертификата
	// В продакшене нужно использовать более сложную логику
	// Пока возвращаем nil для HTTP-only режима
	return nil, nil
}