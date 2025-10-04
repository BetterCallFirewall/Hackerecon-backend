package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/BetterCallFirewall/Hackerecon/internal/cert"
	"github.com/BetterCallFirewall/Hackerecon/internal/config"
	"github.com/BetterCallFirewall/Hackerecon/internal/storage"
)

type Broadcaster interface {
	Broadcast(data interface{})
}
type Server struct {
	config      *config.Config
	storage     *storage.MemoryStorage
	server      *http.Server
	certManager *cert.CertManager
	broadcaster Broadcaster
}

func NewServer(cfg *config.Config, store *storage.MemoryStorage) *Server {
	certMgr, err := cert.NewCertManager()
	if err != nil {
		panic(err)
	}

	return &Server{
		config:      cfg,
		storage:     store,
		certManager: certMgr,
	}
}

func (s *Server) SetBroadcaster(b Broadcaster) {
	s.broadcaster = b
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

	// Отправляем в WebSocket
	if s.broadcaster != nil {
		s.broadcaster.Broadcast(requestData)
	}

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
	// MITM для HTTPS - расшифровка трафика

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

	// Сообщаем клиенту что туннель установлен
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Извлекаем хост без порта
	host, _, _ := net.SplitHostPort(r.Host)
	if host == "" {
		host = r.Host
	}

	// Получаем сертификат для этого хоста
	certificate, err := s.certManager.GetCertificate(host)
	if err != nil {
		return
	}

	// Оборачиваем соединение в TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*certificate},
	}

	tlsClientConn := tls.Server(clientConn, tlsConfig)
	defer tlsClientConn.Close()

	// Делаем TLS handshake
	if err := tlsClientConn.Handshake(); err != nil {
		return
	}

	// Обрабатываем запросы в цикле (может быть несколько запросов по одному соединению)
	reader := bufio.NewReader(tlsClientConn)

	for {
		// Читаем HTTP запрос от клиента через TLS
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}

		// Формируем полный URL
		req.URL.Scheme = "https"
		req.URL.Host = r.Host

		// Обрабатываем запрос
		s.handleHTTPSRequest(tlsClientConn, req)

		// Если Connection: close - выходим
		if req.Header.Get("Connection") == "close" {
			return
		}
	}
}

func (s *Server) handleHTTPSRequest(clientConn net.Conn, req *http.Request) {
	// Захватываем запрос
	requestData := s.captureRequest(req, req.URL.String())

	// Отправляем запрос к реальному серверу
	response, err := s.forwardRequest(req, req.URL.String())
	if err != nil {
		// Отправляем ошибку клиенту
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer response.Body.Close()

	// Захватываем ответ
	responseData := s.captureResponse(response)

	// Сохраняем
	requestData.Response = responseData
	s.storage.StoreRequest(requestData)

	// Отправляем в WebSocket
	if s.broadcaster != nil {
		s.broadcaster.Broadcast(requestData)
	}

	// Отправляем ответ клиенту
	response.Write(clientConn)
}

func (s *Server) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return nil, nil
}

func (s *Server) GetCAPath() string {
	return s.certManager.GetCAPath()
}
