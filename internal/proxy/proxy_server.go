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

	"github.com/BetterCallFirewall/Hackerecon/internal/config"
	proxymodels "github.com/BetterCallFirewall/Hackerecon/internal/models/proxy"
)

type Broadcaster interface {
	Broadcast(data interface{})
}

type repoI interface {
	StoreRequest(req *proxymodels.RequestData)
}

type certManagerI interface {
	GetCAPath() string
	GetCertificate(host string) (*tls.Certificate, error)
}
type Server struct {
	config      *config.Config
	storage     repoI
	server      *http.Server
	certManager certManagerI
	broadcaster Broadcaster
}

func NewServer(cfg *config.Config, store repoI, certManager certManagerI) *Server {
	return &Server{
		config:      cfg,
		storage:     store,
		certManager: certManager,
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
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}

	targetURL := r.URL.String()

	if !r.URL.IsAbs() {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		targetURL = scheme + "://" + r.Host + r.RequestURI
	}

	requestData := s.captureRequest(r, targetURL)

	response, err := s.forwardRequest(r, targetURL)
	if err != nil {
		http.Error(w, "Proxy error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer response.Body.Close()

	responseData := s.captureResponse(response)

	requestData.Response = responseData
	s.storage.StoreRequest(requestData)

	if s.broadcaster != nil {
		s.broadcaster.Broadcast(requestData)
	}

	s.copyResponse(w, response)
}

func (s *Server) captureRequest(r *http.Request, targetURL string) *proxymodels.RequestData {
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(strings.NewReader(string(body)))

	return &proxymodels.RequestData{
		ID:        uuid.New().String(),
		URL:       targetURL,
		Method:    r.Method,
		Headers:   r.Header,
		Body:      string(body),
		Timestamp: time.Now(),
	}
}

func (s *Server) captureResponse(resp *http.Response) *proxymodels.ResponseData {
	body, _ := io.ReadAll(resp.Body)
	resp.Body = io.NopCloser(strings.NewReader(string(body)))

	return &proxymodels.ResponseData{
		Status:  resp.StatusCode,
		Headers: resp.Header,
		Body:    string(body),
	}
}

func (s *Server) forwardRequest(r *http.Request, targetURL string) (*http.Response, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse 
		},
	}

	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		return nil, err
	}

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
	for name, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
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

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	host, _, _ := net.SplitHostPort(r.Host)
	if host == "" {
		host = r.Host
	}

	certificate, err := s.certManager.GetCertificate(host)
	if err != nil {
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*certificate},
	}

	tlsClientConn := tls.Server(clientConn, tlsConfig)
	defer tlsClientConn.Close()

	if err := tlsClientConn.Handshake(); err != nil {
		return
	}

	reader := bufio.NewReader(tlsClientConn)

	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}

		req.URL.Scheme = "https"
		req.URL.Host = r.Host

		s.handleHTTPSRequest(tlsClientConn, req)

		if req.Header.Get("Connection") == "close" {
			return
		}
	}
}

func (s *Server) handleHTTPSRequest(clientConn net.Conn, req *http.Request) {
	requestData := s.captureRequest(req, req.URL.String())

	response, err := s.forwardRequest(req, req.URL.String())
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer response.Body.Close()

	responseData := s.captureResponse(response)

	requestData.Response = responseData
	s.storage.StoreRequest(requestData)

	if s.broadcaster != nil {
		s.broadcaster.Broadcast(requestData)
	}

	response.Write(clientConn)
}

func (s *Server) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return nil, nil
}

func (s *Server) GetCAPath() string {
	return s.certManager.GetCAPath()
}
