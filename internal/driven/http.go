package driven

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/config"
	"github.com/BetterCallFirewall/Hackerecon/internal/llm"
	"github.com/BetterCallFirewall/Hackerecon/internal/websocket"
)

type SecurityProxyWithGenkit struct {
	port            string
	Analyzer        *GenkitSecurityAnalyzer
	server          *http.Server
	burpIntegration *BurpIntegration
}

func NewSecurityProxyWithGenkit(cfg config.LLMConfig, wsHub *websocket.WebsocketManager) (
	*SecurityProxyWithGenkit, error,
) {
	ctx := context.Background()

	// Инициализируем Genkit один раз с нужными плагинами
	genkitApp, err := llm.InitGenkitApp(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Genkit: %w", err)
	}

	// Создаём analyzer с new signature (no provider needed)
	analyzer := NewGenkitSecurityAnalyzer(genkitApp, cfg.Model, wsHub)
	log.Printf("✅ LLM провайдер: %s (модель: %s)", cfg.Provider, cfg.Model)

	return &SecurityProxyWithGenkit{
		port:            cfg.Port,
		burpIntegration: NewBurpIntegration(cfg.BurpHost, cfg.BurpPort),
		Analyzer:        analyzer,
	}, nil
}

// handleTunneling обрабатывает HTTPS CONNECT запросы
func (ps *SecurityProxyWithGenkit) handleTunneling(w http.ResponseWriter, r *http.Request) {
	// Определяем куда подключаться
	var destConn net.Conn
	var err error

	if ps.burpIntegration.IsEnabled() {
		// Через Burp Suite
		destConn, err = net.DialTimeout("tcp", ps.burpIntegration.host+":"+ps.burpIntegration.port, 10*time.Second)
		if err != nil {
			log.Printf("❌ HTTPS CONNECT %s → Burp недоступен: %v", r.Host, err)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		// Отправляем CONNECT запрос к Burp
		fmt.Fprintf(destConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", r.Host, r.Host)

		// Читаем ответ от Burp
		resp, err := http.ReadResponse(bufio.NewReader(destConn), r)
		if err != nil || resp.StatusCode != 200 {
			log.Printf("❌ Burp CONNECT failed для %s: %v", r.Host, err)
			destConn.Close()
			http.Error(w, "Burp CONNECT failed", http.StatusServiceUnavailable)
			return
		}
		log.Printf("🔗 HTTPS %s → %s", r.Host, ps.burpIntegration.GetRouteInfo())
	} else {
		// Напрямую
		destConn, err = net.DialTimeout("tcp", r.Host, 10*time.Second)
		if err != nil {
			log.Printf("❌ HTTPS CONNECT %s → %v", r.Host, err)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		log.Printf("🔗 HTTPS %s → напрямую", r.Host)
	}

	// Устанавливаем туннель
	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking не поддерживается", http.StatusInternalServerError)
		destConn.Close()
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		destConn.Close()
		return
	}

	// Двунаправленный копирование данных
	go ps.transfer(destConn, clientConn)
	go ps.transfer(clientConn, destConn)
}

func (ps *SecurityProxyWithGenkit) transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

// handleHTTP обрабатывает обычные HTTP запросы
func (ps *SecurityProxyWithGenkit) handleHTTP(w http.ResponseWriter, req *http.Request) {
	// Читаем тело запроса для анализа
	body, err := io.ReadAll(req.Body)
	if err != nil {
		log.Printf("❌ Ошибка чтения тела запроса: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Создаем прокси запрос
	outReq := createProxyRequest(req, body)

	// Получаем клиент (через Burp или напрямую)
	client := ps.burpIntegration.GetClient()
	log.Printf("🌐 %s %s → %s", outReq.Method, outReq.URL.String(), ps.burpIntegration.GetRouteInfo())

	// Отправляем запрос
	resp, err := client.Do(outReq)
	if err != nil {
		log.Printf("❌ Ошибка выполнения запроса: %v", err)
		http.Error(w, fmt.Sprintf("Request failed: %v", err), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	// Читаем ответ
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("❌ Ошибка чтения ответа: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Копируем заголовки ответа
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)

	// Анализируем трафик в фоне
	go ps.analyzeTraffic(req, string(body), resp, string(respBody))
}

// createProxyRequest создает правильный прокси запрос
func createProxyRequest(inReq *http.Request, body []byte) *http.Request {
	// Создаем новый запрос с правильным URL
	outReq, err := http.NewRequest(inReq.Method, inReq.URL.String(), strings.NewReader(string(body)))
	if err != nil {
		log.Printf("❌ Ошибка создания запроса: %v", err)
		return nil
	}

	outReq.RequestURI = ""

	// Клонируем заголовки
	outReq.Header = inReq.Header.Clone()

	// Удаляем проблемные заголовки
	for _, h := range []string{"Connection", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailers", "Upgrade"} {
		outReq.Header.Del(h)
	}

	// Устанавливаем правильный Host заголовок
	outReq.Host = inReq.Host

	// Копируем другие важные поля
	outReq.ContentLength = inReq.ContentLength
	outReq.TransferEncoding = inReq.TransferEncoding
	outReq.Close = inReq.Close

	return outReq
}

func (ps *SecurityProxyWithGenkit) analyzeTraffic(
	req *http.Request, reqBody string, resp *http.Response, respBody string,
) {
	// Фильтрация выполняется в Analyzer через RequestFilter
	// INCREASED: 30s → 120s для сложных анализов с retry
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Convert http.Header to map[string]string for new signature
	reqHeaders := headersToMap(req.Header)
	respHeaders := headersToMap(resp.Header)

	err := ps.Analyzer.AnalyzeHTTPTraffic(
		ctx,
		req.Method,
		req.URL.String(),
		reqHeaders,
		respHeaders,
		reqBody,
		respBody,
		resp.StatusCode,
	)
	if err != nil {
		log.Printf("❌ Ошибка анализа %s: %v", req.URL.String(), err)
	}
}

// headersToMap converts http.Header to map[string]string
func headersToMap(headers http.Header) map[string]string {
	result := make(map[string]string)
	for k, v := range headers {
		if len(v) > 0 {
			result[k] = v[0]
		}
	}
	return result
}
