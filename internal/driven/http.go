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
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
)

type SecurityProxyWithGenkit struct {
	port            string
	Analyzer        *GenkitSecurityAnalyzer
	server          *http.Server
	burpIntegration *BurpIntegration
	fallbackMode    bool
}

func NewSecurityProxyWithGenkit(cfg config.LLMConfig, wsHub *websocket.WebsocketManager) (
	*SecurityProxyWithGenkit, error,
) {
	ctx := context.Background()
	var analyzer *GenkitSecurityAnalyzer
	var err error

	// Выбираем провайдера на основе конфигурации
	switch cfg.Provider {
	case "gemini", "": // Пустое значение = gemini по умолчанию
		// Инициализируем Genkit с плагинами
		genkitApp := genkit.Init(
			ctx,
			genkit.WithPlugins(
				&googlegenai.GoogleAI{
					APIKey: cfg.ApiKey,
				},
			),
			genkit.WithDefaultModel(cfg.Model),
		)

		analyzer, err = newGenkitSecurityAnalyzer(genkitApp, cfg.Model, wsHub)
		if err != nil {
			return nil, fmt.Errorf("failed to create Gemini analyzer: %w", err)
		}
		log.Printf("✅ Используется Gemini модель: %s", cfg.Model)

	case "generic":
		// Создаём Generic провайдер
		var format llm.APIFormat
		switch cfg.Format {
		case "ollama":
			format = llm.FormatOllama
		case "raw":
			format = llm.FormatRaw
		default:
			format = llm.FormatOpenAI // По умолчанию OpenAI-compatible
		}

		genericProvider := llm.NewGenericProvider(
			llm.GenericConfig{
				Name:    "custom-llm",
				Model:   cfg.Model, // Передассссвлрасапвреуушмгшаеосрпмлипргскатём модель из конфигурации
				BaseURL: cfg.BaseURL,
				APIKey:  cfg.ApiKey,
				Format:  format,
			},
		)

		// Создаём пустой genkitApp для flows (можно оптимизировать позже)
		genkitApp := genkit.Init(ctx)

		analyzer, err = newSecurityAnalyzerWithProvider(genkitApp, cfg.Model, genericProvider, wsHub)
		if err != nil {
			return nil, fmt.Errorf("failed to create Generic analyzer: %w", err)
		}
		log.Printf("✅ Используется Generic провайдер: %s (модель: %s, формат: %s)", cfg.BaseURL, cfg.Model, cfg.Format)

	default:
		return nil, fmt.Errorf("unknown LLM provider: %s", cfg.Provider)
	}

	burpIntegration := NewBurpIntegration(cfg.BurpHost, cfg.BurpPort)

	proxy := &SecurityProxyWithGenkit{
		port:            cfg.Port,
		burpIntegration: burpIntegration,
		Analyzer:        analyzer,
		fallbackMode:    !burpIntegration.IsHealthy(),
	}

	// Запускаем периодическую проверку здоровья Burp
	if burpIntegration.enabled {
		proxy.startHealthChecker()
	}

	return proxy, nil
}

// Улучшенная обработка HTTPS туннелирования
func (ps *SecurityProxyWithGenkit) handleTunneling(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔒 HTTPS CONNECT: %s", r.Host)

	var destConn net.Conn
	var err error
	var routeInfo string

	if ps.burpIntegration.IsHealthy() && !ps.fallbackMode {
		// Подключение через Burp Suite
		routeInfo = fmt.Sprintf(
			"через Burp Suite (%s:%s)",
			ps.burpIntegration.host, ps.burpIntegration.port,
		)

		destConn, err = net.DialTimeout(
			"tcp",
			ps.burpIntegration.host+":"+ps.burpIntegration.port, 10*time.Second,
		)
		if err != nil {
			log.Printf("❌ Ошибка подключения к Burp: %v", err)
			// Переключаемся в fallback режим
			ps.fallbackMode = true
		} else {
			// Отправляем CONNECT запрос к Burp
			fmt.Fprintf(
				destConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n\r\n",
				r.Host, r.Host,
			)

			// Читаем ответ от Burp
			resp, err := http.ReadResponse(bufio.NewReader(destConn), r)
			if err != nil || resp.StatusCode != 200 {
				log.Printf(
					"❌ Burp CONNECT failed: status=%d, error=%v",
					func() int {
						if resp != nil {
							return resp.StatusCode
						} else {
							return 0
						}
					}(), err,
				)
				destConn.Close()
				ps.fallbackMode = true
				destConn = nil
			}
		}
	}

	// Fallback: прямое подключение
	if destConn == nil || ps.fallbackMode {
		routeInfo = "напрямую (Burp недоступен или в fallback режиме)"
		destConn, err = net.DialTimeout("tcp", r.Host, 10*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	}

	log.Printf("🔗 HTTPS туннель установлен: %s → %s", r.Host, routeInfo)

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

	go ps.transfer(destConn, clientConn)
	go ps.transfer(clientConn, destConn)
}

func (ps *SecurityProxyWithGenkit) transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

// getHTTPClientWithInfo возвращает HTTP клиента и информацию о маршруте с учетом fallback логики
func (ps *SecurityProxyWithGenkit) getHTTPClientWithInfo() (*http.Client, string) {
	if ps.burpIntegration.IsHealthy() {
		return ps.burpIntegration.GetClient(), fmt.Sprintf(
			"через Burp Suite (%s:%s)",
			ps.burpIntegration.host, ps.burpIntegration.port,
		)
	}

	// Fallback mode
	if !ps.fallbackMode {
		log.Printf("⚠️ Переключение в fallback режим - Burp недоступен")
		ps.fallbackMode = true
	}
	return http.DefaultClient, "напрямую (Burp недоступен)"
}

// Исправленная обработка HTTP запросов
func (ps *SecurityProxyWithGenkit) handleHTTP(w http.ResponseWriter, req *http.Request) {
	// Читаем тело запроса для анализа
	body, err := io.ReadAll(req.Body)
	if err != nil {
		log.Printf("❌ Ошибка чтения тела запроса: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Создаем новый запрос для отправки
	outReq := createProxyRequest(req, body)

	// Получаем HTTP клиента с учетом fallback логики
	client, routeInfo := ps.getHTTPClientWithInfo()
	log.Printf("🌐 %s %s → %s", outReq.Method, outReq.URL.String(), routeInfo)

	// Отправляем запрос
	resp, err := client.Do(outReq)
	if err != nil {
		log.Printf("❌ Ошибка выполнения запроса: %v", err)

		// Если использовали Burp и получили ошибку, пробуем напрямую
		if !ps.fallbackMode && ps.burpIntegration.IsHealthy() {
			log.Printf("🔄 Повторная попытка напрямую...")
			ps.fallbackMode = true
			resp, err = http.DefaultClient.Do(outReq)
		}

		// Если всё равно ошибка - возвращаем её клиенту
		if err != nil {
			http.Error(w, fmt.Sprintf("Request failed: %v", err), http.StatusServiceUnavailable)
			return
		}
	}
	defer resp.Body.Close()

	// Читаем ответ
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("❌ Ошибка чтения ответа: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Анализируем в отдельной горутине
	go ps.analyzeTraffic(req, string(body), resp, string(respBody))

	// Возвращаем ответ клиенту (используем простое копирование всех заголовков)
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// Новая функция для создания правильного прокси запроса
func createProxyRequest(inReq *http.Request, body []byte) *http.Request {
	// Создаем новый запрос с правильным URL
	outReq, err := http.NewRequest(inReq.Method, inReq.URL.String(), strings.NewReader(string(body)))
	if err != nil {
		log.Printf("❌ Ошибка создания запроса: %v", err)
		return nil
	}

	outReq.RequestURI = ""

	// Копируем заголовки, исключая проблемные
	copyHeaders(outReq.Header, inReq.Header)

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
	contentType := resp.Header.Get("Content-Type")
	if isSkippableContent(contentType, req.URL.Path) {
		log.Printf("⚪️ Пропуск анализа для %s (Content-Type: %s)", req.URL.String(), contentType)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := ps.Analyzer.AnalyzeHTTPTraffic(ctx, req, resp, reqBody, respBody, contentType)
	if err != nil {
		log.Printf("❌ Ошибка анализа %s: %v", req.URL.String(), err)
	}
}
