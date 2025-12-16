package verification

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// VerificationClient безопасный HTTP клиент для верификации
type VerificationClient struct {
	httpClient *http.Client
	config     VerificationClientConfig
}

// VerificationClientConfig конфигурация клиента
type VerificationClientConfig struct {
	Timeout    time.Duration
	MaxRetries int
	UserAgent  string
}

// TestRequest запрос для верификации
type TestRequest struct {
	URL     string
	Method  string
	Headers map[string]string
	Body    string // Для будущих POST запросов
}

// TestResponse ответ от верификационного запроса
type TestResponse struct {
	URL          string
	StatusCode   int
	ResponseSize int
	ResponseBody string // Первые 1KB для анализа
	Headers      map[string]string
	Duration     time.Duration
}

// NewVerificationClient создает новый клиент верификации
func NewVerificationClient(config VerificationClientConfig) *VerificationClient {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 2
	}
	if config.UserAgent == "" {
		config.UserAgent = "Hackerecon-Verifier/1.0"
	}

	return &VerificationClient{
		httpClient: &http.Client{
			Timeout: config.Timeout,
			// Отключаем редиректы для безопасности
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		config: config,
	}
}

// MakeRequest выполняет безопасный тестовый запрос
func (vc *VerificationClient) MakeRequest(ctx context.Context, req TestRequest) (*TestResponse, error) {
	startTime := time.Now()

	// Создаем HTTP запрос
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Устанавливаем заголовки
	httpReq.Header.Set("User-Agent", vc.config.UserAgent)
	for k, v := range req.Headers {
		// Копируем только безопасные заголовки
		if vc.isSafeHeader(k) {
			httpReq.Header.Set(k, v)
		}
	}

	// Выполняем запрос
	httpResp, err := vc.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer httpResp.Body.Close()

	// Читаем тело с ограничением в 1KB
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, 1024))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	// Собираем заголовки (только безопасные)
	headers := make(map[string]string)
	for k, v := range httpResp.Header {
		if vc.isSafeHeader(k) && len(v) > 0 {
			headers[k] = v[0]
		}
	}

	return &TestResponse{
		URL:          req.URL,
		StatusCode:   httpResp.StatusCode,
		ResponseSize: len(body),
		ResponseBody: string(body),
		Headers:      headers,
		Duration:     time.Since(startTime),
	}, nil
}

// isSafeHeader проверяет, безопасен ли заголовок
func (vc *VerificationClient) isSafeHeader(name string) bool {
	safeHeaders := []string{
		"User-Agent",
		"Accept",
		"Accept-Language",
		"Accept-Encoding",
		"Content-Type",
		"Content-Length",
		"Referer",
		"Origin",
		"Cache-Control",
	}

	lower := strings.ToLower(name)
	for _, safe := range safeHeaders {
		if strings.EqualFold(lower, safe) {
			return true
		}
	}
	return false
}