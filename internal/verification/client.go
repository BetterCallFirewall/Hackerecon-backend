package verification

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/BetterCallFirewall/Hackerecon/internal/models"
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
func (vc *VerificationClient) MakeRequest(ctx context.Context, req models.TestRequest) (*TestResponse, error) {
	startTime := time.Now()

	// Создаем HTTP запрос
	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bodyReader)
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

// ExecuteTestRequest выполняет тестовый запрос из models.TestRequest
func (vc *VerificationClient) ExecuteTestRequest(ctx context.Context, testReq models.TestRequest) (*models.TestResult, error) {
	startTime := time.Now()

	// Создаем HTTP запрос
	var bodyReader io.Reader
	if testReq.Body != "" {
		bodyReader = strings.NewReader(testReq.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, testReq.Method, testReq.URL, bodyReader)
	if err != nil {
		return &models.TestResult{
			Error: fmt.Sprintf("creating request: %v", err),
		}, err
	}

	// Устанавливаем заголовки
	httpReq.Header.Set("User-Agent", vc.config.UserAgent)
	for k, v := range testReq.Headers {
		if vc.isSafeHeader(k) {
			httpReq.Header.Set(k, v)
		}
	}

	// Выполняем запрос
	httpResp, err := vc.httpClient.Do(httpReq)
	if err != nil {
		return &models.TestResult{
			Error: fmt.Sprintf("executing request: %v", err),
		}, err
	}
	defer httpResp.Body.Close()

	// Читаем тело с ограничением в 5KB для анализа
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, 5*1024))
	if err != nil {
		return &models.TestResult{
			StatusCode: httpResp.StatusCode,
			Error:      fmt.Sprintf("reading response body: %v", err),
		}, err
	}

	// Собираем заголовки
	headers := make(map[string]string)
	for k, v := range httpResp.Header {
		if vc.isSafeHeader(k) && len(v) > 0 {
			headers[k] = v[0]
		}
	}

	return &models.TestResult{
		StatusCode:   httpResp.StatusCode,
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
		// CRITICAL: Разрешаем Cookie и Authorization для тестирования JWT/session-based атак
		"Cookie",
		"Authorization",
		// Разрешаем custom headers для CSRF и auth тестов
		"X-CSRF-Token",
		"X-Requested-With",
	}

	lower := strings.ToLower(name)
	for _, safe := range safeHeaders {
		if strings.EqualFold(lower, safe) {
			return true
		}
	}
	return false
}
