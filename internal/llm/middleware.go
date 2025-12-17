package llm

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/firebase/genkit/go/ai"
)

// NOTE: Для просмотра LLM запросов/ответов используй GenKit DevUI!
// Запусти: genkit start -- go run cmd/main.go
// Затем открой: http://localhost:4000
// Там увидишь все flow executions, traces, входные/выходные данные

// RetryMiddleware создает middleware для автоматического retry при ошибках
func RetryMiddleware(maxAttempts int, initialDelay time.Duration) ai.ModelMiddleware {
	return func(next ai.ModelFunc) ai.ModelFunc {
		return func(ctx context.Context, req *ai.ModelRequest, cb ai.ModelStreamCallback) (*ai.ModelResponse, error) {
			var lastErr error

			for attempt := 1; attempt <= maxAttempts; attempt++ {
				resp, err := next(ctx, req, cb)
				if err == nil {
					// Успех - логируем только если были retry
					if attempt > 1 {
						log.Printf("✅ LLM retry успешен на попытке %d/%d", attempt, maxAttempts)
					}
					return resp, nil
				}

				lastErr = err

				// Последняя попытка - не делаем задержку
				if attempt == maxAttempts {
					log.Printf("❌ LLM: все retry попытки исчерпаны (%d/%d): %v", attempt, maxAttempts, err)
					break
				}

				// Exponential backoff: 1s → 2s → 4s (cap at 30s)
				delay := initialDelay * time.Duration(1<<uint(attempt-1))
				if delay > 30*time.Second {
					delay = 30 * time.Second
				}

				log.Printf("⚠️ LLM ошибка на попытке %d/%d: %v. Retry через %v...",
					attempt, maxAttempts, err, delay)

				// Проверяем контекст перед ожиданием
				select {
				case <-ctx.Done():
					return nil, fmt.Errorf("context cancelled during retry: %w", ctx.Err())
				case <-time.After(delay):
					// Продолжаем retry
				}
			}

			return nil, fmt.Errorf("failed after %d attempts: %w", maxAttempts, lastErr)
		}
	}
}
