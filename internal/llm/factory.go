package llm

import (
	"fmt"

	"github.com/firebase/genkit/go/genkit"
)

// ProviderType - тип провайдера
type ProviderType string

const (
	ProviderTypeGemini  ProviderType = "gemini"
	ProviderTypeGeneric ProviderType = "generic"
)

// ProviderConfig - универсальная конфигурация для создания провайдера
type ProviderConfig struct {
	// Type - тип провайдера ("gemini" или "generic")
	Type ProviderType

	// --- Для Gemini ---
	GenkitApp *genkit.Genkit
	Model     string // "gemini-1.5-pro", "gemini-1.5-flash", etc.

	// --- Для Generic провайдера ---
	Name    string    // Название (для логирования)
	BaseURL string    // Базовый URL API
	APIKey  string    // API ключ (опционально)
	Format  APIFormat // Формат API ("openai", "ollama", "raw")
}

// NewProvider создаёт провайдер на основе конфигурации
func NewProvider(cfg ProviderConfig) (Provider, error) {
	switch cfg.Type {
	case ProviderTypeGemini:
		if cfg.GenkitApp == nil {
			return nil, fmt.Errorf("gemini provider requires GenkitApp")
		}
		if cfg.Model == "" {
			cfg.Model = "gemini-1.5-pro" // Default
		}
		return NewGeminiProvider(cfg.GenkitApp, cfg.Model), nil

	case ProviderTypeGeneric:
		if cfg.BaseURL == "" {
			return nil, fmt.Errorf("generic provider requires BaseURL")
		}
		return NewGenericProvider(GenericConfig{
			Name:    cfg.Name,
			Model:   cfg.Model,
			BaseURL: cfg.BaseURL,
			APIKey:  cfg.APIKey,
			Format:  cfg.Format,
		}), nil

	default:
		return nil, fmt.Errorf("unknown provider type: %s", cfg.Type)
	}
}

// Примеры использования для документации:

// NewOllamaProvider - helper для создания Ollama провайдера
// Пример:
//
//	provider := llm.NewOllamaProvider("http://localhost:11434", "llama3.1:8b")
func NewOllamaProvider(baseURL, model string) Provider {
	name := fmt.Sprintf("ollama-%s", model)
	return NewGenericProvider(GenericConfig{
		Name:    name,
		Model:   model,
		BaseURL: baseURL,
		Format:  FormatOllama,
	})
}

// NewLocalAIProvider - helper для создания LocalAI провайдера
// Пример:
//
//	provider := llm.NewLocalAIProvider("http://localhost:8080", "gpt-4")
func NewLocalAIProvider(baseURL, model string) Provider {
	return NewGenericProvider(GenericConfig{
		Name:    "localai",
		Model:   model,
		BaseURL: baseURL,
		Format:  FormatOpenAI,
	})
}

// NewLMStudioProvider - helper для создания LM Studio провайдера
// Пример:
//
//	provider := llm.NewLMStudioProvider("http://localhost:1234", "llama-3.2-3b")
func NewLMStudioProvider(baseURL, model string) Provider {
	return NewGenericProvider(GenericConfig{
		Name:    "lm-studio",
		Model:   model,
		BaseURL: baseURL,
		Format:  FormatOpenAI,
	})
}
