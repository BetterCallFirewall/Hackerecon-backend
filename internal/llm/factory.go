package llm

import (
	"github.com/BetterCallFirewall/Hackerecon/internal/config"
	"github.com/firebase/genkit/go/genkit"
)

// NewProvider создаёт провайдер на основе конфигурации с уже инициализированным GenkitApp
func NewProvider(genkitApp *genkit.Genkit, cfg config.LLMConfig) (Provider, error) {
	return NewSimpleProvider(genkitApp, cfg)
}
