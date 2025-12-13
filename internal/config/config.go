package config

import (
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	LLM LLMConfig `yaml:"llm"`
}

type LLMConfig struct {
	// Общие настройки
	Provider string `yaml:"provider"` // "gemini" или "generic"
	Model    string `yaml:"model"`
	ApiKey   string `yaml:"apiKey"`

	// Для Generic провайдера
	BaseURL string `yaml:"baseUrl"` // Базовый URL API
	Format  string `yaml:"format"`  // "openai", "ollama", "raw"

	Port     string `yaml:"port"`
	BurpHost string `yaml:"burpHost"`
	BurpPort string `yaml:"burpPort"`
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func Load() (*Config, error) {
	err := godotenv.Load()
	if err != nil {
		return nil, err
	}
	return &Config{
		LLM: LLMConfig{
			Provider: getEnvOrDefault("LLM_PROVIDER", "gemini"),
			Model:    os.Getenv("LLM_MODEL"),
			ApiKey:   os.Getenv("API_KEY"),
			BaseURL:  os.Getenv("LLM_BASE_URL"),
			Format:   getEnvOrDefault("LLM_FORMAT", "openai"),
			Port:     os.Getenv("PORT"),
			BurpHost: os.Getenv("BURP_HOST"),
			BurpPort: os.Getenv("BURP_PORT"),
		},
	}, nil
}
