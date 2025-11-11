package config

import (
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	Proxy ProxyConfig `yaml:"proxy"`
	Web   WebConfig   `yaml:"web"`
	Cert  CertConfig  `yaml:"cert"`
	LLM   LLMConfig   `yaml:"llm"`
}

type LLMConfig struct {
	// Общие настройки
	Provider string `yaml:"provider"` // "gemini" или "generic"
	Model    string `yaml:"model"`
	ApiKey   string `yaml:"apiKey"`

	// Для Generic провайдера
	BaseURL string `yaml:"baseUrl"` // Базовый URL API
	Format  string `yaml:"format"`  // "openai", "ollama", "raw"

	// Старые поля (для совместимости)
	URL      string `yaml:"url"`
	Port     string `yaml:"port"`
	BurpHost string `yaml:"burpHost"`
	BurpPort string `yaml:"burpPort"`
}

type ProxyConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

type WebConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

type CertConfig struct {
	CertFile string `yaml:"cert_file"`
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
		Proxy: ProxyConfig{
			ListenAddr: os.Getenv("PROXY_LISTEN_ADDR"),
		},
		Web: WebConfig{
			ListenAddr: os.Getenv("WEB_LISTEN_ADDR"),
		},
		Cert: CertConfig{
			CertFile: os.Getenv("PROXY_CERT_FILE"),
		},
		LLM: LLMConfig{
			Provider: getEnvOrDefault("LLM_PROVIDER", "gemini"), // Default: gemini
			Model:    os.Getenv("LLM_MODEL"),
			ApiKey:   os.Getenv("API_KEY"),
			BaseURL:  os.Getenv("LLM_BASE_URL"),
			Format:   getEnvOrDefault("LLM_FORMAT", "openai"),

			// Старые поля
			URL:      os.Getenv("LLM_URL"),
			Port:     os.Getenv("PORT"),
			BurpHost: os.Getenv("BURP_HOST"),
			BurpPort: os.Getenv("BURP_PORT"),
		},
	}, nil
}
