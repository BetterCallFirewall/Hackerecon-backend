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
	Model    string `yaml:"model"`
	URL      string `yaml:"url"`
	Port     string `yaml:"port"`
	BurpHost string `yaml:"burpHost"`
	BurpPort string `yaml:"burpPort"`
	ApiKey   string `yaml:"apiKey"`
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
			Model:    os.Getenv("LLM_MODEL"),
			URL:      os.Getenv("LLM_URL"),
			Port:     os.Getenv("PORT"),
			BurpHost: os.Getenv("BURP_HOST"),
			BurpPort: os.Getenv("BURP_PORT"),
			ApiKey:   os.Getenv("API_KEY"),
		},
	}, nil
}
