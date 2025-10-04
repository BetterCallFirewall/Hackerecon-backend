package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Proxy ProxyConfig `yaml:"proxy"`
	Web   WebConfig   `yaml:"web"`
	LLM   LLMConfig   `yaml:"llm"`
}

type ProxyConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

type WebConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

type LLMConfig struct {
	URL   string `yaml:"url"`
	Model string `yaml:"model"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// Значения по умолчанию
	if cfg.Proxy.ListenAddr == "" {
		cfg.Proxy.ListenAddr = ":8080"
	}
	if cfg.Web.ListenAddr == "" {
		cfg.Web.ListenAddr = ":8081"
	}
	if cfg.LLM.URL == "" {
		cfg.LLM.URL = "http://localhost:11434/api/generate"
	}
	if cfg.LLM.Model == "" {
		cfg.LLM.Model = "llama2"
	}

	return &cfg, nil
}
