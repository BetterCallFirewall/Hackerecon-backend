package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Proxy ProxyConfig `yaml:"proxy"`
	Web   WebConfig   `yaml:"web"`
}

type ProxyConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

type WebConfig struct {
	ListenAddr string `yaml:"listen_addr"`
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

	return &cfg, nil
}
