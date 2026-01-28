package config

import (
	"time"

	"github.com/caarlos0/env/v10"
)

// Config holds all application configuration.
type Config struct {
	// Server
	Env      string `env:"SECUREINFER_ENV" envDefault:"development"`
	Host     string `env:"API_HOST" envDefault:"0.0.0.0"`
	Port     int    `env:"API_PORT" envDefault:"8000"`
	LogLevel string `env:"LOG_LEVEL" envDefault:"info"`

	// Database
	DatabaseURL string `env:"DATABASE_URL" envDefault:"./data/secureinfer.db"`

	// Redis
	RedisURL string `env:"REDIS_URL" envDefault:"redis://localhost:6379/0"`

	// Ollama
	OllamaURL string `env:"OLLAMA_URL" envDefault:"http://localhost:11434"`
	ModelName string `env:"MODEL_NAME" envDefault:"phi3.5:3.8b-mini-instruct-q4_K_M"`

	// Security - Risk Scoring
	RiskThresholdWarn  int `env:"RISK_THRESHOLD_WARN" envDefault:"50"`
	RiskThresholdBlock int `env:"RISK_THRESHOLD_BLOCK" envDefault:"80"`

	// Security - Rate Limiting
	RateLimitRPM   int `env:"RATE_LIMIT_RPM" envDefault:"60"`
	RateLimitBurst int `env:"RATE_LIMIT_BURST" envDefault:"10"`

	// Security - Extraction Detection
	ExtractionWindow          time.Duration `env:"EXTRACTION_WINDOW" envDefault:"1h"`
	ExtractionMaxSimilar      int           `env:"EXTRACTION_MAX_SIMILAR" envDefault:"20"`
	ExtractionSimilarityThreshold float64   `env:"EXTRACTION_SIMILARITY_THRESHOLD" envDefault:"0.85"`

	// Security - Model Verification
	ModelExpectedHash string `env:"MODEL_EXPECTED_HASH" envDefault:""`

	// Observability
	MetricsEnabled bool `env:"METRICS_ENABLED" envDefault:"true"`
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// MustLoad loads config or panics.
func MustLoad() *Config {
	cfg, err := Load()
	if err != nil {
		panic("failed to load config: " + err.Error())
	}
	return cfg
}
