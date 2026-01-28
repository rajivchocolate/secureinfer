package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/rajivchocolate/secureinfer/internal/api"
	"github.com/rajivchocolate/secureinfer/internal/config"
	"github.com/rajivchocolate/secureinfer/internal/inference"
	"github.com/rajivchocolate/secureinfer/internal/security"
	"github.com/rajivchocolate/secureinfer/internal/store"
)

func main() {
	// Load configuration
	cfg := config.MustLoad()

	// Setup logging
	setupLogging(cfg)

	log.Info().
		Str("env", cfg.Env).
		Int("port", cfg.Port).
		Str("model", cfg.ModelName).
		Msg("Starting SecureInfer")

	// Initialize stores
	db, err := store.NewSQLite(cfg.DatabaseURL)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to database")
	}
	defer db.Close()

	var cache store.Cache
	redisCache, err := store.NewRedis(cfg.RedisURL)
	if err != nil {
		log.Warn().Err(err).Msg("Redis unavailable, using in-memory fallback")
		cache = store.NewMemoryStore()
	} else {
		cache = redisCache
	}

	// Initialize inference client
	ollama := inference.NewOllamaClient(cfg.OllamaURL, cfg.ModelName)

	// Initialize security components
	securitySvc := security.NewService(
		security.WithRiskScorer(cfg.RiskThresholdWarn, cfg.RiskThresholdBlock),
		security.WithExtractionDetector(cfg.ExtractionWindow, cfg.ExtractionMaxSimilar, cfg.ExtractionSimilarityThreshold),
		security.WithTenantIsolator(),
		security.WithModelVerifier(cfg.ModelExpectedHash),
		security.WithStore(cache),
	)

	// Create API server
	server := api.NewServer(cfg, db, cache, ollama, securitySvc)

	// HTTP server with timeouts
	httpServer := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler:      server.Router(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second, // Longer for LLM responses
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	done := make(chan bool, 1)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		log.Info().Msg("Shutting down server...")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := httpServer.Shutdown(ctx); err != nil {
			log.Error().Err(err).Msg("Server shutdown error")
		}
		close(done)
	}()

	// Start server
	log.Info().Msgf("Server listening on %s:%d", cfg.Host, cfg.Port)
	if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal().Err(err).Msg("Server error")
	}

	<-done
	log.Info().Msg("Server stopped")
}

func setupLogging(cfg *config.Config) {
	// Parse log level
	level, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	// Pretty logging for development
	if cfg.Env == "development" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

	// Add default fields
	log.Logger = log.With().
		Str("service", "secureinfer").
		Logger()
}
