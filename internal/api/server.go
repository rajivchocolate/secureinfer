package api

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"time"

	"github.com/rajivchocolate/secureinfer/internal/config"
	"github.com/rajivchocolate/secureinfer/internal/inference"
	"github.com/rajivchocolate/secureinfer/internal/security"
	"github.com/rajivchocolate/secureinfer/internal/store"
)

// Server holds all dependencies for the HTTP server.
type Server struct {
	cfg      *config.Config
	db       *store.SQLite
	cache    store.Cache
	ollama   *inference.OllamaClient
	security *security.Service
}

// NewServer creates a new API server.
func NewServer(
	cfg *config.Config,
	db *store.SQLite,
	cache store.Cache,
	ollama *inference.OllamaClient,
	security *security.Service,
) *Server {
	return &Server{
		cfg:      cfg,
		db:       db,
		cache:    cache,
		ollama:   ollama,
		security: security,
	}
}

// Router returns the configured Chi router.
func (s *Server) Router() *chi.Mux {
	r := chi.NewRouter()

	// Base middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(s.loggingMiddleware)

	// Rate limiting (per IP for now, per API key in auth middleware)
	r.Use(httprate.Limit(
		s.cfg.RateLimitRPM,
		time.Minute,
		httprate.WithKeyFuncs(httprate.KeyByIP),
		httprate.WithLimitHandler(rateLimitExceeded),
	))

	// Health check (no auth)
	r.Get("/health", s.handleHealth)
	r.Get("/", s.handleRoot)

	// Metrics (no auth in dev, secured in prod)
	if s.cfg.MetricsEnabled {
		r.Handle("/metrics", promhttp.Handler())
	}

	// API routes (authenticated)
	r.Route("/v1", func(r chi.Router) {
		r.Use(s.authMiddleware)
		r.Use(s.securityMiddleware)

		// Chat completions (OpenAI-compatible)
		r.Post("/chat/completions", s.handleChatCompletions)

		// Security endpoints
		r.Route("/security", func(r chi.Router) {
			r.Get("/risk/{tenant_id}", s.handleGetRiskScore)
			r.Get("/events", s.handleGetSecurityEvents)
			r.Post("/verify-model", s.handleVerifyModel)
		})

		// Tenant management
		r.Route("/tenants", func(r chi.Router) {
			r.Post("/", s.handleCreateTenant)
			r.Get("/{tenant_id}", s.handleGetTenant)
			r.Delete("/{tenant_id}/context", s.handleClearContext)
		})
	})

	return r
}
