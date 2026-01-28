package api

import (
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/rajivchocolate/secureinfer/internal/config"
	"github.com/rajivchocolate/secureinfer/internal/inference"
	"github.com/rajivchocolate/secureinfer/internal/security"
	"github.com/rajivchocolate/secureinfer/internal/store"
)

// Server holds all dependencies for the HTTP server.
type Server struct {
	cfg           *config.Config
	db            *store.SQLite
	cache         store.Cache
	ollama        *inference.OllamaClient
	security      *security.Service
	ipRateLimiter *IPRateLimiter
	limits        RequestLimits
}

// NewServer creates a new API server with production defaults.
func NewServer(
	cfg *config.Config,
	db *store.SQLite,
	cache store.Cache,
	ollama *inference.OllamaClient,
	security *security.Service,
) *Server {
	return &Server{
		cfg:           cfg,
		db:            db,
		cache:         cache,
		ollama:        ollama,
		security:      security,
		ipRateLimiter: NewIPRateLimiter(100, time.Minute), // 100 req/min per IP
		limits:        DefaultLimits(),
	}
}

// Router returns the configured Chi router with production middleware stack.
func (s *Server) Router() *chi.Mux {
	r := chi.NewRouter()

	// =================================================================
	// LAYER 1: Foundation middleware (runs on every request)
	// =================================================================

	// Panic recovery - catches panics and returns 500
	r.Use(s.panicRecoveryMiddleware)

	// Request ID for tracing
	r.Use(middleware.RequestID)
	r.Use(s.requestIDMiddleware)

	// Security headers on all responses
	r.Use(s.securityHeadersMiddleware)

	// CORS handling
	r.Use(s.corsMiddleware)

	// Real IP extraction (needed for rate limiting)
	r.Use(middleware.RealIP)

	// Request logging
	r.Use(s.loggingMiddleware)

	// =================================================================
	// LAYER 2: Rate limiting (before body parsing)
	// =================================================================

	// IP-based rate limiting (defense against abuse before auth)
	r.Use(s.ipRateLimitMiddleware(s.ipRateLimiter))

	// Request body size limit
	r.Use(s.requestSizeLimitMiddleware(s.limits.MaxBodySize))

	// Per-tenant rate limiting (uses httprate for token bucket)
	r.Use(httprate.Limit(
		s.cfg.RateLimitRPM,
		time.Minute,
		httprate.WithKeyFuncs(httprate.KeyByIP),
		httprate.WithLimitHandler(rateLimitExceeded),
	))

	// =================================================================
	// PUBLIC ROUTES (no authentication required)
	// =================================================================

	// Health check
	r.Get("/health", s.handleHealth)

	// Root info
	r.Get("/", s.handleRoot)

	// Metrics (consider auth in production)
	if s.cfg.MetricsEnabled {
		r.Handle("/metrics", promhttp.Handler())
	}

	// =================================================================
	// AUTHENTICATED API ROUTES
	// =================================================================

	r.Route("/v1", func(r chi.Router) {
		// Authentication - validates API key, extracts tenant
		r.Use(s.authMiddleware)

		// Pre-request security checks (tenant blocks, etc.)
		r.Use(s.securityMiddleware)

		// Request timeout
		r.Use(s.timeoutMiddleware(30 * time.Second))

		// ----------------------------------------
		// Chat Completions (OpenAI-compatible)
		// ----------------------------------------
		r.Post("/chat/completions", s.handleChatCompletions)

		// ----------------------------------------
		// Security Monitoring Endpoints
		// ----------------------------------------
		r.Route("/security", func(r chi.Router) {
			// Get risk score for a tenant (own tenant only)
			r.Get("/risk/{tenant_id}", s.handleGetRiskScore)

			// Get recent security events (admin-only in production)
			r.Get("/events", s.handleGetSecurityEvents)

			// Verify model integrity
			r.Post("/verify-model", s.handleVerifyModel)
		})

		// ----------------------------------------
		// Tenant Management
		// ----------------------------------------
		r.Route("/tenants", func(r chi.Router) {
			// Create new tenant
			r.Post("/", s.handleCreateTenant)

			// Get tenant info (own tenant only)
			r.Get("/{tenant_id}", s.handleGetTenant)

			// Clear conversation context (own tenant only)
			r.Delete("/{tenant_id}/context", s.handleClearContext)
		})
	})

	return r
}

// GetLimits returns the current request limits.
func (s *Server) GetLimits() RequestLimits {
	return s.limits
}

// SetLimits updates the request limits.
func (s *Server) SetLimits(limits RequestLimits) {
	s.limits = limits
}
