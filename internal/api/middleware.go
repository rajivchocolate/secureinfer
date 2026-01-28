package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog/log"

	"github.com/rajivchocolate/secureinfer/internal/security"
)

type contextKey string

const (
	tenantIDKey contextKey = "tenant_id"
	apiKeyKey   contextKey = "api_key"
)

// loggingMiddleware logs request details.
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		defer func() {
			log.Info().
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Int("status", ww.Status()).
				Int("bytes", ww.BytesWritten()).
				Dur("duration", time.Since(start)).
				Str("ip", getIP(r)).
				Str("request_id", middleware.GetReqID(r.Context())).
				Msg("Request")
		}()

		next.ServeHTTP(ww, r)
	})
}

// authMiddleware validates API keys and extracts tenant ID.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeError(w, http.StatusUnauthorized, "missing authorization header")
			return
		}

		// Expect "Bearer <api_key>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			writeError(w, http.StatusUnauthorized, "invalid authorization format")
			return
		}

		apiKey := parts[1]

		// Validate API key and get tenant
		tenant, err := s.db.ValidateAPIKey(r.Context(), apiKey)
		if err != nil {
			log.Warn().
				Str("ip", getIP(r)).
				Msg("Invalid API key attempt")
			writeError(w, http.StatusUnauthorized, "invalid api key")
			return
		}

		// Add tenant to context
		ctx := context.WithValue(r.Context(), tenantIDKey, tenant.ID)
		ctx = context.WithValue(ctx, apiKeyKey, apiKey)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// securityMiddleware runs security checks on each request.
func (s *Server) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		tenantID := getTenantID(ctx)

		// Pre-request security check (rate limiting already done)
		preCheck := &security.PreRequestCheck{
			TenantID:  tenantID,
			IP:        getIP(r),
			UserAgent: r.UserAgent(),
			Path:      r.URL.Path,
			Method:    r.Method,
		}

		if blocked, reason := s.security.PreCheck(ctx, preCheck); blocked {
			log.Warn().
				Str("tenant", tenantID).
				Str("reason", reason).
				Msg("Request pre-blocked")
			writeError(w, http.StatusForbidden, reason)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// rateLimitExceeded handles rate limit exceeded responses.
func rateLimitExceeded(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
}

// getTenantID extracts tenant ID from context.
func getTenantID(ctx context.Context) string {
	if id, ok := ctx.Value(tenantIDKey).(string); ok {
		return id
	}
	return ""
}

// getIP extracts client IP from request.
func getIP(r *http.Request) string {
	// Check X-Forwarded-For first (for proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fall back to RemoteAddr
	return strings.Split(r.RemoteAddr, ":")[0]
}
