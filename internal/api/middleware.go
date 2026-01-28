package api

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog/log"

	"github.com/rajivchocolate/secureinfer/internal/security"
)

type contextKey string

const (
	tenantIDKey   contextKey = "tenant_id"
	apiKeyKey     contextKey = "api_key"
	requestIDKey  contextKey = "request_id"
	requestStart  contextKey = "request_start"
)

// RequestLimits defines limits for incoming requests.
type RequestLimits struct {
	MaxBodySize       int64 // Maximum request body size in bytes
	MaxPromptLength   int   // Maximum prompt/message length in characters
	MaxMessages       int   // Maximum messages in conversation
	MaxTokensPerReq   int   // Maximum tokens requested per request
}

// DefaultLimits returns production-safe default limits.
func DefaultLimits() RequestLimits {
	return RequestLimits{
		MaxBodySize:       1 * 1024 * 1024,  // 1MB
		MaxPromptLength:   32000,             // 32K characters
		MaxMessages:       100,               // 100 messages per conversation
		MaxTokensPerReq:   4096,              // 4K tokens max response
	}
}

// securityHeadersMiddleware adds production security headers.
func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		// Enable XSS filter
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Strict Transport Security (HSTS) - enforce HTTPS
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// Content Security Policy - restrict resource loading
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

		// Referrer policy - don't leak referrer
		w.Header().Set("Referrer-Policy", "no-referrer")

		// Permissions policy - disable unnecessary features
		w.Header().Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")

		// Prevent caching of sensitive API responses
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		next.ServeHTTP(w, r)
	})
}

// requestSizeLimitMiddleware enforces request body size limits.
func (s *Server) requestSizeLimitMiddleware(maxSize int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > maxSize {
				writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
				return
			}

			// Wrap body with size limit reader
			r.Body = &limitedReader{
				reader:    r.Body,
				remaining: maxSize,
			}

			next.ServeHTTP(w, r)
		})
	}
}

// limitedReader wraps io.ReadCloser with a size limit.
type limitedReader struct {
	reader    io.ReadCloser
	remaining int64
}

func (lr *limitedReader) Read(p []byte) (int, error) {
	if lr.remaining <= 0 {
		return 0, &http.MaxBytesError{Limit: lr.remaining}
	}

	if int64(len(p)) > lr.remaining {
		p = p[:lr.remaining]
	}

	n, err := lr.reader.Read(p)
	lr.remaining -= int64(n)
	return n, err
}

func (lr *limitedReader) Close() error {
	return lr.reader.Close()
}

// loggingMiddleware logs request details with timing.
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		// Add request start time to context
		ctx := context.WithValue(r.Context(), requestStart, start)
		r = r.WithContext(ctx)

		defer func() {
			duration := time.Since(start)
			tenantID := getTenantID(r.Context())

			logEvent := log.Info()

			// Warn on slow requests
			if duration > 5*time.Second {
				logEvent = log.Warn()
			}

			logEvent.
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Int("status", ww.Status()).
				Int("bytes", ww.BytesWritten()).
				Dur("duration", duration).
				Str("ip", getIP(r)).
				Str("tenant", tenantID).
				Str("request_id", middleware.GetReqID(r.Context())).
				Str("user_agent", sanitizeUserAgent(r.UserAgent())).
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

		// Validate API key format before DB lookup
		if !isValidAPIKeyFormat(apiKey) {
			log.Warn().
				Str("ip", getIP(r)).
				Msg("Malformed API key attempt")
			writeError(w, http.StatusUnauthorized, "invalid api key")
			return
		}

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

		// Pre-request security check
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
				Str("ip", getIP(r)).
				Msg("Request pre-blocked")
			writeError(w, http.StatusForbidden, reason)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// IPRateLimiter provides per-IP rate limiting.
type IPRateLimiter struct {
	mu       sync.RWMutex
	requests map[string]*rateLimitEntry
	limit    int
	window   time.Duration
}

type rateLimitEntry struct {
	count    int
	resetAt  time.Time
}

// NewIPRateLimiter creates a new IP-based rate limiter.
func NewIPRateLimiter(limit int, window time.Duration) *IPRateLimiter {
	rl := &IPRateLimiter{
		requests: make(map[string]*rateLimitEntry),
		limit:    limit,
		window:   window,
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

func (rl *IPRateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	entry, exists := rl.requests[ip]

	if !exists || now.After(entry.resetAt) {
		rl.requests[ip] = &rateLimitEntry{
			count:   1,
			resetAt: now.Add(rl.window),
		}
		return true
	}

	if entry.count >= rl.limit {
		return false
	}

	entry.count++
	return true
}

func (rl *IPRateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, entry := range rl.requests {
			if now.After(entry.resetAt) {
				delete(rl.requests, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// ipRateLimitMiddleware applies per-IP rate limiting.
func (s *Server) ipRateLimitMiddleware(limiter *IPRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := getIP(r)

			if !limiter.Allow(ip) {
				log.Warn().
					Str("ip", ip).
					Msg("IP rate limit exceeded")
				writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// timeoutMiddleware adds request timeout.
func (s *Server) timeoutMiddleware(timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			r = r.WithContext(ctx)

			done := make(chan struct{})
			go func() {
				next.ServeHTTP(w, r)
				close(done)
			}()

			select {
			case <-done:
				return
			case <-ctx.Done():
				writeError(w, http.StatusGatewayTimeout, "request timeout")
				return
			}
		})
	}
}

// panicRecoveryMiddleware recovers from panics and logs them.
func (s *Server) panicRecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Error().
					Interface("panic", err).
					Str("path", r.URL.Path).
					Str("method", r.Method).
					Msg("Panic recovered")

				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()

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

// getIP extracts client IP from request with security considerations.
func getIP(r *http.Request) string {
	// Note: X-Forwarded-For can be spoofed if not properly configured
	// In production, only trust these headers from known load balancers/proxies

	// Check X-Forwarded-For first (for proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP (original client)
		parts := strings.Split(xff, ",")
		ip := strings.TrimSpace(parts[0])
		if isValidIP(ip) {
			return ip
		}
	}

	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if isValidIP(xri) {
			return xri
		}
	}

	// Fall back to RemoteAddr
	addr := r.RemoteAddr
	// Handle IPv6 addresses with port
	if strings.Contains(addr, "[") {
		// IPv6: [::1]:8080
		if idx := strings.LastIndex(addr, "]:"); idx != -1 {
			return addr[1:idx]
		}
	}
	// IPv4: 127.0.0.1:8080
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

// isValidIP validates IP address format.
func isValidIP(ip string) bool {
	// Basic validation - not empty and reasonable length
	if len(ip) == 0 || len(ip) > 45 { // Max IPv6 length
		return false
	}
	// Check for obviously invalid characters
	for _, c := range ip {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '.' || c == ':') {
			return false
		}
	}
	return true
}

// isValidAPIKeyFormat validates API key format before DB lookup.
func isValidAPIKeyFormat(key string) bool {
	// API keys should be 32-64 characters, alphanumeric with dashes
	if len(key) < 32 || len(key) > 64 {
		return false
	}
	for _, c := range key {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// sanitizeUserAgent sanitizes user agent for logging.
func sanitizeUserAgent(ua string) string {
	// Truncate and remove control characters
	if len(ua) > 200 {
		ua = ua[:200]
	}

	var sanitized strings.Builder
	for _, r := range ua {
		if r >= 32 && r < 127 { // Printable ASCII only
			sanitized.WriteRune(r)
		}
	}
	return sanitized.String()
}

// corsMiddleware adds CORS headers for API access.
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only allow specific origins in production
		// For development, can use more permissive settings
		origin := r.Header.Get("Origin")

		// In production, validate against allowed origins list
		allowedOrigins := []string{
			"http://localhost:3000",
			"http://localhost:8080",
		}

		allowed := false
		for _, ao := range allowedOrigins {
			if origin == ao {
				allowed = true
				break
			}
		}

		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-Request-ID")
		w.Header().Set("Access-Control-Max-Age", "86400")

		// Handle preflight
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// requestIDMiddleware ensures every request has a unique ID.
func (s *Server) requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = middleware.GetReqID(r.Context())
		}

		// Add to response headers for correlation
		w.Header().Set("X-Request-ID", requestID)

		ctx := context.WithValue(r.Context(), requestIDKey, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
