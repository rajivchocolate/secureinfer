package security

import (
	"context"
	"sync"

	"github.com/rajivchocolate/secureinfer/internal/store"
)

// Action represents the security decision.
type Action int

const (
	ActionAllow Action = iota
	ActionWarn
	ActionBlock
)

// Message represents a chat message for security analysis.
type Message struct {
	Role    string
	Content string
}

// RequestContext contains all info needed for security checks.
type RequestContext struct {
	TenantID  string
	Message   string    // Latest user message
	Messages  []Message // Full conversation
	IP        string
	UserAgent string
}

// PreRequestCheck contains info for pre-request validation.
type PreRequestCheck struct {
	TenantID  string
	IP        string
	UserAgent string
	Path      string
	Method    string
}

// CheckResult is the result of security checks.
type CheckResult struct {
	Action    Action
	RiskScore int
	Reasons   []string
	Flags     map[string]bool
}

// Service orchestrates all security components.
type Service struct {
	mu sync.RWMutex

	riskScorer   *RiskScorer
	extraction   *ExtractionDetector
	tenant       *TenantIsolator
	verifier     *ModelVerifier
	store        store.Cache

	// Configuration
	warnThreshold  int
	blockThreshold int
}

// Option configures the security service.
type Option func(*Service)

// NewService creates a new security service.
func NewService(opts ...Option) *Service {
	s := &Service{
		warnThreshold:  50,
		blockThreshold: 80,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// WithRiskScorer configures the risk scorer.
func WithRiskScorer(warn, block int) Option {
	return func(s *Service) {
		s.riskScorer = NewRiskScorer()
		s.warnThreshold = warn
		s.blockThreshold = block
	}
}

// WithExtractionDetector configures extraction detection.
func WithExtractionDetector(window interface{}, maxSimilar int, threshold float64) Option {
	return func(s *Service) {
		s.extraction = NewExtractionDetector(maxSimilar, threshold)
	}
}

// WithTenantIsolator configures tenant isolation.
func WithTenantIsolator() Option {
	return func(s *Service) {
		s.tenant = NewTenantIsolator()
	}
}

// WithModelVerifier configures model verification.
func WithModelVerifier(expectedHash string) Option {
	return func(s *Service) {
		s.verifier = NewModelVerifier(expectedHash)
	}
}

// WithStore sets the cache store.
func WithStore(cache store.Cache) Option {
	return func(s *Service) {
		s.store = cache
	}
}

// Check runs all security checks on a request.
func (s *Service) Check(ctx context.Context, req *RequestContext) (*CheckResult, error) {
	result := &CheckResult{
		Action: ActionAllow,
		Flags:  make(map[string]bool),
	}

	var totalScore int
	var reasons []string

	// 1. Risk scoring based on message content
	if s.riskScorer != nil {
		score, riskReasons := s.riskScorer.Score(ctx, req)
		totalScore += score
		reasons = append(reasons, riskReasons...)

		// Set flags for specific risks
		for _, r := range riskReasons {
			result.Flags[r] = true
		}
	}

	// 2. Extraction detection
	if s.extraction != nil {
		isExtraction, extractionScore, extractionReasons := s.extraction.Check(ctx, req, s.store)
		if isExtraction {
			totalScore += extractionScore
			reasons = append(reasons, extractionReasons...)
			result.Flags["extraction_attempt"] = true
		}
	}

	// 3. Tenant isolation check
	if s.tenant != nil {
		violation, tenantReasons := s.tenant.CheckViolation(ctx, req)
		if violation {
			totalScore += 30
			reasons = append(reasons, tenantReasons...)
			result.Flags["tenant_violation"] = true
		}
	}

	result.RiskScore = min(totalScore, 100)
	result.Reasons = reasons

	// Determine action based on score
	switch {
	case result.RiskScore >= s.blockThreshold:
		result.Action = ActionBlock
	case result.RiskScore >= s.warnThreshold:
		result.Action = ActionWarn
	default:
		result.Action = ActionAllow
	}

	// Record the check result
	if s.store != nil {
		s.recordCheck(ctx, req, result)
	}

	return result, nil
}

// PreCheck performs pre-request validation (before body is parsed).
func (s *Service) PreCheck(ctx context.Context, check *PreRequestCheck) (blocked bool, reason string) {
	// Check if tenant is blocked
	if s.store != nil {
		blocked, _ := s.store.Get(ctx, "blocked:"+check.TenantID)
		if blocked != "" {
			return true, "tenant blocked due to security violations"
		}
	}

	// Check IP reputation (in production, use external service)
	// This is a placeholder for learning

	return false, ""
}

// GetRiskScore returns the current risk score for a tenant.
func (s *Service) GetRiskScore(ctx context.Context, tenantID string) (int, map[string]int) {
	if s.riskScorer == nil || s.store == nil {
		return 0, nil
	}

	return s.riskScorer.GetTenantScore(ctx, tenantID, s.store)
}

// GetIsolatedContext returns tenant-isolated conversation context.
func (s *Service) GetIsolatedContext(ctx context.Context, tenantID string, messages []interface{}) []interface{} {
	if s.tenant == nil {
		return messages
	}
	return s.tenant.GetContext(ctx, tenantID, messages, s.store)
}

// StoreContext stores conversation context for a tenant.
func (s *Service) StoreContext(ctx context.Context, tenantID string, messages []interface{}, response string) {
	if s.tenant != nil && s.store != nil {
		s.tenant.StoreContext(ctx, tenantID, messages, response, s.store)
	}
}

// ClearContext clears conversation context for a tenant.
func (s *Service) ClearContext(ctx context.Context, tenantID string) error {
	if s.tenant != nil && s.store != nil {
		return s.tenant.ClearContext(ctx, tenantID, s.store)
	}
	return nil
}

// VerifyModel checks model integrity.
func (s *Service) VerifyModel(ctx context.Context) (*VerificationResult, error) {
	if s.verifier == nil {
		return &VerificationResult{Valid: true, Message: "verification not configured"}, nil
	}
	return s.verifier.Verify(ctx)
}

// GetRecentEvents returns recent security events.
func (s *Service) GetRecentEvents(ctx context.Context, limit int) ([]SecurityEvent, error) {
	// In production, fetch from database
	// For now, return from memory/cache
	return []SecurityEvent{}, nil
}

// recordCheck records a security check for auditing.
func (s *Service) recordCheck(ctx context.Context, req *RequestContext, result *CheckResult) {
	// Increment request counter for tenant
	s.store.Incr(ctx, "requests:"+req.TenantID)

	// Record high-risk events
	if result.RiskScore >= s.warnThreshold {
		// In production, write to database
		// For learning, just increment a counter
		s.store.Incr(ctx, "warnings:"+req.TenantID)
	}

	// Auto-block after too many violations
	if result.Action == ActionBlock {
		violations, _ := s.store.Incr(ctx, "violations:"+req.TenantID)
		if violations > 10 {
			s.store.Set(ctx, "blocked:"+req.TenantID, "auto-blocked", 3600) // 1 hour
		}
	}
}

// SecurityEvent represents a security event for logging.
type SecurityEvent struct {
	Timestamp string                 `json:"timestamp"`
	TenantID  string                 `json:"tenant_id"`
	Type      string                 `json:"type"`
	RiskScore int                    `json:"risk_score"`
	Action    string                 `json:"action"`
	Details   map[string]interface{} `json:"details"`
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
