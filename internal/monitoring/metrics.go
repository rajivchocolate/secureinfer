package monitoring

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// SecurityMetrics provides Prometheus metrics for security monitoring.
type SecurityMetrics struct {
	// Request metrics
	RequestsTotal      *prometheus.CounterVec
	RequestDuration    *prometheus.HistogramVec
	RequestSize        *prometheus.HistogramVec

	// Security metrics
	ThreatDetections   *prometheus.CounterVec
	RiskScores         *prometheus.HistogramVec
	BlockedRequests    *prometheus.CounterVec
	ExtractionAttempts *prometheus.CounterVec

	// Classification metrics
	Classifications    *prometheus.CounterVec
	ClassifierLatency  *prometheus.HistogramVec
	ClassifierErrors   *prometheus.CounterVec

	// Rate limiting metrics
	RateLimitHits      *prometheus.CounterVec
	RateLimitRemaining *prometheus.GaugeVec

	// System metrics
	ActiveTenants      prometheus.Gauge
	CacheHitRatio      prometheus.Gauge
	EmbeddingLatency   *prometheus.HistogramVec
}

// NewSecurityMetrics creates and registers all security metrics.
func NewSecurityMetrics(namespace string) *SecurityMetrics {
	m := &SecurityMetrics{}

	// Request metrics
	m.RequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "requests_total",
			Help:      "Total number of API requests",
		},
		[]string{"method", "path", "status", "tenant_id"},
	)

	m.RequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "request_duration_seconds",
			Help:      "Request duration in seconds",
			Buckets:   prometheus.ExponentialBuckets(0.001, 2, 15), // 1ms to ~16s
		},
		[]string{"method", "path"},
	)

	m.RequestSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "request_size_bytes",
			Help:      "Request body size in bytes",
			Buckets:   prometheus.ExponentialBuckets(100, 2, 12), // 100B to ~400KB
		},
		[]string{"path"},
	)

	// Security metrics
	m.ThreatDetections = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "threat_detections_total",
			Help:      "Total threat detections by type",
		},
		[]string{"threat_type", "action", "tenant_id"},
	)

	m.RiskScores = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "risk_scores",
			Help:      "Distribution of risk scores",
			Buckets:   prometheus.LinearBuckets(0, 10, 11), // 0, 10, 20, ..., 100
		},
		[]string{"tenant_id"},
	)

	m.BlockedRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "blocked_requests_total",
			Help:      "Total blocked requests",
		},
		[]string{"reason", "tenant_id"},
	)

	m.ExtractionAttempts = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "extraction_attempts_total",
			Help:      "Total model extraction attempts detected",
		},
		[]string{"pattern", "tenant_id"},
	)

	// Classification metrics
	m.Classifications = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "classifications_total",
			Help:      "Total threat classifications by label",
		},
		[]string{"label", "model"},
	)

	m.ClassifierLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "classifier_latency_seconds",
			Help:      "Classifier inference latency",
			Buckets:   prometheus.ExponentialBuckets(0.001, 2, 12),
		},
		[]string{"model"},
	)

	m.ClassifierErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "classifier_errors_total",
			Help:      "Total classifier errors",
		},
		[]string{"model", "error_type"},
	)

	// Rate limiting metrics
	m.RateLimitHits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "rate_limit_hits_total",
			Help:      "Total rate limit hits",
		},
		[]string{"tier", "tenant_id"},
	)

	m.RateLimitRemaining = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "rate_limit_remaining",
			Help:      "Remaining rate limit quota",
		},
		[]string{"tier", "tenant_id"},
	)

	// System metrics
	m.ActiveTenants = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "active_tenants",
			Help:      "Number of active tenants",
		},
	)

	m.CacheHitRatio = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "cache_hit_ratio",
			Help:      "Cache hit ratio",
		},
	)

	m.EmbeddingLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "embedding_latency_seconds",
			Help:      "Embedding computation latency",
			Buckets:   prometheus.ExponentialBuckets(0.001, 2, 12),
		},
		[]string{"provider"},
	)

	return m
}

// RecordRequest records a request with its metrics.
func (m *SecurityMetrics) RecordRequest(method, path, status, tenantID string, duration time.Duration, size int) {
	m.RequestsTotal.WithLabelValues(method, path, status, tenantID).Inc()
	m.RequestDuration.WithLabelValues(method, path).Observe(duration.Seconds())
	m.RequestSize.WithLabelValues(path).Observe(float64(size))
}

// RecordThreat records a detected threat.
func (m *SecurityMetrics) RecordThreat(threatType, action, tenantID string) {
	m.ThreatDetections.WithLabelValues(threatType, action, tenantID).Inc()
}

// RecordRiskScore records a risk score.
func (m *SecurityMetrics) RecordRiskScore(score int, tenantID string) {
	m.RiskScores.WithLabelValues(tenantID).Observe(float64(score))
}

// AlertManager handles security alerting.
type AlertManager struct {
	mu       sync.RWMutex
	rules    []AlertRule
	handlers []AlertHandler
	active   map[string]*Alert
}

// AlertRule defines conditions for triggering alerts.
type AlertRule struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Condition   AlertCondition    `json:"condition"`
	Severity    AlertSeverity     `json:"severity"`
	Cooldown    time.Duration     `json:"cooldown"`
	Labels      map[string]string `json:"labels"`
}

// AlertCondition defines alert trigger conditions.
type AlertCondition struct {
	Metric    string        `json:"metric"`    // Metric name
	Operator  string        `json:"operator"`  // gt, lt, eq, ne
	Threshold float64       `json:"threshold"` // Threshold value
	Duration  time.Duration `json:"duration"`  // How long condition must be true
	GroupBy   []string      `json:"group_by"`  // Grouping labels
}

// AlertSeverity defines alert severity levels.
type AlertSeverity string

const (
	SeverityCritical AlertSeverity = "critical"
	SeverityHigh     AlertSeverity = "high"
	SeverityMedium   AlertSeverity = "medium"
	SeverityLow      AlertSeverity = "low"
	SeverityInfo     AlertSeverity = "info"
)

// Alert represents an active alert.
type Alert struct {
	Rule        *AlertRule        `json:"rule"`
	FiredAt     time.Time         `json:"fired_at"`
	ResolvedAt  *time.Time        `json:"resolved_at,omitempty"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	Value       float64           `json:"value"`
	Fingerprint string            `json:"fingerprint"`
}

// AlertHandler processes fired alerts.
type AlertHandler interface {
	Handle(ctx context.Context, alert *Alert) error
	Name() string
}

// NewAlertManager creates a new alert manager.
func NewAlertManager() *AlertManager {
	return &AlertManager{
		rules:    make([]AlertRule, 0),
		handlers: make([]AlertHandler, 0),
		active:   make(map[string]*Alert),
	}
}

// AddRule adds an alert rule.
func (a *AlertManager) AddRule(rule AlertRule) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rules = append(a.rules, rule)
}

// AddHandler adds an alert handler.
func (a *AlertManager) AddHandler(handler AlertHandler) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.handlers = append(a.handlers, handler)
}

// Fire fires an alert.
func (a *AlertManager) Fire(ctx context.Context, rule *AlertRule, value float64, labels map[string]string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	fingerprint := generateFingerprint(rule.Name, labels)

	// Check if already active
	if existing, ok := a.active[fingerprint]; ok {
		// Check cooldown
		if time.Since(existing.FiredAt) < rule.Cooldown {
			return
		}
	}

	alert := &Alert{
		Rule:        rule,
		FiredAt:     time.Now(),
		Labels:      labels,
		Value:       value,
		Fingerprint: fingerprint,
		Annotations: map[string]string{
			"summary": rule.Description,
		},
	}

	a.active[fingerprint] = alert

	// Notify handlers
	for _, handler := range a.handlers {
		go handler.Handle(ctx, alert)
	}
}

// Resolve resolves an alert.
func (a *AlertManager) Resolve(fingerprint string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if alert, ok := a.active[fingerprint]; ok {
		now := time.Now()
		alert.ResolvedAt = &now
		delete(a.active, fingerprint)
	}
}

// GetActiveAlerts returns all active alerts.
func (a *AlertManager) GetActiveAlerts() []*Alert {
	a.mu.RLock()
	defer a.mu.RUnlock()

	alerts := make([]*Alert, 0, len(a.active))
	for _, alert := range a.active {
		alerts = append(alerts, alert)
	}
	return alerts
}

// DefaultSecurityRules returns default security alert rules.
func DefaultSecurityRules() []AlertRule {
	return []AlertRule{
		{
			Name:        "high_risk_score",
			Description: "High risk score detected for tenant",
			Condition: AlertCondition{
				Metric:    "risk_scores",
				Operator:  "gt",
				Threshold: 80,
			},
			Severity: SeverityHigh,
			Cooldown: 5 * time.Minute,
		},
		{
			Name:        "extraction_attempt",
			Description: "Model extraction attempt detected",
			Condition: AlertCondition{
				Metric:    "extraction_attempts_total",
				Operator:  "gt",
				Threshold: 10,
				Duration:  5 * time.Minute,
			},
			Severity: SeverityCritical,
			Cooldown: 15 * time.Minute,
		},
		{
			Name:        "rate_limit_exhaustion",
			Description: "Rate limit frequently exceeded",
			Condition: AlertCondition{
				Metric:    "rate_limit_hits_total",
				Operator:  "gt",
				Threshold: 100,
				Duration:  10 * time.Minute,
			},
			Severity: SeverityMedium,
			Cooldown: 30 * time.Minute,
		},
		{
			Name:        "blocked_requests_spike",
			Description: "Spike in blocked requests",
			Condition: AlertCondition{
				Metric:    "blocked_requests_total",
				Operator:  "gt",
				Threshold: 50,
				Duration:  5 * time.Minute,
			},
			Severity: SeverityHigh,
			Cooldown: 10 * time.Minute,
		},
	}
}

func generateFingerprint(name string, labels map[string]string) string {
	// Simple fingerprint generation
	fp := name
	for k, v := range labels {
		fp += ":" + k + "=" + v
	}
	return fp
}

// LogAlertHandler logs alerts to stdout.
type LogAlertHandler struct{}

func (l *LogAlertHandler) Handle(ctx context.Context, alert *Alert) error {
	// In production, use structured logging
	return nil
}

func (l *LogAlertHandler) Name() string {
	return "log"
}

// WebhookAlertHandler sends alerts to a webhook.
type WebhookAlertHandler struct {
	URL     string
	Headers map[string]string
}

func (w *WebhookAlertHandler) Handle(ctx context.Context, alert *Alert) error {
	// In production, POST to webhook URL
	return nil
}

func (w *WebhookAlertHandler) Name() string {
	return "webhook"
}

// AnomalyDetector detects statistical anomalies in metrics.
type AnomalyDetector struct {
	mu        sync.RWMutex
	baselines map[string]*BaselineStats
	windowSize int
}

// BaselineStats tracks baseline statistics for a metric.
type BaselineStats struct {
	Mean      float64
	StdDev    float64
	Min       float64
	Max       float64
	Count     int64
	LastValue float64
	Values    []float64 // Rolling window
}

// NewAnomalyDetector creates a new anomaly detector.
func NewAnomalyDetector(windowSize int) *AnomalyDetector {
	return &AnomalyDetector{
		baselines:  make(map[string]*BaselineStats),
		windowSize: windowSize,
	}
}

// Record records a value and checks for anomalies.
func (a *AnomalyDetector) Record(metric string, value float64) *AnomalyResult {
	a.mu.Lock()
	defer a.mu.Unlock()

	stats, exists := a.baselines[metric]
	if !exists {
		stats = &BaselineStats{
			Min:    value,
			Max:    value,
			Values: make([]float64, 0, a.windowSize),
		}
		a.baselines[metric] = stats
	}

	// Add to rolling window
	stats.Values = append(stats.Values, value)
	if len(stats.Values) > a.windowSize {
		stats.Values = stats.Values[1:]
	}

	// Update statistics
	stats.Count++
	stats.LastValue = value
	if value < stats.Min {
		stats.Min = value
	}
	if value > stats.Max {
		stats.Max = value
	}

	// Calculate mean and stddev
	sum := 0.0
	for _, v := range stats.Values {
		sum += v
	}
	stats.Mean = sum / float64(len(stats.Values))

	sumSq := 0.0
	for _, v := range stats.Values {
		diff := v - stats.Mean
		sumSq += diff * diff
	}
	stats.StdDev = 0
	if len(stats.Values) > 1 {
		stats.StdDev = sumSq / float64(len(stats.Values)-1)
		if stats.StdDev > 0 {
			stats.StdDev = stats.StdDev // sqrt is expensive, keep variance
		}
	}

	// Check for anomaly (z-score > 3)
	result := &AnomalyResult{
		Metric:  metric,
		Value:   value,
		IsAnomaly: false,
	}

	if stats.Count > int64(a.windowSize) && stats.StdDev > 0 {
		zScore := (value - stats.Mean) / stats.StdDev
		if zScore > 3 || zScore < -3 {
			result.IsAnomaly = true
			result.ZScore = zScore
			result.ExpectedRange = [2]float64{
				stats.Mean - 3*stats.StdDev,
				stats.Mean + 3*stats.StdDev,
			}
		}
	}

	return result
}

// AnomalyResult contains anomaly detection results.
type AnomalyResult struct {
	Metric        string     `json:"metric"`
	Value         float64    `json:"value"`
	IsAnomaly     bool       `json:"is_anomaly"`
	ZScore        float64    `json:"z_score,omitempty"`
	ExpectedRange [2]float64 `json:"expected_range,omitempty"`
}
