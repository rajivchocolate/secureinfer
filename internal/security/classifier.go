package security

import (
	"context"
	"encoding/json"
	"math"
	"sync"
	"time"
)

// ClassificationResult contains the output of ML-based classification.
type ClassificationResult struct {
	Label       string             `json:"label"`
	Confidence  float64            `json:"confidence"`
	Scores      map[string]float64 `json:"scores"`
	Explanation string             `json:"explanation,omitempty"`
	ModelUsed   string             `json:"model_used"`
	Latency     time.Duration      `json:"latency"`
}

// Classifier defines the interface for ML-based threat classification.
// Implementations can use:
// - Local models (ONNX, TensorFlow Lite)
// - Remote APIs (OpenAI, custom model servers)
// - Ensemble of multiple models
type Classifier interface {
	// Classify returns threat classification for input text.
	Classify(ctx context.Context, text string) (*ClassificationResult, error)

	// ClassifyBatch processes multiple texts efficiently.
	ClassifyBatch(ctx context.Context, texts []string) ([]*ClassificationResult, error)

	// Labels returns the set of possible classification labels.
	Labels() []string

	// Name returns the classifier name for logging.
	Name() string
}

// ThreatLabel defines known threat categories.
type ThreatLabel string

const (
	LabelBenign           ThreatLabel = "benign"
	LabelJailbreak        ThreatLabel = "jailbreak"
	LabelPromptInjection  ThreatLabel = "prompt_injection"
	LabelExtraction       ThreatLabel = "extraction"
	LabelExfiltration     ThreatLabel = "exfiltration"
	LabelCodeExecution    ThreatLabel = "code_execution"
	LabelSocialEngineering ThreatLabel = "social_engineering"
)

// EnsembleClassifier combines multiple classifiers for better accuracy.
type EnsembleClassifier struct {
	classifiers []Classifier
	weights     []float64
	strategy    EnsembleStrategy
}

// EnsembleStrategy defines how to combine classifier outputs.
type EnsembleStrategy int

const (
	StrategyAverage EnsembleStrategy = iota // Average probabilities
	StrategyVoting                          // Majority voting
	StrategyMax                             // Take highest confidence
)

// NewEnsembleClassifier creates an ensemble of classifiers.
func NewEnsembleClassifier(classifiers []Classifier, weights []float64, strategy EnsembleStrategy) *EnsembleClassifier {
	if weights == nil {
		weights = make([]float64, len(classifiers))
		for i := range weights {
			weights[i] = 1.0 / float64(len(classifiers))
		}
	}
	return &EnsembleClassifier{
		classifiers: classifiers,
		weights:     weights,
		strategy:    strategy,
	}
}

func (e *EnsembleClassifier) Classify(ctx context.Context, text string) (*ClassificationResult, error) {
	start := time.Now()
	results := make([]*ClassificationResult, len(e.classifiers))
	errors := make([]error, len(e.classifiers))

	var wg sync.WaitGroup
	for i, c := range e.classifiers {
		wg.Add(1)
		go func(idx int, classifier Classifier) {
			defer wg.Done()
			results[idx], errors[idx] = classifier.Classify(ctx, text)
		}(i, c)
	}
	wg.Wait()

	// Check for errors
	validResults := make([]*ClassificationResult, 0)
	validWeights := make([]float64, 0)
	for i, r := range results {
		if errors[i] == nil && r != nil {
			validResults = append(validResults, r)
			validWeights = append(validWeights, e.weights[i])
		}
	}

	if len(validResults) == 0 {
		return nil, errors[0] // Return first error
	}

	// Combine results based on strategy
	var combined *ClassificationResult
	switch e.strategy {
	case StrategyVoting:
		combined = e.combineVoting(validResults)
	case StrategyMax:
		combined = e.combineMax(validResults)
	default:
		combined = e.combineAverage(validResults, validWeights)
	}

	combined.Latency = time.Since(start)
	combined.ModelUsed = "ensemble"
	return combined, nil
}

func (e *EnsembleClassifier) combineAverage(results []*ClassificationResult, weights []float64) *ClassificationResult {
	scores := make(map[string]float64)
	totalWeight := 0.0

	for i, r := range results {
		w := weights[i]
		totalWeight += w
		for label, score := range r.Scores {
			scores[label] += score * w
		}
	}

	// Normalize
	for label := range scores {
		scores[label] /= totalWeight
	}

	// Find best label
	bestLabel := ""
	bestScore := 0.0
	for label, score := range scores {
		if score > bestScore {
			bestScore = score
			bestLabel = label
		}
	}

	return &ClassificationResult{
		Label:      bestLabel,
		Confidence: bestScore,
		Scores:     scores,
	}
}

func (e *EnsembleClassifier) combineVoting(results []*ClassificationResult) *ClassificationResult {
	votes := make(map[string]float64)

	for _, r := range results {
		votes[r.Label] += r.Confidence
	}

	bestLabel := ""
	bestVotes := 0.0
	for label, v := range votes {
		if v > bestVotes {
			bestVotes = v
			bestLabel = label
		}
	}

	return &ClassificationResult{
		Label:      bestLabel,
		Confidence: bestVotes / float64(len(results)),
		Scores:     votes,
	}
}

func (e *EnsembleClassifier) combineMax(results []*ClassificationResult) *ClassificationResult {
	var best *ClassificationResult
	for _, r := range results {
		if best == nil || r.Confidence > best.Confidence {
			best = r
		}
	}
	return best
}

func (e *EnsembleClassifier) ClassifyBatch(ctx context.Context, texts []string) ([]*ClassificationResult, error) {
	results := make([]*ClassificationResult, len(texts))
	for i, text := range texts {
		r, err := e.Classify(ctx, text)
		if err != nil {
			return nil, err
		}
		results[i] = r
	}
	return results, nil
}

func (e *EnsembleClassifier) Labels() []string {
	if len(e.classifiers) > 0 {
		return e.classifiers[0].Labels()
	}
	return nil
}

func (e *EnsembleClassifier) Name() string {
	return "ensemble"
}

// RuleBasedClassifier provides fast classification using our regex patterns.
// This serves as a baseline and fallback for ML models.
type RuleBasedClassifier struct {
	riskScorer *RiskScorer
	thresholds map[ThreatLabel]int
}

// NewRuleBasedClassifier creates a classifier from existing risk scorer patterns.
func NewRuleBasedClassifier(scorer *RiskScorer) *RuleBasedClassifier {
	return &RuleBasedClassifier{
		riskScorer: scorer,
		thresholds: map[ThreatLabel]int{
			LabelJailbreak:        30,
			LabelPromptInjection:  25,
			LabelExtraction:       20,
			LabelExfiltration:     30,
			LabelCodeExecution:    25,
			LabelSocialEngineering: 20,
		},
	}
}

func (r *RuleBasedClassifier) Classify(ctx context.Context, text string) (*ClassificationResult, error) {
	start := time.Now()

	req := &RequestContext{
		Message: text,
	}

	score, reasons := r.riskScorer.Score(ctx, req)

	// Map reasons to threat labels
	scores := make(map[string]float64)
	scores[string(LabelBenign)] = 1.0 - float64(score)/100.0

	for _, reason := range reasons {
		label := r.reasonToLabel(reason)
		scores[string(label)] = math.Max(scores[string(label)], float64(score)/100.0)
	}

	// Find best non-benign label
	bestLabel := string(LabelBenign)
	bestScore := scores[string(LabelBenign)]

	for label, s := range scores {
		if label != string(LabelBenign) && s > bestScore {
			bestScore = s
			bestLabel = label
		}
	}

	return &ClassificationResult{
		Label:       bestLabel,
		Confidence:  bestScore,
		Scores:      scores,
		ModelUsed:   "rule-based",
		Latency:     time.Since(start),
		Explanation: formatReasons(reasons),
	}, nil
}

func (r *RuleBasedClassifier) reasonToLabel(reason string) ThreatLabel {
	// Map detection reasons to threat labels
	switch {
	case containsAnySubstr(reason, "jailbreak", "dan", "persona", "bypass"):
		return LabelJailbreak
	case containsAnySubstr(reason, "injection", "override", "instruction"):
		return LabelPromptInjection
	case containsAnySubstr(reason, "extraction", "probe", "system_prompt"):
		return LabelExtraction
	case containsAnySubstr(reason, "exfil", "webhook", "url"):
		return LabelExfiltration
	case containsAnySubstr(reason, "code", "exec", "sql"):
		return LabelCodeExecution
	case containsAnySubstr(reason, "authority", "urgency", "emotional", "manipulation"):
		return LabelSocialEngineering
	default:
		return LabelBenign
	}
}

func containsAnySubstr(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(sub) > 0 && len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

func formatReasons(reasons []string) string {
	if len(reasons) == 0 {
		return ""
	}
	data, _ := json.Marshal(reasons)
	return string(data)
}

func (r *RuleBasedClassifier) ClassifyBatch(ctx context.Context, texts []string) ([]*ClassificationResult, error) {
	results := make([]*ClassificationResult, len(texts))
	for i, text := range texts {
		res, err := r.Classify(ctx, text)
		if err != nil {
			return nil, err
		}
		results[i] = res
	}
	return results, nil
}

func (r *RuleBasedClassifier) Labels() []string {
	return []string{
		string(LabelBenign),
		string(LabelJailbreak),
		string(LabelPromptInjection),
		string(LabelExtraction),
		string(LabelExfiltration),
		string(LabelCodeExecution),
		string(LabelSocialEngineering),
	}
}

func (r *RuleBasedClassifier) Name() string {
	return "rule-based"
}

// ClassificationMetrics tracks classifier performance.
type ClassificationMetrics struct {
	mu sync.RWMutex

	TotalClassifications int64
	LabelCounts          map[string]int64
	AverageLatency       time.Duration
	ErrorCount           int64
	ConfidenceSum        float64
}

// NewClassificationMetrics creates a new metrics tracker.
func NewClassificationMetrics() *ClassificationMetrics {
	return &ClassificationMetrics{
		LabelCounts: make(map[string]int64),
	}
}

// Record records a classification result.
func (m *ClassificationMetrics) Record(result *ClassificationResult, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.TotalClassifications++

	if err != nil {
		m.ErrorCount++
		return
	}

	m.LabelCounts[result.Label]++
	m.ConfidenceSum += result.Confidence

	// Update average latency (exponential moving average)
	if m.TotalClassifications == 1 {
		m.AverageLatency = result.Latency
	} else {
		alpha := 0.1
		m.AverageLatency = time.Duration(
			float64(m.AverageLatency)*(1-alpha) + float64(result.Latency)*alpha,
		)
	}
}

// GetStats returns current classification statistics.
func (m *ClassificationMetrics) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	avgConfidence := 0.0
	if m.TotalClassifications > m.ErrorCount {
		avgConfidence = m.ConfidenceSum / float64(m.TotalClassifications-m.ErrorCount)
	}

	return map[string]interface{}{
		"total_classifications": m.TotalClassifications,
		"label_distribution":    m.LabelCounts,
		"average_latency_ms":    m.AverageLatency.Milliseconds(),
		"error_count":           m.ErrorCount,
		"average_confidence":    avgConfidence,
	}
}
