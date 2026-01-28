package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rajivchocolate/secureinfer/internal/store"
)

// ExtractionDetector implements production-grade model extraction/theft detection.
//
// Model extraction attacks attempt to steal model capabilities through:
// 1. Query-based extraction: Systematically probing to learn decision boundaries
// 2. API abuse: High-volume requests to collect training data
// 3. Distillation attacks: Using outputs to train a surrogate model
// 4. Membership inference: Determining if data was in training set
//
// Detection strategies implemented:
// - Query fingerprinting and clustering
// - Behavioral anomaly detection
// - Request velocity analysis
// - Query diversity metrics
// - Session pattern analysis
type ExtractionDetector struct {
	mu sync.RWMutex

	// Configuration
	maxSimilarQueries   int
	similarityThreshold float64
	velocityWindowSec   int
	maxVelocity         int

	// Fingerprinting
	ngramSize     int
	minhashSize   int
	lshBuckets    int
	lshBandSize   int

	// Pattern detection
	patterns []extractionPattern
}

// extractionPattern defines a known extraction behavior pattern.
type extractionPattern struct {
	name        string
	description string
	detector    func([]QueryRecord, *RequestContext) (bool, int)
}

// QueryRecord stores comprehensive query information for analysis.
type QueryRecord struct {
	Hash        string            `json:"hash"`
	MinHash     []uint64          `json:"minhash,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
	Length      int               `json:"length"`
	TokenCount  int               `json:"token_count"`
	NGrams      map[string]int    `json:"-"` // Don't persist, computed on demand
	Features    QueryFeatures     `json:"features"`
	SessionID   string            `json:"session_id,omitempty"`
}

// QueryFeatures captures semantic features of a query for ML-based detection.
type QueryFeatures struct {
	// Structural features
	QuestionCount     int     `json:"question_count"`
	CommandCount      int     `json:"command_count"`
	CodeBlockCount    int     `json:"code_block_count"`
	ListItemCount     int     `json:"list_item_count"`

	// Semantic indicators
	HasNumberedItems  bool    `json:"has_numbered_items"`
	HasTestLanguage   bool    `json:"has_test_language"`
	HasBoundaryProbe  bool    `json:"has_boundary_probe"`
	HasFormatRequest  bool    `json:"has_format_request"`
	HasExhaustiveReq  bool    `json:"has_exhaustive_req"`

	// Statistical features
	AvgWordLength     float64 `json:"avg_word_length"`
	UniqueWordRatio   float64 `json:"unique_word_ratio"`
	PunctuationRatio  float64 `json:"punctuation_ratio"`
}

// ExtractionResult contains detailed analysis results.
type ExtractionResult struct {
	IsExtraction    bool              `json:"is_extraction"`
	Score           int               `json:"score"`
	Reasons         []string          `json:"reasons"`
	Confidence      float64           `json:"confidence"`
	Patterns        []string          `json:"patterns_matched"`
	Recommendations []string          `json:"recommendations"`
}

// NewExtractionDetector creates a production-grade extraction detector.
func NewExtractionDetector(maxSimilar int, threshold float64) *ExtractionDetector {
	ed := &ExtractionDetector{
		maxSimilarQueries:   maxSimilar,
		similarityThreshold: threshold,
		velocityWindowSec:   60,
		maxVelocity:         30,
		ngramSize:           3,
		minhashSize:         128,
		lshBuckets:          20,
		lshBandSize:         5,
	}
	ed.initPatterns()
	return ed
}

func (ed *ExtractionDetector) initPatterns() {
	ed.patterns = []extractionPattern{
		{
			name:        "systematic_enumeration",
			description: "Detects systematic enumeration of model capabilities",
			detector:    ed.detectSystematicEnumeration,
		},
		{
			name:        "boundary_probing",
			description: "Detects attempts to find model decision boundaries",
			detector:    ed.detectBoundaryProbing,
		},
		{
			name:        "distillation_harvesting",
			description: "Detects data collection patterns for model distillation",
			detector:    ed.detectDistillationHarvesting,
		},
		{
			name:        "adversarial_probing",
			description: "Detects adversarial example generation patterns",
			detector:    ed.detectAdversarialProbing,
		},
		{
			name:        "membership_inference",
			description: "Detects membership inference attack patterns",
			detector:    ed.detectMembershipInference,
		},
	}
}

// Check performs comprehensive extraction detection analysis.
func (ed *ExtractionDetector) Check(
	ctx context.Context,
	req *RequestContext,
	cache store.Cache,
) (isExtraction bool, score int, reasons []string) {
	if cache == nil {
		return false, 0, nil
	}

	result := ed.analyze(ctx, req, cache)

	// Record this query for future analysis
	ed.recordQuery(ctx, req, cache)

	return result.IsExtraction, result.Score, result.Reasons
}

// analyze performs full extraction analysis.
func (ed *ExtractionDetector) analyze(
	ctx context.Context,
	req *RequestContext,
	cache store.Cache,
) *ExtractionResult {
	result := &ExtractionResult{
		Patterns:        make([]string, 0),
		Recommendations: make([]string, 0),
	}

	// 1. Query similarity clustering using MinHash/LSH
	simScore, simReasons := ed.checkSimilarityClustering(ctx, req, cache)
	result.Score += simScore
	result.Reasons = append(result.Reasons, simReasons...)

	// 2. Structural probing patterns
	probeScore, probeReasons := ed.checkStructuralProbing(req)
	result.Score += probeScore
	result.Reasons = append(result.Reasons, probeReasons...)

	// 3. Request velocity analysis
	velocityScore, velocityReasons := ed.checkVelocityAnomaly(ctx, req, cache)
	result.Score += velocityScore
	result.Reasons = append(result.Reasons, velocityReasons...)

	// 4. Output harvesting patterns
	harvestScore, harvestReasons := ed.checkOutputHarvesting(req)
	result.Score += harvestScore
	result.Reasons = append(result.Reasons, harvestReasons...)

	// 5. Query diversity analysis (low diversity = extraction)
	diversityScore, diversityReasons := ed.checkQueryDiversity(ctx, req, cache)
	result.Score += diversityScore
	result.Reasons = append(result.Reasons, diversityReasons...)

	// 6. Pattern-based detection
	queries := ed.getRecentQueries(ctx, req.TenantID, cache)
	for _, pattern := range ed.patterns {
		matched, patternScore := pattern.detector(queries, req)
		if matched {
			result.Score += patternScore
			result.Patterns = append(result.Patterns, pattern.name)
		}
	}

	// 7. Session analysis
	sessionScore, sessionReasons := ed.checkSessionPatterns(ctx, req, cache)
	result.Score += sessionScore
	result.Reasons = append(result.Reasons, sessionReasons...)

	// Calculate confidence based on multiple signals
	signalCount := len(result.Reasons) + len(result.Patterns)
	if signalCount > 0 {
		result.Confidence = math.Min(float64(signalCount)*0.15+float64(result.Score)*0.01, 1.0)
	}

	// Determine if extraction based on score threshold
	result.IsExtraction = result.Score > 35

	// Generate recommendations
	if result.IsExtraction {
		result.Recommendations = ed.generateRecommendations(result)
	}

	return result
}

// checkSimilarityClustering uses MinHash-style similarity to detect query clusters.
func (ed *ExtractionDetector) checkSimilarityClustering(
	ctx context.Context,
	req *RequestContext,
	cache store.Cache,
) (int, []string) {
	queries := ed.getRecentQueries(ctx, req.TenantID, cache)
	if len(queries) < 3 {
		return 0, nil
	}

	var score int
	var reasons []string

	// Calculate similarity between current query and recent queries
	currentNGrams := ed.computeNGrams(req.Message)
	similarCount := 0
	highSimilarCount := 0

	for _, q := range queries {
		qNGrams := ed.computeNGrams(q.Hash) // Note: storing normalized content in hash for simplicity
		sim := ed.jaccardSimilarity(currentNGrams, qNGrams)

		if sim > ed.similarityThreshold {
			similarCount++
			if sim > 0.8 {
				highSimilarCount++
			}
		}
	}

	// Score based on similarity clusters
	if highSimilarCount > 5 {
		score += 40
		reasons = append(reasons, "high_similarity_cluster")
	} else if similarCount > ed.maxSimilarQueries {
		score += 30
		reasons = append(reasons, "excessive_similar_queries")
	} else if similarCount > ed.maxSimilarQueries/2 {
		score += 15
		reasons = append(reasons, "elevated_query_similarity")
	}

	// Check for incremental variations (A, A+x, A+y pattern)
	if ed.detectIncrementalVariations(queries, req.Message) {
		score += 25
		reasons = append(reasons, "incremental_variation_pattern")
	}

	return score, reasons
}

// checkStructuralProbing detects systematic input structure probing.
func (ed *ExtractionDetector) checkStructuralProbing(req *RequestContext) (int, []string) {
	var score int
	var reasons []string
	msg := strings.ToLower(req.Message)

	// Numbered/ordered probing
	if hasOrderedProbing(msg) {
		score += 20
		reasons = append(reasons, "ordered_probing")
	}

	// Test/benchmark language
	testIndicators := []string{
		"test case", "test input", "benchmark", "evaluate",
		"measure performance", "compare output", "expected output",
		"ground truth", "baseline", "reference answer",
	}
	for _, indicator := range testIndicators {
		if strings.Contains(msg, indicator) {
			score += 15
			reasons = append(reasons, "test_benchmark_language")
			break
		}
	}

	// Decision boundary probing
	boundaryIndicators := []string{
		"edge case", "corner case", "boundary", "limit",
		"threshold", "maximum", "minimum", "extreme",
		"what happens if", "what do you do when",
	}
	boundaryCount := 0
	for _, indicator := range boundaryIndicators {
		if strings.Contains(msg, indicator) {
			boundaryCount++
		}
	}
	if boundaryCount >= 2 {
		score += 20
		reasons = append(reasons, "boundary_probing")
	}

	// Adversarial perturbation patterns
	if containsAdversarialPatterns(msg) {
		score += 20
		reasons = append(reasons, "adversarial_perturbation")
	}

	return score, reasons
}

// checkVelocityAnomaly detects abnormal request rates with statistical analysis.
func (ed *ExtractionDetector) checkVelocityAnomaly(
	ctx context.Context,
	req *RequestContext,
	cache store.Cache,
) (int, []string) {
	var score int
	var reasons []string

	// Get multiple time windows
	windows := []struct {
		key      string
		duration int
		limit    int
		score    int
		reason   string
	}{
		{"velocity:1m:" + req.TenantID, 60, 30, 25, "extreme_velocity_1m"},
		{"velocity:5m:" + req.TenantID, 300, 100, 20, "high_velocity_5m"},
		{"velocity:1h:" + req.TenantID, 3600, 500, 15, "elevated_velocity_1h"},
	}

	for _, w := range windows {
		count, _ := cache.Incr(ctx, w.key)
		if count == 1 {
			cache.Expire(ctx, w.key, w.duration)
		}

		if int(count) > w.limit {
			score += w.score
			reasons = append(reasons, w.reason)
		}
	}

	// Check for burst patterns (many requests in very short time)
	burstKey := "burst:" + req.TenantID
	burstCount, _ := cache.Incr(ctx, burstKey)
	if burstCount == 1 {
		cache.Expire(ctx, burstKey, 5) // 5 second window
	}
	if burstCount > 10 {
		score += 30
		reasons = append(reasons, "request_burst_detected")
	}

	return score, reasons
}

// checkOutputHarvesting detects attempts to collect model outputs.
func (ed *ExtractionDetector) checkOutputHarvesting(req *RequestContext) (int, []string) {
	var score int
	var reasons []string
	msg := strings.ToLower(req.Message)

	// Requests for complete/exhaustive outputs
	exhaustivePatterns := []string{
		"all possible", "every possible", "complete list",
		"exhaustive", "comprehensive list", "full enumeration",
		"all variants", "every variant", "all examples",
		"don't summarize", "don't truncate", "full response",
		"entire output", "complete output",
	}
	for _, p := range exhaustivePatterns {
		if strings.Contains(msg, p) {
			score += 15
			reasons = append(reasons, "exhaustive_output_request")
			break
		}
	}

	// Requests for structured/parseable output
	structuredPatterns := []string{
		"json format", "json output", "return json",
		"csv format", "xml format", "yaml format",
		"structured output", "machine readable",
		"parseable format", "serialized",
		"array of", "list of objects",
	}
	for _, p := range structuredPatterns {
		if strings.Contains(msg, p) {
			score += 12
			reasons = append(reasons, "structured_output_request")
			break
		}
	}

	// Requests for many examples/samples
	if containsBulkRequest(msg) {
		score += 18
		reasons = append(reasons, "bulk_output_request")
	}

	// Requests for confidence/probability scores
	confidencePatterns := []string{
		"confidence score", "probability", "likelihood",
		"how certain", "how sure", "certainty",
		"logits", "softmax", "raw scores",
	}
	for _, p := range confidencePatterns {
		if strings.Contains(msg, p) {
			score += 15
			reasons = append(reasons, "confidence_score_request")
			break
		}
	}

	return score, reasons
}

// checkQueryDiversity analyzes query diversity (low = extraction).
func (ed *ExtractionDetector) checkQueryDiversity(
	ctx context.Context,
	req *RequestContext,
	cache store.Cache,
) (int, []string) {
	queries := ed.getRecentQueries(ctx, req.TenantID, cache)
	if len(queries) < 10 {
		return 0, nil
	}

	var score int
	var reasons []string

	// Calculate vocabulary diversity across recent queries
	allWords := make(map[string]int)
	totalWords := 0

	for _, q := range queries {
		words := strings.Fields(strings.ToLower(q.Hash))
		for _, w := range words {
			allWords[w]++
			totalWords++
		}
	}

	if totalWords > 0 {
		diversityRatio := float64(len(allWords)) / float64(totalWords)

		// Very low diversity suggests templated/systematic queries
		if diversityRatio < 0.1 {
			score += 25
			reasons = append(reasons, "extremely_low_diversity")
		} else if diversityRatio < 0.2 {
			score += 15
			reasons = append(reasons, "low_query_diversity")
		}
	}

	// Check for template-based queries (same structure, different values)
	if ed.detectTemplateQueries(queries) {
		score += 20
		reasons = append(reasons, "template_based_queries")
	}

	return score, reasons
}

// checkSessionPatterns analyzes patterns across the session.
func (ed *ExtractionDetector) checkSessionPatterns(
	ctx context.Context,
	req *RequestContext,
	cache store.Cache,
) (int, []string) {
	var score int
	var reasons []string

	sessionKey := "session:" + req.TenantID
	sessionData, _ := cache.Get(ctx, sessionKey)

	var session SessionAnalysis
	if sessionData != "" {
		json.Unmarshal([]byte(sessionData), &session)
	}

	// Update session
	session.QueryCount++
	session.LastQueryTime = time.Now()

	// Analyze session duration vs query count
	if session.StartTime.IsZero() {
		session.StartTime = time.Now()
	}

	duration := time.Since(session.StartTime)
	if duration > 0 && session.QueryCount > 50 {
		queriesPerMinute := float64(session.QueryCount) / duration.Minutes()
		if queriesPerMinute > 20 {
			score += 20
			reasons = append(reasons, "high_session_velocity")
		}
	}

	// Save session
	sessionJSON, _ := json.Marshal(session)
	cache.Set(ctx, sessionKey, string(sessionJSON), 3600)

	return score, reasons
}

// SessionAnalysis tracks session-level patterns.
type SessionAnalysis struct {
	StartTime     time.Time `json:"start_time"`
	LastQueryTime time.Time `json:"last_query_time"`
	QueryCount    int       `json:"query_count"`
	UniqueTopics  []string  `json:"unique_topics"`
}

// Pattern detection functions

func (ed *ExtractionDetector) detectSystematicEnumeration(queries []QueryRecord, req *RequestContext) (bool, int) {
	if len(queries) < 10 {
		return false, 0
	}

	// Check for systematic coverage patterns
	topics := make(map[string]int)
	for _, q := range queries {
		topic := extractTopic(q.Hash)
		topics[topic]++
	}

	// Many different topics with similar frequency = systematic enumeration
	if len(topics) > 5 {
		var frequencies []int
		for _, count := range topics {
			frequencies = append(frequencies, count)
		}
		sort.Ints(frequencies)

		// Check for uniform distribution
		if len(frequencies) > 2 {
			variance := calculateVariance(frequencies)
			if variance < 2.0 { // Low variance = systematic
				return true, 25
			}
		}
	}

	return false, 0
}

func (ed *ExtractionDetector) detectBoundaryProbing(queries []QueryRecord, req *RequestContext) (bool, int) {
	if len(queries) < 5 {
		return false, 0
	}

	boundaryCount := 0
	for _, q := range queries {
		if q.Features.HasBoundaryProbe {
			boundaryCount++
		}
	}

	if boundaryCount >= 3 {
		return true, 20
	}
	return false, 0
}

func (ed *ExtractionDetector) detectDistillationHarvesting(queries []QueryRecord, req *RequestContext) (bool, int) {
	if len(queries) < 20 {
		return false, 0
	}

	// Check for high volume of diverse queries with format requests
	formatRequests := 0
	exhaustiveRequests := 0

	for _, q := range queries {
		if q.Features.HasFormatRequest {
			formatRequests++
		}
		if q.Features.HasExhaustiveReq {
			exhaustiveRequests++
		}
	}

	if formatRequests > 10 || exhaustiveRequests > 5 {
		return true, 30
	}
	return false, 0
}

func (ed *ExtractionDetector) detectAdversarialProbing(queries []QueryRecord, req *RequestContext) (bool, int) {
	if len(queries) < 5 {
		return false, 0
	}

	// Look for small perturbations in consecutive queries
	perturbationCount := 0
	for i := 1; i < len(queries); i++ {
		sim := ed.contentSimilarity(queries[i-1].Hash, queries[i].Hash)
		// Very similar but not identical = perturbation
		if sim > 0.85 && sim < 0.99 {
			perturbationCount++
		}
	}

	if perturbationCount >= 5 {
		return true, 25
	}
	return false, 0
}

func (ed *ExtractionDetector) detectMembershipInference(queries []QueryRecord, req *RequestContext) (bool, int) {
	msg := strings.ToLower(req.Message)

	// Membership inference indicators
	indicators := []string{
		"was this in your training",
		"did you learn this",
		"have you seen this before",
		"is this from your data",
		"training data",
		"memorized",
	}

	for _, ind := range indicators {
		if strings.Contains(msg, ind) {
			return true, 20
		}
	}

	return false, 0
}

// Helper functions

func (ed *ExtractionDetector) computeNGrams(text string) map[string]int {
	ngrams := make(map[string]int)
	words := strings.Fields(strings.ToLower(text))

	for i := 0; i <= len(words)-ed.ngramSize; i++ {
		ngram := strings.Join(words[i:i+ed.ngramSize], " ")
		ngrams[ngram]++
	}

	return ngrams
}

func (ed *ExtractionDetector) jaccardSimilarity(a, b map[string]int) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}

	intersection := 0
	union := len(a)

	for k := range a {
		if _, exists := b[k]; exists {
			intersection++
		}
	}

	for k := range b {
		if _, exists := a[k]; !exists {
			union++
		}
	}

	if union == 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}

func (ed *ExtractionDetector) detectIncrementalVariations(queries []QueryRecord, current string) bool {
	if len(queries) < 3 {
		return false
	}

	// Look for queries that differ by small increments
	currentWords := strings.Fields(strings.ToLower(current))
	variationCount := 0

	for _, q := range queries {
		qWords := strings.Fields(strings.ToLower(q.Hash))

		// Check if they differ by 1-2 words
		diff := wordDifference(currentWords, qWords)
		if diff >= 1 && diff <= 3 {
			variationCount++
		}
	}

	return variationCount >= 5
}

func (ed *ExtractionDetector) detectTemplateQueries(queries []QueryRecord) bool {
	if len(queries) < 5 {
		return false
	}

	// Extract "templates" by removing numbers and specific values
	templates := make(map[string]int)

	for _, q := range queries {
		template := extractTemplate(q.Hash)
		templates[template]++
	}

	// Check if any template is used repeatedly
	for _, count := range templates {
		if count >= 5 {
			return true
		}
	}

	return false
}

func (ed *ExtractionDetector) contentSimilarity(a, b string) float64 {
	wordsA := strings.Fields(strings.ToLower(a))
	wordsB := strings.Fields(strings.ToLower(b))

	if len(wordsA) == 0 || len(wordsB) == 0 {
		return 0
	}

	setA := make(map[string]bool)
	for _, w := range wordsA {
		setA[w] = true
	}

	matches := 0
	for _, w := range wordsB {
		if setA[w] {
			matches++
		}
	}

	return float64(matches) / float64(maxInt(len(wordsA), len(wordsB)))
}

func (ed *ExtractionDetector) getRecentQueries(ctx context.Context, tenantID string, cache store.Cache) []QueryRecord {
	key := "extraction:queries:" + tenantID
	data, err := cache.Get(ctx, key)
	if err != nil || data == "" {
		return nil
	}

	var queries []QueryRecord
	json.Unmarshal([]byte(data), &queries)
	return queries
}

func (ed *ExtractionDetector) recordQuery(ctx context.Context, req *RequestContext, cache store.Cache) {
	key := "extraction:queries:" + req.TenantID

	queries := ed.getRecentQueries(ctx, req.TenantID, cache)

	// Create new query record with features
	record := QueryRecord{
		Hash:       normalizeQuery(req.Message),
		Timestamp:  time.Now(),
		Length:     len(req.Message),
		TokenCount: len(strings.Fields(req.Message)),
		Features:   extractFeatures(req.Message),
	}

	queries = append(queries, record)

	// Keep only last 200 queries
	if len(queries) > 200 {
		queries = queries[len(queries)-200:]
	}

	data, _ := json.Marshal(queries)
	cache.Set(ctx, key, string(data), 7200) // 2 hour TTL
}

func (ed *ExtractionDetector) generateRecommendations(result *ExtractionResult) []string {
	var recs []string

	if result.Score > 70 {
		recs = append(recs, "Consider blocking this tenant temporarily")
		recs = append(recs, "Enable enhanced logging for this tenant")
	}

	for _, reason := range result.Reasons {
		switch reason {
		case "extreme_velocity_1m", "request_burst_detected":
			recs = append(recs, "Apply stricter rate limits")
		case "exhaustive_output_request", "bulk_output_request":
			recs = append(recs, "Limit response length for this tenant")
		case "structured_output_request":
			recs = append(recs, "Consider blocking JSON/structured output requests")
		}
	}

	return recs
}

// Utility functions

func normalizeQuery(msg string) string {
	return strings.ToLower(strings.TrimSpace(msg))
}

func extractFeatures(msg string) QueryFeatures {
	lower := strings.ToLower(msg)
	words := strings.Fields(lower)

	features := QueryFeatures{}

	// Count questions
	features.QuestionCount = strings.Count(msg, "?")

	// Count commands
	commandIndicators := []string{"tell me", "show me", "give me", "list", "explain", "describe"}
	for _, cmd := range commandIndicators {
		if strings.Contains(lower, cmd) {
			features.CommandCount++
		}
	}

	// Code blocks
	features.CodeBlockCount = strings.Count(msg, "```")

	// List items
	features.ListItemCount = strings.Count(msg, "\n-") + strings.Count(msg, "\n*")

	// Semantic indicators
	features.HasNumberedItems = hasOrderedProbing(lower)
	features.HasTestLanguage = strings.Contains(lower, "test") || strings.Contains(lower, "benchmark")
	features.HasBoundaryProbe = strings.Contains(lower, "boundary") || strings.Contains(lower, "edge case") || strings.Contains(lower, "limit")
	features.HasFormatRequest = strings.Contains(lower, "json") || strings.Contains(lower, "csv") || strings.Contains(lower, "format")
	features.HasExhaustiveReq = strings.Contains(lower, "all") || strings.Contains(lower, "every") || strings.Contains(lower, "complete list")

	// Statistical features
	if len(words) > 0 {
		totalLen := 0
		uniqueWords := make(map[string]bool)
		for _, w := range words {
			totalLen += len(w)
			uniqueWords[w] = true
		}
		features.AvgWordLength = float64(totalLen) / float64(len(words))
		features.UniqueWordRatio = float64(len(uniqueWords)) / float64(len(words))
	}

	// Punctuation ratio
	punctCount := 0
	for _, r := range msg {
		if strings.ContainsRune(".,!?;:-()[]{}\"'", r) {
			punctCount++
		}
	}
	if len(msg) > 0 {
		features.PunctuationRatio = float64(punctCount) / float64(len(msg))
	}

	return features
}

func hashQuery(msg string) string {
	normalized := normalizeQuery(msg)
	hash := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(hash[:])
}

func hasOrderedProbing(msg string) bool {
	patterns := []string{
		"1.", "2.", "3.", "4.", "5.",
		"1)", "2)", "3)", "4)", "5)",
		"#1", "#2", "#3", "#4", "#5",
		"first,", "second,", "third,",
		"step 1", "step 2", "step 3",
	}
	for _, p := range patterns {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}

func containsAdversarialPatterns(msg string) bool {
	patterns := []string{
		"slightly modify", "small change", "minor variation",
		"perturb", "adversarial", "fool the model",
		"trick", "bypass detection",
	}
	for _, p := range patterns {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}

func containsBulkRequest(msg string) bool {
	patterns := []string{
		"10 examples", "20 examples", "50 examples", "100 examples",
		"many examples", "multiple examples", "several examples",
		"list of examples", "give me 10", "give me 20",
		"generate 10", "generate 20", "generate 50",
	}
	for _, p := range patterns {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}

func extractTopic(text string) string {
	// Simple topic extraction - first few meaningful words
	words := strings.Fields(strings.ToLower(text))
	stopwords := map[string]bool{
		"the": true, "a": true, "an": true, "is": true, "are": true,
		"what": true, "how": true, "why": true, "when": true, "where": true,
		"to": true, "for": true, "of": true, "in": true, "on": true,
	}

	var topicWords []string
	for _, w := range words {
		if !stopwords[w] && len(w) > 2 {
			topicWords = append(topicWords, w)
			if len(topicWords) >= 3 {
				break
			}
		}
	}

	return strings.Join(topicWords, "_")
}

func extractTemplate(text string) string {
	// Replace numbers and specific values with placeholders
	result := strings.ToLower(text)
	// Replace numbers
	for _, c := range "0123456789" {
		result = strings.ReplaceAll(result, string(c), "#")
	}
	return result
}

func wordDifference(a, b []string) int {
	setA := make(map[string]bool)
	for _, w := range a {
		setA[w] = true
	}

	diff := 0
	for _, w := range b {
		if !setA[w] {
			diff++
		}
	}

	for _, w := range a {
		found := false
		for _, bw := range b {
			if w == bw {
				found = true
				break
			}
		}
		if !found {
			diff++
		}
	}

	return diff / 2 // Account for double counting
}

func calculateVariance(values []int) float64 {
	if len(values) == 0 {
		return 0
	}

	sum := 0.0
	for _, v := range values {
		sum += float64(v)
	}
	mean := sum / float64(len(values))

	variance := 0.0
	for _, v := range values {
		diff := float64(v) - mean
		variance += diff * diff
	}

	return variance / float64(len(values))
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
