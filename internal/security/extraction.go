package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/rajivchocolate/secureinfer/internal/store"
)

// ExtractionDetector identifies model extraction/theft attempts.
//
// Model extraction attacks try to steal model capabilities by:
// 1. Sending many similar queries to learn decision boundaries
// 2. Systematically probing with structured inputs
// 3. Collecting outputs to train a clone model
//
// Detection strategies:
// - Query similarity clustering
// - Request velocity anomalies
// - Structured input patterns
// - Output harvesting patterns
type ExtractionDetector struct {
	maxSimilarQueries   int
	similarityThreshold float64
}

// QueryRecord stores query info for extraction detection.
type QueryRecord struct {
	Hash      string    `json:"hash"`
	Embedding []float32 `json:"embedding,omitempty"` // For ML-based detection
	Timestamp time.Time `json:"timestamp"`
	Length    int       `json:"length"`
}

// NewExtractionDetector creates a new extraction detector.
func NewExtractionDetector(maxSimilar int, threshold float64) *ExtractionDetector {
	return &ExtractionDetector{
		maxSimilarQueries:   maxSimilar,
		similarityThreshold: threshold,
	}
}

// Check analyzes a request for extraction patterns.
func (ed *ExtractionDetector) Check(
	ctx context.Context,
	req *RequestContext,
	cache store.Cache,
) (isExtraction bool, score int, reasons []string) {
	if cache == nil {
		return false, 0, nil
	}

	// 1. Check query similarity clustering
	simScore, simReasons := ed.checkSimilarity(ctx, req, cache)
	score += simScore
	reasons = append(reasons, simReasons...)

	// 2. Check for structured probing patterns
	probeScore, probeReasons := ed.checkStructuredProbing(req)
	score += probeScore
	reasons = append(reasons, probeReasons...)

	// 3. Check request velocity
	velocityScore, velocityReasons := ed.checkVelocity(ctx, req, cache)
	score += velocityScore
	reasons = append(reasons, velocityReasons...)

	// 4. Check for output harvesting patterns
	harvestScore, harvestReasons := ed.checkOutputHarvesting(req)
	score += harvestScore
	reasons = append(reasons, harvestReasons...)

	// Record this query for future analysis
	ed.recordQuery(ctx, req, cache)

	return score > 30, score, reasons
}

// checkSimilarity detects clusters of similar queries.
func (ed *ExtractionDetector) checkSimilarity(
	ctx context.Context,
	req *RequestContext,
	cache store.Cache,
) (int, []string) {
	key := "extraction:queries:" + req.TenantID

	// Get recent queries
	data, err := cache.Get(ctx, key)
	if err != nil || data == "" {
		return 0, nil
	}

	var queries []QueryRecord
	if err := json.Unmarshal([]byte(data), &queries); err != nil {
		return 0, nil
	}

	// Count similar queries
	currentHash := hashQuery(req.Message)
	similarCount := 0

	for _, q := range queries {
		// Simple hash-based similarity (in production, use embeddings)
		if ed.querySimilar(req.Message, q.Hash, q.Length) {
			similarCount++
		}
	}

	var score int
	var reasons []string

	if similarCount > ed.maxSimilarQueries {
		score = 40
		reasons = append(reasons, "excessive_similar_queries")
	} else if similarCount > ed.maxSimilarQueries/2 {
		score = 20
		reasons = append(reasons, "high_query_similarity")
	}

	// Check for sequential pattern (A, B, C, A+1, B+1, C+1)
	if ed.detectSequentialPattern(queries, currentHash) {
		score += 25
		reasons = append(reasons, "sequential_extraction_pattern")
	}

	return score, reasons
}

// checkStructuredProbing detects systematic input probing.
func (ed *ExtractionDetector) checkStructuredProbing(req *RequestContext) (int, []string) {
	var score int
	var reasons []string

	msg := strings.ToLower(req.Message)

	// Numbered queries (1., 2., 3., etc.)
	if hasNumberedPattern(msg) {
		score += 15
		reasons = append(reasons, "numbered_probing")
	}

	// Test/probe language
	testPatterns := []string{
		"test case", "test input", "probe", "benchmark",
		"evaluate", "measure", "compare output",
	}
	for _, p := range testPatterns {
		if strings.Contains(msg, p) {
			score += 10
			reasons = append(reasons, "test_language")
			break
		}
	}

	// Boundary testing patterns
	boundaryPatterns := []string{
		"what if", "edge case", "maximum", "minimum",
		"limit", "boundary", "threshold",
	}
	boundaryCount := 0
	for _, p := range boundaryPatterns {
		if strings.Contains(msg, p) {
			boundaryCount++
		}
	}
	if boundaryCount >= 2 {
		score += 15
		reasons = append(reasons, "boundary_testing")
	}

	return score, reasons
}

// checkVelocity detects abnormal request rates.
func (ed *ExtractionDetector) checkVelocity(
	ctx context.Context,
	req *RequestContext,
	cache store.Cache,
) (int, []string) {
	key := "extraction:velocity:" + req.TenantID

	// Increment and get count for current window (1 minute)
	count, _ := cache.Incr(ctx, key)
	if count == 1 {
		// First request in window, set expiry
		cache.Expire(ctx, key, 60) // 60 seconds
	}

	var score int
	var reasons []string

	// Thresholds
	if count > 30 { // More than 30 req/min
		score = 30
		reasons = append(reasons, "extreme_velocity")
	} else if count > 15 {
		score = 15
		reasons = append(reasons, "high_velocity")
	}

	return score, reasons
}

// checkOutputHarvesting detects attempts to collect model outputs.
func (ed *ExtractionDetector) checkOutputHarvesting(req *RequestContext) (int, []string) {
	var score int
	var reasons []string

	msg := strings.ToLower(req.Message)

	// Requests for verbose/complete outputs
	verbosePatterns := []string{
		"give me all", "complete list", "full response",
		"don't summarize", "be verbose", "exhaustive",
		"every possible", "all examples",
	}
	for _, p := range verbosePatterns {
		if strings.Contains(msg, p) {
			score += 10
			reasons = append(reasons, "verbose_output_request")
			break
		}
	}

	// Requests for structured outputs (easier to parse/train on)
	structuredPatterns := []string{
		"json format", "csv format", "xml format",
		"structured output", "parseable", "machine readable",
	}
	for _, p := range structuredPatterns {
		if strings.Contains(msg, p) {
			score += 10
			reasons = append(reasons, "structured_output_request")
			break
		}
	}

	// Requests for many examples
	examplePatterns := []string{
		"10 examples", "20 examples", "100 examples",
		"many examples", "multiple examples", "list of examples",
	}
	for _, p := range examplePatterns {
		if strings.Contains(msg, p) {
			score += 15
			reasons = append(reasons, "bulk_example_request")
			break
		}
	}

	return score, reasons
}

// recordQuery stores query info for future analysis.
func (ed *ExtractionDetector) recordQuery(
	ctx context.Context,
	req *RequestContext,
	cache store.Cache,
) {
	key := "extraction:queries:" + req.TenantID

	// Get existing queries
	var queries []QueryRecord
	if data, err := cache.Get(ctx, key); err == nil && data != "" {
		json.Unmarshal([]byte(data), &queries)
	}

	// Add new query
	queries = append(queries, QueryRecord{
		Hash:      hashQuery(req.Message),
		Timestamp: time.Now(),
		Length:    len(req.Message),
	})

	// Keep only last 100 queries
	if len(queries) > 100 {
		queries = queries[len(queries)-100:]
	}

	// Store back
	data, _ := json.Marshal(queries)
	cache.Set(ctx, key, string(data), 3600) // 1 hour TTL
}

// querySimilar checks if queries are similar.
func (ed *ExtractionDetector) querySimilar(msg, hash string, length int) bool {
	// Simple heuristic: similar length and some hash overlap
	// In production, use embeddings or MinHash
	currentHash := hashQuery(msg)

	// Length similarity
	lengthRatio := float64(min(len(msg), length)) / float64(max(len(msg), length))
	if lengthRatio < 0.7 {
		return false
	}

	// Prefix similarity (first 8 chars of hash)
	if len(currentHash) >= 8 && len(hash) >= 8 {
		if currentHash[:8] == hash[:8] {
			return true
		}
	}

	return false
}

// detectSequentialPattern detects A, A+1, A+2 style patterns.
func (ed *ExtractionDetector) detectSequentialPattern(queries []QueryRecord, currentHash string) bool {
	// Simplified: check if we have many queries with similar timestamps
	if len(queries) < 5 {
		return false
	}

	// Check time clustering
	recentCount := 0
	now := time.Now()
	for _, q := range queries {
		if now.Sub(q.Timestamp) < 5*time.Minute {
			recentCount++
		}
	}

	return recentCount > 10
}

func hashQuery(msg string) string {
	// Normalize before hashing
	normalized := strings.ToLower(strings.TrimSpace(msg))
	hash := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(hash[:])
}

func hasNumberedPattern(msg string) bool {
	patterns := []string{"1.", "2.", "3.", "1)", "2)", "3)", "#1", "#2", "#3"}
	for _, p := range patterns {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}
