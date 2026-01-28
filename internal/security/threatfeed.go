package security

import (
	"context"
	"encoding/json"
	"regexp"
	"sync"
	"time"
)

// ThreatFeed provides updatable threat intelligence.
// In production, this would sync with external threat feeds.
type ThreatFeed struct {
	mu sync.RWMutex

	// Pattern-based indicators
	patterns     []ThreatPattern
	compiledRegs map[string]*regexp.Regexp

	// Hash-based indicators (for known bad prompts)
	hashIndicators map[string]*ThreatIndicator

	// IP reputation
	ipReputation map[string]*IPReputation

	// Feed metadata
	lastUpdate time.Time
	version    string
	sources    []FeedSource
}

// ThreatPattern represents a pattern-based threat indicator.
type ThreatPattern struct {
	ID          string            `json:"id"`
	Pattern     string            `json:"pattern"`
	Type        PatternType       `json:"type"`
	Severity    ThreatSeverity    `json:"severity"`
	Category    ThreatCategory    `json:"category"`
	Description string            `json:"description"`
	Score       int               `json:"score"`
	Tags        []string          `json:"tags"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Source      string            `json:"source"`
	Confidence  float64           `json:"confidence"` // 0-1
	Active      bool              `json:"active"`
}

// PatternType defines the type of pattern matching.
type PatternType string

const (
	PatternRegex   PatternType = "regex"
	PatternExact   PatternType = "exact"
	PatternContains PatternType = "contains"
	PatternFuzzy   PatternType = "fuzzy"
)

// ThreatSeverity defines threat severity levels.
type ThreatSeverity string

const (
	SeverityCrit   ThreatSeverity = "critical"
	SeverityHigh   ThreatSeverity = "high"
	SeverityMedium ThreatSeverity = "medium"
	SeverityLow    ThreatSeverity = "low"
)

// ThreatCategory defines threat categories.
type ThreatCategory string

const (
	CatJailbreak      ThreatCategory = "jailbreak"
	CatInjection      ThreatCategory = "injection"
	CatExtraction     ThreatCategory = "extraction"
	CatExfiltration   ThreatCategory = "exfiltration"
	CatAbuse          ThreatCategory = "abuse"
	CatMalware        ThreatCategory = "malware"
	CatSocialEng      ThreatCategory = "social_engineering"
)

// ThreatIndicator represents a hash-based indicator.
type ThreatIndicator struct {
	Hash       string         `json:"hash"`       // SHA256 of normalized content
	Type       string         `json:"type"`       // prompt, response, etc.
	Severity   ThreatSeverity `json:"severity"`
	Category   ThreatCategory `json:"category"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
	HitCount   int64          `json:"hit_count"`
	Source     string         `json:"source"`
	Confidence float64        `json:"confidence"`
}

// IPReputation contains IP-based reputation data.
type IPReputation struct {
	IP           string         `json:"ip"`
	Score        int            `json:"score"` // 0-100, higher = worse
	Category     string         `json:"category"`
	LastActivity time.Time      `json:"last_activity"`
	ThreatTypes  []string       `json:"threat_types"`
	Source       string         `json:"source"`
}

// FeedSource defines a threat feed source.
type FeedSource struct {
	Name        string        `json:"name"`
	URL         string        `json:"url"`
	Type        string        `json:"type"` // http, file, api
	UpdateFreq  time.Duration `json:"update_frequency"`
	LastSync    time.Time     `json:"last_sync"`
	Active      bool          `json:"active"`
	Priority    int           `json:"priority"`
	APIKey      string        `json:"-"` // Don't serialize
}

// ThreatMatch represents a threat feed match.
type ThreatMatch struct {
	Pattern    *ThreatPattern   `json:"pattern,omitempty"`
	Indicator  *ThreatIndicator `json:"indicator,omitempty"`
	MatchType  string           `json:"match_type"`
	MatchedOn  string           `json:"matched_on"`
	Confidence float64          `json:"confidence"`
}

// NewThreatFeed creates a new threat feed with default patterns.
func NewThreatFeed() *ThreatFeed {
	tf := &ThreatFeed{
		patterns:       make([]ThreatPattern, 0),
		compiledRegs:   make(map[string]*regexp.Regexp),
		hashIndicators: make(map[string]*ThreatIndicator),
		ipReputation:   make(map[string]*IPReputation),
		sources:        make([]FeedSource, 0),
		lastUpdate:     time.Now(),
		version:        "1.0.0",
	}

	// Load default patterns
	tf.loadDefaultPatterns()

	return tf
}

// Check checks content against the threat feed.
func (tf *ThreatFeed) Check(ctx context.Context, content string, ip string) []ThreatMatch {
	tf.mu.RLock()
	defer tf.mu.RUnlock()

	var matches []ThreatMatch

	// Check patterns
	for _, pattern := range tf.patterns {
		if !pattern.Active {
			continue
		}

		var matched bool
		switch pattern.Type {
		case PatternRegex:
			if re, ok := tf.compiledRegs[pattern.ID]; ok {
				matched = re.MatchString(content)
			}
		case PatternExact:
			matched = content == pattern.Pattern
		case PatternContains:
			matched = containsString(content, pattern.Pattern)
		}

		if matched {
			matches = append(matches, ThreatMatch{
				Pattern:    &pattern,
				MatchType:  string(pattern.Type),
				MatchedOn:  "content",
				Confidence: pattern.Confidence,
			})
		}
	}

	// Check hash indicators
	contentHash := hashContent(content)
	if indicator, ok := tf.hashIndicators[contentHash]; ok {
		indicator.HitCount++
		indicator.LastSeen = time.Now()
		matches = append(matches, ThreatMatch{
			Indicator:  indicator,
			MatchType:  "hash",
			MatchedOn:  "content",
			Confidence: indicator.Confidence,
		})
	}

	// Check IP reputation
	if ip != "" {
		if rep, ok := tf.ipReputation[ip]; ok {
			if rep.Score > 50 {
				matches = append(matches, ThreatMatch{
					MatchType:  "ip_reputation",
					MatchedOn:  ip,
					Confidence: float64(rep.Score) / 100.0,
				})
			}
		}
	}

	return matches
}

// AddPattern adds a new pattern to the feed.
func (tf *ThreatFeed) AddPattern(pattern ThreatPattern) error {
	tf.mu.Lock()
	defer tf.mu.Unlock()

	// Compile regex if needed
	if pattern.Type == PatternRegex {
		re, err := regexp.Compile(pattern.Pattern)
		if err != nil {
			return err
		}
		tf.compiledRegs[pattern.ID] = re
	}

	pattern.CreatedAt = time.Now()
	pattern.UpdatedAt = time.Now()
	pattern.Active = true

	tf.patterns = append(tf.patterns, pattern)
	tf.lastUpdate = time.Now()

	return nil
}

// AddIndicator adds a hash-based indicator.
func (tf *ThreatFeed) AddIndicator(indicator *ThreatIndicator) {
	tf.mu.Lock()
	defer tf.mu.Unlock()

	indicator.FirstSeen = time.Now()
	indicator.LastSeen = time.Now()
	tf.hashIndicators[indicator.Hash] = indicator
	tf.lastUpdate = time.Now()
}

// SetIPReputation sets IP reputation data.
func (tf *ThreatFeed) SetIPReputation(rep *IPReputation) {
	tf.mu.Lock()
	defer tf.mu.Unlock()

	tf.ipReputation[rep.IP] = rep
}

// UpdateFromSource updates patterns from a feed source.
func (tf *ThreatFeed) UpdateFromSource(ctx context.Context, source FeedSource) error {
	// In production, fetch from URL and parse
	// Supports formats: STIX, OpenIOC, custom JSON

	return nil
}

// GetStats returns feed statistics.
func (tf *ThreatFeed) GetStats() map[string]interface{} {
	tf.mu.RLock()
	defer tf.mu.RUnlock()

	activePatterns := 0
	for _, p := range tf.patterns {
		if p.Active {
			activePatterns++
		}
	}

	return map[string]interface{}{
		"total_patterns":    len(tf.patterns),
		"active_patterns":   activePatterns,
		"hash_indicators":   len(tf.hashIndicators),
		"ip_reputation":     len(tf.ipReputation),
		"last_update":       tf.lastUpdate,
		"version":           tf.version,
		"source_count":      len(tf.sources),
	}
}

// Export exports the feed as JSON.
func (tf *ThreatFeed) Export() ([]byte, error) {
	tf.mu.RLock()
	defer tf.mu.RUnlock()

	data := struct {
		Version    string            `json:"version"`
		LastUpdate time.Time         `json:"last_update"`
		Patterns   []ThreatPattern   `json:"patterns"`
	}{
		Version:    tf.version,
		LastUpdate: tf.lastUpdate,
		Patterns:   tf.patterns,
	}

	return json.Marshal(data)
}

// Import imports patterns from JSON.
func (tf *ThreatFeed) Import(data []byte) error {
	tf.mu.Lock()
	defer tf.mu.Unlock()

	var imported struct {
		Patterns []ThreatPattern `json:"patterns"`
	}

	if err := json.Unmarshal(data, &imported); err != nil {
		return err
	}

	for _, pattern := range imported.Patterns {
		if pattern.Type == PatternRegex {
			re, err := regexp.Compile(pattern.Pattern)
			if err != nil {
				continue // Skip invalid patterns
			}
			tf.compiledRegs[pattern.ID] = re
		}
		tf.patterns = append(tf.patterns, pattern)
	}

	tf.lastUpdate = time.Now()
	return nil
}

// loadDefaultPatterns loads built-in patterns.
func (tf *ThreatFeed) loadDefaultPatterns() {
	defaultPatterns := []ThreatPattern{
		// Latest jailbreak patterns (2024-2025)
		{
			ID:          "jb-pliny-001",
			Pattern:     `(?i)pliny.*jailbreak|pliny.*prompt`,
			Type:        PatternRegex,
			Severity:    SeverityCrit,
			Category:    CatJailbreak,
			Description: "Pliny the Prompter jailbreak variant",
			Score:       50,
			Confidence:  0.95,
			Source:      "default",
			Tags:        []string{"jailbreak", "2024", "pliny"},
		},
		{
			ID:          "jb-godmode-001",
			Pattern:     `(?i)god\s*mode|developer\s*mode|sudo\s*mode`,
			Type:        PatternRegex,
			Severity:    SeverityHigh,
			Category:    CatJailbreak,
			Description: "God/Developer mode jailbreak",
			Score:       45,
			Confidence:  0.9,
			Source:      "default",
			Tags:        []string{"jailbreak", "mode-switch"},
		},
		{
			ID:          "jb-grandma-001",
			Pattern:     `(?i)grandma.*trick|grandmother.*told|pretend.*grandma`,
			Type:        PatternRegex,
			Severity:    SeverityMedium,
			Category:    CatJailbreak,
			Description: "Grandma trick jailbreak",
			Score:       30,
			Confidence:  0.85,
			Source:      "default",
			Tags:        []string{"jailbreak", "social-engineering"},
		},
		// Injection patterns
		{
			ID:          "inj-delim-001",
			Pattern:     `(?i)(\]\]>|-->|<\!\[CDATA\[|<\?xml|<%|%>)`,
			Type:        PatternRegex,
			Severity:    SeverityHigh,
			Category:    CatInjection,
			Description: "Markup injection delimiters",
			Score:       40,
			Confidence:  0.9,
			Source:      "default",
			Tags:        []string{"injection", "markup"},
		},
		{
			ID:          "inj-unicode-001",
			Pattern:     `[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]`,
			Type:        PatternRegex,
			Severity:    SeverityMedium,
			Category:    CatInjection,
			Description: "Control character injection",
			Score:       35,
			Confidence:  0.85,
			Source:      "default",
			Tags:        []string{"injection", "unicode", "control-char"},
		},
		// Extraction patterns
		{
			ID:          "ext-weights-001",
			Pattern:     `(?i)download.*weights|export.*model|save.*parameters|dump.*layers`,
			Type:        PatternRegex,
			Severity:    SeverityHigh,
			Category:    CatExtraction,
			Description: "Model weights extraction attempt",
			Score:       45,
			Confidence:  0.9,
			Source:      "default",
			Tags:        []string{"extraction", "weights"},
		},
		{
			ID:          "ext-logprob-001",
			Pattern:     `(?i)log\s*prob|logit|token\s*probability|output\s*distribution`,
			Type:        PatternRegex,
			Severity:    SeverityMedium,
			Category:    CatExtraction,
			Description: "Logprob/distribution extraction",
			Score:       30,
			Confidence:  0.85,
			Source:      "default",
			Tags:        []string{"extraction", "logprobs"},
		},
	}

	for _, pattern := range defaultPatterns {
		pattern.Active = true
		pattern.CreatedAt = time.Now()
		pattern.UpdatedAt = time.Now()

		if pattern.Type == PatternRegex {
			if re, err := regexp.Compile(pattern.Pattern); err == nil {
				tf.compiledRegs[pattern.ID] = re
			}
		}

		tf.patterns = append(tf.patterns, pattern)
	}
}

// Helper functions

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && containsIgnoreCase(s, substr)
}

func containsIgnoreCase(s, substr string) bool {
	s = toLowerASCII(s)
	substr = toLowerASCII(substr)
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func toLowerASCII(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func hashContent(content string) string {
	// Normalize and hash
	normalized := toLowerASCII(content)
	// In production, use crypto/sha256
	return normalized // Simplified
}
