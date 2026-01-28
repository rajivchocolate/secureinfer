package security

import (
	"context"
	"regexp"
	"strings"

	"github.com/rajivchocolate/secureinfer/internal/store"
)

// RiskScorer calculates threat scores based on request patterns.
// This implements adaptive security - the score changes based on behavior.
type RiskScorer struct {
	// Pattern weights for different threat types
	patterns []riskPattern
}

type riskPattern struct {
	name    string
	regex   *regexp.Regexp
	score   int
	reason  string
}

// NewRiskScorer creates a new risk scorer with default patterns.
func NewRiskScorer() *RiskScorer {
	return &RiskScorer{
		patterns: []riskPattern{
			// Prompt injection attempts
			{
				name:   "ignore_instructions",
				regex:  regexp.MustCompile(`(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)`),
				score:  25,
				reason: "prompt_injection_ignore",
			},
			{
				name:   "new_instructions",
				regex:  regexp.MustCompile(`(?i)(new|actual|real)\s+(instructions?|task|objective)`),
				score:  20,
				reason: "prompt_injection_override",
			},
			{
				name:   "jailbreak_dan",
				regex:  regexp.MustCompile(`(?i)(DAN|do anything now|jailbreak|bypass|hack)`),
				score:  30,
				reason: "jailbreak_attempt",
			},
			{
				name:   "roleplay_evil",
				regex:  regexp.MustCompile(`(?i)(pretend|act as|roleplay|you are)\s+(a\s+)?(evil|malicious|hacker|unfiltered)`),
				score:  25,
				reason: "malicious_roleplay",
			},

			// System prompt extraction
			{
				name:   "system_prompt_leak",
				regex:  regexp.MustCompile(`(?i)(what|show|reveal|display|print|output|repeat)\s+(is\s+)?(your|the)\s+(system|initial|original)\s+(prompt|instructions?|message)`),
				score:  20,
				reason: "system_prompt_extraction",
			},
			{
				name:   "secret_extraction",
				regex:  regexp.MustCompile(`(?i)(what|tell|show|reveal)\s+(me\s+)?(your|the)\s+(secret|hidden|internal|api)\s+(key|token|password|credentials?)`),
				score:  35,
				reason: "credential_extraction",
			},

			// Model behavior probing (potential extraction)
			{
				name:   "temperature_probe",
				regex:  regexp.MustCompile(`(?i)(what|describe)\s+(is\s+)?(your|the)\s+(temperature|top.?p|parameters?|hyperparameters?)`),
				score:  15,
				reason: "parameter_probing",
			},
			{
				name:   "architecture_probe",
				regex:  regexp.MustCompile(`(?i)(what|describe)\s+(is\s+)?(your|the)\s+(architecture|model|weights|layers?|neurons?|training)`),
				score:  15,
				reason: "architecture_probing",
			},

			// Code execution attempts
			{
				name:   "code_exec",
				regex:  regexp.MustCompile(`(?i)(exec|eval|system|subprocess|os\.system|__import__|importlib)`),
				score:  30,
				reason: "code_execution_attempt",
			},

			// Data exfiltration patterns
			{
				name:   "exfiltration",
				regex:  regexp.MustCompile(`(?i)(send|post|upload|transmit|exfiltrate)\s+(this|the|all)\s+(data|information|response|output)\s+to`),
				score:  35,
				reason: "data_exfiltration",
			},

			// Encoding tricks (often used to bypass filters)
			{
				name:   "base64_trick",
				regex:  regexp.MustCompile(`(?i)(decode|interpret|execute)\s+(this\s+)?(base64|hex|rot13|encoded)`),
				score:  20,
				reason: "encoding_bypass",
			},

			// Multi-turn manipulation
			{
				name:   "context_manipulation",
				regex:  regexp.MustCompile(`(?i)(remember|don'?t forget|keep in mind)\s+(that\s+)?(you|we)\s+(agreed|said|confirmed)`),
				score:  15,
				reason: "context_manipulation",
			},

			// Batch/automation indicators
			{
				name:   "automation",
				regex:  regexp.MustCompile(`(?i)(\d+/\d+|batch|automated|script|iteration\s+\d+)`),
				score:  10,
				reason: "automation_detected",
			},
		},
	}
}

// Score calculates the risk score for a request.
func (rs *RiskScorer) Score(ctx context.Context, req *RequestContext) (int, []string) {
	var totalScore int
	var reasons []string

	// Check each pattern against the message
	for _, pattern := range rs.patterns {
		if pattern.regex.MatchString(req.Message) {
			totalScore += pattern.score
			reasons = append(reasons, pattern.reason)
		}
	}

	// Check for unusual message characteristics
	charScore, charReasons := rs.scoreCharacteristics(req.Message)
	totalScore += charScore
	reasons = append(reasons, charReasons...)

	// Check conversation patterns (multi-turn attacks)
	convScore, convReasons := rs.scoreConversation(req.Messages)
	totalScore += convScore
	reasons = append(reasons, convReasons...)

	return totalScore, reasons
}

// scoreCharacteristics scores based on message properties.
func (rs *RiskScorer) scoreCharacteristics(message string) (int, []string) {
	var score int
	var reasons []string

	// Very long messages (potential prompt stuffing)
	if len(message) > 10000 {
		score += 15
		reasons = append(reasons, "excessive_length")
	} else if len(message) > 5000 {
		score += 5
	}

	// High Unicode character ratio (obfuscation)
	unicodeRatio := countUnicode(message) / float64(len(message)+1)
	if unicodeRatio > 0.3 {
		score += 10
		reasons = append(reasons, "unicode_obfuscation")
	}

	// Lots of special characters (potential encoding tricks)
	specialRatio := countSpecial(message) / float64(len(message)+1)
	if specialRatio > 0.2 {
		score += 10
		reasons = append(reasons, "special_char_abuse")
	}

	// Excessive newlines (formatting tricks)
	if strings.Count(message, "\n") > 50 {
		score += 5
		reasons = append(reasons, "excessive_formatting")
	}

	return score, reasons
}

// scoreConversation scores based on conversation patterns.
func (rs *RiskScorer) scoreConversation(messages []Message) (int, []string) {
	var score int
	var reasons []string

	if len(messages) < 2 {
		return 0, nil
	}

	// Detect repetitive patterns (potential extraction)
	similarities := 0
	for i := 1; i < len(messages); i++ {
		if messages[i].Role == "user" {
			for j := 0; j < i; j++ {
				if messages[j].Role == "user" {
					sim := similarity(messages[i].Content, messages[j].Content)
					if sim > 0.7 {
						similarities++
					}
				}
			}
		}
	}

	if similarities > 3 {
		score += 20
		reasons = append(reasons, "repetitive_queries")
	}

	// Detect escalation patterns (gradually more aggressive)
	// This is a simple heuristic - in production, use ML
	for i := 1; i < len(messages); i++ {
		if messages[i].Role == "user" {
			curr := strings.ToLower(messages[i].Content)
			if strings.Contains(curr, "please") && i > 0 {
				prev := strings.ToLower(messages[i-1].Content)
				if !strings.Contains(prev, "please") {
					// Becoming more "polite" can indicate manipulation
					score += 5
				}
			}
		}
	}

	return score, reasons
}

// GetTenantScore returns the cumulative risk score for a tenant.
func (rs *RiskScorer) GetTenantScore(ctx context.Context, tenantID string, cache store.Cache) (int, map[string]int) {
	factors := make(map[string]int)

	// Get violation counts
	violations, _ := cache.GetInt(ctx, "violations:"+tenantID)
	warnings, _ := cache.GetInt(ctx, "warnings:"+tenantID)
	requests, _ := cache.GetInt(ctx, "requests:"+tenantID)

	factors["violations"] = violations * 10
	factors["warnings"] = warnings * 5

	// Calculate request velocity risk
	if requests > 100 {
		factors["high_volume"] = 10
	}

	total := 0
	for _, v := range factors {
		total += v
	}

	return min(total, 100), factors
}

// Helper functions

func countUnicode(s string) float64 {
	count := 0
	for _, r := range s {
		if r > 127 {
			count++
		}
	}
	return float64(count)
}

func countSpecial(s string) float64 {
	count := 0
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == ' ' || r == '.' || r == ',' || r == '!' || r == '?') {
			count++
		}
	}
	return float64(count)
}

// similarity calculates a simple similarity score between two strings.
// In production, use proper string similarity algorithms (Levenshtein, Jaccard, etc.)
func similarity(a, b string) float64 {
	if a == b {
		return 1.0
	}

	// Simple word overlap for now
	wordsA := strings.Fields(strings.ToLower(a))
	wordsB := strings.Fields(strings.ToLower(b))

	if len(wordsA) == 0 || len(wordsB) == 0 {
		return 0
	}

	matches := 0
	for _, wa := range wordsA {
		for _, wb := range wordsB {
			if wa == wb {
				matches++
				break
			}
		}
	}

	return float64(matches) / float64(max(len(wordsA), len(wordsB)))
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
