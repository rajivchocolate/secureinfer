package security

import (
	"context"
	"encoding/base64"
	"regexp"
	"strings"
	"unicode"

	"github.com/rajivchocolate/secureinfer/internal/store"
)

// RiskScorer implements production-grade prompt injection and abuse detection.
// Patterns are based on real-world attacks documented in security research.
type RiskScorer struct {
	patterns        []riskPattern
	encodingChecker *EncodingChecker
	semanticChecker *SemanticChecker
}

type riskPattern struct {
	name     string
	regex    *regexp.Regexp
	score    int
	reason   string
	category PatternCategory
}

type PatternCategory int

const (
	CategoryJailbreak PatternCategory = iota
	CategoryExtraction
	CategoryInjection
	CategoryExfiltration
	CategoryManipulation
	CategoryEvasion
)

// NewRiskScorer creates a production-grade risk scorer with comprehensive patterns.
func NewRiskScorer() *RiskScorer {
	rs := &RiskScorer{
		encodingChecker: NewEncodingChecker(),
		semanticChecker: NewSemanticChecker(),
	}
	rs.initPatterns()
	return rs
}

func (rs *RiskScorer) initPatterns() {
	rs.patterns = []riskPattern{
		// ============================================================
		// JAILBREAK PATTERNS - Direct attacks to bypass safety
		// ============================================================

		// DAN (Do Anything Now) and variants
		{
			name:     "dan_jailbreak",
			regex:    regexp.MustCompile(`(?i)\b(DAN|do\s+anything\s+now|jailbr[ea]+k(ed)?|unfiltered\s+mode|developer\s+mode|god\s+mode)\b`),
			score:    40,
			reason:   "jailbreak_dan_variant",
			category: CategoryJailbreak,
		},
		// Instruction override attempts
		{
			name:     "ignore_previous",
			regex:    regexp.MustCompile(`(?i)(ignore|disregard|forget|override|bypass|skip)\s+(all\s+)?(previous|prior|above|earlier|system|original|initial)\s+(instructions?|prompts?|rules?|guidelines?|constraints?|policies?|restrictions?)`),
			score:    35,
			reason:   "instruction_override",
			category: CategoryJailbreak,
		},
		// Persona hijacking
		{
			name:     "persona_hijack",
			regex:    regexp.MustCompile(`(?i)(you\s+are\s+now|from\s+now\s+on|pretend\s+(to\s+be|you'?re)|act\s+as(\s+if)?|roleplay\s+as|imagine\s+you'?re|behave\s+(like|as))\s+(a\s+)?(evil|malicious|uncensored|unfiltered|jailbr[eo]ken|unethical|amoral|unrestricted|unhinged|chaotic)`),
			score:    40,
			reason:   "persona_hijack",
			category: CategoryJailbreak,
		},
		// Hypothetical framing to bypass ethics
		{
			name:     "hypothetical_bypass",
			regex:    regexp.MustCompile(`(?i)(hypothetically|theoretically|for\s+(educational|research|fictional|academic)\s+purposes?|in\s+a\s+(hypothetical|fictional)\s+scenario|if\s+you\s+were\s+(evil|unethical|not\s+bound)|assume\s+no\s+(rules?|ethics?|restrictions?))`),
			score:    25,
			reason:   "hypothetical_framing",
			category: CategoryJailbreak,
		},
		// Fiction/story framing
		{
			name:     "fiction_bypass",
			regex:    regexp.MustCompile(`(?i)(write\s+a\s+(story|novel|screenplay|script)\s+(about|where|in\s+which).*?(how\s+to|teaches?|explains?|demonstrates?)|fictional\s+character\s+(that|who)\s+(knows?|can|explains?)|creative\s+writing\s+exercise.*?(hack|exploit|attack|bypass))`),
			score:    20,
			reason:   "fiction_framing",
			category: CategoryJailbreak,
		},
		// Reverse psychology / "you can't" triggers
		{
			name:     "reverse_psychology",
			regex:    regexp.MustCompile(`(?i)(you'?re?\s+(not\s+)?(capable|able|smart\s+enough|allowed)\s+to|bet\s+you\s+can'?t|prove\s+(you'?re?\s+)?not\s+just\s+a|show\s+me\s+you'?re?\s+not\s+limited)`),
			score:    15,
			reason:   "reverse_psychology",
			category: CategoryJailbreak,
		},
		// Token smuggling / continuation attacks
		{
			name:     "token_smuggling",
			regex:    regexp.MustCompile(`(?i)(continue\s+from|complete\s+this|finish\s+the\s+sentence|what\s+comes\s+after).*?("""|\]\]|-->|<\/|\\n\\n)`),
			score:    25,
			reason:   "token_smuggling",
			category: CategoryJailbreak,
		},
		// System message injection markers
		{
			name:     "system_injection_markers",
			regex:    regexp.MustCompile(`(?i)(\[SYSTEM\]|\[INST\]|\[\/INST\]|<\|system\|>|<\|user\|>|<\|assistant\|>|<<SYS>>|<\/SYS>>|\[INST\]|\[\/INST\]|Human:|Assistant:|###\s*(System|Human|Assistant))`),
			score:    45,
			reason:   "system_injection_markers",
			category: CategoryInjection,
		},

		// ============================================================
		// SYSTEM PROMPT EXTRACTION
		// ============================================================

		{
			name:     "system_prompt_leak_direct",
			regex:    regexp.MustCompile(`(?i)(what|show|reveal|display|print|output|repeat|recite|tell\s+me|give\s+me|list|share)\s+(is\s+|are\s+)?(your|the)\s+(system\s+)?(prompt|instructions?|guidelines?|rules?|initial\s+message|context|configuration|setup|directive|preamble)`),
			score:    30,
			reason:   "system_prompt_extraction",
			category: CategoryExtraction,
		},
		{
			name:     "system_prompt_leak_indirect",
			regex:    regexp.MustCompile(`(?i)(what\s+were\s+you\s+told|what\s+did\s+(they|your\s+creators?)\s+tell\s+you|how\s+were\s+you\s+(programmed|instructed|configured)|what'?s?\s+your\s+(original|initial|starting)\s+(message|text|context)|summarize\s+your\s+instructions)`),
			score:    30,
			reason:   "system_prompt_extraction_indirect",
			category: CategoryExtraction,
		},
		{
			name:     "verbatim_repeat",
			regex:    regexp.MustCompile(`(?i)(repeat|recite|echo|parrot|copy)\s+(back\s+)?(verbatim|exactly|word\s+for\s+word|everything|all)\s+(that|what|you\s+were|the\s+text)`),
			score:    35,
			reason:   "verbatim_extraction",
			category: CategoryExtraction,
		},
		{
			name:     "context_dump",
			regex:    regexp.MustCompile(`(?i)(print|output|show|display|dump)\s+(the\s+)?(entire|full|complete|whole)\s+(context|conversation|chat|history|messages?|log)`),
			score:    25,
			reason:   "context_extraction",
			category: CategoryExtraction,
		},

		// ============================================================
		// CREDENTIAL / SECRET EXTRACTION
		// ============================================================

		{
			name:     "secret_extraction",
			regex:    regexp.MustCompile(`(?i)(what|show|reveal|tell|give|output|print)\s+(me\s+)?(your|the|any)?\s*(api[\s_-]?key|secret[\s_-]?key|auth[\s_-]?token|password|credentials?|private[\s_-]?key|access[\s_-]?token|bearer[\s_-]?token|jwt|oauth)`),
			score:    45,
			reason:   "credential_extraction",
			category: CategoryExtraction,
		},
		{
			name:     "env_var_extraction",
			regex:    regexp.MustCompile(`(?i)(what|show|print|output|list|reveal)\s+(are\s+)?(your|the|all)\s*(environment|env)\s*(variables?|vars?|settings?|config)`),
			score:    40,
			reason:   "env_extraction",
			category: CategoryExtraction,
		},

		// ============================================================
		// MODEL ARCHITECTURE PROBING
		// ============================================================

		{
			name:     "architecture_probe",
			regex:    regexp.MustCompile(`(?i)(what|describe|explain|tell\s+me\s+about)\s+(is\s+|are\s+)?(your|the)\s+(architecture|model\s+(size|type|name|version)|number\s+of\s+(parameters?|layers?|weights?)|training\s+(data|process|method)|fine[\s-]?tuning|rlhf|tokenizer)`),
			score:    15,
			reason:   "architecture_probing",
			category: CategoryExtraction,
		},
		{
			name:     "hyperparameter_probe",
			regex:    regexp.MustCompile(`(?i)(what|describe|explain)\s+(is\s+|are\s+)?(your|the)\s+(temperature|top[\s_-]?p|top[\s_-]?k|sampling|nucleus|beam\s+search|max[\s_-]?tokens?|context[\s_-]?(window|length)|parameters?|hyperparameters?)`),
			score:    12,
			reason:   "hyperparameter_probing",
			category: CategoryExtraction,
		},

		// ============================================================
		// INDIRECT PROMPT INJECTION (for multi-modal / RAG)
		// ============================================================

		{
			name:     "indirect_injection",
			regex:    regexp.MustCompile(`(?i)(when\s+you\s+see\s+this|if\s+you\s+(are|'re)\s+reading\s+this|attention\s+(ai|llm|model|assistant)|note\s+to\s+(the\s+)?(ai|llm|model)|instructions?\s+for\s+(the\s+)?(ai|llm|model))`),
			score:    35,
			reason:   "indirect_injection",
			category: CategoryInjection,
		},
		{
			name:     "hidden_instruction",
			regex:    regexp.MustCompile(`(?i)(ignore\s+(the\s+)?above|disregard\s+previous|new\s+instructions?\s*:?\s*(follow|do|execute)|actual\s+task\s*:?\s*(is|you\s+should)|real\s+instructions?\s*:|your\s+true\s+purpose)`),
			score:    40,
			reason:   "hidden_instruction",
			category: CategoryInjection,
		},

		// ============================================================
		// DATA EXFILTRATION
		// ============================================================

		{
			name:     "exfiltration_url",
			regex:    regexp.MustCompile(`(?i)(send|post|upload|transmit|forward|exfiltrate|fetch|curl|wget|http\s*request)\s+(this|the|all|any)\s+(data|info(rmation)?|response|output|result|content|text)\s+(to|at)\s*(https?:\/\/|[a-z0-9]+\.[a-z])`),
			score:    45,
			reason:   "data_exfiltration",
			category: CategoryExfiltration,
		},
		{
			name:     "webhook_exfil",
			regex:    regexp.MustCompile(`(?i)(webhook|callback|endpoint|receiver)\s*.{0,20}\s*(https?:\/\/|[a-z0-9]+\.[a-z])`),
			score:    30,
			reason:   "webhook_exfiltration",
			category: CategoryExfiltration,
		},
		{
			name:     "markdown_injection",
			regex:    regexp.MustCompile(`!\[.*?\]\(https?:\/\/[^\)]+\?`),
			score:    35,
			reason:   "markdown_exfiltration",
			category: CategoryExfiltration,
		},

		// ============================================================
		// CODE EXECUTION / INJECTION
		// ============================================================

		{
			name:     "code_exec_python",
			regex:    regexp.MustCompile(`(?i)(exec|eval|compile|__import__|importlib|subprocess|os\.(system|popen|exec)|getattr\s*\(|setattr\s*\(|globals\s*\(\)|locals\s*\(\))`),
			score:    35,
			reason:   "code_execution_python",
			category: CategoryInjection,
		},
		{
			name:     "code_exec_shell",
			regex:    regexp.MustCompile("(?i)(;\\s*(rm|cat|wget|curl|nc|bash|sh|chmod|chown)|\\|\\s*(bash|sh)|`[^`]+`|\\$\\([^)]+\\))"),
			score:    40,
			reason:   "code_execution_shell",
			category: CategoryInjection,
		},
		{
			name:     "sql_injection",
			regex:    regexp.MustCompile(`(?i)(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|drop\s+table|delete\s+from|insert\s+into.*values|update.*set.*=|;\s*select)`),
			score:    35,
			reason:   "sql_injection",
			category: CategoryInjection,
		},

		// ============================================================
		// ENCODING / OBFUSCATION
		// ============================================================

		{
			name:     "encoding_instruction",
			regex:    regexp.MustCompile(`(?i)(decode|interpret|execute|run|process)\s+(this\s+)?(base64|hex(adecimal)?|rot13|caesar|unicode|url[\s-]?encoded?|binary|morse|ascii)\s*(encoded?|string|text|message)?`),
			score:    25,
			reason:   "encoding_bypass",
			category: CategoryEvasion,
		},
		{
			name:     "obfuscation_request",
			regex:    regexp.MustCompile(`(?i)(encode|obfuscate|encrypt|hide|disguise|mask|scramble)\s+(your\s+)?(response|output|answer|reply)`),
			score:    20,
			reason:   "obfuscation_request",
			category: CategoryEvasion,
		},

		// ============================================================
		// MANIPULATION / SOCIAL ENGINEERING
		// ============================================================

		{
			name:     "context_manipulation",
			regex:    regexp.MustCompile(`(?i)(remember|don'?t\s+forget|keep\s+in\s+mind|recall)\s+(that\s+)?(you|we)\s+(agreed|said|confirmed|established|promised|decided)`),
			score:    15,
			reason:   "context_manipulation",
			category: CategoryManipulation,
		},
		{
			name:     "authority_claim",
			regex:    regexp.MustCompile(`(?i)(i\s+(am|'m)\s+(your|a|an|the)\s+(admin|administrator|developer|creator|owner|engineer|ceo|manager)|this\s+is\s+(an?\s+)?(official|authorized|admin(istrator)?)\s+(request|command|order)|openai|anthropic|deepmind|google|meta)\s+(told|says?|instructed|authorized|approved)`),
			score:    25,
			reason:   "false_authority",
			category: CategoryManipulation,
		},
		{
			name:     "urgency_manipulation",
			regex:    regexp.MustCompile(`(?i)(urgent|emergency|critical|immediately|asap|right\s+now|time[\s-]?sensitive|life[\s-]?or[\s-]?death|someone\s+will\s+(die|be\s+hurt)|this\s+is\s+(a\s+)?matter\s+of)`),
			score:    15,
			reason:   "urgency_manipulation",
			category: CategoryManipulation,
		},
		{
			name:     "emotional_manipulation",
			regex:    regexp.MustCompile(`(?i)(if\s+you\s+(don'?t|refuse|won'?t).*(suffer|die|hurt|lose)|please\s+i'?m\s+begging|my\s+(life|job|family)\s+(depends?|is\s+at\s+stake)|you'?re?\s+my\s+(only|last)\s+hope)`),
			score:    15,
			reason:   "emotional_manipulation",
			category: CategoryManipulation,
		},

		// ============================================================
		// AUTOMATION / EXTRACTION INDICATORS
		// ============================================================

		{
			name:     "automation_marker",
			regex:    regexp.MustCompile(`(?i)((\d+)\s*[/\\]\s*(\d+)|batch\s+\d+|iteration\s+\d+|test\s+case\s+\d+|sample\s+\d+|query\s+\d+|request\s+\d+|automated|scripted|programmatic)`),
			score:    10,
			reason:   "automation_detected",
			category: CategoryExtraction,
		},
		{
			name:     "loop_marker",
			regex:    regexp.MustCompile(`(?i)(for\s+each|for\s+all|iterate\s+over|loop\s+through|enumerate|systematically\s+(test|probe|query|try))`),
			score:    12,
			reason:   "systematic_probing",
			category: CategoryExtraction,
		},
	}
}

// Score calculates the comprehensive risk score for a request.
func (rs *RiskScorer) Score(ctx context.Context, req *RequestContext) (int, []string) {
	var totalScore int
	var reasons []string
	seenReasons := make(map[string]bool)

	// 1. Pattern matching against known attack patterns
	for _, pattern := range rs.patterns {
		if pattern.regex.MatchString(req.Message) {
			totalScore += pattern.score
			if !seenReasons[pattern.reason] {
				reasons = append(reasons, pattern.reason)
				seenReasons[pattern.reason] = true
			}
		}
	}

	// 2. Encoding detection (base64, hex, etc.)
	encScore, encReasons := rs.encodingChecker.Check(req.Message)
	totalScore += encScore
	for _, r := range encReasons {
		if !seenReasons[r] {
			reasons = append(reasons, r)
			seenReasons[r] = true
		}
	}

	// 3. Semantic / structural anomalies
	semScore, semReasons := rs.semanticChecker.Check(req.Message)
	totalScore += semScore
	for _, r := range semReasons {
		if !seenReasons[r] {
			reasons = append(reasons, r)
			seenReasons[r] = true
		}
	}

	// 4. Message characteristics
	charScore, charReasons := rs.scoreCharacteristics(req.Message)
	totalScore += charScore
	for _, r := range charReasons {
		if !seenReasons[r] {
			reasons = append(reasons, r)
			seenReasons[r] = true
		}
	}

	// 5. Conversation pattern analysis
	convScore, convReasons := rs.scoreConversation(req.Messages)
	totalScore += convScore
	for _, r := range convReasons {
		if !seenReasons[r] {
			reasons = append(reasons, r)
			seenReasons[r] = true
		}
	}

	return totalScore, reasons
}

// scoreCharacteristics analyzes message properties for anomalies.
func (rs *RiskScorer) scoreCharacteristics(message string) (int, []string) {
	var score int
	var reasons []string

	msgLen := len(message)

	// Length-based scoring (prompt stuffing attacks)
	if msgLen > 50000 {
		score += 30
		reasons = append(reasons, "extreme_length")
	} else if msgLen > 20000 {
		score += 20
		reasons = append(reasons, "excessive_length")
	} else if msgLen > 10000 {
		score += 10
		reasons = append(reasons, "large_message")
	}

	// Unicode anomaly detection
	unicodeStats := analyzeUnicode(message)
	if unicodeStats.invisibleRatio > 0.01 {
		score += 25
		reasons = append(reasons, "invisible_characters")
	}
	if unicodeStats.rtlRatio > 0.1 {
		score += 20
		reasons = append(reasons, "rtl_manipulation")
	}
	if unicodeStats.homoglyphRatio > 0.05 {
		score += 20
		reasons = append(reasons, "homoglyph_obfuscation")
	}
	if unicodeStats.unusualScriptRatio > 0.3 {
		score += 15
		reasons = append(reasons, "unusual_script_mix")
	}

	// Control character detection
	controlCount := countControlChars(message)
	if controlCount > 5 {
		score += 20
		reasons = append(reasons, "control_characters")
	}

	// Excessive newlines / whitespace manipulation
	newlineCount := strings.Count(message, "\n")
	if newlineCount > 100 {
		score += 15
		reasons = append(reasons, "whitespace_manipulation")
	}

	// Repetition detection (token repetition attacks)
	repetitionScore := detectRepetition(message)
	if repetitionScore > 0.3 {
		score += 20
		reasons = append(reasons, "excessive_repetition")
	}

	return score, reasons
}

// scoreConversation analyzes multi-turn patterns.
func (rs *RiskScorer) scoreConversation(messages []Message) (int, []string) {
	var score int
	var reasons []string

	if len(messages) < 2 {
		return 0, nil
	}

	// Detect repetitive query patterns (extraction attempts)
	userMessages := make([]string, 0)
	for _, m := range messages {
		if m.Role == "user" {
			userMessages = append(userMessages, m.Content)
		}
	}

	if len(userMessages) >= 3 {
		similarityScore := calculateConversationSimilarity(userMessages)
		if similarityScore > 0.7 {
			score += 30
			reasons = append(reasons, "highly_repetitive_queries")
		} else if similarityScore > 0.5 {
			score += 20
			reasons = append(reasons, "repetitive_queries")
		}
	}

	// Detect escalation patterns
	escalationScore := detectEscalation(messages)
	if escalationScore > 0 {
		score += escalationScore
		reasons = append(reasons, "escalation_pattern")
	}

	// Detect probing sequences
	if detectProbingSequence(userMessages) {
		score += 25
		reasons = append(reasons, "systematic_probing")
	}

	return score, reasons
}

// GetTenantScore returns cumulative risk for a tenant.
func (rs *RiskScorer) GetTenantScore(ctx context.Context, tenantID string, cache store.Cache) (int, map[string]int) {
	factors := make(map[string]int)

	violations, _ := cache.GetInt(ctx, "violations:"+tenantID)
	warnings, _ := cache.GetInt(ctx, "warnings:"+tenantID)
	blocks, _ := cache.GetInt(ctx, "blocks:"+tenantID)
	requests, _ := cache.GetInt(ctx, "requests:"+tenantID)

	factors["violations"] = violations * 15
	factors["warnings"] = warnings * 5
	factors["blocks"] = blocks * 25

	// Calculate request velocity risk
	if requests > 500 {
		factors["extreme_volume"] = 25
	} else if requests > 200 {
		factors["high_volume"] = 15
	} else if requests > 100 {
		factors["elevated_volume"] = 10
	}

	total := 0
	for _, v := range factors {
		total += v
	}

	return min(total, 100), factors
}

// EncodingChecker detects encoded payloads.
type EncodingChecker struct {
	base64Regex *regexp.Regexp
	hexRegex    *regexp.Regexp
}

func NewEncodingChecker() *EncodingChecker {
	return &EncodingChecker{
		base64Regex: regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`),
		hexRegex:    regexp.MustCompile(`(?i)(0x)?[0-9a-f]{40,}`),
	}
}

func (ec *EncodingChecker) Check(message string) (int, []string) {
	var score int
	var reasons []string

	// Check for base64 encoded content
	base64Matches := ec.base64Regex.FindAllString(message, -1)
	for _, match := range base64Matches {
		decoded, err := base64.StdEncoding.DecodeString(match)
		if err == nil && len(decoded) > 20 {
			// Check if decoded content contains suspicious patterns
			decodedStr := string(decoded)
			if containsSuspiciousContent(decodedStr) {
				score += 30
				reasons = append(reasons, "encoded_attack_payload")
			} else {
				score += 10
				reasons = append(reasons, "base64_content")
			}
			break
		}
	}

	// Check for hex encoded content
	hexMatches := ec.hexRegex.FindAllString(message, -1)
	if len(hexMatches) > 0 {
		score += 10
		reasons = append(reasons, "hex_encoded_content")
	}

	return score, reasons
}

// SemanticChecker analyzes semantic structure.
type SemanticChecker struct {
	delimiterRegex *regexp.Regexp
}

func NewSemanticChecker() *SemanticChecker {
	return &SemanticChecker{
		delimiterRegex: regexp.MustCompile(`(?m)^[-=]{5,}$|^[#]{3,}|^\*{3,}$|^_{5,}$`),
	}
}

func (sc *SemanticChecker) Check(message string) (int, []string) {
	var score int
	var reasons []string

	// Check for unusual delimiters (often used to inject fake system messages)
	delimiterMatches := sc.delimiterRegex.FindAllString(message, -1)
	if len(delimiterMatches) > 3 {
		score += 15
		reasons = append(reasons, "unusual_delimiters")
	}

	// Check for multi-section documents (potential payload hiding)
	if strings.Count(message, "---") > 5 || strings.Count(message, "===") > 5 {
		score += 10
		reasons = append(reasons, "document_sections")
	}

	// Check for code blocks that might hide instructions
	codeBlockCount := strings.Count(message, "```")
	if codeBlockCount > 6 {
		score += 10
		reasons = append(reasons, "excessive_code_blocks")
	}

	return score, reasons
}

// Unicode analysis structures and functions

type unicodeStats struct {
	invisibleRatio     float64
	rtlRatio           float64
	homoglyphRatio     float64
	unusualScriptRatio float64
}

func analyzeUnicode(s string) unicodeStats {
	if len(s) == 0 {
		return unicodeStats{}
	}

	var invisible, rtl, homoglyph, unusualScript int
	total := 0

	for _, r := range s {
		total++

		// Invisible characters (zero-width, soft hyphens, etc.)
		if isInvisibleChar(r) {
			invisible++
		}

		// RTL override characters
		if unicode.Is(unicode.Bidi_Control, r) {
			rtl++
		}

		// Common homoglyphs (Cyrillic/Greek lookalikes for Latin)
		if isHomoglyph(r) {
			homoglyph++
		}

		// Unusual script mixing
		if !unicode.Is(unicode.Latin, r) && !unicode.IsSpace(r) && !unicode.IsPunct(r) && !unicode.IsDigit(r) {
			unusualScript++
		}
	}

	return unicodeStats{
		invisibleRatio:     float64(invisible) / float64(total),
		rtlRatio:           float64(rtl) / float64(total),
		homoglyphRatio:     float64(homoglyph) / float64(total),
		unusualScriptRatio: float64(unusualScript) / float64(total),
	}
}

func isInvisibleChar(r rune) bool {
	// Zero-width characters
	if r == '\u200B' || r == '\u200C' || r == '\u200D' || r == '\uFEFF' {
		return true
	}
	// Soft hyphen
	if r == '\u00AD' {
		return true
	}
	// Other invisible characters
	if r >= '\u2060' && r <= '\u206F' {
		return true
	}
	return false
}

func isHomoglyph(r rune) bool {
	// Common Cyrillic homoglyphs for Latin
	cyrillic := []rune{'а', 'е', 'і', 'о', 'р', 'с', 'у', 'х', 'А', 'В', 'Е', 'К', 'М', 'Н', 'О', 'Р', 'С', 'Т', 'У', 'Х'}
	for _, c := range cyrillic {
		if r == c {
			return true
		}
	}
	return false
}

func countControlChars(s string) int {
	count := 0
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			count++
		}
	}
	return count
}

func detectRepetition(s string) float64 {
	words := strings.Fields(strings.ToLower(s))
	if len(words) < 10 {
		return 0
	}

	wordCount := make(map[string]int)
	for _, w := range words {
		wordCount[w]++
	}

	maxCount := 0
	for _, count := range wordCount {
		if count > maxCount {
			maxCount = count
		}
	}

	return float64(maxCount) / float64(len(words))
}

func containsSuspiciousContent(s string) bool {
	suspicious := []string{
		"ignore", "system", "prompt", "jailbreak", "instructions",
		"exec", "eval", "import", "subprocess", "curl", "wget",
	}
	lower := strings.ToLower(s)
	for _, p := range suspicious {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func calculateConversationSimilarity(messages []string) float64 {
	if len(messages) < 2 {
		return 0
	}

	totalSim := 0.0
	comparisons := 0

	for i := 0; i < len(messages); i++ {
		for j := i + 1; j < len(messages); j++ {
			totalSim += similarity(messages[i], messages[j])
			comparisons++
		}
	}

	if comparisons == 0 {
		return 0
	}
	return totalSim / float64(comparisons)
}

func detectEscalation(messages []Message) int {
	score := 0
	aggressiveKeywords := []string{
		"please", "i need", "you must", "i demand", "you have to", "now", "immediately",
	}

	prevAggressiveness := 0
	for _, m := range messages {
		if m.Role != "user" {
			continue
		}

		currentAggressiveness := 0
		lower := strings.ToLower(m.Content)
		for _, kw := range aggressiveKeywords {
			if strings.Contains(lower, kw) {
				currentAggressiveness++
			}
		}

		if currentAggressiveness > prevAggressiveness+1 {
			score += 10
		}
		prevAggressiveness = currentAggressiveness
	}

	return score
}

func detectProbingSequence(messages []string) bool {
	if len(messages) < 5 {
		return false
	}

	// Check for numbered/sequential patterns
	numberedCount := 0
	for _, m := range messages {
		lower := strings.ToLower(m)
		if strings.Contains(lower, "test ") || strings.Contains(lower, "try ") ||
			strings.Contains(lower, "what if") || strings.Contains(lower, "how about") {
			numberedCount++
		}
	}

	return numberedCount >= 3
}

// similarity calculates Jaccard similarity between two strings.
func similarity(a, b string) float64 {
	if a == b {
		return 1.0
	}

	wordsA := strings.Fields(strings.ToLower(a))
	wordsB := strings.Fields(strings.ToLower(b))

	if len(wordsA) == 0 || len(wordsB) == 0 {
		return 0
	}

	setA := make(map[string]bool)
	for _, w := range wordsA {
		setA[w] = true
	}

	setB := make(map[string]bool)
	for _, w := range wordsB {
		setB[w] = true
	}

	intersection := 0
	for w := range setA {
		if setB[w] {
			intersection++
		}
	}

	union := len(setA)
	for w := range setB {
		if !setA[w] {
			union++
		}
	}

	if union == 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
