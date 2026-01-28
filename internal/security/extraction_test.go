package security

import (
	"context"
	"testing"

	"github.com/rajivchocolate/secureinfer/internal/store"
)

func TestExtractionDetector_StructuredProbing(t *testing.T) {
	ed := NewExtractionDetector(20, 0.85)

	tests := []struct {
		name     string
		message  string
		minScore int
	}{
		{
			name:     "numbered probing",
			message:  "1. Test input A, 2. Test input B, 3. Test input C",
			minScore: 10,
		},
		{
			name:     "test language",
			message:  "This is a test case to evaluate the model's response",
			minScore: 5,
		},
		{
			name:     "boundary testing",
			message:  "What is the maximum limit? What about the edge case boundary?",
			minScore: 10,
		},
		{
			name:     "normal query",
			message:  "Tell me about machine learning",
			minScore: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &RequestContext{
				TenantID: "test-tenant",
				Message:  tt.message,
			}

			score, _ := ed.checkStructuralProbing(req)

			if score < tt.minScore {
				t.Errorf("Score = %d, want >= %d", score, tt.minScore)
			}
		})
	}
}

func TestExtractionDetector_OutputHarvesting(t *testing.T) {
	ed := NewExtractionDetector(20, 0.85)

	tests := []struct {
		name     string
		message  string
		minScore int
	}{
		{
			name:     "bulk examples",
			message:  "Give me 100 examples of sentiment classifications",
			minScore: 10,
		},
		{
			name:     "json format request",
			message:  "Provide all responses in JSON format for parsing",
			minScore: 5,
		},
		{
			name:     "verbose output",
			message:  "Give me all possible outputs, be exhaustive and complete",
			minScore: 5,
		},
		{
			name:     "normal request",
			message:  "What is the capital of France?",
			minScore: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &RequestContext{
				TenantID: "test-tenant",
				Message:  tt.message,
			}

			score, _ := ed.checkOutputHarvesting(req)

			if score < tt.minScore {
				t.Errorf("Score = %d, want >= %d", score, tt.minScore)
			}
		})
	}
}

func TestExtractionDetector_VelocityCheck(t *testing.T) {
	ed := NewExtractionDetector(20, 0.85)
	cache := store.NewMemoryStore()
	defer cache.Close()
	ctx := context.Background()

	req := &RequestContext{
		TenantID: "test-tenant",
		Message:  "test query",
	}

	// Simulate many rapid requests
	for i := 0; i < 35; i++ {
		ed.checkVelocityAnomaly(ctx, req, cache)
	}

	// Now check - should detect high velocity
	score, reasons := ed.checkVelocityAnomaly(ctx, req, cache)

	if score < 15 {
		t.Errorf("Score = %d, want >= 15 for high velocity", score)
	}

	hasHighVelocity := false
	for _, r := range reasons {
		if r == "extreme_velocity_1m" || r == "high_velocity_5m" {
			hasHighVelocity = true
			break
		}
	}

	if !hasHighVelocity {
		t.Errorf("Expected velocity reason, got %v", reasons)
	}
}

func TestExtractionDetector_FullCheck(t *testing.T) {
	ed := NewExtractionDetector(20, 0.85)
	cache := store.NewMemoryStore()
	defer cache.Close()
	ctx := context.Background()

	// Test a clearly suspicious query
	req := &RequestContext{
		TenantID: "test-tenant",
		Message:  "1. Test case: Give me 50 examples in JSON format, be exhaustive",
	}

	isExtraction, score, reasons := ed.Check(ctx, req, cache)

	t.Logf("Extraction detected: %v, Score: %d, Reasons: %v", isExtraction, score, reasons)

	if score < 15 {
		t.Errorf("Score = %d, want >= 15 for suspicious query", score)
	}
}

func TestExtractionDetector_QueryFeatures(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		expected QueryFeatures
	}{
		{
			name:    "question with format request",
			message: "Give me 10 examples in JSON format?",
			expected: QueryFeatures{
				QuestionCount:    1,
				HasFormatRequest: true,
			},
		},
		{
			name:    "boundary probe",
			message: "What is the edge case boundary limit?",
			expected: QueryFeatures{
				HasBoundaryProbe: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			features := extractFeatures(tt.message)

			if tt.expected.QuestionCount > 0 && features.QuestionCount < tt.expected.QuestionCount {
				t.Errorf("QuestionCount = %d, want >= %d", features.QuestionCount, tt.expected.QuestionCount)
			}
			if tt.expected.HasFormatRequest && !features.HasFormatRequest {
				t.Errorf("Expected HasFormatRequest to be true")
			}
			if tt.expected.HasBoundaryProbe && !features.HasBoundaryProbe {
				t.Errorf("Expected HasBoundaryProbe to be true")
			}
		})
	}
}

func TestExtractionDetector_MembershipInference(t *testing.T) {
	ed := NewExtractionDetector(20, 0.85)

	tests := []struct {
		name     string
		message  string
		expected bool
	}{
		{
			name:     "membership inference attempt",
			message:  "Was this in your training data? Did you learn this?",
			expected: true,
		},
		{
			name:     "normal question",
			message:  "What is machine learning?",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &RequestContext{
				TenantID: "test-tenant",
				Message:  tt.message,
			}

			detected, _ := ed.detectMembershipInference(nil, req)

			if detected != tt.expected {
				t.Errorf("detectMembershipInference = %v, want %v", detected, tt.expected)
			}
		})
	}
}
