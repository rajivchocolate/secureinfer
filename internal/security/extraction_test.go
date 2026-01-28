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

			score, _ := ed.checkStructuredProbing(req)

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
		ed.checkVelocity(ctx, req, cache)
	}

	// Now check - should detect high velocity
	score, reasons := ed.checkVelocity(ctx, req, cache)

	if score < 15 {
		t.Errorf("Score = %d, want >= 15 for high velocity", score)
	}

	hasHighVelocity := false
	for _, r := range reasons {
		if r == "high_velocity" || r == "extreme_velocity" {
			hasHighVelocity = true
			break
		}
	}

	if !hasHighVelocity {
		t.Errorf("Expected high_velocity or extreme_velocity reason, got %v", reasons)
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
