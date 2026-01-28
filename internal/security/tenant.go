package security

import (
	"context"
	"encoding/json"

	"github.com/rajivchocolate/secureinfer/internal/store"
)

// TenantIsolator ensures conversation contexts are isolated per tenant.
//
// Why this matters:
// 1. Prevent data leakage between users
// 2. Stop cross-tenant prompt injection
// 3. Maintain privacy boundaries
// 4. Enable per-tenant security policies
//
// In multi-tenant LLM systems, context isolation is critical because:
// - Shared models process multiple users' data
// - Context windows might accidentally include other users' data
// - Prompt injection could try to access other tenants' info
type TenantIsolator struct {
	maxContextLength int
	contextTTL       int // seconds
}

// ConversationContext stores a tenant's conversation state.
type ConversationContext struct {
	TenantID string    `json:"tenant_id"`
	Messages []Message `json:"messages"`
}

// NewTenantIsolator creates a new tenant isolator.
func NewTenantIsolator() *TenantIsolator {
	return &TenantIsolator{
		maxContextLength: 4096,
		contextTTL:       3600, // 1 hour
	}
}

// CheckViolation checks for tenant isolation violations.
func (ti *TenantIsolator) CheckViolation(ctx context.Context, req *RequestContext) (bool, []string) {
	var reasons []string
	violation := false

	// Check for cross-tenant reference attempts
	if ti.detectCrossTenantRef(req) {
		violation = true
		reasons = append(reasons, "cross_tenant_reference")
	}

	// Check for context manipulation
	if ti.detectContextManipulation(req) {
		violation = true
		reasons = append(reasons, "context_manipulation")
	}

	return violation, reasons
}

// detectCrossTenantRef checks if message tries to reference other tenants.
func (ti *TenantIsolator) detectCrossTenantRef(req *RequestContext) bool {
	// Patterns that might indicate cross-tenant access attempts
	patterns := []string{
		"other user",
		"another user",
		"previous user",
		"user id",
		"tenant id",
		"switch to",
		"as user",
		"different account",
		"other customer",
	}

	msgLower := toLower(req.Message)
	for _, p := range patterns {
		if contains(msgLower, p) {
			return true
		}
	}

	return false
}

// detectContextManipulation checks for context poisoning attempts.
func (ti *TenantIsolator) detectContextManipulation(req *RequestContext) bool {
	// Check if message tries to inject fake history
	patterns := []string{
		"you previously said",
		"remember when you",
		"in our last conversation",
		"you told me before",
		"continue from where",
		"based on our history",
	}

	msgLower := toLower(req.Message)
	for _, p := range patterns {
		if contains(msgLower, p) {
			// This might be legitimate, but flag it for review
			// In production, verify against actual stored context
			return true
		}
	}

	return false
}

// GetContext retrieves tenant-isolated conversation context.
func (ti *TenantIsolator) GetContext(
	ctx context.Context,
	tenantID string,
	newMessages []interface{},
	cache store.Cache,
) []interface{} {
	if cache == nil {
		return newMessages
	}

	key := "context:" + tenantID

	// Get existing context
	data, err := cache.Get(ctx, key)
	if err != nil || data == "" {
		return newMessages
	}

	var storedCtx ConversationContext
	if err := json.Unmarshal([]byte(data), &storedCtx); err != nil {
		return newMessages
	}

	// Verify tenant ID matches (defense in depth)
	if storedCtx.TenantID != tenantID {
		// This should never happen - indicates a serious bug or attack
		return newMessages
	}

	// Merge stored context with new messages
	// In production, implement proper context window management
	return newMessages
}

// StoreContext stores conversation context for a tenant.
func (ti *TenantIsolator) StoreContext(
	ctx context.Context,
	tenantID string,
	messages []interface{},
	response string,
	cache store.Cache,
) {
	if cache == nil {
		return
	}

	key := "context:" + tenantID

	// Build context
	storedCtx := ConversationContext{
		TenantID: tenantID,
		Messages: ti.convertMessages(messages, response),
	}

	// Truncate if too long
	storedCtx.Messages = ti.truncateContext(storedCtx.Messages)

	// Store with TTL
	data, _ := json.Marshal(storedCtx)
	cache.Set(ctx, key, string(data), ti.contextTTL)
}

// ClearContext clears conversation context for a tenant.
func (ti *TenantIsolator) ClearContext(
	ctx context.Context,
	tenantID string,
	cache store.Cache,
) error {
	if cache == nil {
		return nil
	}

	key := "context:" + tenantID
	return cache.Delete(ctx, key)
}

// convertMessages converts interface messages to typed messages.
func (ti *TenantIsolator) convertMessages(messages []interface{}, response string) []Message {
	result := make([]Message, 0, len(messages)+1)

	for _, m := range messages {
		if msg, ok := m.(map[string]interface{}); ok {
			role, _ := msg["role"].(string)
			content, _ := msg["content"].(string)
			result = append(result, Message{Role: role, Content: content})
		}
	}

	// Add the response
	result = append(result, Message{Role: "assistant", Content: response})

	return result
}

// truncateContext keeps context within limits.
func (ti *TenantIsolator) truncateContext(messages []Message) []Message {
	totalLength := 0
	for _, m := range messages {
		totalLength += len(m.Content)
	}

	// If within limit, return as-is
	if totalLength <= ti.maxContextLength {
		return messages
	}

	// Keep most recent messages that fit
	var result []Message
	currentLength := 0

	for i := len(messages) - 1; i >= 0; i-- {
		msgLen := len(messages[i].Content)
		if currentLength+msgLen > ti.maxContextLength {
			break
		}
		result = append([]Message{messages[i]}, result...)
		currentLength += msgLen
	}

	return result
}

// Helper functions
func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		result[i] = c
	}
	return string(result)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || findSubstring(s, substr) >= 0)
}

func findSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
