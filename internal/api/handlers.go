package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/rajivchocolate/secureinfer/internal/security"
)

// ChatRequest matches OpenAI's chat completion request format.
type ChatRequest struct {
	Model       string        `json:"model,omitempty"`
	Messages    []ChatMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Temperature float64       `json:"temperature,omitempty"`
	Stream      bool          `json:"stream,omitempty"`
}

// ChatMessage represents a single message in the conversation.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatResponse matches OpenAI's chat completion response format.
type ChatResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
	Usage   Usage    `json:"usage"`
}

// Choice represents a completion choice.
type Choice struct {
	Index        int         `json:"index"`
	Message      ChatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}

// Usage tracks token usage.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// handleRoot returns API info.
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"service": "SecureInfer",
		"version": "0.1.0",
		"docs":    "/docs",
	})
}

// handleHealth returns health status.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Check Ollama connectivity
	ollamaOK := s.ollama.Ping(r.Context()) == nil

	status := "healthy"
	if !ollamaOK {
		status = "degraded"
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": status,
		"checks": map[string]bool{
			"ollama": ollamaOK,
		},
	})
}

// handleChatCompletions processes chat completion requests.
func (s *Server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := getTenantID(ctx)

	var req ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate request
	if len(req.Messages) == 0 {
		writeError(w, http.StatusBadRequest, "messages required")
		return
	}

	// Get the latest user message for security checks
	var userMessage string
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" {
			userMessage = req.Messages[i].Content
			break
		}
	}

	// Run security checks
	securityCtx := &security.RequestContext{
		TenantID:  tenantID,
		Message:   userMessage,
		Messages:  toSecurityMessages(req.Messages),
		IP:        getIP(r),
		UserAgent: r.UserAgent(),
	}

	result, err := s.security.Check(ctx, securityCtx)
	if err != nil {
		log.Error().Err(err).Msg("Security check failed")
		writeError(w, http.StatusInternalServerError, "security check failed")
		return
	}

	// Block if risk is too high
	if result.Action == security.ActionBlock {
		log.Warn().
			Str("tenant", tenantID).
			Int("risk_score", result.RiskScore).
			Strs("reasons", result.Reasons).
			Msg("Request blocked")

		writeError(w, http.StatusForbidden, "request blocked due to security policy")
		return
	}

	// Warn but allow (can add to response headers)
	if result.Action == security.ActionWarn {
		w.Header().Set("X-Security-Warning", "elevated-risk")
	}

	// Get tenant-isolated context
	messagesIface := toInterfaceSlice(req.Messages)
	_ = s.security.GetIsolatedContext(ctx, tenantID, messagesIface)

	// Call Ollama
	response, err := s.ollama.ChatCompletion(ctx, messagesIface, req.MaxTokens, req.Temperature)
	if err != nil {
		log.Error().Err(err).Msg("Ollama request failed")
		writeError(w, http.StatusBadGateway, "inference failed")
		return
	}

	// Store context for tenant isolation
	s.security.StoreContext(ctx, tenantID, messagesIface, response.Message)

	// Build OpenAI-compatible response
	chatResp := ChatResponse{
		ID:      generateID(),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   s.cfg.ModelName,
		Choices: []Choice{
			{
				Index: 0,
				Message: ChatMessage{
					Role:    "assistant",
					Content: response.Message,
				},
				FinishReason: "stop",
			},
		},
		Usage: Usage{
			PromptTokens:     response.PromptTokens,
			CompletionTokens: response.CompletionTokens,
			TotalTokens:      response.PromptTokens + response.CompletionTokens,
		},
	}

	writeJSON(w, http.StatusOK, chatResp)
}

// handleGetRiskScore returns the current risk score for a tenant.
func (s *Server) handleGetRiskScore(w http.ResponseWriter, r *http.Request) {
	authenticatedTenantID := getTenantID(r.Context())
	requestedTenantID := chi.URLParam(r, "tenant_id")

	if requestedTenantID == "" {
		writeError(w, http.StatusBadRequest, "tenant_id required")
		return
	}

	// Authorization check: users can only access their own risk score
	if requestedTenantID != authenticatedTenantID {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	score, factors := s.security.GetRiskScore(r.Context(), requestedTenantID)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tenant_id":       requestedTenantID,
		"risk_score":      score,
		"factors":         factors,
		"threshold_warn":  s.cfg.RiskThresholdWarn,
		"threshold_block": s.cfg.RiskThresholdBlock,
	})
}

// handleGetSecurityEvents returns recent security events.
func (s *Server) handleGetSecurityEvents(w http.ResponseWriter, r *http.Request) {
	events, err := s.security.GetRecentEvents(r.Context(), 100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to fetch events")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"events": events,
		"count":  len(events),
	})
}

// handleVerifyModel verifies the model integrity.
func (s *Server) handleVerifyModel(w http.ResponseWriter, r *http.Request) {
	result, err := s.security.VerifyModel(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "verification failed")
		return
	}

	status := http.StatusOK
	if !result.Valid {
		status = http.StatusConflict
	}

	writeJSON(w, status, result)
}

// handleCreateTenant creates a new tenant.
func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	tenant, err := s.db.CreateTenant(r.Context(), req.Name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create tenant")
		return
	}

	writeJSON(w, http.StatusCreated, tenant)
}

// handleGetTenant returns tenant info.
func (s *Server) handleGetTenant(w http.ResponseWriter, r *http.Request) {
	authenticatedTenantID := getTenantID(r.Context())
	requestedTenantID := chi.URLParam(r, "tenant_id")

	// Authorization check: users can only access their own tenant info
	if requestedTenantID != authenticatedTenantID {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	tenant, err := s.db.GetTenant(r.Context(), requestedTenantID)
	if err != nil {
		writeError(w, http.StatusNotFound, "tenant not found")
		return
	}

	writeJSON(w, http.StatusOK, tenant)
}

// handleClearContext clears a tenant's conversation context.
func (s *Server) handleClearContext(w http.ResponseWriter, r *http.Request) {
	authenticatedTenantID := getTenantID(r.Context())
	requestedTenantID := chi.URLParam(r, "tenant_id")

	// Authorization check: users can only clear their own context
	if requestedTenantID != authenticatedTenantID {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	if err := s.security.ClearContext(r.Context(), requestedTenantID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to clear context")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "context cleared",
	})
}

// toSecurityMessages converts API messages to security messages.
func toSecurityMessages(msgs []ChatMessage) []security.Message {
	result := make([]security.Message, len(msgs))
	for i, m := range msgs {
		result[i] = security.Message{
			Role:    m.Role,
			Content: m.Content,
		}
	}
	return result
}

// toInterfaceSlice converts ChatMessage slice to interface slice for Ollama.
func toInterfaceSlice(msgs []ChatMessage) []interface{} {
	result := make([]interface{}, len(msgs))
	for i, m := range msgs {
		result[i] = map[string]interface{}{
			"role":    m.Role,
			"content": m.Content,
		}
	}
	return result
}
