package inference

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// OllamaClient wraps the Ollama HTTP API.
type OllamaClient struct {
	baseURL    string
	modelName  string
	httpClient *http.Client
}

// ChatMessage represents a message in the conversation.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequest is the request to Ollama's chat endpoint.
type ChatRequest struct {
	Model    string        `json:"model"`
	Messages []ChatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
	Options  *ChatOptions  `json:"options,omitempty"`
}

// ChatOptions configures generation parameters.
type ChatOptions struct {
	Temperature float64 `json:"temperature,omitempty"`
	NumPredict  int     `json:"num_predict,omitempty"` // max_tokens equivalent
	TopP        float64 `json:"top_p,omitempty"`
	TopK        int     `json:"top_k,omitempty"`
}

// ChatResponse is the response from Ollama's chat endpoint.
type ChatResponse struct {
	Model     string      `json:"model"`
	CreatedAt string      `json:"created_at"`
	Message   ChatMessage `json:"message"`
	Done      bool        `json:"done"`

	// Token counts
	PromptEvalCount int `json:"prompt_eval_count"`
	EvalCount       int `json:"eval_count"`
}

// CompletionResult is our internal representation.
type CompletionResult struct {
	Message          string
	PromptTokens     int
	CompletionTokens int
}

// NewOllamaClient creates a new Ollama client.
func NewOllamaClient(baseURL, modelName string) *OllamaClient {
	return &OllamaClient{
		baseURL:   baseURL,
		modelName: modelName,
		httpClient: &http.Client{
			Timeout: 5 * time.Minute, // LLM responses can take a while
		},
	}
}

// Ping checks if Ollama is reachable.
func (c *OllamaClient) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/api/tags", nil)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ollama returned status %d", resp.StatusCode)
	}

	return nil
}

// ChatCompletion sends a chat completion request to Ollama.
func (c *OllamaClient) ChatCompletion(
	ctx context.Context,
	messages []interface{},
	maxTokens int,
	temperature float64,
) (*CompletionResult, error) {
	// Convert messages
	chatMessages := make([]ChatMessage, 0, len(messages))
	for _, m := range messages {
		if msg, ok := m.(map[string]interface{}); ok {
			chatMessages = append(chatMessages, ChatMessage{
				Role:    getString(msg, "role"),
				Content: getString(msg, "content"),
			})
		}
	}

	// Build request
	reqBody := ChatRequest{
		Model:    c.modelName,
		Messages: chatMessages,
		Stream:   false,
		Options: &ChatOptions{
			Temperature: temperature,
			NumPredict:  maxTokens,
		},
	}

	// Set defaults
	if reqBody.Options.Temperature == 0 {
		reqBody.Options.Temperature = 0.7
	}
	if reqBody.Options.NumPredict == 0 {
		reqBody.Options.NumPredict = 512
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send request
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/chat", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ollama error (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse response
	var chatResp ChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &CompletionResult{
		Message:          chatResp.Message.Content,
		PromptTokens:     chatResp.PromptEvalCount,
		CompletionTokens: chatResp.EvalCount,
	}, nil
}

// ListModels returns available models.
func (c *OllamaClient) ListModels(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/api/tags", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	names := make([]string, len(result.Models))
	for i, m := range result.Models {
		names[i] = m.Name
	}

	return names, nil
}

// PullModel pulls a model from Ollama's registry.
func (c *OllamaClient) PullModel(ctx context.Context, model string) error {
	reqBody := map[string]interface{}{
		"name":   model,
		"stream": false,
	}

	jsonBody, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/pull", bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to pull model: %s", string(body))
	}

	return nil
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
