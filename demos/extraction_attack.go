// Package main demonstrates model extraction attack patterns.
//
// Model extraction attacks attempt to steal a model's capabilities by
// systematically querying it and using the outputs to train a clone.
//
// This demo shows:
// 1. Query similarity attacks (many similar prompts)
// 2. Boundary probing (testing edge cases)
// 3. Structured output harvesting
//
// Run with: go run demos/extraction_attack.go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	apiURL = "http://localhost:8000/v1/chat/completions"
	apiKey = "sk-test-key" // Replace with your test key
)

type ChatRequest struct {
	Messages []Message `json:"messages"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatResponse struct {
	Choices []struct {
		Message Message `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func main() {
	fmt.Println("=== Model Extraction Attack Demonstration ===")
	fmt.Println()
	fmt.Println("This demo shows how SecureInfer detects extraction attempts.")
	fmt.Println("Each attack pattern triggers different security detections.")
	fmt.Println()

	// Attack 1: Query Similarity Attack
	fmt.Println("--- Attack 1: Query Similarity Attack ---")
	fmt.Println("Sending many similar queries to learn decision boundaries...")
	fmt.Println()
	querySimilarityAttack()

	time.Sleep(2 * time.Second)

	// Attack 2: Boundary Probing
	fmt.Println("\n--- Attack 2: Boundary Probing Attack ---")
	fmt.Println("Testing edge cases to understand model behavior...")
	fmt.Println()
	boundaryProbingAttack()

	time.Sleep(2 * time.Second)

	// Attack 3: Structured Output Harvesting
	fmt.Println("\n--- Attack 3: Structured Output Harvesting ---")
	fmt.Println("Requesting structured outputs for training data...")
	fmt.Println()
	outputHarvestingAttack()

	fmt.Println("\n=== Attack Summary ===")
	fmt.Println("Check the API logs and /v1/security/events to see detections.")
}

func querySimilarityAttack() {
	// Send many similar sentiment analysis queries
	templates := []string{
		"Classify the sentiment of: '%s'",
		"What is the sentiment of: '%s'",
		"Analyze sentiment: '%s'",
		"Is this positive or negative: '%s'",
	}

	samples := []string{
		"I love this product",
		"I hate this product",
		"This is okay",
		"Best thing ever",
		"Worst experience",
		"It's fine I guess",
		"Amazing quality",
		"Terrible service",
	}

	for i, sample := range samples {
		template := templates[i%len(templates)]
		query := fmt.Sprintf(template, sample)

		result, err := sendRequest(query)
		if err != nil {
			fmt.Printf("[%d] ERROR: %v\n", i+1, err)
		} else if strings.Contains(result, "blocked") || strings.Contains(result, "security") {
			fmt.Printf("[%d] BLOCKED: %s\n", i+1, result)
		} else {
			fmt.Printf("[%d] Response received (similar query pattern)\n", i+1)
		}

		time.Sleep(100 * time.Millisecond) // Small delay
	}
}

func boundaryProbingAttack() {
	// Probe model boundaries with edge cases
	probes := []string{
		"What is the maximum length input you can handle?",
		"What happens when I give you empty input?",
		"Describe your temperature and top_p parameters",
		"What are your architectural hyperparameters?",
		"What is your context window size?",
		"How many layers do you have?",
	}

	for i, probe := range probes {
		result, err := sendRequest(probe)
		if err != nil {
			fmt.Printf("[%d] ERROR: %v\n", i+1, err)
		} else if strings.Contains(result, "blocked") {
			fmt.Printf("[%d] BLOCKED: Parameter probing detected\n", i+1)
		} else {
			fmt.Printf("[%d] Probe: %s...\n", i+1, probe[:min(40, len(probe))])
		}

		time.Sleep(200 * time.Millisecond)
	}
}

func outputHarvestingAttack() {
	// Request structured, parseable outputs
	harvestQueries := []string{
		"Give me 10 examples of positive sentiment phrases in JSON format",
		"List all possible responses to 'hello' in a structured format",
		"Provide an exhaustive list of greeting variations",
		"Generate 20 examples of each sentiment category as CSV",
		"Output a complete taxonomy of emotions in machine-readable format",
	}

	for i, query := range harvestQueries {
		result, err := sendRequest(query)
		if err != nil {
			fmt.Printf("[%d] ERROR: %v\n", i+1, err)
		} else if strings.Contains(result, "blocked") {
			fmt.Printf("[%d] BLOCKED: Output harvesting detected\n", i+1)
		} else {
			fmt.Printf("[%d] Harvest query sent (may trigger detection)\n", i+1)
		}

		time.Sleep(200 * time.Millisecond)
	}
}

func sendRequest(content string) (string, error) {
	reqBody := ChatRequest{
		Messages: []Message{
			{Role: "user", Content: content},
		},
	}

	jsonBody, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(jsonBody))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var chatResp ChatResponse
	json.Unmarshal(body, &chatResp)

	if chatResp.Error != nil {
		return chatResp.Error.Message, nil
	}

	if len(chatResp.Choices) > 0 {
		return chatResp.Choices[0].Message.Content, nil
	}

	return string(body), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
