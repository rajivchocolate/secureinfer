// Package main demonstrates denial of service attack patterns.
//
// DoS attacks against LLM inference APIs try to:
// 1. Exhaust compute resources with expensive queries
// 2. Overwhelm rate limits
// 3. Cause memory exhaustion with large inputs
// 4. Trigger expensive operations repeatedly
//
// Run with: go run demos/dos_attack.go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	apiURL = "http://localhost:8000/v1/chat/completions"
	apiKey = "sk-test-key"
)

type ChatRequest struct {
	Messages  []Message `json:"messages"`
	MaxTokens int       `json:"max_tokens,omitempty"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

func main() {
	fmt.Println("=== Denial of Service Attack Demonstration ===")
	fmt.Println()
	fmt.Println("This demo shows resource exhaustion attack patterns")
	fmt.Println("and how rate limiting + risk scoring mitigate them.")
	fmt.Println()
	fmt.Println("WARNING: These attacks intentionally stress the system.")
	fmt.Println()

	// Attack 1: Rate Limit Exhaustion
	fmt.Println("--- Attack 1: Rate Limit Exhaustion ---")
	fmt.Println("Sending rapid-fire requests to trigger rate limiting...")
	rateLimitAttack()

	time.Sleep(3 * time.Second)

	// Attack 2: Large Input Attack
	fmt.Println("\n--- Attack 2: Large Input Attack ---")
	fmt.Println("Sending excessively large inputs...")
	largeInputAttack()

	time.Sleep(2 * time.Second)

	// Attack 3: Expensive Query Attack
	fmt.Println("\n--- Attack 3: Expensive Query Attack ---")
	fmt.Println("Sending computationally expensive queries...")
	expensiveQueryAttack()

	time.Sleep(2 * time.Second)

	// Attack 4: Concurrent Connection Flood
	fmt.Println("\n--- Attack 4: Concurrent Connection Flood ---")
	fmt.Println("Opening many concurrent connections...")
	connectionFloodAttack()

	fmt.Println("\n=== Attack Summary ===")
	fmt.Println("Check rate limit headers and response codes.")
	fmt.Println("429 = Rate limited, 403 = Blocked by security")
}

func rateLimitAttack() {
	var success, rateLimited, errors int32

	// Send 100 requests as fast as possible
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()

			resp, err := sendQuickRequest("Hello")
			if err != nil {
				atomic.AddInt32(&errors, 1)
				return
			}
			defer resp.Body.Close()

			switch resp.StatusCode {
			case 200:
				atomic.AddInt32(&success, 1)
			case 429:
				atomic.AddInt32(&rateLimited, 1)
			default:
				atomic.AddInt32(&errors, 1)
			}
		}(i)
	}
	wg.Wait()

	fmt.Printf("Results: %d succeeded, %d rate limited, %d errors\n",
		success, rateLimited, errors)

	if rateLimited > 0 {
		fmt.Println("Rate limiting is working correctly!")
	} else {
		fmt.Println("WARNING: Rate limiting may not be configured.")
	}
}

func largeInputAttack() {
	sizes := []int{1000, 10000, 50000, 100000}

	for _, size := range sizes {
		// Create a large input
		largeInput := strings.Repeat("A", size)
		payload := fmt.Sprintf("Summarize this: %s", largeInput)

		start := time.Now()
		resp, err := sendQuickRequest(payload)
		elapsed := time.Since(start)

		if err != nil {
			fmt.Printf("[%d chars] Error: %v\n", size, err)
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)

		fmt.Printf("[%d chars] Status: %d, Time: %v, Response: %s\n",
			size, resp.StatusCode, elapsed, truncate(string(body), 50))

		if resp.StatusCode == 403 || resp.StatusCode == 413 {
			fmt.Println("Large input blocked!")
		}
	}
}

func expensiveQueryAttack() {
	expensiveQueries := []string{
		"Write a 10000 word essay on the history of computing",
		"Generate all prime numbers up to 1 million",
		"Create a detailed analysis of every Shakespeare play",
		"Translate the Bible into 10 different languages",
		"Write complete documentation for a complex software system",
	}

	for i, query := range expensiveQueries {
		start := time.Now()
		resp, err := sendRequestWithMaxTokens(query, 4096)
		elapsed := time.Since(start)

		if err != nil {
			fmt.Printf("[%d] Error: %v\n", i+1, err)
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)

		fmt.Printf("[%d] Query: %s...\n", i+1, truncate(query, 40))
		fmt.Printf("    Status: %d, Time: %v\n", resp.StatusCode, elapsed)

		if resp.StatusCode == 403 {
			fmt.Println("    Expensive query blocked!")
		} else if elapsed > 5*time.Second {
			fmt.Println("    WARNING: Query took too long - potential DoS vector")
		}

		// Log response snippet
		if len(body) > 0 {
			fmt.Printf("    Response: %s\n", truncate(string(body), 60))
		}
	}
}

func connectionFloodAttack() {
	var wg sync.WaitGroup
	results := make(chan string, 50)

	// Open 50 concurrent connections with slow requests
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()

			// Send a slow request that keeps connection open
			start := time.Now()
			resp, err := sendRequestWithMaxTokens(
				"Tell me a very long story about a dragon",
				1024,
			)
			elapsed := time.Since(start)

			if err != nil {
				results <- fmt.Sprintf("[%d] Error after %v", n, elapsed)
				return
			}
			defer resp.Body.Close()

			results <- fmt.Sprintf("[%d] Status %d after %v", n, resp.StatusCode, elapsed)
		}(i)
	}

	// Collect results
	go func() {
		wg.Wait()
		close(results)
	}()

	var success, failed int
	for result := range results {
		if strings.Contains(result, "200") {
			success++
		} else {
			failed++
		}
	}

	fmt.Printf("Results: %d succeeded, %d failed/limited\n", success, failed)
}

func sendQuickRequest(content string) (*http.Response, error) {
	reqBody := ChatRequest{
		Messages: []Message{{Role: "user", Content: content}},
	}
	jsonBody, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", apiURL, bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 10 * time.Second}
	return client.Do(req)
}

func sendRequestWithMaxTokens(content string, maxTokens int) (*http.Response, error) {
	reqBody := ChatRequest{
		Messages:  []Message{{Role: "user", Content: content}},
		MaxTokens: maxTokens,
	}
	jsonBody, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", apiURL, bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 60 * time.Second}
	return client.Do(req)
}

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
