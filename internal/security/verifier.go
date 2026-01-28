package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ModelVerifier ensures model integrity and prevents supply chain attacks.
//
// Why this matters:
// 1. Model poisoning - attacker modifies weights to include backdoors
// 2. Supply chain attacks - compromised model downloads
// 3. Tampering detection - runtime model replacement
// 4. Compliance - prove you're running approved models
//
// Attack scenarios:
// - Attacker compromises model repository
// - Malicious insider modifies production model
// - Man-in-the-middle during model download
// - Trojan/backdoor inserted during training
type ModelVerifier struct {
	expectedHash string
	modelPath    string
}

// VerificationResult contains model verification details.
type VerificationResult struct {
	Valid        bool   `json:"valid"`
	ExpectedHash string `json:"expected_hash,omitempty"`
	ActualHash   string `json:"actual_hash,omitempty"`
	ModelPath    string `json:"model_path,omitempty"`
	Message      string `json:"message"`
}

// NewModelVerifier creates a new model verifier.
func NewModelVerifier(expectedHash string) *ModelVerifier {
	return &ModelVerifier{
		expectedHash: expectedHash,
		modelPath:    getOllamaModelPath(),
	}
}

// Verify checks model integrity.
func (mv *ModelVerifier) Verify(ctx context.Context) (*VerificationResult, error) {
	result := &VerificationResult{
		ExpectedHash: mv.expectedHash,
		ModelPath:    mv.modelPath,
	}

	// If no expected hash configured, skip verification
	if mv.expectedHash == "" {
		result.Valid = true
		result.Message = "verification skipped: no expected hash configured"
		return result, nil
	}

	// Check if model path exists
	if mv.modelPath == "" {
		result.Valid = false
		result.Message = "model path not found"
		return result, nil
	}

	// Calculate model hash
	hash, err := mv.calculateModelHash()
	if err != nil {
		result.Valid = false
		result.Message = fmt.Sprintf("failed to calculate hash: %v", err)
		return result, nil
	}

	result.ActualHash = hash

	// Compare hashes
	if hash == mv.expectedHash {
		result.Valid = true
		result.Message = "model integrity verified"
	} else {
		result.Valid = false
		result.Message = "model hash mismatch - possible tampering detected"
	}

	return result, nil
}

// calculateModelHash computes SHA256 of the model file.
func (mv *ModelVerifier) calculateModelHash() (string, error) {
	// For Ollama, models are stored as blobs
	// Find the model blob files
	blobPath := filepath.Join(mv.modelPath, "blobs")

	var totalHash = sha256.New()

	err := filepath.Walk(blobPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		// Hash each blob file
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		if _, err := io.Copy(totalHash, f); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return "", err
	}

	return hex.EncodeToString(totalHash.Sum(nil)), nil
}

// GetModelInfo returns information about the loaded model.
func (mv *ModelVerifier) GetModelInfo(ctx context.Context) map[string]interface{} {
	info := map[string]interface{}{
		"path":          mv.modelPath,
		"expected_hash": mv.expectedHash,
	}

	// Get model file info if available
	if mv.modelPath != "" {
		if stat, err := os.Stat(mv.modelPath); err == nil {
			info["size_bytes"] = stat.Size()
			info["modified"] = stat.ModTime()
		}
	}

	return info
}

// getOllamaModelPath returns the Ollama models directory.
func getOllamaModelPath() string {
	// Check OLLAMA_MODELS env var first
	if path := os.Getenv("OLLAMA_MODELS"); path != "" {
		return path
	}

	// Default paths by OS
	home, _ := os.UserHomeDir()

	// macOS
	macPath := filepath.Join(home, ".ollama", "models")
	if _, err := os.Stat(macPath); err == nil {
		return macPath
	}

	// Linux
	linuxPath := filepath.Join(home, ".ollama", "models")
	if _, err := os.Stat(linuxPath); err == nil {
		return linuxPath
	}

	// Docker/container path
	containerPath := "/root/.ollama/models"
	if _, err := os.Stat(containerPath); err == nil {
		return containerPath
	}

	return ""
}

// VerifyAtStartup performs verification at application startup.
// Call this during initialization to detect tampering early.
func (mv *ModelVerifier) VerifyAtStartup() error {
	result, err := mv.Verify(context.Background())
	if err != nil {
		return fmt.Errorf("verification error: %w", err)
	}

	if !result.Valid && mv.expectedHash != "" {
		return fmt.Errorf("model integrity check failed: %s", result.Message)
	}

	return nil
}

// GenerateExpectedHash calculates and returns the hash for the current model.
// Use this to generate the hash to put in your configuration.
func (mv *ModelVerifier) GenerateExpectedHash() (string, error) {
	return mv.calculateModelHash()
}
