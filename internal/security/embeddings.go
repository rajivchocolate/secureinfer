package security

import (
	"context"
	"encoding/json"
	"math"
	"sync"
)

// EmbeddingProvider defines the interface for text embedding services.
// This abstraction allows plugging in different embedding backends:
// - Local: sentence-transformers, ollama embeddings
// - Cloud: OpenAI ada-002, Cohere, Voyage AI
// - Self-hosted: text-embedding-inference, TEI
type EmbeddingProvider interface {
	// Embed generates a vector embedding for the given text.
	Embed(ctx context.Context, text string) ([]float32, error)

	// EmbedBatch generates embeddings for multiple texts efficiently.
	EmbedBatch(ctx context.Context, texts []string) ([][]float32, error)

	// Dimension returns the embedding dimension.
	Dimension() int

	// Name returns the provider/model name for logging.
	Name() string
}

// EmbeddingCache caches embeddings to reduce API calls and latency.
type EmbeddingCache struct {
	mu       sync.RWMutex
	cache    map[string][]float32
	maxSize  int
	provider EmbeddingProvider
}

// NewEmbeddingCache creates a new embedding cache.
func NewEmbeddingCache(provider EmbeddingProvider, maxSize int) *EmbeddingCache {
	return &EmbeddingCache{
		cache:    make(map[string][]float32),
		maxSize:  maxSize,
		provider: provider,
	}
}

// Get retrieves or computes an embedding for the given text.
func (ec *EmbeddingCache) Get(ctx context.Context, text string) ([]float32, error) {
	// Check cache first
	ec.mu.RLock()
	if emb, ok := ec.cache[text]; ok {
		ec.mu.RUnlock()
		return emb, nil
	}
	ec.mu.RUnlock()

	// Compute embedding
	emb, err := ec.provider.Embed(ctx, text)
	if err != nil {
		return nil, err
	}

	// Cache it
	ec.mu.Lock()
	if len(ec.cache) >= ec.maxSize {
		// Simple eviction: clear half the cache
		for k := range ec.cache {
			delete(ec.cache, k)
			if len(ec.cache) < ec.maxSize/2 {
				break
			}
		}
	}
	ec.cache[text] = emb
	ec.mu.Unlock()

	return emb, nil
}

// VectorSimilarity calculates similarity between embedding vectors.
type VectorSimilarity struct{}

// CosineSimilarity calculates cosine similarity between two vectors.
func (vs *VectorSimilarity) CosineSimilarity(a, b []float32) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}

	var dotProduct, normA, normB float64
	for i := range a {
		dotProduct += float64(a[i]) * float64(b[i])
		normA += float64(a[i]) * float64(a[i])
		normB += float64(b[i]) * float64(b[i])
	}

	if normA == 0 || normB == 0 {
		return 0
	}

	return dotProduct / (math.Sqrt(normA) * math.Sqrt(normB))
}

// EuclideanDistance calculates Euclidean distance between two vectors.
func (vs *VectorSimilarity) EuclideanDistance(a, b []float32) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return math.MaxFloat64
	}

	var sum float64
	for i := range a {
		diff := float64(a[i]) - float64(b[i])
		sum += diff * diff
	}

	return math.Sqrt(sum)
}

// EmbeddingCluster groups similar embeddings for extraction detection.
type EmbeddingCluster struct {
	Centroid   []float32 `json:"centroid"`
	Count      int       `json:"count"`
	MaxSim     float64   `json:"max_similarity"`
	Timestamps []int64   `json:"timestamps"`
}

// EmbeddingIndex provides efficient similarity search over embeddings.
type EmbeddingIndex struct {
	mu         sync.RWMutex
	embeddings []indexedEmbedding
	clusters   []EmbeddingCluster
	similarity *VectorSimilarity
	threshold  float64
	maxSize    int
}

type indexedEmbedding struct {
	Vector    []float32 `json:"vector"`
	Text      string    `json:"text"`
	TenantID  string    `json:"tenant_id"`
	Timestamp int64     `json:"timestamp"`
	ClusterID int       `json:"cluster_id"`
}

// NewEmbeddingIndex creates a new embedding index.
func NewEmbeddingIndex(threshold float64, maxSize int) *EmbeddingIndex {
	return &EmbeddingIndex{
		embeddings: make([]indexedEmbedding, 0),
		clusters:   make([]EmbeddingCluster, 0),
		similarity: &VectorSimilarity{},
		threshold:  threshold,
		maxSize:    maxSize,
	}
}

// Add adds an embedding to the index and returns similarity info.
func (ei *EmbeddingIndex) Add(embedding []float32, text, tenantID string, timestamp int64) *SimilarityResult {
	ei.mu.Lock()
	defer ei.mu.Unlock()

	result := &SimilarityResult{
		SimilarCount: 0,
		MaxSimilar:   0,
		ClusterID:    -1,
	}

	// Find similar embeddings
	for i, e := range ei.embeddings {
		if e.TenantID != tenantID {
			continue
		}

		sim := ei.similarity.CosineSimilarity(embedding, e.Vector)
		if sim > ei.threshold {
			result.SimilarCount++
			if sim > result.MaxSimilar {
				result.MaxSimilar = sim
				result.MostSimilar = e.Text
			}
		}

		// Check cluster membership
		if sim > 0.9 && e.ClusterID >= 0 {
			result.ClusterID = e.ClusterID
			if result.ClusterID < len(ei.clusters) {
				ei.clusters[result.ClusterID].Count++
				ei.clusters[result.ClusterID].Timestamps = append(
					ei.clusters[result.ClusterID].Timestamps,
					timestamp,
				)
			}
		}
		_ = i // silence unused
	}

	// Create new cluster if highly similar to many
	if result.SimilarCount >= 5 && result.ClusterID < 0 {
		result.ClusterID = len(ei.clusters)
		ei.clusters = append(ei.clusters, EmbeddingCluster{
			Centroid:   embedding,
			Count:      1,
			MaxSim:     result.MaxSimilar,
			Timestamps: []int64{timestamp},
		})
	}

	// Add to index
	if len(ei.embeddings) >= ei.maxSize {
		// Remove oldest
		ei.embeddings = ei.embeddings[1:]
	}

	ei.embeddings = append(ei.embeddings, indexedEmbedding{
		Vector:    embedding,
		Text:      text,
		TenantID:  tenantID,
		Timestamp: timestamp,
		ClusterID: result.ClusterID,
	})

	return result
}

// GetClusterInfo returns information about detected clusters.
func (ei *EmbeddingIndex) GetClusterInfo(tenantID string) []ClusterInfo {
	ei.mu.RLock()
	defer ei.mu.RUnlock()

	var info []ClusterInfo
	clusterCounts := make(map[int]int)

	for _, e := range ei.embeddings {
		if e.TenantID == tenantID && e.ClusterID >= 0 {
			clusterCounts[e.ClusterID]++
		}
	}

	for id, count := range clusterCounts {
		if id < len(ei.clusters) {
			info = append(info, ClusterInfo{
				ClusterID:      id,
				Size:           count,
				TotalQueries:   ei.clusters[id].Count,
				MaxSimilarity:  ei.clusters[id].MaxSim,
				TimestampCount: len(ei.clusters[id].Timestamps),
			})
		}
	}

	return info
}

// SimilarityResult contains the result of similarity analysis.
type SimilarityResult struct {
	SimilarCount int     `json:"similar_count"`
	MaxSimilar   float64 `json:"max_similar"`
	MostSimilar  string  `json:"most_similar"`
	ClusterID    int     `json:"cluster_id"`
}

// ClusterInfo provides information about a query cluster.
type ClusterInfo struct {
	ClusterID      int     `json:"cluster_id"`
	Size           int     `json:"size"`
	TotalQueries   int     `json:"total_queries"`
	MaxSimilarity  float64 `json:"max_similarity"`
	TimestampCount int     `json:"timestamp_count"`
}

// Serialize serializes the index for persistence.
func (ei *EmbeddingIndex) Serialize() ([]byte, error) {
	ei.mu.RLock()
	defer ei.mu.RUnlock()

	data := struct {
		Embeddings []indexedEmbedding `json:"embeddings"`
		Clusters   []EmbeddingCluster `json:"clusters"`
	}{
		Embeddings: ei.embeddings,
		Clusters:   ei.clusters,
	}

	return json.Marshal(data)
}

// Deserialize restores the index from serialized data.
func (ei *EmbeddingIndex) Deserialize(data []byte) error {
	ei.mu.Lock()
	defer ei.mu.Unlock()

	var stored struct {
		Embeddings []indexedEmbedding `json:"embeddings"`
		Clusters   []EmbeddingCluster `json:"clusters"`
	}

	if err := json.Unmarshal(data, &stored); err != nil {
		return err
	}

	ei.embeddings = stored.Embeddings
	ei.clusters = stored.Clusters
	return nil
}

// OllamaEmbeddingProvider implements EmbeddingProvider using Ollama.
type OllamaEmbeddingProvider struct {
	baseURL   string
	model     string
	dimension int
}

// NewOllamaEmbeddingProvider creates a provider using Ollama embeddings.
func NewOllamaEmbeddingProvider(baseURL, model string, dimension int) *OllamaEmbeddingProvider {
	return &OllamaEmbeddingProvider{
		baseURL:   baseURL,
		model:     model,
		dimension: dimension,
	}
}

func (o *OllamaEmbeddingProvider) Embed(ctx context.Context, text string) ([]float32, error) {
	// Placeholder - in production, call Ollama API
	// ollama pull nomic-embed-text (384 dimensions)
	// POST /api/embeddings { "model": "nomic-embed-text", "prompt": text }
	return make([]float32, o.dimension), nil
}

func (o *OllamaEmbeddingProvider) EmbedBatch(ctx context.Context, texts []string) ([][]float32, error) {
	results := make([][]float32, len(texts))
	for i, text := range texts {
		emb, err := o.Embed(ctx, text)
		if err != nil {
			return nil, err
		}
		results[i] = emb
	}
	return results, nil
}

func (o *OllamaEmbeddingProvider) Dimension() int {
	return o.dimension
}

func (o *OllamaEmbeddingProvider) Name() string {
	return "ollama/" + o.model
}
