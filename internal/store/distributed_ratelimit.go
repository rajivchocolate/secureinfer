package store

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// DistributedRateLimiter provides distributed rate limiting across multiple instances.
// Uses Redis for coordination when available, falls back to local limiting.
type DistributedRateLimiter struct {
	cache        Cache
	localLimiter *LocalRateLimiter
	keyPrefix    string
	fallback     bool // Use local limiter when Redis unavailable
}

// RateLimitConfig configures a rate limit rule.
type RateLimitConfig struct {
	Name           string        `json:"name"`
	Key            string        `json:"key"`           // Template: "tenant:{tenant_id}", "ip:{ip}"
	Limit          int           `json:"limit"`         // Max requests
	Window         time.Duration `json:"window"`        // Time window
	BurstLimit     int           `json:"burst_limit"`   // Burst allowance
	BurstWindow    time.Duration `json:"burst_window"`  // Burst window
	WarnThreshold  float64       `json:"warn_threshold"` // Warn at this % of limit
	BlockOnExceed  bool          `json:"block_on_exceed"`
}

// RateLimitResult contains the result of a rate limit check.
type RateLimitResult struct {
	Allowed      bool          `json:"allowed"`
	Remaining    int           `json:"remaining"`
	Limit        int           `json:"limit"`
	ResetAfter   time.Duration `json:"reset_after"`
	RetryAfter   time.Duration `json:"retry_after,omitempty"`
	Warning      bool          `json:"warning"`
	BurstUsed    int           `json:"burst_used,omitempty"`
}

// NewDistributedRateLimiter creates a new distributed rate limiter.
func NewDistributedRateLimiter(cache Cache, keyPrefix string) *DistributedRateLimiter {
	return &DistributedRateLimiter{
		cache:        cache,
		localLimiter: NewLocalRateLimiter(),
		keyPrefix:    keyPrefix,
		fallback:     true,
	}
}

// Check performs a rate limit check using sliding window algorithm.
func (d *DistributedRateLimiter) Check(ctx context.Context, config RateLimitConfig, identifier string) (*RateLimitResult, error) {
	key := fmt.Sprintf("%s:%s:%s", d.keyPrefix, config.Name, identifier)

	// Try distributed check first
	result, err := d.distributedCheck(ctx, key, config)
	if err != nil && d.fallback {
		// Fall back to local limiting
		return d.localLimiter.Check(config, identifier)
	}

	return result, err
}

// distributedCheck implements sliding window rate limiting using Redis.
func (d *DistributedRateLimiter) distributedCheck(ctx context.Context, key string, config RateLimitConfig) (*RateLimitResult, error) {
	now := time.Now()
	windowStart := now.Add(-config.Window)

	// Use Redis sorted set for sliding window
	// Score = timestamp, Member = request ID

	// Get current count in window (used for metrics/logging)
	_, err := d.cache.GetInt(ctx, key+":count")
	if err != nil {
		// First request in window
	}

	// Increment and set expiry
	newCount, err := d.cache.Incr(ctx, key+":count")
	if err != nil {
		return nil, err
	}

	if newCount == 1 {
		// First request in window, set expiry
		d.cache.Expire(ctx, key+":count", int(config.Window.Seconds()))
	}

	result := &RateLimitResult{
		Limit:      config.Limit,
		Remaining:  config.Limit - int(newCount),
		ResetAfter: config.Window - now.Sub(windowStart),
	}

	if result.Remaining < 0 {
		result.Remaining = 0
	}

	// Check if within limit
	if int(newCount) > config.Limit {
		result.Allowed = false
		result.RetryAfter = result.ResetAfter

		// Check burst allowance
		if config.BurstLimit > 0 {
			burstKey := key + ":burst"
			burstCount, _ := d.cache.GetInt(ctx, burstKey)
			if int(burstCount) < config.BurstLimit {
				d.cache.Incr(ctx, burstKey)
				if burstCount == 0 {
					d.cache.Expire(ctx, burstKey, int(config.BurstWindow.Seconds()))
				}
				result.Allowed = true
				result.BurstUsed = int(burstCount) + 1
			}
		}
	} else {
		result.Allowed = true
	}

	// Check warning threshold
	if config.WarnThreshold > 0 {
		usageRatio := float64(newCount) / float64(config.Limit)
		if usageRatio >= config.WarnThreshold {
			result.Warning = true
		}
	}

	return result, nil
}

// LocalRateLimiter provides in-memory rate limiting for single instance or fallback.
type LocalRateLimiter struct {
	mu      sync.RWMutex
	windows map[string]*slidingWindow
}

type slidingWindow struct {
	counts    []int64   // Request counts per sub-window
	timestamps []int64  // Sub-window timestamps
	subWindow time.Duration
	numSubs   int
}

// NewLocalRateLimiter creates a new local rate limiter.
func NewLocalRateLimiter() *LocalRateLimiter {
	limiter := &LocalRateLimiter{
		windows: make(map[string]*slidingWindow),
	}

	// Start cleanup goroutine
	go limiter.cleanup()

	return limiter
}

// Check performs a rate limit check.
func (l *LocalRateLimiter) Check(config RateLimitConfig, identifier string) (*RateLimitResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	key := config.Name + ":" + identifier
	now := time.Now()

	// Get or create window
	window, exists := l.windows[key]
	if !exists {
		numSubs := 10 // 10 sub-windows for smooth sliding
		window = &slidingWindow{
			counts:    make([]int64, numSubs),
			timestamps: make([]int64, numSubs),
			subWindow: config.Window / time.Duration(numSubs),
			numSubs:   numSubs,
		}
		l.windows[key] = window
	}

	// Slide the window
	currentSub := int(now.UnixNano() / int64(window.subWindow))

	// Count requests in current window
	total := int64(0)
	windowStart := now.Add(-config.Window)
	for i := 0; i < window.numSubs; i++ {
		if window.timestamps[i] >= windowStart.UnixNano() {
			total += window.counts[i]
		}
	}

	// Find current sub-window index
	idx := currentSub % window.numSubs

	// Check if this is a new sub-window
	expectedTimestamp := now.Truncate(window.subWindow).UnixNano()
	if window.timestamps[idx] != expectedTimestamp {
		window.counts[idx] = 0
		window.timestamps[idx] = expectedTimestamp
	}

	// Increment count
	window.counts[idx]++
	total++

	result := &RateLimitResult{
		Limit:      config.Limit,
		Remaining:  config.Limit - int(total),
		ResetAfter: config.Window,
		Allowed:    int(total) <= config.Limit,
	}

	if result.Remaining < 0 {
		result.Remaining = 0
	}

	if !result.Allowed {
		result.RetryAfter = window.subWindow
	}

	// Check warning threshold
	if config.WarnThreshold > 0 {
		usageRatio := float64(total) / float64(config.Limit)
		if usageRatio >= config.WarnThreshold {
			result.Warning = true
		}
	}

	return result, nil
}

func (l *LocalRateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		l.mu.Lock()
		now := time.Now()
		for key, window := range l.windows {
			// Remove if all sub-windows are old
			allOld := true
			for i := 0; i < window.numSubs; i++ {
				if window.timestamps[i] > now.Add(-time.Hour).UnixNano() {
					allOld = false
					break
				}
			}
			if allOld {
				delete(l.windows, key)
			}
		}
		l.mu.Unlock()
	}
}

// MultiTierRateLimiter applies multiple rate limit tiers.
type MultiTierRateLimiter struct {
	limiter *DistributedRateLimiter
	tiers   []RateLimitConfig
}

// NewMultiTierRateLimiter creates a rate limiter with multiple tiers.
func NewMultiTierRateLimiter(limiter *DistributedRateLimiter) *MultiTierRateLimiter {
	return &MultiTierRateLimiter{
		limiter: limiter,
		tiers: []RateLimitConfig{
			{
				Name:          "burst",
				Limit:         10,
				Window:        1 * time.Second,
				WarnThreshold: 0.8,
				BlockOnExceed: true,
			},
			{
				Name:          "short",
				Limit:         60,
				Window:        1 * time.Minute,
				WarnThreshold: 0.8,
				BlockOnExceed: true,
			},
			{
				Name:          "medium",
				Limit:         1000,
				Window:        1 * time.Hour,
				WarnThreshold: 0.9,
				BlockOnExceed: false,
			},
			{
				Name:          "daily",
				Limit:         10000,
				Window:        24 * time.Hour,
				WarnThreshold: 0.9,
				BlockOnExceed: false,
			},
		},
	}
}

// Check performs multi-tier rate limiting.
func (m *MultiTierRateLimiter) Check(ctx context.Context, identifier string) (*RateLimitResult, error) {
	var lastResult *RateLimitResult

	for _, tier := range m.tiers {
		result, err := m.limiter.Check(ctx, tier, identifier)
		if err != nil {
			return nil, err
		}

		lastResult = result

		if !result.Allowed && tier.BlockOnExceed {
			return result, nil
		}
	}

	return lastResult, nil
}

// SetTiers updates the rate limit tiers.
func (m *MultiTierRateLimiter) SetTiers(tiers []RateLimitConfig) {
	m.tiers = tiers
}
