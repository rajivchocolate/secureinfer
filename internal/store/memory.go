package store

import (
	"context"
	"strconv"
	"sync"
	"time"
)

// MemoryStore implements Cache using in-memory storage.
// Used as fallback when Redis is unavailable.
type MemoryStore struct {
	mu    sync.RWMutex
	data  map[string]entry
	close chan struct{}
}

type entry struct {
	value     string
	expiresAt time.Time
}

// NewMemoryStore creates a new in-memory cache.
func NewMemoryStore() *MemoryStore {
	m := &MemoryStore{
		data:  make(map[string]entry),
		close: make(chan struct{}),
	}

	// Start cleanup goroutine
	go m.cleanup()

	return m
}

// cleanup periodically removes expired entries.
func (m *MemoryStore) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.mu.Lock()
			now := time.Now()
			for k, v := range m.data {
				if !v.expiresAt.IsZero() && now.After(v.expiresAt) {
					delete(m.data, k)
				}
			}
			m.mu.Unlock()
		case <-m.close:
			return
		}
	}
}

// Get retrieves a value by key.
func (m *MemoryStore) Get(ctx context.Context, key string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	e, ok := m.data[key]
	if !ok {
		return "", nil
	}

	// Check expiry
	if !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
		return "", nil
	}

	return e.value, nil
}

// GetInt retrieves an integer value.
func (m *MemoryStore) GetInt(ctx context.Context, key string) (int, error) {
	val, err := m.Get(ctx, key)
	if err != nil || val == "" {
		return 0, err
	}
	return strconv.Atoi(val)
}

// Set stores a value with optional TTL.
func (m *MemoryStore) Set(ctx context.Context, key, value string, ttl int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	e := entry{value: value}
	if ttl > 0 {
		e.expiresAt = time.Now().Add(time.Duration(ttl) * time.Second)
	}

	m.data[key] = e
	return nil
}

// Delete removes a key.
func (m *MemoryStore) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.data, key)
	return nil
}

// Incr increments a counter.
func (m *MemoryStore) Incr(ctx context.Context, key string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.data[key]
	var val int
	if ok && e.value != "" {
		val, _ = strconv.Atoi(e.value)
	}

	val++
	m.data[key] = entry{
		value:     strconv.Itoa(val),
		expiresAt: e.expiresAt,
	}

	return val, nil
}

// Expire sets TTL on an existing key.
func (m *MemoryStore) Expire(ctx context.Context, key string, ttl int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.data[key]
	if !ok {
		return nil
	}

	e.expiresAt = time.Now().Add(time.Duration(ttl) * time.Second)
	m.data[key] = e
	return nil
}

// Close stops the cleanup goroutine.
func (m *MemoryStore) Close() error {
	close(m.close)
	return nil
}
