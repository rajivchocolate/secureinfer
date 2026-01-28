package store

import "context"

// Cache defines the interface for caching operations.
// Implementations: Redis, in-memory
type Cache interface {
	// Get retrieves a value by key.
	Get(ctx context.Context, key string) (string, error)

	// GetInt retrieves an integer value.
	GetInt(ctx context.Context, key string) (int, error)

	// Set stores a value with optional TTL (seconds).
	Set(ctx context.Context, key, value string, ttl int) error

	// Delete removes a key.
	Delete(ctx context.Context, key string) error

	// Incr increments a counter and returns the new value.
	Incr(ctx context.Context, key string) (int, error)

	// Expire sets TTL on an existing key.
	Expire(ctx context.Context, key string, ttl int) error

	// Close closes the connection.
	Close() error
}
