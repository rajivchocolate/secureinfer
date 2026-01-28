package store

import (
	"context"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisCache implements Cache using Redis.
type RedisCache struct {
	client *redis.Client
}

// NewRedis creates a new Redis cache connection.
func NewRedis(url string) (*RedisCache, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}

	client := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	return &RedisCache{client: client}, nil
}

// Get retrieves a value by key.
func (r *RedisCache) Get(ctx context.Context, key string) (string, error) {
	val, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", nil
	}
	return val, err
}

// GetInt retrieves an integer value.
func (r *RedisCache) GetInt(ctx context.Context, key string) (int, error) {
	val, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(val)
}

// Set stores a value with optional TTL.
func (r *RedisCache) Set(ctx context.Context, key, value string, ttl int) error {
	var expiration time.Duration
	if ttl > 0 {
		expiration = time.Duration(ttl) * time.Second
	}
	return r.client.Set(ctx, key, value, expiration).Err()
}

// Delete removes a key.
func (r *RedisCache) Delete(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}

// Incr increments a counter.
func (r *RedisCache) Incr(ctx context.Context, key string) (int, error) {
	val, err := r.client.Incr(ctx, key).Result()
	return int(val), err
}

// Expire sets TTL on an existing key.
func (r *RedisCache) Expire(ctx context.Context, key string, ttl int) error {
	return r.client.Expire(ctx, key, time.Duration(ttl)*time.Second).Err()
}

// Close closes the Redis connection.
func (r *RedisCache) Close() error {
	return r.client.Close()
}
