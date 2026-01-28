package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// Role defines a user role with associated permissions.
type Role string

const (
	RoleAdmin     Role = "admin"      // Full access to all endpoints
	RoleUser      Role = "user"       // Standard API access
	RoleReadOnly  Role = "read_only"  // Read-only access
	RoleMonitor   Role = "monitor"    // Security monitoring only
	RoleService   Role = "service"    // Service-to-service communication
)

// Permission defines specific API permissions.
type Permission string

const (
	PermChatCompletions   Permission = "chat:completions"
	PermChatStream        Permission = "chat:stream"
	PermSecurityRead      Permission = "security:read"
	PermSecurityWrite     Permission = "security:write"
	PermTenantsCreate     Permission = "tenants:create"
	PermTenantsRead       Permission = "tenants:read"
	PermTenantsDelete     Permission = "tenants:delete"
	PermModelVerify       Permission = "model:verify"
	PermMetricsRead       Permission = "metrics:read"
	PermAdminAll          Permission = "admin:*"
)

// RolePermissions maps roles to their allowed permissions.
var RolePermissions = map[Role][]Permission{
	RoleAdmin: {
		PermAdminAll,
	},
	RoleUser: {
		PermChatCompletions,
		PermChatStream,
		PermSecurityRead,
		PermTenantsRead,
	},
	RoleReadOnly: {
		PermSecurityRead,
		PermTenantsRead,
		PermMetricsRead,
	},
	RoleMonitor: {
		PermSecurityRead,
		PermSecurityWrite,
		PermMetricsRead,
	},
	RoleService: {
		PermChatCompletions,
		PermChatStream,
		PermModelVerify,
	},
}

// APIKey represents an API key with associated metadata.
type APIKey struct {
	ID           string            `json:"id"`
	KeyHash      string            `json:"-"` // Never expose hash
	KeyPrefix    string            `json:"key_prefix"` // First 8 chars for identification
	TenantID     string            `json:"tenant_id"`
	Name         string            `json:"name"`
	Role         Role              `json:"role"`
	Scopes       []Permission      `json:"scopes,omitempty"` // Additional scope restrictions
	CreatedAt    time.Time         `json:"created_at"`
	ExpiresAt    *time.Time        `json:"expires_at,omitempty"`
	LastUsedAt   *time.Time        `json:"last_used_at,omitempty"`
	RotatedFrom  string            `json:"rotated_from,omitempty"`
	RateLimitRPM int               `json:"rate_limit_rpm,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	Active       bool              `json:"active"`
}

// KeyRotation tracks key rotation history.
type KeyRotation struct {
	OldKeyID    string    `json:"old_key_id"`
	NewKeyID    string    `json:"new_key_id"`
	RotatedAt   time.Time `json:"rotated_at"`
	RotatedBy   string    `json:"rotated_by"`
	Reason      string    `json:"reason,omitempty"`
	GracePeriod time.Duration `json:"grace_period"`
}

// RBACManager handles role-based access control.
type RBACManager struct {
	mu sync.RWMutex

	// In production, these would be backed by a database
	keys         map[string]*APIKey // keyHash -> APIKey
	keysByPrefix map[string]*APIKey // prefix -> APIKey
	rotations    []KeyRotation
}

// NewRBACManager creates a new RBAC manager.
func NewRBACManager() *RBACManager {
	return &RBACManager{
		keys:         make(map[string]*APIKey),
		keysByPrefix: make(map[string]*APIKey),
		rotations:    make([]KeyRotation, 0),
	}
}

// GenerateAPIKey creates a new API key with specified role.
func (r *RBACManager) GenerateAPIKey(tenantID, name string, role Role, expiresIn *time.Duration) (string, *APIKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Generate random key: sk-<random>
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", nil, err
	}
	rawKey := "sk-" + hex.EncodeToString(keyBytes)

	// Hash the key for storage
	keyHash := hashKey(rawKey)
	keyPrefix := rawKey[:11] // "sk-" + first 8 chars

	// Create key record
	now := time.Now()
	key := &APIKey{
		ID:        generateID(),
		KeyHash:   keyHash,
		KeyPrefix: keyPrefix,
		TenantID:  tenantID,
		Name:      name,
		Role:      role,
		CreatedAt: now,
		Active:    true,
	}

	if expiresIn != nil {
		exp := now.Add(*expiresIn)
		key.ExpiresAt = &exp
	}

	r.keys[keyHash] = key
	r.keysByPrefix[keyPrefix] = key

	return rawKey, key, nil
}

// ValidateKey validates an API key and returns associated metadata.
func (r *RBACManager) ValidateKey(rawKey string) (*APIKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	keyHash := hashKey(rawKey)
	key, exists := r.keys[keyHash]
	if !exists {
		return nil, errors.New("invalid api key")
	}

	if !key.Active {
		return nil, errors.New("api key is inactive")
	}

	if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
		return nil, errors.New("api key has expired")
	}

	// Update last used (in production, do this async)
	now := time.Now()
	key.LastUsedAt = &now

	return key, nil
}

// HasPermission checks if a key has a specific permission.
func (r *RBACManager) HasPermission(key *APIKey, required Permission) bool {
	// Admin has all permissions
	if key.Role == RoleAdmin {
		return true
	}

	// Check if required permission is explicitly granted via scopes
	if len(key.Scopes) > 0 {
		for _, scope := range key.Scopes {
			if scope == required || scope == PermAdminAll {
				return true
			}
		}
		return false // Scopes are restrictive
	}

	// Check role permissions
	perms, ok := RolePermissions[key.Role]
	if !ok {
		return false
	}

	for _, perm := range perms {
		if perm == required || perm == PermAdminAll {
			return true
		}
	}

	return false
}

// RotateKey rotates an API key, returning a new key.
func (r *RBACManager) RotateKey(oldRawKey string, gracePeriod time.Duration, reason string) (string, *APIKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	oldHash := hashKey(oldRawKey)
	oldKey, exists := r.keys[oldHash]
	if !exists {
		return "", nil, errors.New("key not found")
	}

	// Generate new key with same settings
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", nil, err
	}
	newRawKey := "sk-" + hex.EncodeToString(keyBytes)
	newHash := hashKey(newRawKey)
	newPrefix := newRawKey[:11]

	now := time.Now()
	newKey := &APIKey{
		ID:           generateID(),
		KeyHash:      newHash,
		KeyPrefix:    newPrefix,
		TenantID:     oldKey.TenantID,
		Name:         oldKey.Name + " (rotated)",
		Role:         oldKey.Role,
		Scopes:       oldKey.Scopes,
		CreatedAt:    now,
		ExpiresAt:    oldKey.ExpiresAt,
		RotatedFrom:  oldKey.ID,
		RateLimitRPM: oldKey.RateLimitRPM,
		Metadata:     oldKey.Metadata,
		Active:       true,
	}

	// Record rotation
	rotation := KeyRotation{
		OldKeyID:    oldKey.ID,
		NewKeyID:    newKey.ID,
		RotatedAt:   now,
		Reason:      reason,
		GracePeriod: gracePeriod,
	}

	// If grace period, old key remains active temporarily
	if gracePeriod > 0 {
		graceExpiry := now.Add(gracePeriod)
		oldKey.ExpiresAt = &graceExpiry
	} else {
		oldKey.Active = false
	}

	r.keys[newHash] = newKey
	r.keysByPrefix[newPrefix] = newKey
	r.rotations = append(r.rotations, rotation)

	return newRawKey, newKey, nil
}

// RevokeKey immediately revokes an API key.
func (r *RBACManager) RevokeKey(keyID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, key := range r.keys {
		if key.ID == keyID {
			key.Active = false
			return nil
		}
	}

	return errors.New("key not found")
}

// ListKeys returns all keys for a tenant.
func (r *RBACManager) ListKeys(tenantID string) []*APIKey {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var keys []*APIKey
	for _, key := range r.keys {
		if key.TenantID == tenantID {
			// Create copy without hash
			keyCopy := *key
			keyCopy.KeyHash = ""
			keys = append(keys, &keyCopy)
		}
	}
	return keys
}

// SetKeyScopes updates the scopes for a key.
func (r *RBACManager) SetKeyScopes(keyID string, scopes []Permission) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, key := range r.keys {
		if key.ID == keyID {
			key.Scopes = scopes
			return nil
		}
	}

	return errors.New("key not found")
}

// AuthContext carries authentication info through requests.
type AuthContext struct {
	Key        *APIKey
	TenantID   string
	Role       Role
	Scopes     []Permission
	RequestID  string
}

// ContextKey is the context key for auth info.
type ContextKey string

const AuthContextKey ContextKey = "auth_context"

// GetAuthContext extracts auth context from request context.
func GetAuthContext(ctx context.Context) *AuthContext {
	if v := ctx.Value(AuthContextKey); v != nil {
		if ac, ok := v.(*AuthContext); ok {
			return ac
		}
	}
	return nil
}

// SetAuthContext adds auth context to request context.
func SetAuthContext(ctx context.Context, auth *AuthContext) context.Context {
	return context.WithValue(ctx, AuthContextKey, auth)
}

// Helper functions

func hashKey(key string) string {
	hash := sha256.Sum256([]byte("secureinfer:apikey:" + key))
	return hex.EncodeToString(hash[:])
}

func generateID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}
