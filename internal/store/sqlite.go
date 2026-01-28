package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// SQLite wraps a SQLite database connection.
type SQLite struct {
	db *sql.DB
}

// Tenant represents a tenant/user.
type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// APIKey represents an API key.
type APIKey struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	KeyHash   string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Active    bool      `json:"active"`
}

// NewSQLite creates a new SQLite connection.
func NewSQLite(path string) (*SQLite, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	s := &SQLite{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	return s, nil
}

func (s *SQLite) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS tenants (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS api_keys (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL REFERENCES tenants(id),
		key_hash TEXT NOT NULL UNIQUE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME,
		active BOOLEAN DEFAULT 1
	);

	CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
	CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);

	CREATE TABLE IF NOT EXISTS security_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		tenant_id TEXT NOT NULL,
		event_type TEXT NOT NULL,
		risk_score INTEGER,
		action TEXT,
		details TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_events_tenant ON security_events(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(event_type);
	CREATE INDEX IF NOT EXISTS idx_events_time ON security_events(created_at);

	CREATE TABLE IF NOT EXISTS requests (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		tenant_id TEXT NOT NULL,
		request_hash TEXT,
		tokens_prompt INTEGER,
		tokens_completion INTEGER,
		latency_ms INTEGER,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_requests_tenant ON requests(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_requests_time ON requests(created_at);
	`
	_, err := s.db.Exec(schema)
	return err
}

func (s *SQLite) CreateTenant(ctx context.Context, name string) (*Tenant, error) {
	id := generateID()
	now := time.Now()

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO tenants (id, name, created_at) VALUES (?, ?, ?)",
		id, name, now,
	)
	if err != nil {
		return nil, err
	}

	return &Tenant{ID: id, Name: name, CreatedAt: now}, nil
}

func (s *SQLite) GetTenant(ctx context.Context, id string) (*Tenant, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT id, name, created_at FROM tenants WHERE id = ?", id,
	)

	var t Tenant
	if err := row.Scan(&t.ID, &t.Name, &t.CreatedAt); err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *SQLite) ValidateAPIKey(ctx context.Context, key string) (*Tenant, error) {
	keyHash := hashAPIKey(key)

	row := s.db.QueryRowContext(ctx, `
		SELECT t.id, t.name, t.created_at
		FROM api_keys k
		JOIN tenants t ON k.tenant_id = t.id
		WHERE k.key_hash = ?
		  AND k.active = 1
		  AND (k.expires_at IS NULL OR k.expires_at > ?)
	`, keyHash, time.Now())

	var t Tenant
	if err := row.Scan(&t.ID, &t.Name, &t.CreatedAt); err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *SQLite) CreateAPIKey(ctx context.Context, tenantID string, expiresIn time.Duration) (string, error) {
	key := generateAPIKey()
	keyHash := hashAPIKey(key)
	id := generateID()

	var expiresAt *time.Time
	if expiresIn > 0 {
		t := time.Now().Add(expiresIn)
		expiresAt = &t
	}

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO api_keys (id, tenant_id, key_hash, expires_at) VALUES (?, ?, ?, ?)",
		id, tenantID, keyHash, expiresAt,
	)
	if err != nil {
		return "", err
	}
	return key, nil
}

func (s *SQLite) RecordSecurityEvent(ctx context.Context, tenantID, eventType string, riskScore int, action, details string) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO security_events (tenant_id, event_type, risk_score, action, details) VALUES (?, ?, ?, ?, ?)",
		tenantID, eventType, riskScore, action, details,
	)
	return err
}

func (s *SQLite) GetSecurityEvents(ctx context.Context, limit int) ([]map[string]interface{}, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT tenant_id, event_type, risk_score, action, details, created_at
		FROM security_events ORDER BY created_at DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []map[string]interface{}
	for rows.Next() {
		var tenantID, eventType, action, details string
		var riskScore int
		var createdAt time.Time

		if err := rows.Scan(&tenantID, &eventType, &riskScore, &action, &details, &createdAt); err != nil {
			continue
		}

		events = append(events, map[string]interface{}{
			"tenant_id":  tenantID,
			"event_type": eventType,
			"risk_score": riskScore,
			"action":     action,
			"details":    details,
			"created_at": createdAt,
		})
	}
	return events, nil
}

func (s *SQLite) Close() error {
	return s.db.Close()
}

func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func generateAPIKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return "sk-" + hex.EncodeToString(b)
}

// hashAPIKey creates a salted hash of the API key.
// Note: For production, consider using bcrypt or argon2.
// SHA256 with the key prefix as implicit salt is acceptable for API keys
// since they're already high-entropy random strings.
func hashAPIKey(key string) string {
	// Add a domain separator to prevent hash collisions with other uses
	h := sha256.Sum256([]byte("secureinfer:apikey:" + key))
	return hex.EncodeToString(h[:])
}
