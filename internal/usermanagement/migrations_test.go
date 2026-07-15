package usermanagement

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenSQLiteStoreConfiguresWALAndMigrates(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "users.db")

	store, err := OpenSQLiteStore(ctx, SQLiteConfig{Path: dbPath})
	if err != nil {
		t.Fatalf("OpenSQLiteStore() error = %v", err)
	}
	defer store.Close()

	var journalMode string
	if err = store.DB().QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}
	if journalMode != "wal" {
		t.Fatalf("journal_mode = %q, want wal", journalMode)
	}

	var foreignKeys int
	if err = store.DB().QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		t.Fatalf("query foreign_keys: %v", err)
	}
	if foreignKeys != 1 {
		t.Fatalf("foreign_keys = %d, want 1", foreignKeys)
	}

	assertTableExists(t, store.DB(), "users")
	assertTableExists(t, store.DB(), "sessions")
	assertTableExists(t, store.DB(), "api_keys")
	assertTableExists(t, store.DB(), "model_policies")
	assertTableExists(t, store.DB(), "quota_policies")
	assertTableExists(t, store.DB(), "pricing_rules")
	assertTableExists(t, store.DB(), "usage_ledger")
	assertTableExists(t, store.DB(), "quota_rollups")

	var version int
	if err = store.DB().QueryRowContext(ctx, "SELECT MAX(version) FROM schema_migrations").Scan(&version); err != nil {
		t.Fatalf("query schema version: %v", err)
	}
	if version != CurrentSQLiteSchemaVersion {
		t.Fatalf("schema version = %d, want %d", version, CurrentSQLiteSchemaVersion)
	}
}

func TestMigrateSQLiteIsIdempotent(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "users.db")

	store, err := OpenSQLiteStore(ctx, SQLiteConfig{Path: dbPath})
	if err != nil {
		t.Fatalf("OpenSQLiteStore() error = %v", err)
	}
	defer store.Close()

	if err = MigrateSQLite(ctx, store.DB()); err != nil {
		t.Fatalf("MigrateSQLite() second run error = %v", err)
	}

	var count int
	if err = store.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatalf("query migration count: %v", err)
	}
	if count != len(sqliteMigrations) {
		t.Fatalf("migration count = %d, want %d", count, len(sqliteMigrations))
	}
}

func TestMigrateSQLiteV2NormalizesLegacyMultipleCurrentAssignments(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "users.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err = ConfigureSQLite(ctx, db); err != nil {
		t.Fatalf("ConfigureSQLite() error = %v", err)
	}
	if _, err = db.ExecContext(ctx, `CREATE TABLE schema_migrations (
		version INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	for _, statement := range sqliteMigrations[0].Statements {
		if _, err = db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("apply v1 statement: %v", err)
		}
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO schema_migrations(version, name) VALUES (?, ?)`, 1, sqliteMigrations[0].Name); err != nil {
		t.Fatalf("record v1 migration: %v", err)
	}

	older := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	newer := time.Date(2026, 7, 1, 11, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	if _, err = db.ExecContext(ctx, `INSERT INTO users (
		id, username, email, password_hash, status, role, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"user-1", "legacy", "legacy@example.test", []byte("hash"), UserStatusApproved, UserRoleUser, older, older); err != nil {
		t.Fatalf("insert legacy user: %v", err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO api_keys (
		id, user_id, name, key_hash, prefix, status, created_at, updated_at
	) VALUES
		('key-old', 'user-1', 'old', ?, 'cpak_old', 'active', ?, ?),
		('key-new', 'user-1', 'new', ?, 'cpak_new', 'disabled', ?, ?)`,
		[]byte("old-hash"), older, older, []byte("new-hash"), older, newer); err != nil {
		t.Fatalf("insert legacy api keys: %v", err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO usage_ledger (
		id, user_id, api_key_id, request_id, provider, model, status, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"usage-1", "user-1", "key-old", "request-old", "openai", "gpt-5", UsageStatusSucceeded, newer); err != nil {
		t.Fatalf("insert legacy usage: %v", err)
	}

	if err = MigrateSQLite(ctx, db); err != nil {
		t.Fatalf("MigrateSQLite() error = %v", err)
	}
	var oldStatus, newStatus string
	if err = db.QueryRowContext(ctx, `SELECT status FROM api_keys WHERE id = 'key-old'`).Scan(&oldStatus); err != nil {
		t.Fatalf("query old status: %v", err)
	}
	if err = db.QueryRowContext(ctx, `SELECT status FROM api_keys WHERE id = 'key-new'`).Scan(&newStatus); err != nil {
		t.Fatalf("query new status: %v", err)
	}
	if oldStatus != string(APIKeyStatusRevoked) || newStatus != string(APIKeyStatusDisabled) {
		t.Fatalf("statuses = old %q new %q, want revoked/disabled", oldStatus, newStatus)
	}
	var usageKeyID string
	if err = db.QueryRowContext(ctx, `SELECT api_key_id FROM usage_ledger WHERE id = 'usage-1'`).Scan(&usageKeyID); err != nil {
		t.Fatalf("query usage ledger: %v", err)
	}
	if usageKeyID != "key-old" {
		t.Fatalf("usage api_key_id = %q, want key-old", usageKeyID)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO api_keys (
		id, user_id, name, key_hash, prefix, status, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"key-historical-reuse", "user-1", "history", []byte("old-hash"), "cpak_old", APIKeyStatusRevoked, newer, newer); err != nil {
		t.Fatalf("insert duplicate revoked hash after migration: %v", err)
	}
}

func assertTableExists(t *testing.T, db *sql.DB, table string) {
	t.Helper()
	var name string
	err := db.QueryRow("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&name)
	if err != nil {
		t.Fatalf("table %s does not exist: %v", table, err)
	}
	if name != table {
		t.Fatalf("table name = %q, want %q", name, table)
	}
}
