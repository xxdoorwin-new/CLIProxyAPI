package usermanagement

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
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
