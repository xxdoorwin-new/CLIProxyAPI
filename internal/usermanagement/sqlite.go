package usermanagement

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

type SQLiteConfig struct {
	Path string
}

type SQLiteStore struct {
	db *sql.DB
}

// OpenSQLiteStore opens the durable user-management database. Schema setup is handled
// separately by migrations so callers can control when initialization runs.
func OpenSQLiteStore(ctx context.Context, cfg SQLiteConfig) (*SQLiteStore, error) {
	path := strings.TrimSpace(cfg.Path)
	if path == "" {
		return nil, fmt.Errorf("user management sqlite: path is required")
	}
	if err := ensureSQLiteParent(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("user management sqlite: open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err = ConfigureSQLite(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err = MigrateSQLite(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) DB() *sql.DB {
	if s == nil {
		return nil
	}
	return s.db
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func ensureSQLiteParent(path string) error {
	if strings.HasPrefix(path, "file:") || path == ":memory:" {
		return nil
	}
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("user management sqlite: create database directory: %w", err)
	}
	return nil
}
