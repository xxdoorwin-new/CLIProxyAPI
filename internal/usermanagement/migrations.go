package usermanagement

import (
	"context"
	"database/sql"
	"fmt"
)

const CurrentSQLiteSchemaVersion = 3

type SQLiteMigration struct {
	Version    int
	Name       string
	Statements []string
}

var sqliteMigrations = []SQLiteMigration{
	{
		Version: 1,
		Name:    "create_user_management_schema",
		Statements: []string{
			`CREATE TABLE IF NOT EXISTS users (
				id TEXT PRIMARY KEY,
				username TEXT NOT NULL COLLATE NOCASE,
				email TEXT NOT NULL COLLATE NOCASE,
				display_name TEXT NOT NULL DEFAULT '',
				password_hash BLOB NOT NULL,
				status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'suspended')),
				role TEXT NOT NULL CHECK (role IN ('user', 'admin')),
				metadata_json TEXT NOT NULL DEFAULT '{}',
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				approved_at TEXT,
				rejected_at TEXT,
				suspended_at TEXT,
				UNIQUE(username),
				UNIQUE(email)
			)`,
			`CREATE TABLE IF NOT EXISTS sessions (
				id TEXT PRIMARY KEY,
				user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
				token_hash BLOB NOT NULL UNIQUE,
				status TEXT NOT NULL CHECK (status IN ('active', 'revoked', 'expired')),
				created_at TEXT NOT NULL,
				expires_at TEXT NOT NULL,
				revoked_at TEXT,
				last_seen_at TEXT
			)`,
			`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`,
			`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)`,
			`CREATE TABLE IF NOT EXISTS api_keys (
				id TEXT PRIMARY KEY,
				user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
				name TEXT NOT NULL,
				key_hash BLOB NOT NULL UNIQUE,
				prefix TEXT NOT NULL,
				status TEXT NOT NULL CHECK (status IN ('active', 'disabled', 'revoked')),
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				expires_at TEXT,
				last_used_at TEXT
			)`,
			`CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id)`,
			`CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(prefix)`,
			`CREATE TABLE IF NOT EXISTS model_policies (
				subject_type TEXT NOT NULL CHECK (subject_type IN ('user', 'api_key')),
				subject_id TEXT NOT NULL,
				allow_all INTEGER NOT NULL DEFAULT 0 CHECK (allow_all IN (0, 1)),
				models_json TEXT NOT NULL DEFAULT '[]',
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				PRIMARY KEY(subject_type, subject_id)
			)`,
			`CREATE TABLE IF NOT EXISTS quota_policies (
				user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
				period TEXT NOT NULL CHECK (period IN ('monthly')),
				limit_credits INTEGER NOT NULL DEFAULT 0 CHECK (limit_credits >= 0),
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS pricing_rules (
				model TEXT PRIMARY KEY,
				input_credits_per_million_tokens INTEGER NOT NULL DEFAULT 0 CHECK (input_credits_per_million_tokens >= 0),
				output_credits_per_million_tokens INTEGER NOT NULL DEFAULT 0 CHECK (output_credits_per_million_tokens >= 0),
				cached_credits_per_million_tokens INTEGER NOT NULL DEFAULT 0 CHECK (cached_credits_per_million_tokens >= 0),
				reasoning_credits_per_million_tokens INTEGER NOT NULL DEFAULT 0 CHECK (reasoning_credits_per_million_tokens >= 0),
				image_credits INTEGER NOT NULL DEFAULT 0 CHECK (image_credits >= 0),
				request_credits INTEGER NOT NULL DEFAULT 0 CHECK (request_credits >= 0),
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS usage_ledger (
				id TEXT PRIMARY KEY,
				user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
				api_key_id TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
				request_id TEXT NOT NULL,
				provider TEXT NOT NULL,
				model TEXT NOT NULL,
				model_alias TEXT NOT NULL DEFAULT '',
				input_tokens INTEGER NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
				output_tokens INTEGER NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
				cached_tokens INTEGER NOT NULL DEFAULT 0 CHECK (cached_tokens >= 0),
				reasoning_tokens INTEGER NOT NULL DEFAULT 0 CHECK (reasoning_tokens >= 0),
				image_count INTEGER NOT NULL DEFAULT 0 CHECK (image_count >= 0),
				credit_cost INTEGER NOT NULL DEFAULT 0 CHECK (credit_cost >= 0),
				status TEXT NOT NULL CHECK (status IN ('succeeded', 'failed')),
				error_code TEXT NOT NULL DEFAULT '',
				latency_millis INTEGER NOT NULL DEFAULT 0 CHECK (latency_millis >= 0),
				created_at TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS idx_usage_ledger_user_created ON usage_ledger(user_id, created_at)`,
			`CREATE INDEX IF NOT EXISTS idx_usage_ledger_api_key_created ON usage_ledger(api_key_id, created_at)`,
			`CREATE INDEX IF NOT EXISTS idx_usage_ledger_request_id ON usage_ledger(request_id)`,
			`CREATE TABLE IF NOT EXISTS quota_rollups (
				user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
				period TEXT NOT NULL CHECK (period IN ('monthly')),
				period_start TEXT NOT NULL,
				period_end TEXT NOT NULL,
				limit_credits INTEGER NOT NULL DEFAULT 0 CHECK (limit_credits >= 0),
				used_credits INTEGER NOT NULL DEFAULT 0 CHECK (used_credits >= 0),
				updated_at TEXT NOT NULL,
				PRIMARY KEY(user_id, period, period_start)
			)`,
		},
	},
	{
		Version: 2,
		Name:    "retain_revoked_api_key_assignments",
		Statements: []string{
			`DROP INDEX IF EXISTS idx_usage_ledger_user_created`,
			`DROP INDEX IF EXISTS idx_usage_ledger_api_key_created`,
			`DROP INDEX IF EXISTS idx_usage_ledger_request_id`,
			`DROP INDEX IF EXISTS idx_api_keys_user_id`,
			`DROP INDEX IF EXISTS idx_api_keys_prefix`,
			`ALTER TABLE usage_ledger RENAME TO usage_ledger_old`,
			`ALTER TABLE api_keys RENAME TO api_keys_old`,
			`CREATE TABLE api_keys (
				id TEXT PRIMARY KEY,
				user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
				name TEXT NOT NULL,
				key_hash BLOB NOT NULL,
				prefix TEXT NOT NULL,
				status TEXT NOT NULL CHECK (status IN ('active', 'disabled', 'revoked')),
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				expires_at TEXT,
				last_used_at TEXT
			)`,
			`INSERT INTO api_keys (
				id, user_id, name, key_hash, prefix, status, created_at, updated_at, expires_at, last_used_at
			)
			SELECT
				id,
				user_id,
				name,
				key_hash,
				prefix,
				CASE
					WHEN status IN ('active', 'disabled') AND EXISTS (
						SELECT 1
						FROM api_keys_old newer
						WHERE newer.user_id = api_keys_old.user_id
							AND newer.status IN ('active', 'disabled')
							AND (
								newer.updated_at > api_keys_old.updated_at
								OR (newer.updated_at = api_keys_old.updated_at AND newer.id > api_keys_old.id)
							)
					) THEN 'revoked'
					ELSE status
				END,
				created_at,
				updated_at,
				expires_at,
				last_used_at
			FROM api_keys_old`,
			`CREATE TABLE usage_ledger (
				id TEXT PRIMARY KEY,
				user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
				api_key_id TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
				request_id TEXT NOT NULL,
				provider TEXT NOT NULL,
				model TEXT NOT NULL,
				model_alias TEXT NOT NULL DEFAULT '',
				input_tokens INTEGER NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
				output_tokens INTEGER NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
				cached_tokens INTEGER NOT NULL DEFAULT 0 CHECK (cached_tokens >= 0),
				reasoning_tokens INTEGER NOT NULL DEFAULT 0 CHECK (reasoning_tokens >= 0),
				image_count INTEGER NOT NULL DEFAULT 0 CHECK (image_count >= 0),
				credit_cost INTEGER NOT NULL DEFAULT 0 CHECK (credit_cost >= 0),
				status TEXT NOT NULL CHECK (status IN ('succeeded', 'failed')),
				error_code TEXT NOT NULL DEFAULT '',
				latency_millis INTEGER NOT NULL DEFAULT 0 CHECK (latency_millis >= 0),
				created_at TEXT NOT NULL
			)`,
			`INSERT INTO usage_ledger (
				id, user_id, api_key_id, request_id, provider, model, model_alias,
				input_tokens, output_tokens, cached_tokens, reasoning_tokens, image_count,
				credit_cost, status, error_code, latency_millis, created_at
			)
			SELECT
				id, user_id, api_key_id, request_id, provider, model, model_alias,
				input_tokens, output_tokens, cached_tokens, reasoning_tokens, image_count,
				credit_cost, status, error_code, latency_millis, created_at
			FROM usage_ledger_old`,
			`DROP TABLE usage_ledger_old`,
			`DROP TABLE api_keys_old`,
			`CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id)`,
			`CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(prefix)`,
			`CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_current_user_id_unique ON api_keys(user_id) WHERE status <> 'revoked'`,
			`CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_current_key_hash_unique ON api_keys(key_hash) WHERE status <> 'revoked'`,
			`CREATE INDEX IF NOT EXISTS idx_usage_ledger_user_created ON usage_ledger(user_id, created_at)`,
			`CREATE INDEX IF NOT EXISTS idx_usage_ledger_api_key_created ON usage_ledger(api_key_id, created_at)`,
			`CREATE INDEX IF NOT EXISTS idx_usage_ledger_request_id ON usage_ledger(request_id)`,
		},
	},
	{
		Version: 3,
		Name:    "add_usage_total_tokens_reporting_index",
		Statements: []string{
			`ALTER TABLE usage_ledger ADD COLUMN total_tokens INTEGER NOT NULL DEFAULT 0 CHECK (total_tokens >= 0)`,
			`CREATE INDEX IF NOT EXISTS idx_usage_ledger_created ON usage_ledger(created_at)`,
		},
	},
}

func ConfigureSQLite(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("user management sqlite: database is nil")
	}
	pragmas := []string{
		"PRAGMA busy_timeout = 5000",
		"PRAGMA foreign_keys = ON",
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
	}
	for _, pragma := range pragmas {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			return fmt.Errorf("user management sqlite: apply %s: %w", pragma, err)
		}
	}
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("user management sqlite: ping database: %w", err)
	}
	return nil
}

func MigrateSQLite(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("user management sqlite: database is nil")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("user management sqlite: begin migration: %w", err)
	}
	defer tx.Rollback()

	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("user management sqlite: ensure migration table: %w", err)
	}

	applied, err := appliedSQLiteMigrations(ctx, tx)
	if err != nil {
		return err
	}
	for _, migration := range sqliteMigrations {
		if applied[migration.Version] {
			continue
		}
		for _, statement := range migration.Statements {
			if _, err = tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("user management sqlite: migration %d %s: %w", migration.Version, migration.Name, err)
			}
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, name) VALUES (?, ?)`, migration.Version, migration.Name); err != nil {
			return fmt.Errorf("user management sqlite: record migration %d: %w", migration.Version, err)
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("user management sqlite: commit migration: %w", err)
	}
	return nil
}

func appliedSQLiteMigrations(ctx context.Context, tx *sql.Tx) (map[int]bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("user management sqlite: list applied migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[int]bool)
	for rows.Next() {
		var version int
		if err = rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("user management sqlite: scan migration: %w", err)
		}
		applied[version] = true
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("user management sqlite: iterate migrations: %w", err)
	}
	return applied, nil
}
