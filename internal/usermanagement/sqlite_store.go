package usermanagement

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var _ Store = (*SQLiteStore)(nil)

func (s *SQLiteStore) CreateUser(ctx context.Context, params CreateUserParams) (*User, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	user := &User{
		ID:           UserID(uuid.NewString()),
		Username:     strings.TrimSpace(params.Username),
		Email:        strings.TrimSpace(params.Email),
		DisplayName:  strings.TrimSpace(params.DisplayName),
		PasswordHash: append([]byte(nil), params.PasswordHash...),
		Status:       params.Status,
		Role:         params.Role,
		Metadata:     copyStringMap(params.Metadata),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	metadata, err := json.Marshal(user.Metadata)
	if err != nil {
		return nil, fmt.Errorf("%w: metadata cannot be encoded: %v", ErrInvalid, err)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO users (
		id, username, email, display_name, password_hash, status, role, metadata_json, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		user.ID, user.Username, user.Email, user.DisplayName, user.PasswordHash, user.Status, user.Role, string(metadata),
		formatTime(user.CreatedAt), formatTime(user.UpdatedAt),
	)
	if err != nil {
		return nil, mapSQLiteWriteError(err)
	}
	return user, nil
}

func (s *SQLiteStore) GetUser(ctx context.Context, id UserID) (*User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, username, email, display_name, password_hash, status, role,
		metadata_json, created_at, updated_at, approved_at, rejected_at, suspended_at FROM users WHERE id = ?`, id)
	return scanUser(row)
}

func (s *SQLiteStore) FindUserByIdentity(ctx context.Context, identity string) (*User, error) {
	identity = strings.TrimSpace(identity)
	row := s.db.QueryRowContext(ctx, `SELECT id, username, email, display_name, password_hash, status, role,
		metadata_json, created_at, updated_at, approved_at, rejected_at, suspended_at
		FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE LIMIT 1`, identity, identity)
	return scanUser(row)
}

func (s *SQLiteStore) ListUsers(ctx context.Context, filter UserFilter) ([]User, error) {
	var args []any
	query := `SELECT id, username, email, display_name, password_hash, status, role,
		metadata_json, created_at, updated_at, approved_at, rejected_at, suspended_at FROM users`
	var where []string
	if filter.Status != "" {
		where = append(where, "status = ?")
		args = append(args, filter.Status)
	}
	if filter.Role != "" {
		where = append(where, "role = ?")
		args = append(args, filter.Role)
	}
	if q := strings.TrimSpace(filter.Query); q != "" {
		where = append(where, "(username LIKE ? OR email LIKE ? OR display_name LIKE ?)")
		pattern := "%" + q + "%"
		args = append(args, pattern, pattern, pattern)
	}
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY created_at DESC, username ASC"
	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
		if filter.Offset > 0 {
			query += " OFFSET ?"
			args = append(args, filter.Offset)
		}
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("user management sqlite: list users: %w", err)
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		user, errScan := scanUser(rows)
		if errScan != nil {
			return nil, errScan
		}
		users = append(users, *user)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("user management sqlite: iterate users: %w", err)
	}
	return users, nil
}

func (s *SQLiteStore) UpdateUser(ctx context.Context, id UserID, params UpdateUserParams) (*User, error) {
	sets := []string{"updated_at = ?"}
	args := []any{formatTime(time.Now().UTC())}
	if params.DisplayName != nil {
		sets = append(sets, "display_name = ?")
		args = append(args, strings.TrimSpace(*params.DisplayName))
	}
	if len(params.PasswordHash) > 0 {
		sets = append(sets, "password_hash = ?")
		args = append(args, params.PasswordHash)
	}
	if params.Status != nil {
		if !params.Status.IsValid() {
			return nil, invalid("invalid user status %q", *params.Status)
		}
		sets = append(sets, "status = ?")
		args = append(args, *params.Status)
	}
	if params.Role != nil {
		if !params.Role.IsValid() {
			return nil, invalid("invalid user role %q", *params.Role)
		}
		sets = append(sets, "role = ?")
		args = append(args, *params.Role)
	}
	if params.Metadata != nil {
		metadata, err := json.Marshal(params.Metadata)
		if err != nil {
			return nil, fmt.Errorf("%w: metadata cannot be encoded: %v", ErrInvalid, err)
		}
		sets = append(sets, "metadata_json = ?")
		args = append(args, string(metadata))
	}
	if params.ApprovedAt != nil {
		sets = append(sets, "approved_at = ?")
		args = append(args, formatTime(*params.ApprovedAt))
	}
	if params.RejectedAt != nil {
		sets = append(sets, "rejected_at = ?")
		args = append(args, formatTime(*params.RejectedAt))
	}
	if params.SuspendedAt != nil {
		sets = append(sets, "suspended_at = ?")
		args = append(args, formatTime(*params.SuspendedAt))
	}
	args = append(args, id)
	result, err := s.db.ExecContext(ctx, "UPDATE users SET "+strings.Join(sets, ", ")+" WHERE id = ?", args...)
	if err != nil {
		return nil, mapSQLiteWriteError(err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return nil, ErrNotFound
	}
	return s.GetUser(ctx, id)
}

func (s *SQLiteStore) DeleteUser(ctx context.Context, id UserID) error {
	if id == "" {
		return ErrInvalid
	}
	// model_policies has no FK to users, clean it up explicitly.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM model_policies WHERE subject_type = ? AND subject_id = ?`,
		PolicySubjectUser, string(id)); err != nil {
		return fmt.Errorf("user management sqlite: delete user model policy: %w", err)
	}
	// Deleting the user row cascades sessions, api_keys, quota_policies, quota_rollups, usage_ledger.
	result, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return mapSQLiteWriteError(err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) CreateSession(ctx context.Context, params CreateSessionParams) (*Session, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	session := &Session{
		ID:        SessionID(uuid.NewString()),
		UserID:    params.UserID,
		TokenHash: append([]byte(nil), params.TokenHash...),
		Status:    SessionStatusActive,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: params.ExpiresAt.UTC(),
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (
		id, user_id, token_hash, status, created_at, expires_at
	) VALUES (?, ?, ?, ?, ?, ?)`, session.ID, session.UserID, session.TokenHash, session.Status, formatTime(session.CreatedAt), formatTime(session.ExpiresAt))
	if err != nil {
		return nil, mapSQLiteWriteError(err)
	}
	return session, nil
}

func (s *SQLiteStore) GetSession(ctx context.Context, id SessionID) (*Session, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, user_id, token_hash, status, created_at, expires_at, revoked_at, last_seen_at
		FROM sessions WHERE id = ?`, id)
	return scanSession(row)
}

func (s *SQLiteStore) FindSessionByTokenHash(ctx context.Context, tokenHash []byte) (*Session, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, user_id, token_hash, status, created_at, expires_at, revoked_at, last_seen_at
		FROM sessions WHERE token_hash = ?`, tokenHash)
	return scanSession(row)
}

func (s *SQLiteStore) UpdateSession(ctx context.Context, id SessionID, params UpdateSessionParams) (*Session, error) {
	var sets []string
	var args []any
	if params.Status != nil {
		if !params.Status.IsValid() {
			return nil, invalid("invalid session status %q", *params.Status)
		}
		sets = append(sets, "status = ?")
		args = append(args, *params.Status)
	}
	if params.RevokedAt != nil {
		sets = append(sets, "revoked_at = ?")
		args = append(args, formatTime(*params.RevokedAt))
	}
	if params.LastSeenAt != nil {
		sets = append(sets, "last_seen_at = ?")
		args = append(args, formatTime(*params.LastSeenAt))
	}
	if len(sets) == 0 {
		return s.GetSession(ctx, id)
	}
	args = append(args, id)
	result, err := s.db.ExecContext(ctx, "UPDATE sessions SET "+strings.Join(sets, ", ")+" WHERE id = ?", args...)
	if err != nil {
		return nil, mapSQLiteWriteError(err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return nil, ErrNotFound
	}
	return s.GetSession(ctx, id)
}

func (s *SQLiteStore) RevokeSessionsForUser(ctx context.Context, userID UserID) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET status = ?, revoked_at = ? WHERE user_id = ? AND status = ?`,
		SessionStatusRevoked, formatTime(time.Now().UTC()), userID, SessionStatusActive)
	if err != nil {
		return mapSQLiteWriteError(err)
	}
	return nil
}

func (s *SQLiteStore) DeleteExpiredSessions(ctx context.Context, before time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, formatTime(before))
	if err != nil {
		return 0, mapSQLiteWriteError(err)
	}
	return result.RowsAffected()
}

func (s *SQLiteStore) CreateAPIKey(ctx context.Context, params CreateAPIKeyParams) (*APIKey, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	key := &APIKey{
		ID:        APIKeyID(uuid.NewString()),
		UserID:    params.UserID,
		Name:      strings.TrimSpace(params.Name),
		KeyHash:   append([]byte(nil), params.KeyHash...),
		Prefix:    strings.TrimSpace(params.Prefix),
		Status:    params.Status,
		CreatedAt: now,
		UpdatedAt: now,
		ExpiresAt: params.ExpiresAt,
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO api_keys (
		id, user_id, name, key_hash, prefix, status, created_at, updated_at, expires_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		key.ID, key.UserID, key.Name, key.KeyHash, key.Prefix, key.Status, formatTime(key.CreatedAt), formatTime(key.UpdatedAt), formatOptionalTime(key.ExpiresAt),
	)
	if err != nil {
		return nil, mapSQLiteWriteError(err)
	}
	return key, nil
}

func (s *SQLiteStore) AssignAPIKey(ctx context.Context, params AssignAPIKeyParams) (*APIKey, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("user management sqlite: begin api key assignment transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()
	keyHash := append([]byte(nil), params.KeyHash...)
	name := strings.TrimSpace(params.Name)
	prefix := strings.TrimSpace(params.Prefix)

	current, err := scanAPIKey(tx.QueryRowContext(ctx, `SELECT id, user_id, name, key_hash, prefix, status, created_at, updated_at, expires_at, last_used_at
		FROM api_keys WHERE key_hash = ? AND status <> ? ORDER BY updated_at DESC, id DESC LIMIT 1`, keyHash, APIKeyStatusRevoked))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if current != nil {
		if current.UserID != params.UserID {
			return nil, ErrConflict
		}
		status := APIKeyStatusActive
		_, err = tx.ExecContext(ctx, `UPDATE api_keys
			SET name = ?, prefix = ?, key_hash = ?, status = ?, expires_at = ?, updated_at = ?
			WHERE id = ?`,
			name, prefix, keyHash, status, formatOptionalTime(params.ExpiresAt), formatTime(now), current.ID)
		if err != nil {
			return nil, mapSQLiteWriteError(err)
		}
		assigned, errGet := scanAPIKey(tx.QueryRowContext(ctx, `SELECT id, user_id, name, key_hash, prefix, status, created_at, updated_at, expires_at, last_used_at
			FROM api_keys WHERE id = ?`, current.ID))
		if errGet != nil {
			return nil, errGet
		}
		if err = tx.Commit(); err != nil {
			return nil, fmt.Errorf("user management sqlite: commit api key assignment transaction: %w", err)
		}
		return assigned, nil
	}

	_, err = tx.ExecContext(ctx, `UPDATE api_keys
		SET status = ?, updated_at = ?
		WHERE user_id = ? AND status <> ?`,
		APIKeyStatusRevoked, formatTime(now), params.UserID, APIKeyStatusRevoked)
	if err != nil {
		return nil, mapSQLiteWriteError(err)
	}

	key := &APIKey{
		ID:        APIKeyID(uuid.NewString()),
		UserID:    params.UserID,
		Name:      name,
		KeyHash:   keyHash,
		Prefix:    prefix,
		Status:    APIKeyStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
		ExpiresAt: params.ExpiresAt,
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO api_keys (
		id, user_id, name, key_hash, prefix, status, created_at, updated_at, expires_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		key.ID, key.UserID, key.Name, key.KeyHash, key.Prefix, key.Status, formatTime(key.CreatedAt), formatTime(key.UpdatedAt), formatOptionalTime(key.ExpiresAt),
	)
	if err != nil {
		mapped := mapSQLiteWriteError(err)
		if errors.Is(mapped, ErrAlreadyExists) {
			return nil, ErrConflict
		}
		return nil, mapped
	}
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("user management sqlite: commit api key assignment transaction: %w", err)
	}
	return key, nil
}

func (s *SQLiteStore) GetAPIKey(ctx context.Context, id APIKeyID) (*APIKey, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, user_id, name, key_hash, prefix, status, created_at, updated_at, expires_at, last_used_at
		FROM api_keys WHERE id = ?`, id)
	return scanAPIKey(row)
}

func (s *SQLiteStore) ListAPIKeysByUser(ctx context.Context, userID UserID) ([]APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, name, key_hash, prefix, status, created_at, updated_at, expires_at, last_used_at
		FROM api_keys WHERE user_id = ? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("user management sqlite: list api keys: %w", err)
	}
	defer rows.Close()
	var keys []APIKey
	for rows.Next() {
		key, errScan := scanAPIKey(rows)
		if errScan != nil {
			return nil, errScan
		}
		keys = append(keys, *key)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("user management sqlite: iterate api keys: %w", err)
	}
	return keys, nil
}

func (s *SQLiteStore) ListCurrentAPIKeysByUser(ctx context.Context, userID UserID) ([]APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, name, key_hash, prefix, status, created_at, updated_at, expires_at, last_used_at
		FROM api_keys WHERE user_id = ? AND status <> ? ORDER BY updated_at DESC, id DESC`, userID, APIKeyStatusRevoked)
	if err != nil {
		return nil, fmt.Errorf("user management sqlite: list current api keys: %w", err)
	}
	defer rows.Close()
	var keys []APIKey
	for rows.Next() {
		key, errScan := scanAPIKey(rows)
		if errScan != nil {
			return nil, errScan
		}
		keys = append(keys, *key)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("user management sqlite: iterate current api keys: %w", err)
	}
	return keys, nil
}

func (s *SQLiteStore) FindAPIKeyByPrefix(ctx context.Context, prefix string) ([]APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, name, key_hash, prefix, status, created_at, updated_at, expires_at, last_used_at
		FROM api_keys WHERE prefix = ? ORDER BY created_at DESC`, strings.TrimSpace(prefix))
	if err != nil {
		return nil, fmt.Errorf("user management sqlite: find api keys by prefix: %w", err)
	}
	defer rows.Close()
	var keys []APIKey
	for rows.Next() {
		key, errScan := scanAPIKey(rows)
		if errScan != nil {
			return nil, errScan
		}
		keys = append(keys, *key)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("user management sqlite: iterate api keys: %w", err)
	}
	return keys, nil
}

func (s *SQLiteStore) FindAPIKeyByFingerprint(ctx context.Context, fingerprint []byte) ([]APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, name, key_hash, prefix, status, created_at, updated_at, expires_at, last_used_at
		FROM api_keys WHERE key_hash = ? ORDER BY created_at DESC`, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("user management sqlite: find api keys by fingerprint: %w", err)
	}
	defer rows.Close()
	var keys []APIKey
	for rows.Next() {
		key, errScan := scanAPIKey(rows)
		if errScan != nil {
			return nil, errScan
		}
		keys = append(keys, *key)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("user management sqlite: iterate api keys: %w", err)
	}
	return keys, nil
}

func (s *SQLiteStore) FindCurrentAPIKeyByFingerprint(ctx context.Context, fingerprint []byte) ([]APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, name, key_hash, prefix, status, created_at, updated_at, expires_at, last_used_at
		FROM api_keys WHERE key_hash = ? AND status <> ? ORDER BY updated_at DESC, id DESC`, fingerprint, APIKeyStatusRevoked)
	if err != nil {
		return nil, fmt.Errorf("user management sqlite: find current api keys by fingerprint: %w", err)
	}
	defer rows.Close()
	var keys []APIKey
	for rows.Next() {
		key, errScan := scanAPIKey(rows)
		if errScan != nil {
			return nil, errScan
		}
		keys = append(keys, *key)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("user management sqlite: iterate current api keys: %w", err)
	}
	return keys, nil
}

func (s *SQLiteStore) UpdateAPIKey(ctx context.Context, id APIKeyID, params UpdateAPIKeyParams) (*APIKey, error) {
	sets := []string{"updated_at = ?"}
	args := []any{formatTime(time.Now().UTC())}
	if params.Name != nil {
		sets = append(sets, "name = ?")
		args = append(args, strings.TrimSpace(*params.Name))
	}
	if len(params.KeyHash) > 0 {
		sets = append(sets, "key_hash = ?")
		args = append(args, params.KeyHash)
	}
	if params.Prefix != nil {
		sets = append(sets, "prefix = ?")
		args = append(args, strings.TrimSpace(*params.Prefix))
	}
	if params.Status != nil {
		if !params.Status.IsValid() {
			return nil, invalid("invalid api key status %q", *params.Status)
		}
		sets = append(sets, "status = ?")
		args = append(args, *params.Status)
	}
	if params.ExpiresAt != nil {
		sets = append(sets, "expires_at = ?")
		args = append(args, formatTime(*params.ExpiresAt))
	}
	if params.LastUsedAt != nil {
		sets = append(sets, "last_used_at = ?")
		args = append(args, formatTime(*params.LastUsedAt))
	}
	args = append(args, id)
	result, err := s.db.ExecContext(ctx, "UPDATE api_keys SET "+strings.Join(sets, ", ")+" WHERE id = ?", args...)
	if err != nil {
		return nil, mapSQLiteWriteError(err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return nil, ErrNotFound
	}
	return s.GetAPIKey(ctx, id)
}

func (s *SQLiteStore) DeleteAPIKey(ctx context.Context, id APIKeyID) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM api_keys WHERE id = ?`, id)
	if err != nil {
		return mapSQLiteWriteError(err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) SetModelPolicy(ctx context.Context, params SetModelPolicyParams) (*ModelPolicy, error) {
	params.Models = NormalizeModelList(params.Models)
	if err := params.Validate(); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	models, err := json.Marshal(params.Models)
	if err != nil {
		return nil, fmt.Errorf("%w: models cannot be encoded: %v", ErrInvalid, err)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO model_policies (
		subject_type, subject_id, allow_all, models_json, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?)
	ON CONFLICT(subject_type, subject_id) DO UPDATE SET
		allow_all = excluded.allow_all,
		models_json = excluded.models_json,
		updated_at = excluded.updated_at`,
		params.SubjectType, params.SubjectID, boolInt(params.AllowAll), string(models), formatTime(now), formatTime(now),
	)
	if err != nil {
		return nil, mapSQLiteWriteError(err)
	}
	return s.GetModelPolicy(ctx, params.SubjectType, params.SubjectID)
}

func (s *SQLiteStore) GetModelPolicy(ctx context.Context, subjectType PolicySubjectType, subjectID string) (*ModelPolicy, error) {
	row := s.db.QueryRowContext(ctx, `SELECT subject_type, subject_id, allow_all, models_json, created_at, updated_at
		FROM model_policies WHERE subject_type = ? AND subject_id = ?`, subjectType, subjectID)
	return scanModelPolicy(row)
}

func (s *SQLiteStore) DeleteModelPolicy(ctx context.Context, subjectType PolicySubjectType, subjectID string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM model_policies WHERE subject_type = ? AND subject_id = ?`, subjectType, subjectID)
	if err != nil {
		return mapSQLiteWriteError(err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) SetQuotaPolicy(ctx context.Context, params SetQuotaPolicyParams) (*QuotaPolicy, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `INSERT INTO quota_policies (
		user_id, period, limit_credits, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?)
	ON CONFLICT(user_id) DO UPDATE SET
		period = excluded.period,
		limit_credits = excluded.limit_credits,
		updated_at = excluded.updated_at`,
		params.UserID, params.Period, params.LimitCredits, formatTime(now), formatTime(now),
	)
	if err != nil {
		return nil, mapSQLiteWriteError(err)
	}
	return s.GetQuotaPolicy(ctx, params.UserID)
}

func (s *SQLiteStore) GetQuotaPolicy(ctx context.Context, userID UserID) (*QuotaPolicy, error) {
	row := s.db.QueryRowContext(ctx, `SELECT user_id, period, limit_credits, created_at, updated_at FROM quota_policies WHERE user_id = ?`, userID)
	var policy QuotaPolicy
	var createdAt, updatedAt string
	err := row.Scan(&policy.UserID, &policy.Period, &policy.LimitCredits, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("user management sqlite: scan quota policy: %w", err)
	}
	policy.CreatedAt = parseStoredTime(createdAt)
	policy.UpdatedAt = parseStoredTime(updatedAt)
	return &policy, nil
}

func (s *SQLiteStore) SetPricingRule(ctx context.Context, params SetPricingRuleParams) (*PricingRule, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	model := strings.TrimSpace(params.Model)
	_, err := s.db.ExecContext(ctx, `INSERT INTO pricing_rules (
		model, input_credits_per_million_tokens, output_credits_per_million_tokens,
		cached_credits_per_million_tokens, reasoning_credits_per_million_tokens,
		image_credits, request_credits, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(model) DO UPDATE SET
		input_credits_per_million_tokens = excluded.input_credits_per_million_tokens,
		output_credits_per_million_tokens = excluded.output_credits_per_million_tokens,
		cached_credits_per_million_tokens = excluded.cached_credits_per_million_tokens,
		reasoning_credits_per_million_tokens = excluded.reasoning_credits_per_million_tokens,
		image_credits = excluded.image_credits,
		request_credits = excluded.request_credits,
		updated_at = excluded.updated_at`,
		model, params.InputCreditsPerMillionTokens, params.OutputCreditsPerMillionTokens,
		params.CachedCreditsPerMillionTokens, params.ReasoningCreditsPerMillionTokens,
		params.ImageCredits, params.RequestCredits, formatTime(now), formatTime(now),
	)
	if err != nil {
		return nil, mapSQLiteWriteError(err)
	}
	return s.GetPricingRule(ctx, model)
}

func (s *SQLiteStore) GetPricingRule(ctx context.Context, model string) (*PricingRule, error) {
	row := s.db.QueryRowContext(ctx, `SELECT model, input_credits_per_million_tokens, output_credits_per_million_tokens,
		cached_credits_per_million_tokens, reasoning_credits_per_million_tokens, image_credits, request_credits,
		created_at, updated_at FROM pricing_rules WHERE model = ?`, strings.TrimSpace(model))
	return scanPricingRule(row)
}

func (s *SQLiteStore) ListPricingRules(ctx context.Context) ([]PricingRule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT model, input_credits_per_million_tokens, output_credits_per_million_tokens,
		cached_credits_per_million_tokens, reasoning_credits_per_million_tokens, image_credits, request_credits,
		created_at, updated_at FROM pricing_rules ORDER BY model ASC`)
	if err != nil {
		return nil, fmt.Errorf("user management sqlite: list pricing rules: %w", err)
	}
	defer rows.Close()
	var rules []PricingRule
	for rows.Next() {
		rule, errScan := scanPricingRule(rows)
		if errScan != nil {
			return nil, errScan
		}
		rules = append(rules, *rule)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("user management sqlite: iterate pricing rules: %w", err)
	}
	return rules, nil
}

func (s *SQLiteStore) DeletePricingRule(ctx context.Context, model string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM pricing_rules WHERE model = ?`, strings.TrimSpace(model))
	if err != nil {
		return mapSQLiteWriteError(err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) AppendUsageLedgerRow(ctx context.Context, params CreateUsageLedgerRowParams) (*UsageLedgerRow, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	row := &UsageLedgerRow{
		ID:              UsageLedgerID(uuid.NewString()),
		UserID:          params.UserID,
		APIKeyID:        params.APIKeyID,
		RequestID:       strings.TrimSpace(params.RequestID),
		Provider:        strings.TrimSpace(params.Provider),
		Model:           strings.TrimSpace(params.Model),
		ModelAlias:      strings.TrimSpace(params.ModelAlias),
		InputTokens:     params.InputTokens,
		OutputTokens:    params.OutputTokens,
		CachedTokens:    params.CachedTokens,
		ReasoningTokens: params.ReasoningTokens,
		ImageCount:      params.ImageCount,
		CreditCost:      params.CreditCost,
		Status:          params.Status,
		ErrorCode:       strings.TrimSpace(params.ErrorCode),
		LatencyMillis:   params.LatencyMillis,
		CreatedAt:       params.CreatedAt.UTC(),
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO usage_ledger (
		id, user_id, api_key_id, request_id, provider, model, model_alias,
		input_tokens, output_tokens, cached_tokens, reasoning_tokens, image_count,
		credit_cost, status, error_code, latency_millis, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		row.ID, row.UserID, row.APIKeyID, row.RequestID, row.Provider, row.Model, row.ModelAlias,
		row.InputTokens, row.OutputTokens, row.CachedTokens, row.ReasoningTokens, row.ImageCount,
		row.CreditCost, row.Status, row.ErrorCode, row.LatencyMillis, formatTime(row.CreatedAt),
	)
	if err != nil {
		return nil, mapSQLiteWriteError(err)
	}
	return row, nil
}

func (s *SQLiteStore) AppendUsageLedgerRowWithRollup(ctx context.Context, params AppendUsageLedgerRowWithRollupParams) (*UsageLedgerWriteResult, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("user management sqlite: begin usage ledger transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	row := &UsageLedgerRow{
		ID:              UsageLedgerID(uuid.NewString()),
		UserID:          params.Ledger.UserID,
		APIKeyID:        params.Ledger.APIKeyID,
		RequestID:       strings.TrimSpace(params.Ledger.RequestID),
		Provider:        strings.TrimSpace(params.Ledger.Provider),
		Model:           strings.TrimSpace(params.Ledger.Model),
		ModelAlias:      strings.TrimSpace(params.Ledger.ModelAlias),
		InputTokens:     params.Ledger.InputTokens,
		OutputTokens:    params.Ledger.OutputTokens,
		CachedTokens:    params.Ledger.CachedTokens,
		ReasoningTokens: params.Ledger.ReasoningTokens,
		ImageCount:      params.Ledger.ImageCount,
		CreditCost:      params.Ledger.CreditCost,
		Status:          params.Ledger.Status,
		ErrorCode:       strings.TrimSpace(params.Ledger.ErrorCode),
		LatencyMillis:   params.Ledger.LatencyMillis,
		CreatedAt:       params.Ledger.CreatedAt.UTC(),
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO usage_ledger (
		id, user_id, api_key_id, request_id, provider, model, model_alias,
		input_tokens, output_tokens, cached_tokens, reasoning_tokens, image_count,
		credit_cost, status, error_code, latency_millis, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		row.ID, row.UserID, row.APIKeyID, row.RequestID, row.Provider, row.Model, row.ModelAlias,
		row.InputTokens, row.OutputTokens, row.CachedTokens, row.ReasoningTokens, row.ImageCount,
		row.CreditCost, row.Status, row.ErrorCode, row.LatencyMillis, formatTime(row.CreatedAt),
	)
	if err != nil {
		return nil, mapSQLiteWriteError(err)
	}

	var usedCredits int64
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(credit_cost), 0)
		FROM usage_ledger
		WHERE user_id = ? AND created_at >= ? AND created_at < ?`,
		params.Ledger.UserID, formatTime(params.PeriodStart), formatTime(params.PeriodEnd),
	).Scan(&usedCredits)
	if err != nil {
		return nil, fmt.Errorf("user management sqlite: sum usage credits for rollup: %w", err)
	}

	updatedAt := time.Now().UTC()
	_, err = tx.ExecContext(ctx, `INSERT INTO quota_rollups (
		user_id, period, period_start, period_end, limit_credits, used_credits, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(user_id, period, period_start) DO UPDATE SET
		period_end = excluded.period_end,
		limit_credits = excluded.limit_credits,
		used_credits = excluded.used_credits,
		updated_at = excluded.updated_at`,
		params.Ledger.UserID, params.Period, formatTime(params.PeriodStart), formatTime(params.PeriodEnd),
		params.LimitCredits, usedCredits, formatTime(updatedAt),
	)
	if err != nil {
		return nil, mapSQLiteWriteError(err)
	}

	rollup := &QuotaRollup{
		UserID:       params.Ledger.UserID,
		Period:       params.Period,
		PeriodStart:  params.PeriodStart.UTC(),
		PeriodEnd:    params.PeriodEnd.UTC(),
		LimitCredits: params.LimitCredits,
		UsedCredits:  usedCredits,
		UpdatedAt:    updatedAt,
	}
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("user management sqlite: commit usage ledger transaction: %w", err)
	}
	return &UsageLedgerWriteResult{Ledger: row, Rollup: rollup}, nil
}

func (s *SQLiteStore) ListUsageLedgerRows(ctx context.Context, filter UsageLedgerFilter) ([]UsageLedgerRow, error) {
	query := `SELECT id, user_id, api_key_id, request_id, provider, model, model_alias,
		input_tokens, output_tokens, cached_tokens, reasoning_tokens, image_count,
		credit_cost, status, error_code, latency_millis, created_at FROM usage_ledger`
	where, args := usageLedgerWhere(filter)
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY created_at DESC"
	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
		if filter.Offset > 0 {
			query += " OFFSET ?"
			args = append(args, filter.Offset)
		}
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("user management sqlite: list usage ledger: %w", err)
	}
	defer rows.Close()
	var ledger []UsageLedgerRow
	for rows.Next() {
		row, errScan := scanUsageLedgerRow(rows)
		if errScan != nil {
			return nil, errScan
		}
		ledger = append(ledger, *row)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("user management sqlite: iterate usage ledger: %w", err)
	}
	return ledger, nil
}

func (s *SQLiteStore) CountUsageLedgerRows(ctx context.Context, filter UsageLedgerFilter) (int64, error) {
	where, args := usageLedgerWhere(filter)
	query := "SELECT COUNT(*) FROM usage_ledger"
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	var total int64
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("user management sqlite: count usage ledger: %w", err)
	}
	return total, nil
}

func (s *SQLiteStore) SumUsageCredits(ctx context.Context, userID UserID, from, to time.Time) (int64, error) {
	filter := UsageLedgerFilter{UserID: userID, From: from, To: to}
	where, args := usageLedgerWhere(filter)
	query := "SELECT COALESCE(SUM(credit_cost), 0) FROM usage_ledger"
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	var total int64
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("user management sqlite: sum usage credits: %w", err)
	}
	return total, nil
}

func (s *SQLiteStore) UpsertQuotaRollup(ctx context.Context, params UpsertQuotaRollupParams) (*QuotaRollup, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	updatedAt := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `INSERT INTO quota_rollups (
		user_id, period, period_start, period_end, limit_credits, used_credits, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(user_id, period, period_start) DO UPDATE SET
		period_end = excluded.period_end,
		limit_credits = excluded.limit_credits,
		used_credits = excluded.used_credits,
		updated_at = excluded.updated_at`,
		params.UserID, params.Period, formatTime(params.PeriodStart), formatTime(params.PeriodEnd),
		params.LimitCredits, params.UsedCredits, formatTime(updatedAt),
	)
	if err != nil {
		return nil, mapSQLiteWriteError(err)
	}
	return s.GetQuotaRollup(ctx, params.UserID, params.Period, params.PeriodStart)
}

func (s *SQLiteStore) GetQuotaRollup(ctx context.Context, userID UserID, period QuotaPeriod, periodStart time.Time) (*QuotaRollup, error) {
	row := s.db.QueryRowContext(ctx, `SELECT user_id, period, period_start, period_end, limit_credits, used_credits, updated_at
		FROM quota_rollups WHERE user_id = ? AND period = ? AND period_start = ?`, userID, period, formatTime(periodStart))
	var rollup QuotaRollup
	var start, end, updated string
	err := row.Scan(&rollup.UserID, &rollup.Period, &start, &end, &rollup.LimitCredits, &rollup.UsedCredits, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("user management sqlite: scan quota rollup: %w", err)
	}
	rollup.PeriodStart = parseStoredTime(start)
	rollup.PeriodEnd = parseStoredTime(end)
	rollup.UpdatedAt = parseStoredTime(updated)
	return &rollup, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanUser(row scanner) (*User, error) {
	var user User
	var metadataJSON, createdAt, updatedAt string
	var approvedAt, rejectedAt, suspendedAt sql.NullString
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.DisplayName, &user.PasswordHash, &user.Status, &user.Role,
		&metadataJSON, &createdAt, &updatedAt, &approvedAt, &rejectedAt, &suspendedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("user management sqlite: scan user: %w", err)
	}
	if metadataJSON != "" {
		if err = json.Unmarshal([]byte(metadataJSON), &user.Metadata); err != nil {
			return nil, fmt.Errorf("user management sqlite: decode user metadata: %w", err)
		}
	}
	user.CreatedAt = parseStoredTime(createdAt)
	user.UpdatedAt = parseStoredTime(updatedAt)
	user.ApprovedAt = parseOptionalStoredTime(approvedAt)
	user.RejectedAt = parseOptionalStoredTime(rejectedAt)
	user.SuspendedAt = parseOptionalStoredTime(suspendedAt)
	return &user, nil
}

func scanSession(row scanner) (*Session, error) {
	var session Session
	var createdAt, expiresAt string
	var revokedAt, lastSeenAt sql.NullString
	err := row.Scan(&session.ID, &session.UserID, &session.TokenHash, &session.Status, &createdAt, &expiresAt, &revokedAt, &lastSeenAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("user management sqlite: scan session: %w", err)
	}
	session.CreatedAt = parseStoredTime(createdAt)
	session.ExpiresAt = parseStoredTime(expiresAt)
	session.RevokedAt = parseOptionalStoredTime(revokedAt)
	session.LastSeenAt = parseOptionalStoredTime(lastSeenAt)
	return &session, nil
}

func scanAPIKey(row scanner) (*APIKey, error) {
	var key APIKey
	var createdAt, updatedAt string
	var expiresAt, lastUsedAt sql.NullString
	err := row.Scan(&key.ID, &key.UserID, &key.Name, &key.KeyHash, &key.Prefix, &key.Status, &createdAt, &updatedAt, &expiresAt, &lastUsedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("user management sqlite: scan api key: %w", err)
	}
	key.CreatedAt = parseStoredTime(createdAt)
	key.UpdatedAt = parseStoredTime(updatedAt)
	key.ExpiresAt = parseOptionalStoredTime(expiresAt)
	key.LastUsedAt = parseOptionalStoredTime(lastUsedAt)
	return &key, nil
}

func scanModelPolicy(row scanner) (*ModelPolicy, error) {
	var policy ModelPolicy
	var allowAll int
	var modelsJSON, createdAt, updatedAt string
	err := row.Scan(&policy.SubjectType, &policy.SubjectID, &allowAll, &modelsJSON, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("user management sqlite: scan model policy: %w", err)
	}
	if modelsJSON != "" {
		if err = json.Unmarshal([]byte(modelsJSON), &policy.Models); err != nil {
			return nil, fmt.Errorf("user management sqlite: decode model policy: %w", err)
		}
	}
	policy.AllowAll = allowAll == 1
	policy.CreatedAt = parseStoredTime(createdAt)
	policy.UpdatedAt = parseStoredTime(updatedAt)
	return &policy, nil
}

func scanPricingRule(row scanner) (*PricingRule, error) {
	var rule PricingRule
	var createdAt, updatedAt string
	err := row.Scan(&rule.Model, &rule.InputCreditsPerMillionTokens, &rule.OutputCreditsPerMillionTokens,
		&rule.CachedCreditsPerMillionTokens, &rule.ReasoningCreditsPerMillionTokens, &rule.ImageCredits,
		&rule.RequestCredits, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("user management sqlite: scan pricing rule: %w", err)
	}
	rule.CreatedAt = parseStoredTime(createdAt)
	rule.UpdatedAt = parseStoredTime(updatedAt)
	return &rule, nil
}

func scanUsageLedgerRow(row scanner) (*UsageLedgerRow, error) {
	var ledger UsageLedgerRow
	var createdAt string
	err := row.Scan(&ledger.ID, &ledger.UserID, &ledger.APIKeyID, &ledger.RequestID, &ledger.Provider, &ledger.Model,
		&ledger.ModelAlias, &ledger.InputTokens, &ledger.OutputTokens, &ledger.CachedTokens, &ledger.ReasoningTokens,
		&ledger.ImageCount, &ledger.CreditCost, &ledger.Status, &ledger.ErrorCode, &ledger.LatencyMillis, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("user management sqlite: scan usage ledger: %w", err)
	}
	ledger.CreatedAt = parseStoredTime(createdAt)
	return &ledger, nil
}

func usageLedgerWhere(filter UsageLedgerFilter) ([]string, []any) {
	var where []string
	var args []any
	if filter.UserID != "" {
		where = append(where, "user_id = ?")
		args = append(args, filter.UserID)
	}
	if filter.APIKeyID != "" {
		where = append(where, "api_key_id = ?")
		args = append(args, filter.APIKeyID)
	}
	if filter.Model != "" {
		where = append(where, "model = ?")
		args = append(args, filter.Model)
	}
	if filter.Status != "" {
		where = append(where, "status = ?")
		args = append(args, filter.Status)
	}
	if !filter.From.IsZero() {
		where = append(where, "created_at >= ?")
		args = append(args, formatTime(filter.From))
	}
	if !filter.To.IsZero() {
		where = append(where, "created_at < ?")
		args = append(args, formatTime(filter.To))
	}
	return where, args
}

func formatOptionalTime(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return formatTime(*t)
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func parseStoredTime(raw string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, raw)
	return t
}

func parseOptionalStoredTime(raw sql.NullString) *time.Time {
	if !raw.Valid || raw.String == "" {
		return nil
	}
	t := parseStoredTime(raw.String)
	return &t
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func mapSQLiteWriteError(err error) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "constraint") || strings.Contains(msg, "unique") {
		return fmt.Errorf("%w: %v", ErrAlreadyExists, err)
	}
	return fmt.Errorf("user management sqlite: %w", err)
}
