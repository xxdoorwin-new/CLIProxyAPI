package usermanagement

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteStoreCreatesUsersAndEnforcesUniqueIdentity(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)

	user, err := store.CreateUser(ctx, CreateUserParams{
		Username:     "alice",
		Email:        "alice@example.test",
		DisplayName:  "Alice",
		PasswordHash: []byte("password-hash"),
		Status:       UserStatusPending,
		Role:         UserRoleUser,
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	if user.ID == "" {
		t.Fatal("CreateUser() returned empty id")
	}

	found, err := store.FindUserByIdentity(ctx, "ALICE@example.test")
	if err != nil {
		t.Fatalf("FindUserByIdentity() error = %v", err)
	}
	if found.ID != user.ID {
		t.Fatalf("FindUserByIdentity() id = %q, want %q", found.ID, user.ID)
	}

	_, err = store.CreateUser(ctx, CreateUserParams{
		Username:     "ALICE",
		Email:        "other@example.test",
		PasswordHash: []byte("other-hash"),
		Status:       UserStatusPending,
		Role:         UserRoleUser,
	})
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate username error = %v, want ErrAlreadyExists", err)
	}
}

func TestSQLiteStoreStoresHashedAPIKeys(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	user := createTestUser(t, ctx, store)

	hash := []byte("sha256-or-bcrypt-hash")
	key, err := store.CreateAPIKey(ctx, CreateAPIKeyParams{
		UserID:  user.ID,
		Name:    "default",
		KeyHash: hash,
		Prefix:  "cpak_1234",
		Status:  APIKeyStatusActive,
	})
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	if !bytes.Equal(key.KeyHash, hash) {
		t.Fatalf("CreateAPIKey() hash = %q, want %q", key.KeyHash, hash)
	}

	fetched, err := store.GetAPIKey(ctx, key.ID)
	if err != nil {
		t.Fatalf("GetAPIKey() error = %v", err)
	}
	if fetched.Prefix != "cpak_1234" || !bytes.Equal(fetched.KeyHash, hash) {
		t.Fatalf("GetAPIKey() = prefix %q hash %q", fetched.Prefix, fetched.KeyHash)
	}

	byPrefix, err := store.FindAPIKeyByPrefix(ctx, "cpak_1234")
	if err != nil {
		t.Fatalf("FindAPIKeyByPrefix() error = %v", err)
	}
	if len(byPrefix) != 1 || byPrefix[0].ID != key.ID {
		t.Fatalf("FindAPIKeyByPrefix() = %#v, want one key %q", byPrefix, key.ID)
	}
}

func TestSQLiteStoreQueriesUsageAndUpdatesQuotaRollups(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	user := createTestUser(t, ctx, store)
	key, err := store.CreateAPIKey(ctx, CreateAPIKeyParams{
		UserID:  user.ID,
		Name:    "usage",
		KeyHash: []byte("usage-hash"),
		Prefix:  "cpak_usage",
		Status:  APIKeyStatusActive,
	})
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	_, err = store.AppendUsageLedgerRow(ctx, CreateUsageLedgerRowParams{
		UserID:        user.ID,
		APIKeyID:      key.ID,
		RequestID:     "request-1",
		Provider:      "openai",
		Model:         "gpt-5",
		InputTokens:   100,
		OutputTokens:  50,
		CreditCost:    7,
		Status:        UsageStatusSucceeded,
		LatencyMillis: 123,
		CreatedAt:     start.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("AppendUsageLedgerRow() error = %v", err)
	}
	_, err = store.AppendUsageLedgerRow(ctx, CreateUsageLedgerRowParams{
		UserID:     user.ID,
		APIKeyID:   key.ID,
		RequestID:  "request-2",
		Provider:   "openai",
		Model:      "gpt-5",
		CreditCost: 3,
		Status:     UsageStatusFailed,
		ErrorCode:  "upstream_429",
		CreatedAt:  start.Add(3 * time.Hour),
	})
	if err != nil {
		t.Fatalf("AppendUsageLedgerRow() second error = %v", err)
	}

	total, err := store.SumUsageCredits(ctx, user.ID, start, start.AddDate(0, 1, 0))
	if err != nil {
		t.Fatalf("SumUsageCredits() error = %v", err)
	}
	if total != 10 {
		t.Fatalf("SumUsageCredits() = %d, want 10", total)
	}

	rows, err := store.ListUsageLedgerRows(ctx, UsageLedgerFilter{UserID: user.ID, Status: UsageStatusFailed})
	if err != nil {
		t.Fatalf("ListUsageLedgerRows() error = %v", err)
	}
	if len(rows) != 1 || rows[0].RequestID != "request-2" {
		t.Fatalf("failed usage rows = %#v, want request-2", rows)
	}

	rollup, err := store.UpsertQuotaRollup(ctx, UpsertQuotaRollupParams{
		UserID:       user.ID,
		Period:       QuotaPeriodMonthly,
		PeriodStart:  start,
		PeriodEnd:    start.AddDate(0, 1, 0),
		LimitCredits: 100,
		UsedCredits:  10,
	})
	if err != nil {
		t.Fatalf("UpsertQuotaRollup() error = %v", err)
	}
	if rollup.LimitCredits != 100 || rollup.UsedCredits != 10 {
		t.Fatalf("rollup = %#v, want limit 100 used 10", rollup)
	}

	rollup, err = store.UpsertQuotaRollup(ctx, UpsertQuotaRollupParams{
		UserID:       user.ID,
		Period:       QuotaPeriodMonthly,
		PeriodStart:  start,
		PeriodEnd:    start.AddDate(0, 1, 0),
		LimitCredits: 200,
		UsedCredits:  25,
	})
	if err != nil {
		t.Fatalf("UpsertQuotaRollup() update error = %v", err)
	}
	if rollup.LimitCredits != 200 || rollup.UsedCredits != 25 {
		t.Fatalf("updated rollup = %#v, want limit 200 used 25", rollup)
	}
}

func newTestSQLiteStore(t *testing.T) *SQLiteStore {
	t.Helper()
	store, err := OpenSQLiteStore(context.Background(), SQLiteConfig{
		Path: filepath.Join(t.TempDir(), "users.db"),
	})
	if err != nil {
		t.Fatalf("OpenSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})
	return store
}

func createTestUser(t *testing.T, ctx context.Context, store *SQLiteStore) *User {
	t.Helper()
	user, err := store.CreateUser(ctx, CreateUserParams{
		Username:     "user-" + time.Now().Format("150405.000000000"),
		Email:        "user-" + time.Now().Format("150405.000000000") + "@example.test",
		PasswordHash: []byte("password-hash"),
		Status:       UserStatusApproved,
		Role:         UserRoleUser,
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	return user
}
