package usermanagement

import (
	"context"
	"testing"
	"time"
)

func TestUsageRecorderWritesLedgerAndRollup(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	user := createTestUser(t, ctx, store)
	key := createTestAPIKey(t, ctx, store, user.ID)

	if _, err := store.SetQuotaPolicy(ctx, SetQuotaPolicyParams{
		UserID:       user.ID,
		Period:       QuotaPeriodMonthly,
		LimitCredits: 100,
	}); err != nil {
		t.Fatalf("SetQuotaPolicy() error = %v", err)
	}
	if _, err := store.SetPricingRule(ctx, SetPricingRuleParams{
		Model:                         "gpt-5",
		InputCreditsPerMillionTokens:  1_000_000,
		OutputCreditsPerMillionTokens: 2_000_000,
		RequestCredits:                3,
	}); err != nil {
		t.Fatalf("SetPricingRule() error = %v", err)
	}

	recorder := NewUsageRecorder(store, UsageRecorderConfig{})
	result, err := recorder.RecordUsage(ctx, RecordUsageParams{
		UserID:       user.ID,
		APIKeyID:     key.ID,
		RequestID:    "req-1",
		Provider:     "openai",
		Model:        "gpt-5",
		ModelAlias:   "codex-pro",
		InputTokens:  2,
		OutputTokens: 3,
		TotalTokens:  5,
		Latency:      1500 * time.Millisecond,
		RequestedAt:  time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("RecordUsage() error = %v", err)
	}
	if result.Ledger.CreditCost != 11 {
		t.Fatalf("CreditCost = %d, want 11", result.Ledger.CreditCost)
	}
	if result.Ledger.UserID != user.ID || result.Ledger.APIKeyID != key.ID || result.Ledger.RequestID != "req-1" {
		t.Fatalf("ledger identity = %#v", result.Ledger)
	}
	if result.Ledger.ModelAlias != "codex-pro" || result.Ledger.LatencyMillis != 1500 {
		t.Fatalf("ledger facts = %#v", result.Ledger)
	}
	if result.Ledger.TotalTokens != 5 {
		t.Fatalf("TotalTokens = %d, want 5", result.Ledger.TotalTokens)
	}
	if result.Rollup.UsedCredits != 11 || result.Rollup.LimitCredits != 100 {
		t.Fatalf("rollup = %#v, want used=11 limit=100", result.Rollup)
	}
}

func TestUsageRecorderAppliesMissingUsageCreditsAndMonthlyRollover(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	user := createTestUser(t, ctx, store)
	key := createTestAPIKey(t, ctx, store, user.ID)

	if _, err := store.SetQuotaPolicy(ctx, SetQuotaPolicyParams{
		UserID:       user.ID,
		Period:       QuotaPeriodMonthly,
		LimitCredits: 50,
	}); err != nil {
		t.Fatalf("SetQuotaPolicy() error = %v", err)
	}
	recorder := NewUsageRecorder(store, UsageRecorderConfig{MissingUsageCredits: 7})

	june := time.Date(2026, 6, 30, 23, 59, 0, 0, time.UTC)
	if _, err := recorder.RecordUsage(ctx, RecordUsageParams{
		UserID:      user.ID,
		APIKeyID:    key.ID,
		RequestID:   "req-june",
		Provider:    "openai",
		Model:       "gpt-5",
		RequestedAt: june,
	}); err != nil {
		t.Fatalf("RecordUsage() June error = %v", err)
	}

	july := time.Date(2026, 7, 1, 0, 1, 0, 0, time.UTC)
	result, err := recorder.RecordUsage(ctx, RecordUsageParams{
		UserID:      user.ID,
		APIKeyID:    key.ID,
		RequestID:   "req-july",
		Provider:    "openai",
		Model:       "gpt-5",
		RequestedAt: july,
	})
	if err != nil {
		t.Fatalf("RecordUsage() July error = %v", err)
	}
	if result.Ledger.CreditCost != 7 {
		t.Fatalf("missing usage CreditCost = %d, want 7", result.Ledger.CreditCost)
	}
	if result.Rollup.PeriodStart != CurrentMonthlyPeriod(july).Start || result.Rollup.UsedCredits != 7 {
		t.Fatalf("July rollup = %#v, want fresh used=7", result.Rollup)
	}
	juneRollup, err := store.GetQuotaRollup(ctx, user.ID, QuotaPeriodMonthly, CurrentMonthlyPeriod(june).Start)
	if err != nil {
		t.Fatalf("GetQuotaRollup(June) error = %v", err)
	}
	if juneRollup.UsedCredits != 7 {
		t.Fatalf("June UsedCredits = %d, want 7", juneRollup.UsedCredits)
	}
}

func TestUsageRecorderRecordsFailedRoutedRequest(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	user := createTestUser(t, ctx, store)
	key := createTestAPIKey(t, ctx, store, user.ID)

	recorder := NewUsageRecorder(store, UsageRecorderConfig{})
	result, err := recorder.RecordUsage(ctx, RecordUsageParams{
		UserID:         user.ID,
		APIKeyID:       key.ID,
		RequestID:      "req-failed",
		Provider:       "openai",
		Model:          "gpt-5",
		Failed:         true,
		HTTPStatusCode: 502,
		RequestedAt:    time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("RecordUsage() error = %v", err)
	}
	if result.Ledger.Status != UsageStatusFailed || result.Ledger.ErrorCode != "502" {
		t.Fatalf("failed ledger = %#v", result.Ledger)
	}
}

func TestUsageSummaryServiceReturnsRemainingQuotaAndRecentUsage(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	user := createTestUser(t, ctx, store)
	key := createTestAPIKey(t, ctx, store, user.ID)

	if _, err := store.SetQuotaPolicy(ctx, SetQuotaPolicyParams{
		UserID:       user.ID,
		Period:       QuotaPeriodMonthly,
		LimitCredits: 20,
	}); err != nil {
		t.Fatalf("SetQuotaPolicy() error = %v", err)
	}
	recorder := NewUsageRecorder(store, UsageRecorderConfig{MissingUsageCredits: 5})
	now := time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC)
	if _, err := recorder.RecordUsage(ctx, RecordUsageParams{
		UserID:      user.ID,
		APIKeyID:    key.ID,
		RequestID:   "req-summary",
		Provider:    "openai",
		Model:       "gpt-5",
		RequestedAt: now,
	}); err != nil {
		t.Fatalf("RecordUsage() error = %v", err)
	}

	service := NewUsageSummaryService(store, store, store)
	service.now = func() time.Time { return now }
	summary, err := service.Summary(ctx, UsageSummaryQuery{
		UserID: user.ID,
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("Summary() error = %v", err)
	}
	if summary.Quota.UsedCredits != 5 || summary.Quota.RemainingCredits != 15 {
		t.Fatalf("quota = %#v, want used=5 remaining=15", summary.Quota)
	}
	if len(summary.RecentUsage) != 1 || summary.RecentUsage[0].RequestID != "req-summary" {
		t.Fatalf("recent usage = %#v", summary.RecentUsage)
	}
}

func createTestAPIKey(t *testing.T, ctx context.Context, store *SQLiteStore, userID UserID) *APIKey {
	t.Helper()
	key, err := store.CreateAPIKey(ctx, CreateAPIKeyParams{
		UserID:  userID,
		Name:    "default",
		KeyHash: []byte("key-hash"),
		Prefix:  "cpak_test",
		Status:  APIKeyStatusActive,
	})
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	return key
}
