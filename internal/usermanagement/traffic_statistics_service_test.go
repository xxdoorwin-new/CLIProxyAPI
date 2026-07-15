package usermanagement

import (
	"context"
	"testing"
	"time"
)

func TestTrafficStatisticsRanksAndBucketsInViewerTimeZone(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	alice := createTestUser(t, ctx, store)
	bob := createTestUser(t, ctx, store)
	aliceKey := createTestAPIKey(t, ctx, store, alice.ID)
	bobKey, err := store.CreateAPIKey(ctx, CreateAPIKeyParams{
		UserID: bob.ID, Name: "default", KeyHash: []byte("bob-key-hash"), Prefix: "cpak_bob", Status: APIKeyStatusActive,
	})
	if err != nil {
		t.Fatalf("CreateAPIKey(bob) error = %v", err)
	}

	appendUsage := func(userID UserID, keyID APIKeyID, request string, provider string, model string, tokens int64, credits int64, createdAt time.Time) {
		t.Helper()
		_, err := store.AppendUsageLedgerRow(ctx, CreateUsageLedgerRowParams{
			UserID: userID, APIKeyID: keyID, RequestID: request, Provider: provider, Model: model,
			InputTokens: tokens, TotalTokens: tokens, CreditCost: credits, Status: UsageStatusSucceeded, CreatedAt: createdAt,
		})
		if err != nil {
			t.Fatalf("AppendUsageLedgerRow() error = %v", err)
		}
	}

	appendUsage(alice.ID, aliceKey.ID, "alice-1", "anthropic", "claude-sonnet-5", 10, 2, time.Date(2026, 7, 1, 15, 0, 0, 0, time.UTC))
	appendUsage(bob.ID, bobKey.ID, "bob-1", "openai", "gpt-5", 20, 3, time.Date(2026, 7, 1, 16, 0, 0, 0, time.UTC))
	_, err = store.AppendUsageLedgerRow(ctx, CreateUsageLedgerRowParams{
		UserID: bob.ID, APIKeyID: bobKey.ID, RequestID: "bob-legacy", Provider: "openai", Model: "gpt-5",
		InputTokens: 3, OutputTokens: 4, CreditCost: 1, Status: UsageStatusSucceeded,
		CreatedAt: time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("AppendUsageLedgerRow(legacy) error = %v", err)
	}

	service := NewTrafficStatisticsService(store, store)
	service.now = func() time.Time { return time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC) }
	report, err := service.Statistics(ctx, TrafficStatisticsQuery{
		From: "2026-07-01", To: "2026-07-02", TimeZone: "Asia/Taipei", GroupBy: TrafficGroupByModel,
	})
	if err != nil {
		t.Fatalf("Statistics() error = %v", err)
	}
	if len(report.Ranking) != 2 || report.Ranking[0].UserID != bob.ID || report.Ranking[0].TotalTokens != 27 {
		t.Fatalf("ranking = %#v, want Bob first with 27 tokens", report.Ranking)
	}
	if report.Summary.TotalTokens != 37 || report.Summary.TotalCredits != 6 || report.Summary.Requests != 3 {
		t.Fatalf("summary = %#v, want tokens=37 credits=6 requests=3", report.Summary)
	}
	if !report.HasEstimatedTotal || len(report.Daily) != 2 || report.Daily[0].TotalTokens != 10 || report.Daily[1].TotalTokens != 27 {
		t.Fatalf("daily = %#v estimated=%v", report.Daily, report.HasEstimatedTotal)
	}
	if len(report.Series) != 2 || report.Series[0].Provider == "" || report.Series[0].Model == "" {
		t.Fatalf("series = %#v, want provider and exact model", report.Series)
	}
}

func TestTrafficStatisticsRejectsInvalidTimeZoneAndLongRange(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	service := NewTrafficStatisticsService(store, store)

	if _, err := service.Statistics(ctx, TrafficStatisticsQuery{TimeZone: "not/a-zone"}); err == nil {
		t.Fatal("Statistics() invalid time zone error = nil")
	}
	if _, err := service.Statistics(ctx, TrafficStatisticsQuery{
		TimeZone: "UTC", From: "2026-01-01", To: "2026-02-01",
	}); err == nil {
		t.Fatal("Statistics() long range error = nil")
	}
}
