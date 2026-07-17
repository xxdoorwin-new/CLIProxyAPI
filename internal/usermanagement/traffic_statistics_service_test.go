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
	if len(report.Ranking[0].Series) != 1 || report.Ranking[0].Series[0].Provider != "openai" || report.Ranking[0].Series[0].Model != "gpt-5" || report.Ranking[0].Series[0].TotalTokens != 27 {
		t.Fatalf("bob's ranking series = %#v, want single openai/gpt-5 entry with 27 tokens", report.Ranking[0].Series)
	}
	if len(report.Ranking[1].Series) != 1 || report.Ranking[1].Series[0].Provider != "anthropic" || report.Ranking[1].Series[0].Model != "claude-sonnet-5" || report.Ranking[1].Series[0].TotalTokens != 10 {
		t.Fatalf("alice's ranking series = %#v, want single anthropic/claude-sonnet-5 entry with 10 tokens", report.Ranking[1].Series)
	}
}

func TestTrafficStatisticsRankingCapsPerUserSeriesWithOtherBucket(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	alice := createTestUser(t, ctx, store)
	aliceKey := createTestAPIKey(t, ctx, store, alice.ID)

	appendUsage := func(request string, provider string, model string, tokens int64) {
		t.Helper()
		_, err := store.AppendUsageLedgerRow(ctx, CreateUsageLedgerRowParams{
			UserID: alice.ID, APIKeyID: aliceKey.ID, RequestID: request, Provider: provider, Model: model,
			InputTokens: tokens, TotalTokens: tokens, CreditCost: 1, Status: UsageStatusSucceeded,
			CreatedAt: time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
		})
		if err != nil {
			t.Fatalf("AppendUsageLedgerRow() error = %v", err)
		}
	}

	// Six distinct models for the same user: the per-user series should cap at
	// the top 5 by tokens plus a single "other" bucket for the smallest one.
	appendUsage("m1", "openai", "model-a", 60)
	appendUsage("m2", "openai", "model-b", 50)
	appendUsage("m3", "openai", "model-c", 40)
	appendUsage("m4", "openai", "model-d", 30)
	appendUsage("m5", "openai", "model-e", 20)
	appendUsage("m6", "openai", "model-f", 5)

	service := NewTrafficStatisticsService(store, store)
	service.now = func() time.Time { return time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC) }
	report, err := service.Statistics(ctx, TrafficStatisticsQuery{
		From: "2026-07-01", To: "2026-07-01", TimeZone: "UTC", GroupBy: TrafficGroupByModel,
	})
	if err != nil {
		t.Fatalf("Statistics() error = %v", err)
	}
	if len(report.Ranking) != 1 {
		t.Fatalf("ranking = %#v, want single user", report.Ranking)
	}
	series := report.Ranking[0].Series
	if len(series) != 6 {
		t.Fatalf("series = %#v, want 5 named entries plus one other bucket", series)
	}
	last := series[len(series)-1]
	if !last.Other || last.TotalTokens != 5 {
		t.Fatalf("other bucket = %#v, want other=true tokens=5", last)
	}
}

func TestTrafficStatisticsHourlyGranularityBucketsWithinSingleDay(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	alice := createTestUser(t, ctx, store)
	aliceKey := createTestAPIKey(t, ctx, store, alice.ID)

	appendUsage := func(request string, provider string, model string, tokens int64, credits int64, createdAt time.Time) {
		t.Helper()
		_, err := store.AppendUsageLedgerRow(ctx, CreateUsageLedgerRowParams{
			UserID: alice.ID, APIKeyID: aliceKey.ID, RequestID: request, Provider: provider, Model: model,
			InputTokens: tokens, TotalTokens: tokens, CreditCost: credits, Status: UsageStatusSucceeded, CreatedAt: createdAt,
		})
		if err != nil {
			t.Fatalf("AppendUsageLedgerRow() error = %v", err)
		}
	}

	appendUsage("alice-h1", "anthropic", "claude-sonnet-5", 10, 2, time.Date(2026, 7, 1, 9, 30, 0, 0, time.UTC))
	appendUsage("alice-h2", "openai", "gpt-5", 5, 1, time.Date(2026, 7, 1, 14, 15, 0, 0, time.UTC))

	service := NewTrafficStatisticsService(store, store)
	service.now = func() time.Time { return time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC) }
	report, err := service.Statistics(ctx, TrafficStatisticsQuery{
		From: "2026-07-01", To: "2026-07-01", TimeZone: "UTC", Granularity: TrafficGranularityHour, GroupBy: TrafficGroupByModel,
	})
	if err != nil {
		t.Fatalf("Statistics() error = %v", err)
	}
	if report.Granularity != "hour" {
		t.Fatalf("granularity = %q, want hour", report.Granularity)
	}
	if len(report.Daily) != 24 {
		t.Fatalf("daily buckets = %d, want 24", len(report.Daily))
	}
	if report.Daily[0].Date != "2026-07-01T00:00:00" {
		t.Fatalf("first bucket date = %q, want 2026-07-01T00:00:00", report.Daily[0].Date)
	}
	var nineAM, twoPM *TrafficDailyPoint
	for i := range report.Daily {
		switch report.Daily[i].Date {
		case "2026-07-01T09:00:00":
			nineAM = &report.Daily[i]
		case "2026-07-01T14:00:00":
			twoPM = &report.Daily[i]
		}
	}
	if nineAM == nil || nineAM.TotalTokens != 10 {
		t.Fatalf("09:00 bucket = %#v, want 10 tokens", nineAM)
	}
	if twoPM == nil || twoPM.TotalTokens != 5 {
		t.Fatalf("14:00 bucket = %#v, want 5 tokens", twoPM)
	}
}

func TestTrafficStatisticsRejectsHourGranularityAcrossMultipleDays(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	service := NewTrafficStatisticsService(store, store)

	if _, err := service.Statistics(ctx, TrafficStatisticsQuery{
		TimeZone: "UTC", From: "2026-07-01", To: "2026-07-02", Granularity: TrafficGranularityHour,
	}); err == nil {
		t.Fatal("Statistics() hour granularity multi-day error = nil")
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
