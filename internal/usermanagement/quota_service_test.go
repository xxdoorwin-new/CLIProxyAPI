package usermanagement

import (
	"context"
	"testing"
	"time"
)

func TestQuotaServiceReportsAvailabilityFromCurrentRollup(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	user := createTestUser(t, ctx, store)
	service := NewQuotaService(store, store)
	now := time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }

	if _, err := service.SetPolicy(ctx, SetQuotaPolicyParams{
		UserID:       user.ID,
		Period:       QuotaPeriodMonthly,
		LimitCredits: 100,
	}); err != nil {
		t.Fatalf("SetPolicy() error = %v", err)
	}
	period := CurrentMonthlyPeriod(now)
	if _, err := store.UpsertQuotaRollup(ctx, UpsertQuotaRollupParams{
		UserID:       user.ID,
		Period:       QuotaPeriodMonthly,
		PeriodStart:  period.Start,
		PeriodEnd:    period.End,
		LimitCredits: 100,
		UsedCredits:  90,
	}); err != nil {
		t.Fatalf("UpsertQuotaRollup() error = %v", err)
	}

	available, summary, err := service.HasAvailableQuota(ctx, user.ID, 10)
	if err != nil {
		t.Fatalf("HasAvailableQuota() error = %v", err)
	}
	if !available || summary.RemainingCredits != 10 {
		t.Fatalf("available = %v summary = %#v, want 10 remaining available", available, summary)
	}
	available, _, err = service.HasAvailableQuota(ctx, user.ID, 11)
	if err != nil {
		t.Fatalf("HasAvailableQuota() second error = %v", err)
	}
	if available {
		t.Fatal("HasAvailableQuota() = true for exhausted quota")
	}
}

func TestQuotaServiceMonthlyRolloverStartsFresh(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	user := createTestUser(t, ctx, store)
	service := NewQuotaService(store, store)
	june := time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return june }

	if _, err := service.SetPolicy(ctx, SetQuotaPolicyParams{
		UserID:       user.ID,
		Period:       QuotaPeriodMonthly,
		LimitCredits: 100,
	}); err != nil {
		t.Fatalf("SetPolicy() error = %v", err)
	}
	junePeriod := CurrentMonthlyPeriod(june)
	if _, err := store.UpsertQuotaRollup(ctx, UpsertQuotaRollupParams{
		UserID:       user.ID,
		Period:       QuotaPeriodMonthly,
		PeriodStart:  junePeriod.Start,
		PeriodEnd:    junePeriod.End,
		LimitCredits: 100,
		UsedCredits:  100,
	}); err != nil {
		t.Fatalf("UpsertQuotaRollup() error = %v", err)
	}

	service.now = func() time.Time { return time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC) }
	available, summary, err := service.HasAvailableQuota(ctx, user.ID, 1)
	if err != nil {
		t.Fatalf("HasAvailableQuota() error = %v", err)
	}
	if !available || summary.UsedCredits != 0 || summary.RemainingCredits != 100 {
		t.Fatalf("available = %v summary = %#v, want fresh July quota", available, summary)
	}
}
