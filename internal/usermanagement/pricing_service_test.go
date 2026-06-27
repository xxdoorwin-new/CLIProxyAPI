package usermanagement

import (
	"context"
	"errors"
	"testing"
)

func TestPricingServiceCalculatesCreditBreakdown(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	service := NewPricingService(store)

	_, err := service.SetRule(ctx, SetPricingRuleParams{
		Model:                            "gpt-5",
		InputCreditsPerMillionTokens:     100,
		OutputCreditsPerMillionTokens:    200,
		CachedCreditsPerMillionTokens:    10,
		ReasoningCreditsPerMillionTokens: 300,
		ImageCredits:                     5,
		RequestCredits:                   2,
	})
	if err != nil {
		t.Fatalf("SetRule() error = %v", err)
	}

	breakdown, err := service.CalculateCredits(ctx, UsageFacts{
		Model:           "gpt-5",
		InputTokens:     1_500_000,
		OutputTokens:    500_000,
		CachedTokens:    1,
		ReasoningTokens: 2_000_000,
		ImageCount:      2,
		RequestCount:    1,
	})
	if err != nil {
		t.Fatalf("CalculateCredits() error = %v", err)
	}
	if breakdown.InputCredits != 150 ||
		breakdown.OutputCredits != 100 ||
		breakdown.CachedCredits != 1 ||
		breakdown.ReasoningCredits != 600 ||
		breakdown.ImageCredits != 10 ||
		breakdown.RequestCredits != 2 ||
		breakdown.TotalCredits != 863 {
		t.Fatalf("breakdown = %#v", breakdown)
	}
}

func TestCalculateCreditsWithRuleZeroUsageIsFree(t *testing.T) {
	breakdown := CalculateCreditsWithRule(PricingRule{
		Model:                        "gpt-5",
		InputCreditsPerMillionTokens: 100,
		RequestCredits:               2,
	}, UsageFacts{Model: "gpt-5"})
	if breakdown.TotalCredits != 0 {
		t.Fatalf("TotalCredits = %d, want 0", breakdown.TotalCredits)
	}
}

func TestPricingServiceRejectsNegativeUsageFacts(t *testing.T) {
	err := UsageFacts{Model: "gpt-5", InputTokens: -1}.Validate()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Validate() error = %v, want ErrInvalid", err)
	}
}
