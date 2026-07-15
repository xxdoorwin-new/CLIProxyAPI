package usermanagement

import (
	"context"
	"math"
	"strings"
)

const tokensPerMillion = float64(1_000_000)

type PricingService struct {
	pricing PricingStore
}

type UsageFacts struct {
	Model           string
	InputTokens     int64
	OutputTokens    int64
	CachedTokens    int64
	ReasoningTokens int64
	ImageCount      int64
	RequestCount    int64
}

type CreditBreakdown struct {
	Model            string
	InputCredits     int64
	OutputCredits    int64
	CachedCredits    int64
	ReasoningCredits int64
	ImageCredits     int64
	RequestCredits   int64
	TotalCredits     int64
}

func NewPricingService(pricing PricingStore) *PricingService {
	return &PricingService{pricing: pricing}
}

func (s *PricingService) SetRule(ctx context.Context, params SetPricingRuleParams) (*PricingRule, error) {
	if s == nil || s.pricing == nil {
		return nil, ErrInvalid
	}
	return s.pricing.SetPricingRule(ctx, params)
}

func (s *PricingService) CalculateCredits(ctx context.Context, facts UsageFacts) (*CreditBreakdown, error) {
	if s == nil || s.pricing == nil {
		return nil, ErrInvalid
	}
	if err := facts.Validate(); err != nil {
		return nil, err
	}
	rule, err := s.pricing.GetPricingRule(ctx, facts.Model)
	if err != nil {
		return nil, err
	}
	return CalculateCreditsWithRule(*rule, facts), nil
}

func CalculateCreditsWithRule(rule PricingRule, facts UsageFacts) *CreditBreakdown {
	breakdown := &CreditBreakdown{
		Model:            strings.TrimSpace(facts.Model),
		InputCredits:     ceilTokenCredits(facts.InputTokens, rule.InputCreditsPerMillionTokens),
		OutputCredits:    ceilTokenCredits(facts.OutputTokens, rule.OutputCreditsPerMillionTokens),
		CachedCredits:    ceilTokenCredits(facts.CachedTokens, rule.CachedCreditsPerMillionTokens),
		ReasoningCredits: ceilTokenCredits(facts.ReasoningTokens, rule.ReasoningCreditsPerMillionTokens),
		ImageCredits:     ceilUnitCredits(facts.ImageCount, rule.ImageCredits),
		RequestCredits:   ceilUnitCredits(facts.RequestCount, rule.RequestCredits),
	}
	breakdown.TotalCredits = breakdown.InputCredits +
		breakdown.OutputCredits +
		breakdown.CachedCredits +
		breakdown.ReasoningCredits +
		breakdown.ImageCredits +
		breakdown.RequestCredits
	return breakdown
}

func (f UsageFacts) Validate() error {
	if strings.TrimSpace(f.Model) == "" {
		return invalid("model is required")
	}
	if f.InputTokens < 0 ||
		f.OutputTokens < 0 ||
		f.CachedTokens < 0 ||
		f.ReasoningTokens < 0 ||
		f.ImageCount < 0 ||
		f.RequestCount < 0 {
		return invalid("usage facts cannot be negative")
	}
	return nil
}

// ceilTokenCredits converts token usage into whole credits using a
// per-million-token rate that may be fractional, rounding up so a request is
// never undercharged.
func ceilTokenCredits(tokens int64, creditsPerMillion float64) int64 {
	if tokens <= 0 || creditsPerMillion <= 0 {
		return 0
	}
	return int64(math.Ceil(float64(tokens) * creditsPerMillion / tokensPerMillion))
}

// ceilUnitCredits converts a per-unit count (images, requests) into whole
// credits using a rate that may be fractional, rounding up.
func ceilUnitCredits(count int64, creditsPerUnit float64) int64 {
	if count <= 0 || creditsPerUnit <= 0 {
		return 0
	}
	return int64(math.Ceil(float64(count) * creditsPerUnit))
}
