package usermanagement

import (
	"context"
	"errors"
	"time"
)

type QuotaService struct {
	policies QuotaPolicyStore
	rollups  QuotaRollupStore
	now      func() time.Time
}

type QuotaSummary struct {
	UserID           UserID
	Period           QuotaPeriod
	LimitCredits     int64
	UsedCredits      int64
	RemainingCredits int64
	PeriodStart      time.Time
	PeriodEnd        time.Time
}

func NewQuotaService(policies QuotaPolicyStore, rollups QuotaRollupStore) *QuotaService {
	return &QuotaService{
		policies: policies,
		rollups:  rollups,
		now:      time.Now,
	}
}

func (s *QuotaService) SetPolicy(ctx context.Context, params SetQuotaPolicyParams) (*QuotaPolicy, error) {
	if s == nil || s.policies == nil {
		return nil, ErrInvalid
	}
	return s.policies.SetQuotaPolicy(ctx, params)
}

func (s *QuotaService) Summary(ctx context.Context, userID UserID) (*QuotaSummary, error) {
	if s == nil || s.policies == nil || s.rollups == nil {
		return nil, ErrInvalid
	}
	policy, err := s.policies.GetQuotaPolicy(ctx, userID)
	if errors.Is(err, ErrNotFound) {
		return &QuotaSummary{
			UserID:           userID,
			Period:           QuotaPeriodMonthly,
			LimitCredits:     0,
			UsedCredits:      0,
			RemainingCredits: 0,
			PeriodStart:      CurrentMonthlyPeriod(s.now().UTC()).Start,
			PeriodEnd:        CurrentMonthlyPeriod(s.now().UTC()).End,
		}, nil
	}
	if err != nil {
		return nil, err
	}
	period := CurrentMonthlyPeriod(s.now().UTC())
	used := int64(0)
	rollup, err := s.rollups.GetQuotaRollup(ctx, userID, policy.Period, period.Start)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if rollup != nil {
		used = rollup.UsedCredits
	}
	remaining := policy.LimitCredits - used
	if remaining < 0 {
		remaining = 0
	}
	return &QuotaSummary{
		UserID:           userID,
		Period:           policy.Period,
		LimitCredits:     policy.LimitCredits,
		UsedCredits:      used,
		RemainingCredits: remaining,
		PeriodStart:      period.Start,
		PeriodEnd:        period.End,
	}, nil
}

func (s *QuotaService) HasAvailableQuota(ctx context.Context, userID UserID, requiredCredits int64) (bool, *QuotaSummary, error) {
	if requiredCredits <= 0 {
		requiredCredits = 1
	}
	summary, err := s.Summary(ctx, userID)
	if err != nil {
		return false, nil, err
	}
	// LimitCredits == 0 means unlimited — always allow.
	if summary.LimitCredits == 0 {
		return true, summary, nil
	}
	return summary.RemainingCredits >= requiredCredits, summary, nil
}

type PeriodBounds struct {
	Start time.Time
	End   time.Time
}

func CurrentMonthlyPeriod(now time.Time) PeriodBounds {
	now = now.UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	return PeriodBounds{
		Start: start,
		End:   start.AddDate(0, 1, 0),
	}
}
