package usermanagement

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

type UsageRecorderConfig struct {
	MissingUsageCredits int64
}

type UsageRecorder struct {
	store               *SQLiteStore
	missingUsageCredits int64
	now                 func() time.Time
}

type RecordUsageParams struct {
	UserID          UserID
	APIKeyID        APIKeyID
	RequestID       string
	Provider        string
	Model           string
	ModelAlias      string
	InputTokens     int64
	OutputTokens    int64
	CachedTokens    int64
	ReasoningTokens int64
	TotalTokens     int64
	ImageCount      int64
	Failed          bool
	ErrorCode       string
	HTTPStatusCode  int
	Latency         time.Duration
	RequestedAt     time.Time
}

func NewUsageRecorder(store *SQLiteStore, cfg UsageRecorderConfig) *UsageRecorder {
	if cfg.MissingUsageCredits < 0 {
		cfg.MissingUsageCredits = 0
	}
	return &UsageRecorder{
		store:               store,
		missingUsageCredits: cfg.MissingUsageCredits,
		now:                 time.Now,
	}
}

func (r *UsageRecorder) RecordUsage(ctx context.Context, params RecordUsageParams) (*UsageLedgerWriteResult, error) {
	if r == nil || r.store == nil {
		return nil, ErrInvalid
	}
	createdAt := params.RequestedAt
	if createdAt.IsZero() {
		createdAt = r.now()
	}
	createdAt = createdAt.UTC()

	model := strings.TrimSpace(params.Model)
	if model == "" {
		model = strings.TrimSpace(params.ModelAlias)
	}
	alias := strings.TrimSpace(params.ModelAlias)
	if alias == "" {
		alias = model
	}
	provider := strings.TrimSpace(params.Provider)
	if provider == "" {
		provider = "unknown"
	}
	requestID := strings.TrimSpace(params.RequestID)
	if requestID == "" {
		requestID = "usage-" + uuid.NewString()
	}

	status := UsageStatusSucceeded
	if params.Failed || (params.HTTPStatusCode >= 400) {
		status = UsageStatusFailed
	}
	errorCode := strings.TrimSpace(params.ErrorCode)
	if errorCode == "" && status == UsageStatusFailed && params.HTTPStatusCode > 0 {
		errorCode = strconv.Itoa(params.HTTPStatusCode)
	}

	creditCost, err := r.creditCost(ctx, model, params)
	if err != nil {
		return nil, err
	}
	period := CurrentMonthlyPeriod(createdAt)
	policy, err := r.store.GetQuotaPolicy(ctx, params.UserID)
	if errors.Is(err, ErrNotFound) {
		policy = &QuotaPolicy{
			UserID:       params.UserID,
			Period:       QuotaPeriodMonthly,
			LimitCredits: 0,
		}
	} else if err != nil {
		return nil, err
	}

	latencyMillis := params.Latency.Milliseconds()
	if latencyMillis < 0 {
		latencyMillis = 0
	}
	return r.store.AppendUsageLedgerRowWithRollup(ctx, AppendUsageLedgerRowWithRollupParams{
		Ledger: CreateUsageLedgerRowParams{
			UserID:          params.UserID,
			APIKeyID:        params.APIKeyID,
			RequestID:       requestID,
			Provider:        provider,
			Model:           model,
			ModelAlias:      alias,
			InputTokens:     params.InputTokens,
			OutputTokens:    params.OutputTokens,
			CachedTokens:    params.CachedTokens,
			ReasoningTokens: params.ReasoningTokens,
			TotalTokens:     params.TotalTokens,
			ImageCount:      params.ImageCount,
			CreditCost:      creditCost,
			Status:          status,
			ErrorCode:       errorCode,
			LatencyMillis:   latencyMillis,
			CreatedAt:       createdAt,
		},
		Period:       policy.Period,
		PeriodStart:  period.Start,
		PeriodEnd:    period.End,
		LimitCredits: policy.LimitCredits,
	})
}

func (r *UsageRecorder) creditCost(ctx context.Context, model string, params RecordUsageParams) (int64, error) {
	if !params.hasBillableFacts() {
		return r.missingUsageCredits, nil
	}
	facts := UsageFacts{
		Model:           model,
		InputTokens:     params.InputTokens,
		OutputTokens:    params.OutputTokens,
		CachedTokens:    params.CachedTokens,
		ReasoningTokens: params.ReasoningTokens,
		ImageCount:      params.ImageCount,
		RequestCount:    1,
	}
	breakdown, err := NewPricingService(r.store).CalculateCredits(ctx, facts)
	if errors.Is(err, ErrNotFound) {
		// No pricing rule for this model; fall back to the same default used
		// when token data is absent so unregistered models are still billed.
		return r.missingUsageCredits, nil
	}
	if err != nil {
		return 0, err
	}
	return breakdown.TotalCredits, nil
}

func (p RecordUsageParams) hasBillableFacts() bool {
	return p.InputTokens > 0 ||
		p.OutputTokens > 0 ||
		p.CachedTokens > 0 ||
		p.ReasoningTokens > 0 ||
		p.ImageCount > 0
}
