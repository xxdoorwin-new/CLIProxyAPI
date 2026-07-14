package usermanagement

import (
	"context"
	"time"
)

type UsageSummaryQuery struct {
	UserID   UserID
	APIKeyID APIKeyID
	Limit    int
	Offset   int
}

type UsageSummary struct {
	Quota       QuotaSummary
	RecentUsage []UsageLedgerRow
	Total       int64
}

type UsageSummaryService struct {
	quota  *QuotaService
	ledger UsageLedgerStore
	now    func() time.Time
}

func NewUsageSummaryService(policies QuotaPolicyStore, rollups QuotaRollupStore, ledger UsageLedgerStore) *UsageSummaryService {
	quota := NewQuotaService(policies, rollups)
	service := &UsageSummaryService{
		quota:  quota,
		ledger: ledger,
		now:    time.Now,
	}
	quota.now = service.now
	return service
}

func (s *UsageSummaryService) Summary(ctx context.Context, query UsageSummaryQuery) (*UsageSummary, error) {
	if s == nil || s.quota == nil || s.ledger == nil {
		return nil, ErrInvalid
	}
	if query.UserID == "" {
		return nil, invalid("user id is required")
	}
	s.quota.now = s.now
	quota, err := s.quota.Summary(ctx, query.UserID)
	if err != nil {
		return nil, err
	}
	limit := query.Limit
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.ledger.ListUsageLedgerRows(ctx, UsageLedgerFilter{
		UserID:   query.UserID,
		APIKeyID: query.APIKeyID,
		Limit:    limit,
		Offset:   query.Offset,
	})
	if err != nil {
		return nil, err
	}
	total, err := s.ledger.CountUsageLedgerRows(ctx, UsageLedgerFilter{
		UserID:   query.UserID,
		APIKeyID: query.APIKeyID,
	})
	if err != nil {
		return nil, err
	}
	return &UsageSummary{
		Quota:       *quota,
		RecentUsage: rows,
		Total:       total,
	}, nil
}
