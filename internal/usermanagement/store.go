package usermanagement

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound      = errors.New("user management: not found")
	ErrAlreadyExists = errors.New("user management: already exists")
	ErrConflict      = errors.New("user management: conflict")
	ErrInvalid       = errors.New("user management: invalid")
	ErrUnauthorized  = errors.New("user management: unauthorized")
	ErrForbidden     = errors.New("user management: forbidden")
)

type Store interface {
	UserStore
	SessionStore
	APIKeyStore
	ModelPolicyStore
	QuotaPolicyStore
	PricingStore
	UsageLedgerStore
	QuotaRollupStore
	Close() error
}

type UserStore interface {
	CreateUser(ctx context.Context, params CreateUserParams) (*User, error)
	GetUser(ctx context.Context, id UserID) (*User, error)
	FindUserByIdentity(ctx context.Context, identity string) (*User, error)
	ListUsers(ctx context.Context, filter UserFilter) ([]User, error)
	UpdateUser(ctx context.Context, id UserID, params UpdateUserParams) (*User, error)
}

type SessionStore interface {
	CreateSession(ctx context.Context, params CreateSessionParams) (*Session, error)
	GetSession(ctx context.Context, id SessionID) (*Session, error)
	FindSessionByTokenHash(ctx context.Context, tokenHash []byte) (*Session, error)
	UpdateSession(ctx context.Context, id SessionID, params UpdateSessionParams) (*Session, error)
	RevokeSessionsForUser(ctx context.Context, userID UserID) error
	DeleteExpiredSessions(ctx context.Context, before time.Time) (int64, error)
}

type APIKeyStore interface {
	CreateAPIKey(ctx context.Context, params CreateAPIKeyParams) (*APIKey, error)
	GetAPIKey(ctx context.Context, id APIKeyID) (*APIKey, error)
	ListAPIKeysByUser(ctx context.Context, userID UserID) ([]APIKey, error)
	FindAPIKeyByPrefix(ctx context.Context, prefix string) ([]APIKey, error)
	FindAPIKeyByFingerprint(ctx context.Context, fingerprint []byte) ([]APIKey, error)
	UpdateAPIKey(ctx context.Context, id APIKeyID, params UpdateAPIKeyParams) (*APIKey, error)
	DeleteAPIKey(ctx context.Context, id APIKeyID) error
}

type ModelPolicyStore interface {
	SetModelPolicy(ctx context.Context, params SetModelPolicyParams) (*ModelPolicy, error)
	GetModelPolicy(ctx context.Context, subjectType PolicySubjectType, subjectID string) (*ModelPolicy, error)
	DeleteModelPolicy(ctx context.Context, subjectType PolicySubjectType, subjectID string) error
}

type QuotaPolicyStore interface {
	SetQuotaPolicy(ctx context.Context, params SetQuotaPolicyParams) (*QuotaPolicy, error)
	GetQuotaPolicy(ctx context.Context, userID UserID) (*QuotaPolicy, error)
}

type PricingStore interface {
	SetPricingRule(ctx context.Context, params SetPricingRuleParams) (*PricingRule, error)
	GetPricingRule(ctx context.Context, model string) (*PricingRule, error)
	ListPricingRules(ctx context.Context) ([]PricingRule, error)
	DeletePricingRule(ctx context.Context, model string) error
}

type UsageLedgerStore interface {
	AppendUsageLedgerRow(ctx context.Context, params CreateUsageLedgerRowParams) (*UsageLedgerRow, error)
	ListUsageLedgerRows(ctx context.Context, filter UsageLedgerFilter) ([]UsageLedgerRow, error)
	SumUsageCredits(ctx context.Context, userID UserID, from, to time.Time) (int64, error)
}

type QuotaRollupStore interface {
	UpsertQuotaRollup(ctx context.Context, params UpsertQuotaRollupParams) (*QuotaRollup, error)
	GetQuotaRollup(ctx context.Context, userID UserID, period QuotaPeriod, periodStart time.Time) (*QuotaRollup, error)
}
