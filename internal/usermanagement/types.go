package usermanagement

import "time"

type UserID string
type SessionID string
type APIKeyID string
type UsageLedgerID string

type UserStatus string
type UserRole string
type SessionStatus string
type APIKeyStatus string
type PolicySubjectType string
type QuotaPeriod string
type UsageStatus string

const (
	UserStatusPending   UserStatus = "pending"
	UserStatusApproved  UserStatus = "approved"
	UserStatusRejected  UserStatus = "rejected"
	UserStatusSuspended UserStatus = "suspended"

	UserRoleUser  UserRole = "user"
	UserRoleAdmin UserRole = "admin"

	SessionStatusActive  SessionStatus = "active"
	SessionStatusRevoked SessionStatus = "revoked"
	SessionStatusExpired SessionStatus = "expired"

	APIKeyStatusActive   APIKeyStatus = "active"
	APIKeyStatusDisabled APIKeyStatus = "disabled"
	APIKeyStatusRevoked  APIKeyStatus = "revoked"

	PolicySubjectUser   PolicySubjectType = "user"
	PolicySubjectAPIKey PolicySubjectType = "api_key"

	QuotaPeriodMonthly QuotaPeriod = "monthly"

	UsageStatusSucceeded UsageStatus = "succeeded"
	UsageStatusFailed    UsageStatus = "failed"
)

// User is the durable account record used by registration, approval, and sessions.
type User struct {
	ID           UserID
	Username     string
	Email        string
	DisplayName  string
	PasswordHash []byte
	Status       UserStatus
	Role         UserRole
	Metadata     map[string]string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	ApprovedAt   *time.Time
	RejectedAt   *time.Time
	SuspendedAt  *time.Time
}

type UserFilter struct {
	Status UserStatus
	Role   UserRole
	Query  string
	Limit  int
	Offset int
}

type CreateUserParams struct {
	Username     string
	Email        string
	DisplayName  string
	PasswordHash []byte
	Status       UserStatus
	Role         UserRole
	Metadata     map[string]string
}

type UpdateUserParams struct {
	DisplayName  *string
	PasswordHash []byte
	Status       *UserStatus
	Role         *UserRole
	Metadata     map[string]string
	ApprovedAt   *time.Time
	RejectedAt   *time.Time
	SuspendedAt  *time.Time
}

// Session authenticates management UI and user portal requests.
type Session struct {
	ID         SessionID
	UserID     UserID
	TokenHash  []byte
	Status     SessionStatus
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	LastSeenAt *time.Time
}

type CreateSessionParams struct {
	UserID    UserID
	TokenHash []byte
	ExpiresAt time.Time
}

type UpdateSessionParams struct {
	Status     *SessionStatus
	RevokedAt  *time.Time
	LastSeenAt *time.Time
}

// APIKey stores ownership metadata for a configured caller API key.
// KeyHash is a stable fingerprint of the configured key, not an independently
// generated user-management secret.
type APIKey struct {
	ID         APIKeyID
	UserID     UserID
	Name       string
	KeyHash    []byte
	Prefix     string
	Status     APIKeyStatus
	CreatedAt  time.Time
	UpdatedAt  time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
}

type CreateAPIKeyParams struct {
	UserID    UserID
	Name      string
	KeyHash   []byte
	Prefix    string
	Status    APIKeyStatus
	ExpiresAt *time.Time
}

type AssignAPIKeyParams struct {
	UserID    UserID
	Name      string
	KeyHash   []byte
	Prefix    string
	ExpiresAt *time.Time
}

type UpdateAPIKeyParams struct {
	Name       *string
	KeyHash    []byte
	Prefix     *string
	Status     *APIKeyStatus
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
}

type ConfiguredAPIKeyRef struct {
	Fingerprint string
	Prefix      string
}

// ModelPolicy grants client-visible models to either a user or an API key.
type ModelPolicy struct {
	SubjectType PolicySubjectType
	SubjectID   string
	AllowAll    bool
	Models      []string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type SetModelPolicyParams struct {
	SubjectType PolicySubjectType
	SubjectID   string
	AllowAll    bool
	Models      []string
}

type QuotaPolicy struct {
	UserID       UserID
	Period       QuotaPeriod
	LimitCredits int64
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type SetQuotaPolicyParams struct {
	UserID       UserID
	Period       QuotaPeriod
	LimitCredits int64
}

// PricingRule converts raw usage facts into credit costs. Rates may be
// fractional; the per-request credit total is rounded up to a whole credit.
type PricingRule struct {
	Model                            string
	InputCreditsPerMillionTokens     float64
	OutputCreditsPerMillionTokens    float64
	CachedCreditsPerMillionTokens    float64
	ReasoningCreditsPerMillionTokens float64
	ImageCredits                     float64
	RequestCredits                   float64
	CreatedAt                        time.Time
	UpdatedAt                        time.Time
}

type SetPricingRuleParams struct {
	Model                            string
	InputCreditsPerMillionTokens     float64
	OutputCreditsPerMillionTokens    float64
	CachedCreditsPerMillionTokens    float64
	ReasoningCreditsPerMillionTokens float64
	ImageCredits                     float64
	RequestCredits                   float64
}

type UsageLedgerRow struct {
	ID              UsageLedgerID
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
	CreditCost      int64
	Status          UsageStatus
	ErrorCode       string
	LatencyMillis   int64
	CreatedAt       time.Time
}

type CreateUsageLedgerRowParams struct {
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
	CreditCost      int64
	Status          UsageStatus
	ErrorCode       string
	LatencyMillis   int64
	CreatedAt       time.Time
}

type AppendUsageLedgerRowWithRollupParams struct {
	Ledger       CreateUsageLedgerRowParams
	Period       QuotaPeriod
	PeriodStart  time.Time
	PeriodEnd    time.Time
	LimitCredits int64
}

type UsageLedgerWriteResult struct {
	Ledger *UsageLedgerRow
	Rollup *QuotaRollup
}

type UsageLedgerFilter struct {
	UserID   UserID
	APIKeyID APIKeyID
	Provider string
	Model    string
	Status   UsageStatus
	From     time.Time
	To       time.Time
	Limit    int
	Offset   int
}

type TrafficMetric string
type TrafficGroupBy string

const (
	TrafficMetricTokens   TrafficMetric = "tokens"
	TrafficMetricCredits  TrafficMetric = "credits"
	TrafficMetricRequests TrafficMetric = "requests"

	TrafficGroupByProvider TrafficGroupBy = "provider"
	TrafficGroupByModel    TrafficGroupBy = "model"
)

type TrafficStatisticsQuery struct {
	UserID   UserID
	From     string
	To       string
	TimeZone string
	Provider string
	Model    string
	Status   UsageStatus
	GroupBy  TrafficGroupBy
}

type TrafficStatistics struct {
	PeriodStart       string               `json:"period_start"`
	PeriodEnd         string               `json:"period_end"`
	TimeZone          string               `json:"time_zone"`
	Summary           TrafficSummary       `json:"summary"`
	Ranking           []TrafficUserRanking `json:"ranking,omitempty"`
	Daily             []TrafficDailyPoint  `json:"daily"`
	Series            []TrafficModelSeries `json:"series"`
	Providers         []string             `json:"providers"`
	Models            []string             `json:"models"`
	HasEstimatedTotal bool                 `json:"has_estimated_total"`
}

type TrafficSummary struct {
	TotalTokens  int64 `json:"total_tokens"`
	TotalCredits int64 `json:"total_credits"`
	Requests     int64 `json:"requests"`
	ActiveUsers  int64 `json:"active_users"`
	Failed       int64 `json:"failed_requests"`
}

type TrafficUserRanking struct {
	UserID       UserID `json:"user_id"`
	Username     string `json:"username"`
	DisplayName  string `json:"display_name,omitempty"`
	TotalTokens  int64  `json:"total_tokens"`
	TotalCredits int64  `json:"total_credits"`
	Requests     int64  `json:"requests"`
}

type TrafficDailyPoint struct {
	Date         string `json:"date"`
	TotalTokens  int64  `json:"total_tokens"`
	TotalCredits int64  `json:"total_credits"`
	Requests     int64  `json:"requests"`
}

type TrafficModelSeries struct {
	Key          string              `json:"key"`
	Provider     string              `json:"provider,omitempty"`
	Model        string              `json:"model,omitempty"`
	Other        bool                `json:"other,omitempty"`
	TotalTokens  int64               `json:"total_tokens"`
	TotalCredits int64               `json:"total_credits"`
	Requests     int64               `json:"requests"`
	Points       []TrafficDailyPoint `json:"points"`
}

type QuotaRollup struct {
	UserID       UserID
	Period       QuotaPeriod
	PeriodStart  time.Time
	PeriodEnd    time.Time
	LimitCredits int64
	UsedCredits  int64
	UpdatedAt    time.Time
}

type UpsertQuotaRollupParams struct {
	UserID       UserID
	Period       QuotaPeriod
	PeriodStart  time.Time
	PeriodEnd    time.Time
	LimitCredits int64
	UsedCredits  int64
}
