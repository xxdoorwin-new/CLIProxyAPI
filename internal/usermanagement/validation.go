package usermanagement

import (
	"fmt"
	"strings"
)

func (s UserStatus) IsValid() bool {
	switch s {
	case UserStatusPending, UserStatusApproved, UserStatusRejected, UserStatusSuspended:
		return true
	default:
		return false
	}
}

func (r UserRole) IsValid() bool {
	switch r {
	case UserRoleUser, UserRoleAdmin:
		return true
	default:
		return false
	}
}

func (s SessionStatus) IsValid() bool {
	switch s {
	case SessionStatusActive, SessionStatusRevoked, SessionStatusExpired:
		return true
	default:
		return false
	}
}

func (s APIKeyStatus) IsValid() bool {
	switch s {
	case APIKeyStatusActive, APIKeyStatusDisabled, APIKeyStatusRevoked:
		return true
	default:
		return false
	}
}

func (t PolicySubjectType) IsValid() bool {
	switch t {
	case PolicySubjectUser, PolicySubjectAPIKey:
		return true
	default:
		return false
	}
}

func (p QuotaPeriod) IsValid() bool {
	return p == QuotaPeriodMonthly
}

func (s UsageStatus) IsValid() bool {
	switch s {
	case UsageStatusSucceeded, UsageStatusFailed:
		return true
	default:
		return false
	}
}

func (p CreateUserParams) Validate() error {
	if strings.TrimSpace(p.Username) == "" {
		return invalid("username is required")
	}
	if strings.TrimSpace(p.Email) == "" {
		return invalid("email is required")
	}
	if len(p.PasswordHash) == 0 {
		return invalid("password hash is required")
	}
	if !p.Status.IsValid() {
		return invalid("invalid user status %q", p.Status)
	}
	if !p.Role.IsValid() {
		return invalid("invalid user role %q", p.Role)
	}
	return nil
}

func (p CreateSessionParams) Validate() error {
	if p.UserID == "" {
		return invalid("user id is required")
	}
	if len(p.TokenHash) == 0 {
		return invalid("token hash is required")
	}
	if p.ExpiresAt.IsZero() {
		return invalid("session expiration is required")
	}
	return nil
}

func (p CreateAPIKeyParams) Validate() error {
	if p.UserID == "" {
		return invalid("user id is required")
	}
	if strings.TrimSpace(p.Name) == "" {
		return invalid("key name is required")
	}
	if len(p.KeyHash) == 0 {
		return invalid("key hash is required")
	}
	if strings.TrimSpace(p.Prefix) == "" {
		return invalid("key prefix is required")
	}
	if !p.Status.IsValid() {
		return invalid("invalid api key status %q", p.Status)
	}
	return nil
}

func (p SetModelPolicyParams) Validate() error {
	if !p.SubjectType.IsValid() {
		return invalid("invalid policy subject type %q", p.SubjectType)
	}
	if strings.TrimSpace(p.SubjectID) == "" {
		return invalid("policy subject id is required")
	}
	if !p.AllowAll {
		for _, model := range p.Models {
			if strings.TrimSpace(model) == "" {
				return invalid("model policy contains an empty model name")
			}
		}
	}
	return nil
}

func (p SetQuotaPolicyParams) Validate() error {
	if p.UserID == "" {
		return invalid("user id is required")
	}
	if !p.Period.IsValid() {
		return invalid("invalid quota period %q", p.Period)
	}
	if p.LimitCredits < 0 {
		return invalid("limit credits cannot be negative")
	}
	return nil
}

func (p SetPricingRuleParams) Validate() error {
	if strings.TrimSpace(p.Model) == "" {
		return invalid("model is required")
	}
	if p.InputCreditsPerMillionTokens < 0 ||
		p.OutputCreditsPerMillionTokens < 0 ||
		p.CachedCreditsPerMillionTokens < 0 ||
		p.ReasoningCreditsPerMillionTokens < 0 ||
		p.ImageCredits < 0 ||
		p.RequestCredits < 0 {
		return invalid("pricing credits cannot be negative")
	}
	return nil
}

func (p CreateUsageLedgerRowParams) Validate() error {
	if p.UserID == "" {
		return invalid("user id is required")
	}
	if p.APIKeyID == "" {
		return invalid("api key id is required")
	}
	if strings.TrimSpace(p.RequestID) == "" {
		return invalid("request id is required")
	}
	if strings.TrimSpace(p.Provider) == "" {
		return invalid("provider is required")
	}
	if strings.TrimSpace(p.Model) == "" {
		return invalid("model is required")
	}
	if !p.Status.IsValid() {
		return invalid("invalid usage status %q", p.Status)
	}
	if p.InputTokens < 0 ||
		p.OutputTokens < 0 ||
		p.CachedTokens < 0 ||
		p.ReasoningTokens < 0 ||
		p.ImageCount < 0 ||
		p.CreditCost < 0 ||
		p.LatencyMillis < 0 {
		return invalid("usage counters cannot be negative")
	}
	if p.CreatedAt.IsZero() {
		return invalid("usage creation time is required")
	}
	return nil
}

func (p AppendUsageLedgerRowWithRollupParams) Validate() error {
	if err := p.Ledger.Validate(); err != nil {
		return err
	}
	if !p.Period.IsValid() {
		return invalid("invalid quota period %q", p.Period)
	}
	if p.PeriodStart.IsZero() || p.PeriodEnd.IsZero() {
		return invalid("quota period bounds are required")
	}
	if !p.PeriodEnd.After(p.PeriodStart) {
		return invalid("quota period end must be after start")
	}
	if p.LimitCredits < 0 {
		return invalid("limit credits cannot be negative")
	}
	return nil
}

func (p UpsertQuotaRollupParams) Validate() error {
	if p.UserID == "" {
		return invalid("user id is required")
	}
	if !p.Period.IsValid() {
		return invalid("invalid quota period %q", p.Period)
	}
	if p.PeriodStart.IsZero() || p.PeriodEnd.IsZero() {
		return invalid("quota period bounds are required")
	}
	if !p.PeriodEnd.After(p.PeriodStart) {
		return invalid("quota period end must be after start")
	}
	if p.LimitCredits < 0 || p.UsedCredits < 0 {
		return invalid("quota credits cannot be negative")
	}
	return nil
}

func NormalizeModelList(models []string) []string {
	if len(models) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(models))
	normalized := make([]string, 0, len(models))
	for _, model := range models {
		model = strings.TrimSpace(model)
		if model == "" {
			continue
		}
		key := strings.ToLower(model)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, model)
	}
	return normalized
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}
