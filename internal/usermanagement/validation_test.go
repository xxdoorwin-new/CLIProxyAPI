package usermanagement

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestDomainEnumValidation(t *testing.T) {
	if !UserStatusApproved.IsValid() || !UserRoleAdmin.IsValid() || !SessionStatusActive.IsValid() ||
		!APIKeyStatusActive.IsValid() || !PolicySubjectUser.IsValid() || !QuotaPeriodMonthly.IsValid() ||
		!UsageStatusSucceeded.IsValid() {
		t.Fatal("known enum value reported invalid")
	}
	if UserStatus("unknown").IsValid() || UserRole("owner").IsValid() || QuotaPeriod("daily").IsValid() {
		t.Fatal("unknown enum value reported valid")
	}
}

func TestCreateUserParamsValidate(t *testing.T) {
	params := CreateUserParams{
		Username:     "alice",
		Email:        "alice@example.test",
		PasswordHash: []byte("hash"),
		Status:       UserStatusPending,
		Role:         UserRoleUser,
	}
	if err := params.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	params.Status = UserStatus("weird")
	if err := params.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Validate() error = %v, want ErrInvalid", err)
	}
}

func TestPolicyAndPricingValidation(t *testing.T) {
	policy := SetModelPolicyParams{
		SubjectType: PolicySubjectUser,
		SubjectID:   "user-1",
		Models:      []string{"gpt-5"},
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("policy Validate() error = %v", err)
	}

	pricing := SetPricingRuleParams{
		Model:                        "gpt-5",
		InputCreditsPerMillionTokens: -1,
	}
	if err := pricing.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("pricing Validate() error = %v, want ErrInvalid", err)
	}
}

func TestUsageAndRollupValidation(t *testing.T) {
	usage := CreateUsageLedgerRowParams{
		UserID:    "user-1",
		APIKeyID:  "key-1",
		RequestID: "request-1",
		Provider:  "openai",
		Model:     "gpt-5",
		Status:    UsageStatusSucceeded,
		CreatedAt: time.Now(),
	}
	if err := usage.Validate(); err != nil {
		t.Fatalf("usage Validate() error = %v", err)
	}

	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	rollup := UpsertQuotaRollupParams{
		UserID:       "user-1",
		Period:       QuotaPeriodMonthly,
		PeriodStart:  start,
		PeriodEnd:    start.AddDate(0, 1, 0),
		LimitCredits: 100,
		UsedCredits:  10,
	}
	if err := rollup.Validate(); err != nil {
		t.Fatalf("rollup Validate() error = %v", err)
	}
	rollup.PeriodEnd = start
	if err := rollup.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("rollup Validate() error = %v, want ErrInvalid", err)
	}
}

func TestNormalizeModelList(t *testing.T) {
	got := NormalizeModelList([]string{" gpt-5 ", "", "GPT-5", "claude-sonnet"})
	want := []string{"gpt-5", "claude-sonnet"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NormalizeModelList() = %#v, want %#v", got, want)
	}
}
