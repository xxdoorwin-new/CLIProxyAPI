package usermanagement

import (
	"context"
	"testing"
)

func TestModelPolicyServiceAssignsAndResolvesUserModels(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	user := createTestUser(t, ctx, store)
	service := NewModelPolicyService(store)

	policy, err := service.SetUserModels(ctx, user.ID, false, []string{" gpt-5 ", "gpt-5", "claude-sonnet"})
	if err != nil {
		t.Fatalf("SetUserModels() error = %v", err)
	}
	if policy.AllowAll || len(policy.Models) != 2 {
		t.Fatalf("policy = %#v, want two normalized models", policy)
	}

	allowed, resolved, err := service.IsModelAllowed(ctx, user.ID, "", "gpt-5")
	if err != nil {
		t.Fatalf("IsModelAllowed() error = %v", err)
	}
	if !allowed || resolved.SubjectType != PolicySubjectUser {
		t.Fatalf("allowed = %v resolved = %#v, want user policy allow", allowed, resolved)
	}

	allowed, _, err = service.IsModelAllowed(ctx, user.ID, "", "gpt-4")
	if err != nil {
		t.Fatalf("IsModelAllowed() disallowed error = %v", err)
	}
	if allowed {
		t.Fatal("IsModelAllowed() = true for disallowed model")
	}
}

func TestModelPolicyServiceKeyPolicyOverridesUserPolicy(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	user := createTestUser(t, ctx, store)
	key, err := store.CreateAPIKey(ctx, CreateAPIKeyParams{
		UserID:  user.ID,
		Name:    "default",
		KeyHash: []byte("hash"),
		Prefix:  "prefix",
		Status:  APIKeyStatusActive,
	})
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	service := NewModelPolicyService(store)
	if _, err = service.SetUserModels(ctx, user.ID, false, []string{"gpt-5"}); err != nil {
		t.Fatalf("SetUserModels() error = %v", err)
	}
	if _, err = service.SetAPIKeyModels(ctx, key.ID, false, []string{"claude-sonnet"}); err != nil {
		t.Fatalf("SetAPIKeyModels() error = %v", err)
	}

	allowed, resolved, err := service.IsModelAllowed(ctx, user.ID, key.ID, "claude-sonnet")
	if err != nil {
		t.Fatalf("IsModelAllowed() error = %v", err)
	}
	if !allowed || resolved.SubjectType != PolicySubjectAPIKey {
		t.Fatalf("allowed = %v resolved = %#v, want key policy allow", allowed, resolved)
	}
	allowed, _, err = service.IsModelAllowed(ctx, user.ID, key.ID, "gpt-5")
	if err != nil {
		t.Fatalf("IsModelAllowed() second error = %v", err)
	}
	if allowed {
		t.Fatal("key policy should override user policy")
	}
}

func TestModelPolicyServiceDenyEmptyPolicyByDefault(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	user := createTestUser(t, ctx, store)
	service := NewModelPolicyService(store)

	allowed, resolved, err := service.IsModelAllowed(ctx, user.ID, "", "gpt-5")
	if err != nil {
		t.Fatalf("IsModelAllowed() error = %v", err)
	}
	if allowed || resolved.SubjectID != "" {
		t.Fatalf("allowed = %v resolved = %#v, want default deny", allowed, resolved)
	}
}
