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

func TestModelPolicyServiceDisablesUserModels(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	user := createTestUser(t, ctx, store)
	service := NewModelPolicyService(store)

	policy, err := service.SetUserModelsWithDisabled(ctx, user.ID, true, nil, []string{" gpt-5 ", "GPT-5"})
	if err != nil {
		t.Fatalf("SetUserModelsWithDisabled() error = %v", err)
	}
	if len(policy.DisabledModels) != 1 || policy.DisabledModels[0] != "gpt-5" {
		t.Fatalf("disabled models = %#v, want normalized single model", policy.DisabledModels)
	}

	allowed, _, err := service.IsModelAllowed(ctx, user.ID, "", "claude-sonnet")
	if err != nil || !allowed {
		t.Fatalf("IsModelAllowed() for other model = %v, err = %v; want allowed", allowed, err)
	}
	allowed, _, err = service.IsModelAllowed(ctx, user.ID, "", "models/gpt-5")
	if err != nil || allowed {
		t.Fatalf("IsModelAllowed() for disabled model = %v, err = %v; want denied", allowed, err)
	}
}

func TestModelPolicyServiceUserDisabledModelOverridesAPIKeyPolicy(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	user := createTestUser(t, ctx, store)
	key, err := store.CreateAPIKey(ctx, CreateAPIKeyParams{
		UserID: user.ID, Name: "default", KeyHash: []byte("hash"), Prefix: "prefix", Status: APIKeyStatusActive,
	})
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	service := NewModelPolicyService(store)
	if _, err = service.SetUserModelsWithDisabled(ctx, user.ID, true, nil, []string{"gpt-5"}); err != nil {
		t.Fatalf("SetUserModelsWithDisabled() error = %v", err)
	}
	if _, err = service.SetAPIKeyModels(ctx, key.ID, true, nil); err != nil {
		t.Fatalf("SetAPIKeyModels() error = %v", err)
	}

	allowed, _, err := service.IsModelAllowed(ctx, user.ID, key.ID, "gpt-5")
	if err != nil || allowed {
		t.Fatalf("IsModelAllowed() = %v, err = %v; want disabled model denied", allowed, err)
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
