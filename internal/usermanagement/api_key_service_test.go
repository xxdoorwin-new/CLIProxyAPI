package usermanagement

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestUserAPIKeyServiceCreateListRenameAndUpdateLastUsed(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	user := createTestUser(t, ctx, store)
	configuredKey := "configured-key-1"
	service := NewUserAPIKeyService(store, store, []string{configuredKey})

	key, err := service.BindKey(ctx, BindUserAPIKeyRequest{
		UserID:                   user.ID,
		Name:                     "default",
		ConfiguredKeyFingerprint: ConfiguredAPIKeyFingerprintHex(configuredKey),
	})
	if err != nil {
		t.Fatalf("BindKey() error = %v", err)
	}
	if got, want := EncodeAPIKeyFingerprint(key.KeyHash), ConfiguredAPIKeyFingerprintHex(configuredKey); got != want {
		t.Fatalf("fingerprint = %q, want %q", got, want)
	}

	renamed, err := service.RenameKey(ctx, key.ID, "renamed")
	if err != nil {
		t.Fatalf("RenameKey() error = %v", err)
	}
	if renamed.Name != "renamed" {
		t.Fatalf("Name = %q, want renamed", renamed.Name)
	}

	usedAt := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	used, err := service.UpdateLastUsed(ctx, key.ID, usedAt)
	if err != nil {
		t.Fatalf("UpdateLastUsed() error = %v", err)
	}
	if used.LastUsedAt == nil || !used.LastUsedAt.Equal(usedAt) {
		t.Fatalf("LastUsedAt = %v, want %v", used.LastUsedAt, usedAt)
	}

	metadata, err := service.ListKeyMetadataByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListKeyMetadataByUser() error = %v", err)
	}
	if len(metadata) != 1 || metadata[0].Prefix == "" || metadata[0].Name != "renamed" {
		t.Fatalf("metadata = %#v", metadata)
	}
	if !metadata[0].ConfiguredKeyPresent || metadata[0].ConfiguredKeyFingerprint != ConfiguredAPIKeyFingerprintHex(configuredKey) {
		t.Fatalf("metadata configured fields = %#v", metadata[0])
	}
}

func TestUserAPIKeyServiceDisableEnableAndUnbind(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	user := createTestUser(t, ctx, store)
	configuredKey := "configured-key-2"
	service := NewUserAPIKeyService(store, store, []string{configuredKey})
	key, err := service.BindKey(ctx, BindUserAPIKeyRequest{
		UserID:                   user.ID,
		Name:                     "default",
		ConfiguredKeyFingerprint: ConfiguredAPIKeyFingerprintHex(configuredKey),
	})
	if err != nil {
		t.Fatalf("BindKey() error = %v", err)
	}

	disabled, err := service.DisableKey(ctx, key.ID)
	if err != nil {
		t.Fatalf("DisableKey() error = %v", err)
	}
	if disabled.Status != APIKeyStatusDisabled {
		t.Fatalf("Status = %q, want disabled", disabled.Status)
	}

	enabled, err := service.EnableKey(ctx, key.ID)
	if err != nil {
		t.Fatalf("EnableKey() error = %v", err)
	}
	if enabled.Status != APIKeyStatusActive {
		t.Fatalf("Status = %q, want active", enabled.Status)
	}

	if err = service.UnbindKey(ctx, key.ID); err != nil {
		t.Fatalf("UnbindKey() error = %v", err)
	}
	if _, err = store.GetAPIKey(ctx, key.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetAPIKey() after unbind error = %v, want ErrNotFound", err)
	}
}

func TestUserAPIKeyServiceRejectsInactiveOwner(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	hash, err := HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	user, err := store.CreateUser(ctx, CreateUserParams{
		Username:     "pending-key",
		Email:        "pending-key@example.test",
		PasswordHash: hash,
		Status:       UserStatusPending,
		Role:         UserRoleUser,
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	configuredKey := "configured-key-3"
	service := NewUserAPIKeyService(store, store, []string{configuredKey})

	_, err = service.BindKey(ctx, BindUserAPIKeyRequest{
		UserID:                   user.ID,
		Name:                     "default",
		ConfiguredKeyFingerprint: ConfiguredAPIKeyFingerprintHex(configuredKey),
	})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("BindKey() error = %v, want ErrForbidden", err)
	}
}

func TestUserAPIKeyServiceListsConfiguredSelectionAndMissingBinding(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	user := createTestUser(t, ctx, store)
	boundKey := "configured-key-4"
	unboundKey := "configured-key-5"
	service := NewUserAPIKeyService(store, store, []string{boundKey, unboundKey})

	binding, err := service.BindKey(ctx, BindUserAPIKeyRequest{
		UserID:                   user.ID,
		Name:                     "bound",
		ConfiguredKeyFingerprint: ConfiguredAPIKeyFingerprintHex(boundKey),
	})
	if err != nil {
		t.Fatalf("BindKey() error = %v", err)
	}

	selections, err := service.ListConfiguredAPIKeys(ctx)
	if err != nil {
		t.Fatalf("ListConfiguredAPIKeys() error = %v", err)
	}
	if len(selections) != 2 {
		t.Fatalf("selection count = %d, want 2", len(selections))
	}
	if !selections[0].Assigned || selections[0].AssignedKeyID != binding.ID || selections[0].AssignedUserID != user.ID {
		t.Fatalf("bound selection = %#v", selections[0])
	}
	if selections[1].Assigned || !selections[1].ConfiguredPresent {
		t.Fatalf("unbound selection = %#v", selections[1])
	}

	missingService := NewUserAPIKeyService(store, store, []string{unboundKey})
	metadata, err := missingService.ListKeyMetadataByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListKeyMetadataByUser() error = %v", err)
	}
	if len(metadata) != 1 || metadata[0].ConfiguredKeyPresent {
		t.Fatalf("missing metadata = %#v", metadata)
	}
}
