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
	unbound, err := store.GetAPIKey(ctx, key.ID)
	if err != nil {
		t.Fatalf("GetAPIKey() after unbind error = %v", err)
	}
	if unbound.Status != APIKeyStatusRevoked {
		t.Fatalf("Status after unbind = %q, want revoked", unbound.Status)
	}
}

func TestUserAPIKeyServiceAssignsSingleCurrentKeyAndPreservesHistory(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	user := createTestUser(t, ctx, store)
	configuredKeys := []string{"configured-replace-1", "configured-replace-2"}
	service := NewUserAPIKeyService(store, store, configuredKeys)

	first, err := service.BindKey(ctx, BindUserAPIKeyRequest{
		UserID:                   user.ID,
		Name:                     "first",
		ConfiguredKeyFingerprint: ConfiguredAPIKeyFingerprintHex(configuredKeys[0]),
	})
	if err != nil {
		t.Fatalf("BindKey(first) error = %v", err)
	}
	second, err := service.BindKey(ctx, BindUserAPIKeyRequest{
		UserID:                   user.ID,
		Name:                     "second",
		ConfiguredKeyFingerprint: ConfiguredAPIKeyFingerprintHex(configuredKeys[1]),
	})
	if err != nil {
		t.Fatalf("BindKey(second) error = %v", err)
	}
	if second.ID == first.ID {
		t.Fatalf("replacement reused old assignment id %q", second.ID)
	}

	history, err := store.ListAPIKeysByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListAPIKeysByUser() error = %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("history count = %d, want 2", len(history))
	}
	current, err := service.ListKeyMetadataByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListKeyMetadataByUser() error = %v", err)
	}
	if len(current) != 1 || current[0].ID != second.ID {
		t.Fatalf("current metadata = %#v, want only second assignment", current)
	}
	old, err := store.GetAPIKey(ctx, first.ID)
	if err != nil {
		t.Fatalf("GetAPIKey(first) error = %v", err)
	}
	if old.Status != APIKeyStatusRevoked {
		t.Fatalf("first status = %q, want revoked", old.Status)
	}
}

func TestUserAPIKeyServiceRejectsOccupiedKeyAndKeepsExistingAssignment(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	owner := createTestUser(t, ctx, store)
	other := createTestUser(t, ctx, store)
	configuredKeys := []string{"configured-owned", "configured-other"}
	service := NewUserAPIKeyService(store, store, configuredKeys)

	owned, err := service.BindKey(ctx, BindUserAPIKeyRequest{
		UserID:                   owner.ID,
		Name:                     "owned",
		ConfiguredKeyFingerprint: ConfiguredAPIKeyFingerprintHex(configuredKeys[0]),
	})
	if err != nil {
		t.Fatalf("BindKey(owner) error = %v", err)
	}
	otherCurrent, err := service.BindKey(ctx, BindUserAPIKeyRequest{
		UserID:                   other.ID,
		Name:                     "other",
		ConfiguredKeyFingerprint: ConfiguredAPIKeyFingerprintHex(configuredKeys[1]),
	})
	if err != nil {
		t.Fatalf("BindKey(other) error = %v", err)
	}

	_, err = service.BindKey(ctx, BindUserAPIKeyRequest{
		UserID:                   other.ID,
		Name:                     "conflict",
		ConfiguredKeyFingerprint: ConfiguredAPIKeyFingerprintHex(configuredKeys[0]),
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("BindKey(occupied) error = %v, want ErrConflict", err)
	}
	current, err := service.ListKeyMetadataByUser(ctx, other.ID)
	if err != nil {
		t.Fatalf("ListKeyMetadataByUser(other) error = %v", err)
	}
	if len(current) != 1 || current[0].ID != otherCurrent.ID {
		t.Fatalf("other current = %#v, want unchanged %q", current, otherCurrent.ID)
	}
	ownerCurrent, err := service.ListKeyMetadataByUser(ctx, owner.ID)
	if err != nil {
		t.Fatalf("ListKeyMetadataByUser(owner) error = %v", err)
	}
	if len(ownerCurrent) != 1 || ownerCurrent[0].ID != owned.ID {
		t.Fatalf("owner current = %#v, want unchanged %q", ownerCurrent, owned.ID)
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
	otherUser := createTestUser(t, ctx, store)
	boundKey := "configured-key-4"
	unboundKey := "configured-key-5"
	occupiedKey := "configured-key-6"
	service := NewUserAPIKeyService(store, store, []string{boundKey, unboundKey, occupiedKey})

	binding, err := service.BindKey(ctx, BindUserAPIKeyRequest{
		UserID:                   user.ID,
		Name:                     "bound",
		ConfiguredKeyFingerprint: ConfiguredAPIKeyFingerprintHex(boundKey),
	})
	if err != nil {
		t.Fatalf("BindKey() error = %v", err)
	}
	occupied, err := service.BindKey(ctx, BindUserAPIKeyRequest{
		UserID:                   otherUser.ID,
		Name:                     "occupied",
		ConfiguredKeyFingerprint: ConfiguredAPIKeyFingerprintHex(occupiedKey),
	})
	if err != nil {
		t.Fatalf("BindKey(occupied) error = %v", err)
	}

	selections, err := service.ListConfiguredAPIKeysForUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListConfiguredAPIKeys() error = %v", err)
	}
	if len(selections) != 3 {
		t.Fatalf("selection count = %d, want 3", len(selections))
	}
	if !selections[0].Assigned || selections[0].AssignedKeyID != binding.ID || selections[0].AssignedUserID != user.ID || selections[0].State != "assigned_to_selected_user" {
		t.Fatalf("bound selection = %#v", selections[0])
	}
	if selections[1].Assigned || !selections[1].ConfiguredPresent {
		t.Fatalf("unbound selection = %#v", selections[1])
	}
	if !selections[2].Assigned || selections[2].AssignedKeyID != occupied.ID || selections[2].State != "assigned_to_other_user" || selections[2].AssignedUsername == "" {
		t.Fatalf("occupied selection = %#v", selections[2])
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
