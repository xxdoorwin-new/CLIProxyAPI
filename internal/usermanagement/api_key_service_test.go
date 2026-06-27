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
	service := NewUserAPIKeyService(store, store)

	credential, err := service.CreateKey(ctx, CreateUserAPIKeyRequest{
		UserID: user.ID,
		Name:   "default",
	})
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}
	if credential.Plaintext == "" || !VerifyUserAPIKey(credential.Plaintext, credential.APIKey.KeyHash) {
		t.Fatalf("credential = %#v", credential)
	}

	renamed, err := service.RenameKey(ctx, credential.APIKey.ID, "renamed")
	if err != nil {
		t.Fatalf("RenameKey() error = %v", err)
	}
	if renamed.Name != "renamed" {
		t.Fatalf("Name = %q, want renamed", renamed.Name)
	}

	usedAt := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	used, err := service.UpdateLastUsed(ctx, credential.APIKey.ID, usedAt)
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
}

func TestUserAPIKeyServiceDisableRevokeAndRotate(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	user := createTestUser(t, ctx, store)
	service := NewUserAPIKeyService(store, store)
	credential, err := service.CreateKey(ctx, CreateUserAPIKeyRequest{UserID: user.ID, Name: "default"})
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	disabled, err := service.DisableKey(ctx, credential.APIKey.ID)
	if err != nil {
		t.Fatalf("DisableKey() error = %v", err)
	}
	if disabled.Status != APIKeyStatusDisabled {
		t.Fatalf("Status = %q, want disabled", disabled.Status)
	}

	rotated, err := service.RotateKey(ctx, credential.APIKey.ID)
	if err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}
	if rotated.Plaintext == credential.Plaintext {
		t.Fatal("RotateKey() returned same plaintext key")
	}
	if !VerifyUserAPIKey(rotated.Plaintext, rotated.APIKey.KeyHash) {
		t.Fatal("rotated key hash did not verify")
	}
	if VerifyUserAPIKey(credential.Plaintext, rotated.APIKey.KeyHash) {
		t.Fatal("old plaintext verifies against rotated hash")
	}

	revoked, err := service.RevokeKey(ctx, credential.APIKey.ID)
	if err != nil {
		t.Fatalf("RevokeKey() error = %v", err)
	}
	if revoked.Status != APIKeyStatusRevoked {
		t.Fatalf("Status = %q, want revoked", revoked.Status)
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
	service := NewUserAPIKeyService(store, store)

	_, err = service.CreateKey(ctx, CreateUserAPIKeyRequest{UserID: user.ID, Name: "default"})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("CreateKey() error = %v, want ErrForbidden", err)
	}
}
