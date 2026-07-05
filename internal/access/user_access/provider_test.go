package useraccess

import (
	"context"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/usermanagement"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
)

func TestProviderAuthenticatesActiveUserAPIKey(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	user := createApprovedUser(t, ctx, store)
	configuredKey := "configured-provider-key"
	keyService := usermanagement.NewUserAPIKeyService(store, store, []string{configuredKey})
	key, err := keyService.BindKey(ctx, usermanagement.BindUserAPIKeyRequest{
		UserID:                   user.ID,
		Name:                     "default",
		ConfiguredKeyFingerprint: usermanagement.ConfiguredAPIKeyFingerprintHex(configuredKey),
	})
	if err != nil {
		t.Fatalf("BindKey() error = %v", err)
	}

	provider := NewProvider(store, store, []string{configuredKey})
	req, err := http.NewRequest(http.MethodPost, "http://example.test/v1/chat/completions", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+configuredKey)

	result, authErr := provider.Authenticate(ctx, req)
	if authErr != nil {
		t.Fatalf("Authenticate() error = %v", authErr)
	}
	if result.Provider != DefaultProviderName {
		t.Fatalf("Provider = %q, want %q", result.Provider, DefaultProviderName)
	}
	if result.Principal != string(user.ID) {
		t.Fatalf("Principal = %q, want user id %q", result.Principal, user.ID)
	}
	if result.Metadata["api_key_id"] != string(key.ID) {
		t.Fatalf("api_key_id metadata = %q, want %q", result.Metadata["api_key_id"], key.ID)
	}
}

func TestProviderRejectsUnknownUserAPIKey(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	provider := NewProvider(store, store, []string{"known-configured-key"})
	req, err := http.NewRequest(http.MethodPost, "http://example.test/v1/chat/completions", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer cpak_unknown")

	_, authErr := provider.Authenticate(ctx, req)
	if authErr == nil || authErr.Code != sdkaccess.AuthErrorCodeInvalidCredential {
		t.Fatalf("Authenticate() error = %v, want invalid credential", authErr)
	}
}

func TestProviderRejectsDisabledUserAPIKeyBinding(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	user := createApprovedUser(t, ctx, store)
	configuredKey := "configured-disabled-key"
	keyService := usermanagement.NewUserAPIKeyService(store, store, []string{configuredKey})
	key, err := keyService.BindKey(ctx, usermanagement.BindUserAPIKeyRequest{
		UserID:                   user.ID,
		Name:                     "default",
		ConfiguredKeyFingerprint: usermanagement.ConfiguredAPIKeyFingerprintHex(configuredKey),
	})
	if err != nil {
		t.Fatalf("BindKey() error = %v", err)
	}
	if _, err = keyService.DisableKey(ctx, key.ID); err != nil {
		t.Fatalf("DisableKey() error = %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://example.test/v1/chat/completions", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+configuredKey)

	_, authErr := NewProvider(store, store, []string{configuredKey}).Authenticate(ctx, req)
	if authErr == nil || authErr.Code != sdkaccess.AuthErrorCodeInvalidCredential {
		t.Fatalf("Authenticate() error = %v, want invalid credential", authErr)
	}
}

func TestProviderRejectsSuspendedOwner(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	user := createApprovedUser(t, ctx, store)
	configuredKey := "configured-suspended-key"
	keyService := usermanagement.NewUserAPIKeyService(store, store, []string{configuredKey})
	_, err := keyService.BindKey(ctx, usermanagement.BindUserAPIKeyRequest{
		UserID:                   user.ID,
		Name:                     "default",
		ConfiguredKeyFingerprint: usermanagement.ConfiguredAPIKeyFingerprintHex(configuredKey),
	})
	if err != nil {
		t.Fatalf("BindKey() error = %v", err)
	}
	lifecycle := usermanagement.NewUserLifecycleService(store, store)
	if _, err = lifecycle.SuspendUser(ctx, user.ID); err != nil {
		t.Fatalf("SuspendUser() error = %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://example.test/v1/chat/completions", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+configuredKey)

	_, authErr := NewProvider(store, store, []string{configuredKey}).Authenticate(ctx, req)
	if authErr == nil || authErr.Code != sdkaccess.AuthErrorCodeInvalidCredential {
		t.Fatalf("Authenticate() error = %v, want invalid credential", authErr)
	}
}

func TestProviderReportsMissingCredentials(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	provider := NewProvider(store, store, nil)
	req, err := http.NewRequest(http.MethodPost, "http://example.test/v1/chat/completions", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	_, authErr := provider.Authenticate(ctx, req)
	if authErr == nil || authErr.Code != sdkaccess.AuthErrorCodeNoCredentials {
		t.Fatalf("Authenticate() error = %v, want no credentials", authErr)
	}
}

func TestProviderRejectsUnboundConfiguredAPIKey(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	configuredKey := "configured-but-unbound"
	provider := NewProvider(store, store, []string{configuredKey})
	req, err := http.NewRequest(http.MethodPost, "http://example.test/v1/chat/completions", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+configuredKey)

	_, authErr := provider.Authenticate(ctx, req)
	if authErr == nil || authErr.Code != sdkaccess.AuthErrorCodeInvalidCredential {
		t.Fatalf("Authenticate() error = %v, want invalid credential", authErr)
	}
}

func TestProviderRejectsMissingConfiguredAPIKey(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	user := createApprovedUser(t, ctx, store)
	configuredKey := "configured-then-removed"
	keyService := usermanagement.NewUserAPIKeyService(store, store, []string{configuredKey})
	if _, err := keyService.BindKey(ctx, usermanagement.BindUserAPIKeyRequest{
		UserID:                   user.ID,
		Name:                     "default",
		ConfiguredKeyFingerprint: usermanagement.ConfiguredAPIKeyFingerprintHex(configuredKey),
	}); err != nil {
		t.Fatalf("BindKey() error = %v", err)
	}

	provider := NewProvider(store, store, []string{"other-configured-key"})
	req, err := http.NewRequest(http.MethodPost, "http://example.test/v1/chat/completions", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+configuredKey)

	_, authErr := provider.Authenticate(ctx, req)
	if authErr == nil || authErr.Code != sdkaccess.AuthErrorCodeInvalidCredential {
		t.Fatalf("Authenticate() error = %v, want invalid credential", authErr)
	}
}

func newTestStore(t *testing.T) *usermanagement.SQLiteStore {
	t.Helper()
	store, err := usermanagement.OpenSQLiteStore(context.Background(), usermanagement.SQLiteConfig{Path: t.TempDir() + "/users.db"})
	if err != nil {
		t.Fatalf("OpenSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})
	return store
}

func createApprovedUser(t *testing.T, ctx context.Context, store *usermanagement.SQLiteStore) *usermanagement.User {
	t.Helper()
	hash, err := usermanagement.HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	user, err := store.CreateUser(ctx, usermanagement.CreateUserParams{
		Username:     "alice",
		Email:        "alice@example.test",
		PasswordHash: hash,
		Status:       usermanagement.UserStatusApproved,
		Role:         usermanagement.UserRoleUser,
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	return user
}
