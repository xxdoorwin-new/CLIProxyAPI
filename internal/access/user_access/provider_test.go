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
	keyService := usermanagement.NewUserAPIKeyService(store, store)
	credential, err := keyService.CreateKey(ctx, usermanagement.CreateUserAPIKeyRequest{UserID: user.ID, Name: "default"})
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	provider := NewProvider(store, store)
	req, err := http.NewRequest(http.MethodPost, "http://example.test/v1/chat/completions", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+credential.Plaintext)

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
	if result.Metadata["api_key_id"] != string(credential.APIKey.ID) {
		t.Fatalf("api_key_id metadata = %q, want %q", result.Metadata["api_key_id"], credential.APIKey.ID)
	}
}

func TestProviderRejectsUnknownUserAPIKey(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	provider := NewProvider(store, store)
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

func TestProviderRejectsRevokedUserAPIKey(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	user := createApprovedUser(t, ctx, store)
	keyService := usermanagement.NewUserAPIKeyService(store, store)
	credential, err := keyService.CreateKey(ctx, usermanagement.CreateUserAPIKeyRequest{UserID: user.ID, Name: "default"})
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}
	if _, err = keyService.RevokeKey(ctx, credential.APIKey.ID); err != nil {
		t.Fatalf("RevokeKey() error = %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://example.test/v1/chat/completions", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+credential.Plaintext)

	_, authErr := NewProvider(store, store).Authenticate(ctx, req)
	if authErr == nil || authErr.Code != sdkaccess.AuthErrorCodeInvalidCredential {
		t.Fatalf("Authenticate() error = %v, want invalid credential", authErr)
	}
}

func TestProviderRejectsSuspendedOwner(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	user := createApprovedUser(t, ctx, store)
	keyService := usermanagement.NewUserAPIKeyService(store, store)
	credential, err := keyService.CreateKey(ctx, usermanagement.CreateUserAPIKeyRequest{UserID: user.ID, Name: "default"})
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}
	lifecycle := usermanagement.NewUserLifecycleService(store, store)
	if _, err = lifecycle.SuspendUser(ctx, user.ID); err != nil {
		t.Fatalf("SuspendUser() error = %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://example.test/v1/chat/completions", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+credential.Plaintext)

	_, authErr := NewProvider(store, store).Authenticate(ctx, req)
	if authErr == nil || authErr.Code != sdkaccess.AuthErrorCodeInvalidCredential {
		t.Fatalf("Authenticate() error = %v, want invalid credential", authErr)
	}
}

func TestProviderReportsMissingCredentials(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	provider := NewProvider(store, store)
	req, err := http.NewRequest(http.MethodPost, "http://example.test/v1/chat/completions", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	_, authErr := provider.Authenticate(ctx, req)
	if authErr == nil || authErr.Code != sdkaccess.AuthErrorCodeNoCredentials {
		t.Fatalf("Authenticate() error = %v, want no credentials", authErr)
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
