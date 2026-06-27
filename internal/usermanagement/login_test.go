package usermanagement

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLoginServiceCreatesSessionForApprovedUser(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	hash, err := HashPassword("secret-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	user, err := store.CreateUser(ctx, CreateUserParams{
		Username:     "approved",
		Email:        "approved@example.test",
		PasswordHash: hash,
		Status:       UserStatusApproved,
		Role:         UserRoleUser,
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	login := NewLoginService(store, store)
	credential, err := login.Login(ctx, LoginRequest{
		Identity: "approved@example.test",
		Password: "secret-password",
		TTL:      time.Hour,
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if credential.Session.UserID != user.ID || credential.Token == "" {
		t.Fatalf("credential = %#v, want user %q with token", credential, user.ID)
	}
}

func TestLoginServiceRejectsPendingAndSuspendedUsers(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	hash, err := HashPassword("secret-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	pending, err := store.CreateUser(ctx, CreateUserParams{
		Username:     "pending-login",
		Email:        "pending-login@example.test",
		PasswordHash: hash,
		Status:       UserStatusPending,
		Role:         UserRoleUser,
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	login := NewLoginService(store, store)

	_, err = login.Login(ctx, LoginRequest{Identity: pending.Email, Password: "secret-password"})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("Login() pending error = %v, want ErrForbidden", err)
	}

	status := UserStatusSuspended
	if _, err = store.UpdateUser(ctx, pending.ID, UpdateUserParams{Status: &status}); err != nil {
		t.Fatalf("UpdateUser() error = %v", err)
	}
	_, err = login.Login(ctx, LoginRequest{Identity: pending.Email, Password: "secret-password"})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("Login() suspended error = %v, want ErrForbidden", err)
	}
}

func TestLoginServiceRejectsBadPassword(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	user := createTestUser(t, ctx, store)
	login := NewLoginService(store, store)

	_, err := login.Login(ctx, LoginRequest{Identity: user.Email, Password: "wrong"})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Login() error = %v, want ErrUnauthorized", err)
	}
}
