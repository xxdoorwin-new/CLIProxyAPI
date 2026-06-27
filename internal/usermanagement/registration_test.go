package usermanagement

import (
	"context"
	"errors"
	"testing"
)

func TestRegistrationServiceCreatesPendingUser(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	service := NewRegistrationService(store)

	user, err := service.Register(ctx, RegisterUserRequest{
		Username:    "alice",
		Email:       "alice@example.test",
		Password:    "secret-password",
		DisplayName: "Alice",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if user.Status != UserStatusPending {
		t.Fatalf("Status = %q, want pending", user.Status)
	}
	if user.Role != UserRoleUser {
		t.Fatalf("Role = %q, want user", user.Role)
	}
	if !VerifyPassword("secret-password", user.PasswordHash) {
		t.Fatal("registered password hash did not verify")
	}
}

func TestRegistrationServiceRejectsDuplicateIdentity(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	service := NewRegistrationService(store)

	_, err := service.Register(ctx, RegisterUserRequest{
		Username: "alice",
		Email:    "alice@example.test",
		Password: "secret-password",
	})
	if err != nil {
		t.Fatalf("Register() first error = %v", err)
	}
	_, err = service.Register(ctx, RegisterUserRequest{
		Username: "alice2",
		Email:    "ALICE@example.test",
		Password: "secret-password",
	})
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("Register() duplicate error = %v, want ErrAlreadyExists", err)
	}
}
