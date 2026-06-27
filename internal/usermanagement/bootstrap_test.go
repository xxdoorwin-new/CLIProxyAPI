package usermanagement

import (
	"context"
	"errors"
	"testing"
)

func TestBootstrapServiceCreatesFirstAdmin(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	service := NewBootstrapService(store)

	admin, err := service.CreateFirstAdmin(ctx, BootstrapAdminRequest{
		ManagementAuthorized: true,
		Username:             "admin",
		Email:                "admin@example.test",
		Password:             "admin-password",
		DisplayName:          "Admin",
	})
	if err != nil {
		t.Fatalf("CreateFirstAdmin() error = %v", err)
	}
	if admin.Status != UserStatusApproved || admin.Role != UserRoleAdmin {
		t.Fatalf("admin = %#v, want approved admin", admin)
	}
	if !VerifyPassword("admin-password", admin.PasswordHash) {
		t.Fatal("admin password hash did not verify")
	}
}

func TestBootstrapServiceRequiresManagementAuthorization(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	service := NewBootstrapService(store)

	_, err := service.CreateFirstAdmin(ctx, BootstrapAdminRequest{
		ManagementAuthorized: false,
		Username:             "admin",
		Email:                "admin@example.test",
		Password:             "admin-password",
	})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("CreateFirstAdmin() error = %v, want ErrUnauthorized", err)
	}
}

func TestBootstrapServiceRejectsWhenAdminExists(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	service := NewBootstrapService(store)

	_, err := service.CreateFirstAdmin(ctx, BootstrapAdminRequest{
		ManagementAuthorized: true,
		Username:             "admin",
		Email:                "admin@example.test",
		Password:             "admin-password",
	})
	if err != nil {
		t.Fatalf("CreateFirstAdmin() first error = %v", err)
	}
	_, err = service.CreateFirstAdmin(ctx, BootstrapAdminRequest{
		ManagementAuthorized: true,
		Username:             "admin2",
		Email:                "admin2@example.test",
		Password:             "admin-password",
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("CreateFirstAdmin() second error = %v, want ErrConflict", err)
	}
}
