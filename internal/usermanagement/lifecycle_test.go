package usermanagement

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestUserLifecycleServiceApprovesRejectsAndAssignsRole(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	user := createTestUser(t, ctx, store)
	service := NewUserLifecycleService(store, store)

	admin, err := service.ApproveUser(ctx, user.ID, UserRoleAdmin)
	if err != nil {
		t.Fatalf("ApproveUser() error = %v", err)
	}
	if admin.Status != UserStatusApproved || admin.Role != UserRoleAdmin || admin.ApprovedAt == nil {
		t.Fatalf("approved user = %#v", admin)
	}

	ordinary, err := service.AssignRole(ctx, user.ID, UserRoleUser)
	if err != nil {
		t.Fatalf("AssignRole() error = %v", err)
	}
	if ordinary.Role != UserRoleUser {
		t.Fatalf("Role = %q, want user", ordinary.Role)
	}

	rejected, err := service.RejectUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("RejectUser() error = %v", err)
	}
	if rejected.Status != UserStatusRejected || rejected.RejectedAt == nil {
		t.Fatalf("rejected user = %#v", rejected)
	}
}

func TestUserLifecycleServiceSuspendsReactivatesAndRevokesSessions(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	user := createTestUser(t, ctx, store)
	service := NewUserLifecycleService(store, store)

	session, err := store.CreateSession(ctx, CreateSessionParams{
		UserID:    user.ID,
		TokenHash: []byte("session-hash"),
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	suspended, err := service.SuspendUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("SuspendUser() error = %v", err)
	}
	if suspended.Status != UserStatusSuspended || suspended.SuspendedAt == nil {
		t.Fatalf("suspended user = %#v", suspended)
	}
	revoked, err := store.GetSession(ctx, session.ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if revoked.Status != SessionStatusRevoked || revoked.RevokedAt == nil {
		t.Fatalf("revoked session = %#v", revoked)
	}

	reactivated, err := service.ReactivateUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ReactivateUser() error = %v", err)
	}
	if reactivated.Status != UserStatusApproved {
		t.Fatalf("Status = %q, want approved", reactivated.Status)
	}
}

func TestUserLifecycleServiceRejectsInvalidRole(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	user := createTestUser(t, ctx, store)
	service := NewUserLifecycleService(store, store)

	_, err := service.AssignRole(ctx, user.ID, UserRole("owner"))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("AssignRole() error = %v, want ErrInvalid", err)
	}
}
