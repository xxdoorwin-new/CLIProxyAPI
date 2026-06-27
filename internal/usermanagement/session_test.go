package usermanagement

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSessionServiceCreatesAndResolvesPrincipal(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	user := createTestUser(t, ctx, store)
	service := NewSessionService(store, store)

	credential, err := service.CreateSession(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	if credential.Token == "" {
		t.Fatal("CreateSession() returned empty token")
	}
	if string(credential.Session.TokenHash) == credential.Token {
		t.Fatal("session stored plaintext token")
	}

	principal, err := service.ResolvePrincipal(ctx, credential.Token)
	if err != nil {
		t.Fatalf("ResolvePrincipal() error = %v", err)
	}
	if principal.UserID != user.ID || principal.Role != UserRoleUser {
		t.Fatalf("principal = %#v, want user %q role user", principal, user.ID)
	}

	stored, err := store.GetSession(ctx, credential.Session.ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if stored.LastSeenAt == nil {
		t.Fatal("ResolvePrincipal() did not update last_seen_at")
	}
}

func TestSessionServiceRejectsExpiredAndRevokedSessions(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	user := createTestUser(t, ctx, store)
	service := NewSessionService(store, store)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }

	expired, err := service.CreateSession(ctx, user.ID, time.Minute)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	service.now = func() time.Time { return now.Add(2 * time.Minute) }
	_, err = service.ResolvePrincipal(ctx, expired.Token)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("ResolvePrincipal() expired error = %v, want ErrUnauthorized", err)
	}
	storedExpired, err := store.GetSession(ctx, expired.Session.ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if storedExpired.Status != SessionStatusExpired {
		t.Fatalf("expired session status = %q, want expired", storedExpired.Status)
	}

	service.now = func() time.Time { return now }
	revoked, err := service.CreateSession(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatalf("CreateSession() second error = %v", err)
	}
	if err = service.RevokeSession(ctx, revoked.Token); err != nil {
		t.Fatalf("RevokeSession() error = %v", err)
	}
	_, err = service.ResolvePrincipal(ctx, revoked.Token)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("ResolvePrincipal() revoked error = %v, want ErrUnauthorized", err)
	}
}

func TestSessionServiceRejectsInactiveUsers(t *testing.T) {
	ctx := context.Background()
	store := newTestSQLiteStore(t)
	user, err := store.CreateUser(ctx, CreateUserParams{
		Username:     "pending",
		Email:        "pending@example.test",
		PasswordHash: []byte("hash"),
		Status:       UserStatusPending,
		Role:         UserRoleUser,
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	service := NewSessionService(store, store)

	credential, err := service.CreateSession(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	_, err = service.ResolvePrincipal(ctx, credential.Token)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("ResolvePrincipal() inactive error = %v, want ErrForbidden", err)
	}
}
