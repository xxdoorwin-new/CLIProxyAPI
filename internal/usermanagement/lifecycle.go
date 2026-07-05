package usermanagement

import (
	"context"
	"time"
)

type UserLifecycleService struct {
	users    UserStore
	sessions SessionStore
}

func NewUserLifecycleService(users UserStore, sessions SessionStore) *UserLifecycleService {
	return &UserLifecycleService{users: users, sessions: sessions}
}

func (s *UserLifecycleService) ApproveUser(ctx context.Context, id UserID, role UserRole) (*User, error) {
	if role == "" {
		role = UserRoleUser
	}
	if !role.IsValid() {
		return nil, invalid("invalid user role %q", role)
	}
	now := time.Now().UTC()
	status := UserStatusApproved
	return s.updateStatus(ctx, id, UpdateUserParams{
		Status:     &status,
		Role:       &role,
		ApprovedAt: &now,
	})
}

func (s *UserLifecycleService) RejectUser(ctx context.Context, id UserID) (*User, error) {
	now := time.Now().UTC()
	status := UserStatusRejected
	user, err := s.updateStatus(ctx, id, UpdateUserParams{
		Status:     &status,
		RejectedAt: &now,
	})
	if err != nil {
		return nil, err
	}
	if s.sessions != nil {
		if err = s.sessions.RevokeSessionsForUser(ctx, id); err != nil {
			return nil, err
		}
	}
	return user, nil
}

func (s *UserLifecycleService) SuspendUser(ctx context.Context, id UserID) (*User, error) {
	now := time.Now().UTC()
	status := UserStatusSuspended
	user, err := s.updateStatus(ctx, id, UpdateUserParams{
		Status:      &status,
		SuspendedAt: &now,
	})
	if err != nil {
		return nil, err
	}
	if s.sessions != nil {
		if err = s.sessions.RevokeSessionsForUser(ctx, id); err != nil {
			return nil, err
		}
	}
	return user, nil
}

func (s *UserLifecycleService) ReactivateUser(ctx context.Context, id UserID) (*User, error) {
	now := time.Now().UTC()
	status := UserStatusApproved
	return s.updateStatus(ctx, id, UpdateUserParams{
		Status:     &status,
		ApprovedAt: &now,
	})
}

func (s *UserLifecycleService) DeleteUser(ctx context.Context, id UserID) error {
	if s == nil || s.users == nil {
		return ErrInvalid
	}
	if id == "" {
		return invalid("user id is required")
	}
	// Revoke active sessions before removing the account.
	if s.sessions != nil {
		if err := s.sessions.RevokeSessionsForUser(ctx, id); err != nil {
			return err
		}
	}
	return s.users.DeleteUser(ctx, id)
}

func (s *UserLifecycleService) AssignRole(ctx context.Context, id UserID, role UserRole) (*User, error) {
	if !role.IsValid() {
		return nil, invalid("invalid user role %q", role)
	}
	return s.updateStatus(ctx, id, UpdateUserParams{Role: &role})
}

func (s *UserLifecycleService) updateStatus(ctx context.Context, id UserID, params UpdateUserParams) (*User, error) {
	if s == nil || s.users == nil {
		return nil, ErrInvalid
	}
	if id == "" {
		return nil, invalid("user id is required")
	}
	return s.users.UpdateUser(ctx, id, params)
}
