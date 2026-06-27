package usermanagement

import (
	"context"
	"strings"
)

type BootstrapService struct {
	users UserStore
}

type BootstrapAdminRequest struct {
	ManagementAuthorized bool
	Username             string
	Email                string
	Password             string
	DisplayName          string
	Metadata             map[string]string
}

func NewBootstrapService(users UserStore) *BootstrapService {
	return &BootstrapService{users: users}
}

func (s *BootstrapService) CreateFirstAdmin(ctx context.Context, req BootstrapAdminRequest) (*User, error) {
	if s == nil || s.users == nil {
		return nil, ErrInvalid
	}
	if !req.ManagementAuthorized {
		return nil, ErrUnauthorized
	}
	existing, err := s.users.ListUsers(ctx, UserFilter{Role: UserRoleAdmin, Limit: 1})
	if err != nil {
		return nil, err
	}
	if len(existing) > 0 {
		return nil, ErrConflict
	}
	hash, err := HashPassword(req.Password)
	if err != nil {
		return nil, err
	}
	return s.users.CreateUser(ctx, CreateUserParams{
		Username:     strings.TrimSpace(req.Username),
		Email:        strings.TrimSpace(req.Email),
		DisplayName:  strings.TrimSpace(req.DisplayName),
		PasswordHash: hash,
		Status:       UserStatusApproved,
		Role:         UserRoleAdmin,
		Metadata:     req.Metadata,
	})
}
