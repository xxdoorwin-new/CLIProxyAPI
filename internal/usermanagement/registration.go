package usermanagement

import (
	"context"
	"strings"
)

type RegistrationService struct {
	users UserStore
}

type RegisterUserRequest struct {
	Username    string
	Email       string
	Password    string
	DisplayName string
	Metadata    map[string]string
}

func NewRegistrationService(users UserStore) *RegistrationService {
	return &RegistrationService{users: users}
}

func (s *RegistrationService) Register(ctx context.Context, req RegisterUserRequest) (*User, error) {
	if s == nil || s.users == nil {
		return nil, ErrInvalid
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
		Status:       UserStatusPending,
		Role:         UserRoleUser,
		Metadata:     req.Metadata,
	})
}
