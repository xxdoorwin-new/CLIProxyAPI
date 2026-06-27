package usermanagement

import (
	"context"
	"errors"
	"strings"
	"time"
)

type LoginService struct {
	users    UserStore
	sessions *SessionService
}

type LoginRequest struct {
	Identity string
	Password string
	TTL      time.Duration
}

func NewLoginService(users UserStore, sessions SessionStore) *LoginService {
	return &LoginService{
		users:    users,
		sessions: NewSessionService(users, sessions),
	}
}

func (s *LoginService) Login(ctx context.Context, req LoginRequest) (*SessionCredential, error) {
	if s == nil || s.users == nil || s.sessions == nil {
		return nil, ErrInvalid
	}
	identity := strings.TrimSpace(req.Identity)
	if identity == "" {
		return nil, ErrUnauthorized
	}
	user, err := s.users.FindUserByIdentity(ctx, identity)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrUnauthorized
	}
	if err != nil {
		return nil, err
	}
	if !VerifyPassword(req.Password, user.PasswordHash) {
		return nil, ErrUnauthorized
	}
	if user.Status != UserStatusApproved {
		return nil, ErrForbidden
	}
	return s.sessions.CreateSession(ctx, user.ID, req.TTL)
}
