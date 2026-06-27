package usermanagement

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"
)

const (
	defaultSessionTTL   = 24 * time.Hour
	sessionTokenBytes   = 32
	sessionTokenVersion = "cps_"
)

type SessionService struct {
	users    UserStore
	sessions SessionStore
	now      func() time.Time
}

type SessionCredential struct {
	Session *Session
	Token   string
}

type Principal struct {
	UserID    UserID
	SessionID SessionID
	Username  string
	Email     string
	Role      UserRole
	Status    UserStatus
}

func NewSessionService(users UserStore, sessions SessionStore) *SessionService {
	return &SessionService{
		users:    users,
		sessions: sessions,
		now:      time.Now,
	}
}

func (s *SessionService) CreateSession(ctx context.Context, userID UserID, ttl time.Duration) (*SessionCredential, error) {
	if s == nil || s.sessions == nil {
		return nil, ErrInvalid
	}
	if userID == "" {
		return nil, invalid("user id is required")
	}
	if ttl <= 0 {
		ttl = defaultSessionTTL
	}
	token, err := GenerateSessionToken()
	if err != nil {
		return nil, err
	}
	session, err := s.sessions.CreateSession(ctx, CreateSessionParams{
		UserID:    userID,
		TokenHash: HashSessionToken(token),
		ExpiresAt: s.now().UTC().Add(ttl),
	})
	if err != nil {
		return nil, err
	}
	return &SessionCredential{Session: session, Token: token}, nil
}

func (s *SessionService) ResolvePrincipal(ctx context.Context, token string) (*Principal, error) {
	if s == nil || s.users == nil || s.sessions == nil {
		return nil, ErrInvalid
	}
	if token == "" {
		return nil, ErrUnauthorized
	}
	session, err := s.sessions.FindSessionByTokenHash(ctx, HashSessionToken(token))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrUnauthorized
	}
	if err != nil {
		return nil, err
	}
	if session.Status != SessionStatusActive {
		return nil, ErrUnauthorized
	}
	now := s.now().UTC()
	if !session.ExpiresAt.After(now) {
		expired := SessionStatusExpired
		_, _ = s.sessions.UpdateSession(ctx, session.ID, UpdateSessionParams{Status: &expired})
		return nil, ErrUnauthorized
	}
	user, err := s.users.GetUser(ctx, session.UserID)
	if err != nil {
		return nil, err
	}
	if user.Status != UserStatusApproved {
		return nil, ErrForbidden
	}
	_, _ = s.sessions.UpdateSession(ctx, session.ID, UpdateSessionParams{LastSeenAt: &now})
	return &Principal{
		UserID:    user.ID,
		SessionID: session.ID,
		Username:  user.Username,
		Email:     user.Email,
		Role:      user.Role,
		Status:    user.Status,
	}, nil
}

func (s *SessionService) RevokeSession(ctx context.Context, token string) error {
	if s == nil || s.sessions == nil {
		return ErrInvalid
	}
	if token == "" {
		return ErrUnauthorized
	}
	session, err := s.sessions.FindSessionByTokenHash(ctx, HashSessionToken(token))
	if errors.Is(err, ErrNotFound) {
		return ErrUnauthorized
	}
	if err != nil {
		return err
	}
	now := s.now().UTC()
	status := SessionStatusRevoked
	_, err = s.sessions.UpdateSession(ctx, session.ID, UpdateSessionParams{
		Status:    &status,
		RevokedAt: &now,
	})
	return err
}

func (s *SessionService) DeleteExpiredSessions(ctx context.Context, before time.Time) (int64, error) {
	if s == nil || s.sessions == nil {
		return 0, ErrInvalid
	}
	return s.sessions.DeleteExpiredSessions(ctx, before)
}

func GenerateSessionToken() (string, error) {
	raw := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return sessionTokenVersion + base64.RawURLEncoding.EncodeToString(raw), nil
}

func HashSessionToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
