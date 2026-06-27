package usermanagement

import (
	"context"
	"strings"
	"time"
)

type UserAPIKeyService struct {
	users UserStore
	keys  APIKeyStore
	now   func() time.Time
}

type CreateUserAPIKeyRequest struct {
	UserID    UserID
	Name      string
	ExpiresAt *time.Time
}

type UserAPIKeyCredential struct {
	APIKey    *APIKey
	Plaintext string
}

type APIKeyMetadata struct {
	ID         APIKeyID
	UserID     UserID
	Name       string
	Prefix     string
	Status     APIKeyStatus
	CreatedAt  time.Time
	UpdatedAt  time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
}

func NewUserAPIKeyService(users UserStore, keys APIKeyStore) *UserAPIKeyService {
	return &UserAPIKeyService{users: users, keys: keys, now: time.Now}
}

func (s *UserAPIKeyService) CreateKey(ctx context.Context, req CreateUserAPIKeyRequest) (*UserAPIKeyCredential, error) {
	if s == nil || s.users == nil || s.keys == nil {
		return nil, ErrInvalid
	}
	if err := s.ensureApprovedUser(ctx, req.UserID); err != nil {
		return nil, err
	}
	secret, err := GenerateUserAPIKey()
	if err != nil {
		return nil, err
	}
	key, err := s.keys.CreateAPIKey(ctx, CreateAPIKeyParams{
		UserID:    req.UserID,
		Name:      strings.TrimSpace(req.Name),
		KeyHash:   secret.Hash,
		Prefix:    secret.Prefix,
		Status:    APIKeyStatusActive,
		ExpiresAt: req.ExpiresAt,
	})
	if err != nil {
		return nil, err
	}
	return &UserAPIKeyCredential{APIKey: key, Plaintext: secret.Plaintext}, nil
}

func (s *UserAPIKeyService) RenameKey(ctx context.Context, id APIKeyID, name string) (*APIKey, error) {
	if strings.TrimSpace(name) == "" {
		return nil, invalid("key name is required")
	}
	return s.keys.UpdateAPIKey(ctx, id, UpdateAPIKeyParams{Name: &name})
}

func (s *UserAPIKeyService) DisableKey(ctx context.Context, id APIKeyID) (*APIKey, error) {
	status := APIKeyStatusDisabled
	return s.keys.UpdateAPIKey(ctx, id, UpdateAPIKeyParams{Status: &status})
}

func (s *UserAPIKeyService) RevokeKey(ctx context.Context, id APIKeyID) (*APIKey, error) {
	status := APIKeyStatusRevoked
	return s.keys.UpdateAPIKey(ctx, id, UpdateAPIKeyParams{Status: &status})
}

func (s *UserAPIKeyService) RotateKey(ctx context.Context, id APIKeyID) (*UserAPIKeyCredential, error) {
	secret, err := GenerateUserAPIKey()
	if err != nil {
		return nil, err
	}
	status := APIKeyStatusActive
	prefix := secret.Prefix
	key, err := s.keys.UpdateAPIKey(ctx, id, UpdateAPIKeyParams{
		KeyHash: secret.Hash,
		Prefix:  &prefix,
		Status:  &status,
	})
	if err != nil {
		return nil, err
	}
	return &UserAPIKeyCredential{APIKey: key, Plaintext: secret.Plaintext}, nil
}

func (s *UserAPIKeyService) ListKeyMetadataByUser(ctx context.Context, userID UserID) ([]APIKeyMetadata, error) {
	keys, err := s.keys.ListAPIKeysByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	metadata := make([]APIKeyMetadata, 0, len(keys))
	for _, key := range keys {
		metadata = append(metadata, APIKeyMetadataFromKey(key))
	}
	return metadata, nil
}

func (s *UserAPIKeyService) UpdateLastUsed(ctx context.Context, id APIKeyID, usedAt time.Time) (*APIKey, error) {
	if usedAt.IsZero() {
		usedAt = s.now().UTC()
	}
	return s.keys.UpdateAPIKey(ctx, id, UpdateAPIKeyParams{LastUsedAt: &usedAt})
}

func (s *UserAPIKeyService) ensureApprovedUser(ctx context.Context, userID UserID) error {
	if userID == "" {
		return invalid("user id is required")
	}
	user, err := s.users.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if user.Status != UserStatusApproved {
		return ErrForbidden
	}
	return nil
}

func APIKeyMetadataFromKey(key APIKey) APIKeyMetadata {
	return APIKeyMetadata{
		ID:         key.ID,
		UserID:     key.UserID,
		Name:       key.Name,
		Prefix:     key.Prefix,
		Status:     key.Status,
		CreatedAt:  key.CreatedAt,
		UpdatedAt:  key.UpdatedAt,
		ExpiresAt:  key.ExpiresAt,
		LastUsedAt: key.LastUsedAt,
	}
}
