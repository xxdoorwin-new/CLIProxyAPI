package usermanagement

import (
	"context"
	"strings"
	"time"
)

type UserAPIKeyService struct {
	users      UserStore
	keys       APIKeyStore
	configured configuredAPIKeyIndex
	now        func() time.Time
}

type BindUserAPIKeyRequest struct {
	UserID                   UserID
	Name                     string
	ConfiguredKeyFingerprint string
	ExpiresAt                *time.Time
}

type APIKeyMetadata struct {
	ID                       APIKeyID
	UserID                   UserID
	Name                     string
	Prefix                   string
	Status                   APIKeyStatus
	ConfiguredKeyFingerprint string
	ConfiguredKeyPresent     bool
	CreatedAt                time.Time
	UpdatedAt                time.Time
	ExpiresAt                *time.Time
	LastUsedAt               *time.Time
}

type ConfiguredAPIKeySelection struct {
	Fingerprint       string
	Prefix            string
	Assigned          bool
	AssignedUserID    UserID
	AssignedKeyID     APIKeyID
	AssignedKeyName   string
	AssignedStatus    APIKeyStatus
	LastUsedAt        *time.Time
	ConfiguredPresent bool
}

func NewUserAPIKeyService(users UserStore, keys APIKeyStore, configuredKeys ...[]string) *UserAPIKeyService {
	var configured []string
	if len(configuredKeys) > 0 {
		configured = configuredKeys[0]
	}
	return &UserAPIKeyService{users: users, keys: keys, configured: newConfiguredAPIKeyIndex(configured), now: time.Now}
}

func (s *UserAPIKeyService) BindKey(ctx context.Context, req BindUserAPIKeyRequest) (*APIKey, error) {
	if s == nil || s.users == nil || s.keys == nil {
		return nil, ErrInvalid
	}
	if err := s.ensureApprovedUser(ctx, req.UserID); err != nil {
		return nil, err
	}
	ref, ok := s.configured.byFingerprint[strings.TrimSpace(req.ConfiguredKeyFingerprint)]
	if !ok {
		return nil, invalid("configured api key is not available")
	}
	fingerprint, err := DecodeAPIKeyFingerprint(ref.Fingerprint)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = ref.Prefix
	}
	key, err := s.keys.CreateAPIKey(ctx, CreateAPIKeyParams{
		UserID:    req.UserID,
		Name:      name,
		KeyHash:   fingerprint,
		Prefix:    ref.Prefix,
		Status:    APIKeyStatusActive,
		ExpiresAt: req.ExpiresAt,
	})
	if err != nil {
		return nil, err
	}
	return key, nil
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

func (s *UserAPIKeyService) EnableKey(ctx context.Context, id APIKeyID) (*APIKey, error) {
	status := APIKeyStatusActive
	return s.keys.UpdateAPIKey(ctx, id, UpdateAPIKeyParams{Status: &status})
}

func (s *UserAPIKeyService) UnbindKey(ctx context.Context, id APIKeyID) error {
	return s.keys.DeleteAPIKey(ctx, id)
}

func (s *UserAPIKeyService) ListKeyMetadataByUser(ctx context.Context, userID UserID) ([]APIKeyMetadata, error) {
	keys, err := s.keys.ListAPIKeysByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	metadata := make([]APIKeyMetadata, 0, len(keys))
	for _, key := range keys {
		metadata = append(metadata, s.APIKeyMetadataFromKey(key))
	}
	return metadata, nil
}

func (s *UserAPIKeyService) ListConfiguredAPIKeys(ctx context.Context) ([]ConfiguredAPIKeySelection, error) {
	if s == nil || s.keys == nil {
		return nil, ErrInvalid
	}
	selections := make([]ConfiguredAPIKeySelection, 0, len(s.configured.ordered))
	for _, ref := range s.configured.ordered {
		fingerprint, err := DecodeAPIKeyFingerprint(ref.Fingerprint)
		if err != nil {
			return nil, err
		}
		bindings, err := s.keys.FindAPIKeyByFingerprint(ctx, fingerprint)
		if err != nil {
			return nil, err
		}
		selection := ConfiguredAPIKeySelection{
			Fingerprint:       ref.Fingerprint,
			Prefix:            ref.Prefix,
			ConfiguredPresent: true,
		}
		if len(bindings) > 0 {
			binding := bindings[0]
			selection.Assigned = true
			selection.AssignedUserID = binding.UserID
			selection.AssignedKeyID = binding.ID
			selection.AssignedKeyName = binding.Name
			selection.AssignedStatus = binding.Status
			selection.LastUsedAt = binding.LastUsedAt
		}
		selections = append(selections, selection)
	}
	return selections, nil
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

func (s *UserAPIKeyService) APIKeyMetadataFromKey(key APIKey) APIKeyMetadata {
	fingerprint := EncodeAPIKeyFingerprint(key.KeyHash)
	_, present := s.configured.byFingerprint[fingerprint]
	return APIKeyMetadata{
		ID:                       key.ID,
		UserID:                   key.UserID,
		Name:                     key.Name,
		Prefix:                   key.Prefix,
		Status:                   key.Status,
		ConfiguredKeyFingerprint: fingerprint,
		ConfiguredKeyPresent:     present,
		CreatedAt:                key.CreatedAt,
		UpdatedAt:                key.UpdatedAt,
		ExpiresAt:                key.ExpiresAt,
		LastUsedAt:               key.LastUsedAt,
	}
}

type configuredAPIKeyIndex struct {
	ordered       []ConfiguredAPIKeyRef
	byFingerprint map[string]ConfiguredAPIKeyRef
}

func newConfiguredAPIKeyIndex(keys []string) configuredAPIKeyIndex {
	index := configuredAPIKeyIndex{byFingerprint: map[string]ConfiguredAPIKeyRef{}}
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		fingerprint := ConfiguredAPIKeyFingerprintHex(key)
		if _, ok := seen[fingerprint]; ok {
			continue
		}
		seen[fingerprint] = struct{}{}
		ref := ConfiguredAPIKeyRef{
			Fingerprint: fingerprint,
			Prefix:      DisplayPrefixForUserAPIKey(key),
		}
		index.ordered = append(index.ordered, ref)
		index.byFingerprint[fingerprint] = ref
	}
	return index
}
