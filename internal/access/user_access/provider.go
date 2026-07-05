package useraccess

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/usermanagement"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
)

const (
	AccessProviderTypeUserAPIKey = "user-api-key"
	DefaultProviderName          = "user-api-key"
)

type Provider struct {
	name       string
	users      usermanagement.UserStore
	keys       usermanagement.APIKeyStore
	configured map[string]struct{}
	now        func() time.Time
}

func NewProvider(users usermanagement.UserStore, keys usermanagement.APIKeyStore, configuredKeys []string) *Provider {
	configured := make(map[string]struct{}, len(configuredKeys))
	for _, key := range configuredKeys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		configured[usermanagement.ConfiguredAPIKeyFingerprintHex(key)] = struct{}{}
	}
	return &Provider{
		name:       DefaultProviderName,
		users:      users,
		keys:       keys,
		configured: configured,
		now:        time.Now,
	}
}

func Register(users usermanagement.UserStore, keys usermanagement.APIKeyStore, configuredKeys []string, enabled bool) {
	if !enabled || users == nil || keys == nil {
		sdkaccess.UnregisterProvider(AccessProviderTypeUserAPIKey)
		return
	}
	sdkaccess.RegisterProvider(AccessProviderTypeUserAPIKey, NewProvider(users, keys, configuredKeys))
}

func (p *Provider) Identifier() string {
	if p == nil || strings.TrimSpace(p.name) == "" {
		return DefaultProviderName
	}
	return p.name
}

func (p *Provider) Authenticate(ctx context.Context, r *http.Request) (*sdkaccess.Result, *sdkaccess.AuthError) {
	if p == nil || p.users == nil || p.keys == nil {
		return nil, sdkaccess.NewNotHandledError()
	}
	candidates := credentialCandidates(r)
	if len(candidates) == 0 {
		return nil, sdkaccess.NewNoCredentialsError()
	}

	for _, candidate := range candidates {
		result, authErr := p.authenticateCandidate(ctx, candidate)
		if authErr == nil {
			return result, nil
		}
		if authErr.Code == sdkaccess.AuthErrorCodeInternal {
			return nil, authErr
		}
	}
	return nil, sdkaccess.NewInvalidCredentialError()
}

func (p *Provider) authenticateCandidate(ctx context.Context, candidate credentialCandidate) (*sdkaccess.Result, *sdkaccess.AuthError) {
	fingerprint := usermanagement.ConfiguredAPIKeyFingerprint(candidate.value)
	fingerprintHex := usermanagement.EncodeAPIKeyFingerprint(fingerprint)
	if fingerprintHex == "" {
		return nil, sdkaccess.NewInvalidCredentialError()
	}
	if _, ok := p.configured[fingerprintHex]; !ok {
		return nil, sdkaccess.NewInvalidCredentialError()
	}
	keys, err := p.keys.FindAPIKeyByFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, sdkaccess.NewInternalAuthError("User API key lookup failed", err)
	}
	for _, key := range keys {
		if key.Status != usermanagement.APIKeyStatusActive {
			continue
		}
		if key.ExpiresAt != nil && !key.ExpiresAt.After(p.now().UTC()) {
			return nil, sdkaccess.NewInvalidCredentialError()
		}
		user, errUser := p.users.GetUser(ctx, key.UserID)
		if errors.Is(errUser, usermanagement.ErrNotFound) {
			return nil, sdkaccess.NewInvalidCredentialError()
		}
		if errUser != nil {
			return nil, sdkaccess.NewInternalAuthError("User API key owner lookup failed", errUser)
		}
		if user.Status != usermanagement.UserStatusApproved {
			return nil, sdkaccess.NewInvalidCredentialError()
		}
		now := p.now().UTC()
		_, _ = p.keys.UpdateAPIKey(ctx, key.ID, usermanagement.UpdateAPIKeyParams{LastUsedAt: &now})
		return &sdkaccess.Result{
			Provider:  p.Identifier(),
			Principal: string(user.ID),
			Metadata: map[string]string{
				"source":         candidate.source,
				"user_id":        string(user.ID),
				"user_role":      string(user.Role),
				"api_key_id":     string(key.ID),
				"api_key_prefix": key.Prefix,
			},
		}, nil
	}
	return nil, sdkaccess.NewInvalidCredentialError()
}

type credentialCandidate struct {
	value  string
	source string
}

func credentialCandidates(r *http.Request) []credentialCandidate {
	if r == nil {
		return nil
	}
	authHeader := r.Header.Get("Authorization")
	candidates := []credentialCandidate{
		{value: extractBearerToken(authHeader), source: "authorization"},
		{value: strings.TrimSpace(r.Header.Get("X-Goog-Api-Key")), source: "x-goog-api-key"},
		{value: strings.TrimSpace(r.Header.Get("X-Api-Key")), source: "x-api-key"},
	}
	if r.URL != nil {
		q := r.URL.Query()
		candidates = append(candidates,
			credentialCandidate{value: strings.TrimSpace(q.Get("key")), source: "query-key"},
			credentialCandidate{value: strings.TrimSpace(q.Get("auth_token")), source: "query-auth-token"},
		)
	}
	filtered := candidates[:0]
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate.value) == "" {
			continue
		}
		filtered = append(filtered, candidate)
	}
	return filtered
}

func extractBearerToken(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return header
	}
	if strings.ToLower(parts[0]) != "bearer" {
		return header
	}
	return strings.TrimSpace(parts[1])
}
