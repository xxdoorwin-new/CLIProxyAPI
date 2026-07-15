package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/usermanagement"
)

type userAPIKeyResponse struct {
	ID                       string     `json:"id"`
	UserID                   string     `json:"user_id"`
	Name                     string     `json:"name"`
	Prefix                   string     `json:"prefix"`
	APIKey                   string     `json:"api_key,omitempty"`
	Status                   string     `json:"status"`
	ConfiguredKeyFingerprint string     `json:"configured_key_fingerprint"`
	ConfiguredKeyPresent     bool       `json:"configured_key_present"`
	CreatedAt                time.Time  `json:"created_at"`
	UpdatedAt                time.Time  `json:"updated_at"`
	ExpiresAt                *time.Time `json:"expires_at,omitempty"`
	LastUsedAt               *time.Time `json:"last_used_at,omitempty"`
}

type configuredAPIKeyResponse struct {
	Fingerprint         string     `json:"fingerprint"`
	Prefix              string     `json:"prefix"`
	State               string     `json:"state"`
	Assigned            bool       `json:"assigned"`
	AssignedUserID      string     `json:"assigned_user_id,omitempty"`
	AssignedUsername    string     `json:"assigned_username,omitempty"`
	AssignedDisplayName string     `json:"assigned_display_name,omitempty"`
	AssignedKeyID       string     `json:"assigned_key_id,omitempty"`
	AssignedKeyName     string     `json:"assigned_key_name,omitempty"`
	AssignedStatus      string     `json:"assigned_status,omitempty"`
	SelectedUserID      string     `json:"selected_user_id,omitempty"`
	LastUsedAt          *time.Time `json:"last_used_at,omitempty"`
	ConfiguredPresent   bool       `json:"configured_present"`
}

func (s *Server) handleAdminListConfiguredAPIKeys(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	selections, err := usermanagement.NewUserAPIKeyService(store, store, s.configuredAPIKeys()).ListConfiguredAPIKeysForUser(c.Request.Context(), usermanagement.UserID(c.Query("user_id")))
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	out := make([]configuredAPIKeyResponse, 0, len(selections))
	for i := range selections {
		out = append(out, toConfiguredAPIKeyResponse(selections[i]))
	}
	c.JSON(http.StatusOK, gin.H{"api_keys": out})
}

func (s *Server) handleAdminListUserAPIKeys(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	keys, err := usermanagement.NewUserAPIKeyService(store, store, s.configuredAPIKeys()).ListKeyMetadataByUser(c.Request.Context(), usermanagement.UserID(c.Param("id")))
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	out := make([]userAPIKeyResponse, 0, len(keys))
	for i := range keys {
		out = append(out, toAPIKeyMetadataResponse(keys[i]))
	}
	c.JSON(http.StatusOK, gin.H{"api_keys": out})
}

func (s *Server) handleAdminBindUserAPIKey(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	var body struct {
		Name                     string     `json:"name"`
		ConfiguredKeyFingerprint string     `json:"configured_key_fingerprint"`
		ExpiresAt                *time.Time `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	key, err := usermanagement.NewUserAPIKeyService(store, store, s.configuredAPIKeys()).BindKey(c.Request.Context(), usermanagement.BindUserAPIKeyRequest{
		UserID:                   usermanagement.UserID(c.Param("id")),
		Name:                     body.Name,
		ConfiguredKeyFingerprint: body.ConfiguredKeyFingerprint,
		ExpiresAt:                body.ExpiresAt,
	})
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	metadata := usermanagement.NewUserAPIKeyService(store, store, s.configuredAPIKeys()).APIKeyMetadataFromKey(*key)
	c.JSON(http.StatusOK, gin.H{"api_key": toAPIKeyMetadataResponse(metadata)})
}

func (s *Server) handleAdminRenameUserAPIKey(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	if !s.ensureUserAPIKeyOwner(c, store) {
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	key, err := usermanagement.NewUserAPIKeyService(store, store, s.configuredAPIKeys()).RenameKey(c.Request.Context(), usermanagement.APIKeyID(c.Param("key_id")), body.Name)
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"api_key": toAPIKeyResponse(key)})
}

func (s *Server) handleAdminDisableUserAPIKey(c *gin.Context) {
	s.handleAdminUserAPIKeyAction(c, func(service *usermanagement.UserAPIKeyService, keyID usermanagement.APIKeyID) (*usermanagement.APIKey, error) {
		return service.DisableKey(c.Request.Context(), keyID)
	})
}

func (s *Server) handleAdminEnableUserAPIKey(c *gin.Context) {
	s.handleAdminUserAPIKeyAction(c, func(service *usermanagement.UserAPIKeyService, keyID usermanagement.APIKeyID) (*usermanagement.APIKey, error) {
		return service.EnableKey(c.Request.Context(), keyID)
	})
}

func (s *Server) handleAdminUnbindUserAPIKey(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	if !s.ensureUserAPIKeyOwner(c, store) {
		return
	}
	service := usermanagement.NewUserAPIKeyService(store, store, s.configuredAPIKeys())
	if err := service.UnbindKey(c.Request.Context(), usermanagement.APIKeyID(c.Param("key_id"))); err != nil {
		writeUserManagementError(c, err)
		return
	}
	key, err := store.GetAPIKey(c.Request.Context(), usermanagement.APIKeyID(c.Param("key_id")))
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"api_key": toAPIKeyMetadataResponse(service.APIKeyMetadataFromKey(*key))})
}

func (s *Server) handleAdminUserAPIKeyAction(c *gin.Context, action func(*usermanagement.UserAPIKeyService, usermanagement.APIKeyID) (*usermanagement.APIKey, error)) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	if !s.ensureUserAPIKeyOwner(c, store) {
		return
	}
	key, err := action(usermanagement.NewUserAPIKeyService(store, store, s.configuredAPIKeys()), usermanagement.APIKeyID(c.Param("key_id")))
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"api_key": toAPIKeyResponse(key)})
}

func (s *Server) ensureUserAPIKeyOwner(c *gin.Context, store *usermanagement.SQLiteStore) bool {
	key, err := store.GetAPIKey(c.Request.Context(), usermanagement.APIKeyID(c.Param("key_id")))
	if err != nil {
		writeUserManagementError(c, err)
		return false
	}
	if key.UserID != usermanagement.UserID(c.Param("id")) || key.Status == usermanagement.APIKeyStatusRevoked {
		writeUserManagementError(c, usermanagement.ErrNotFound)
		return false
	}
	return true
}

func (s *Server) configuredAPIKeys() []string {
	if s == nil || s.cfg == nil {
		return nil
	}
	return append([]string(nil), s.cfg.APIKeys...)
}

func (s *Server) configuredAPIKeyByFingerprint(fingerprint string) string {
	for _, key := range s.configuredAPIKeys() {
		if usermanagement.ConfiguredAPIKeyFingerprintHex(key) == fingerprint {
			return key
		}
	}
	return ""
}

func toAPIKeyResponse(key *usermanagement.APIKey) userAPIKeyResponse {
	if key == nil {
		return userAPIKeyResponse{}
	}
	return userAPIKeyResponse{
		ID:                       string(key.ID),
		UserID:                   string(key.UserID),
		Name:                     key.Name,
		Prefix:                   key.Prefix,
		Status:                   string(key.Status),
		ConfiguredKeyFingerprint: usermanagement.EncodeAPIKeyFingerprint(key.KeyHash),
		ConfiguredKeyPresent:     false,
		CreatedAt:                key.CreatedAt,
		UpdatedAt:                key.UpdatedAt,
		ExpiresAt:                key.ExpiresAt,
		LastUsedAt:               key.LastUsedAt,
	}
}

func toAPIKeyMetadataResponse(key usermanagement.APIKeyMetadata) userAPIKeyResponse {
	return userAPIKeyResponse{
		ID:                       string(key.ID),
		UserID:                   string(key.UserID),
		Name:                     key.Name,
		Prefix:                   key.Prefix,
		Status:                   string(key.Status),
		ConfiguredKeyFingerprint: key.ConfiguredKeyFingerprint,
		ConfiguredKeyPresent:     key.ConfiguredKeyPresent,
		CreatedAt:                key.CreatedAt,
		UpdatedAt:                key.UpdatedAt,
		ExpiresAt:                key.ExpiresAt,
		LastUsedAt:               key.LastUsedAt,
	}
}

func toConfiguredAPIKeyResponse(selection usermanagement.ConfiguredAPIKeySelection) configuredAPIKeyResponse {
	return configuredAPIKeyResponse{
		Fingerprint:         selection.Fingerprint,
		Prefix:              selection.Prefix,
		State:               selection.State,
		Assigned:            selection.Assigned,
		AssignedUserID:      string(selection.AssignedUserID),
		AssignedUsername:    selection.AssignedUsername,
		AssignedDisplayName: selection.AssignedDisplayName,
		AssignedKeyID:       string(selection.AssignedKeyID),
		AssignedKeyName:     selection.AssignedKeyName,
		AssignedStatus:      string(selection.AssignedStatus),
		SelectedUserID:      string(selection.SelectedUserID),
		LastUsedAt:          selection.LastUsedAt,
		ConfiguredPresent:   selection.ConfiguredPresent,
	}
}
