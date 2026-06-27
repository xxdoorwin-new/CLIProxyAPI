package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/usermanagement"
)

type userAPIKeyResponse struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	Plaintext  string     `json:"plaintext,omitempty"`
}

func (s *Server) handleAdminListUserAPIKeys(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	keys, err := usermanagement.NewUserAPIKeyService(store, store).ListKeyMetadataByUser(c.Request.Context(), usermanagement.UserID(c.Param("id")))
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	out := make([]userAPIKeyResponse, 0, len(keys))
	for i := range keys {
		out = append(out, toAPIKeyMetadataResponse(keys[i], ""))
	}
	c.JSON(http.StatusOK, gin.H{"api_keys": out})
}

func (s *Server) handleAdminCreateUserAPIKey(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	var body struct {
		Name      string     `json:"name"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	credential, err := usermanagement.NewUserAPIKeyService(store, store).CreateKey(c.Request.Context(), usermanagement.CreateUserAPIKeyRequest{
		UserID:    usermanagement.UserID(c.Param("id")),
		Name:      body.Name,
		ExpiresAt: body.ExpiresAt,
	})
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"api_key": toAPIKeyResponse(credential.APIKey, credential.Plaintext)})
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
	key, err := usermanagement.NewUserAPIKeyService(store, store).RenameKey(c.Request.Context(), usermanagement.APIKeyID(c.Param("key_id")), body.Name)
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"api_key": toAPIKeyResponse(key, "")})
}

func (s *Server) handleAdminDisableUserAPIKey(c *gin.Context) {
	s.handleAdminUserAPIKeyAction(c, func(service *usermanagement.UserAPIKeyService, keyID usermanagement.APIKeyID) (*usermanagement.UserAPIKeyCredential, *usermanagement.APIKey, error) {
		key, err := service.DisableKey(c.Request.Context(), keyID)
		return nil, key, err
	})
}

func (s *Server) handleAdminRevokeUserAPIKey(c *gin.Context) {
	s.handleAdminUserAPIKeyAction(c, func(service *usermanagement.UserAPIKeyService, keyID usermanagement.APIKeyID) (*usermanagement.UserAPIKeyCredential, *usermanagement.APIKey, error) {
		key, err := service.RevokeKey(c.Request.Context(), keyID)
		return nil, key, err
	})
}

func (s *Server) handleAdminRotateUserAPIKey(c *gin.Context) {
	s.handleAdminUserAPIKeyAction(c, func(service *usermanagement.UserAPIKeyService, keyID usermanagement.APIKeyID) (*usermanagement.UserAPIKeyCredential, *usermanagement.APIKey, error) {
		credential, err := service.RotateKey(c.Request.Context(), keyID)
		if credential == nil {
			return nil, nil, err
		}
		return credential, credential.APIKey, err
	})
}

func (s *Server) handleAdminUserAPIKeyAction(c *gin.Context, action func(*usermanagement.UserAPIKeyService, usermanagement.APIKeyID) (*usermanagement.UserAPIKeyCredential, *usermanagement.APIKey, error)) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	if !s.ensureUserAPIKeyOwner(c, store) {
		return
	}
	credential, key, err := action(usermanagement.NewUserAPIKeyService(store, store), usermanagement.APIKeyID(c.Param("key_id")))
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	plaintext := ""
	if credential != nil {
		plaintext = credential.Plaintext
	}
	c.JSON(http.StatusOK, gin.H{"api_key": toAPIKeyResponse(key, plaintext)})
}

func (s *Server) ensureUserAPIKeyOwner(c *gin.Context, store *usermanagement.SQLiteStore) bool {
	key, err := store.GetAPIKey(c.Request.Context(), usermanagement.APIKeyID(c.Param("key_id")))
	if err != nil {
		writeUserManagementError(c, err)
		return false
	}
	if key.UserID != usermanagement.UserID(c.Param("id")) {
		writeUserManagementError(c, usermanagement.ErrNotFound)
		return false
	}
	return true
}

func toAPIKeyResponse(key *usermanagement.APIKey, plaintext string) userAPIKeyResponse {
	if key == nil {
		return userAPIKeyResponse{}
	}
	return userAPIKeyResponse{
		ID:         string(key.ID),
		UserID:     string(key.UserID),
		Name:       key.Name,
		Prefix:     key.Prefix,
		Status:     string(key.Status),
		CreatedAt:  key.CreatedAt,
		UpdatedAt:  key.UpdatedAt,
		ExpiresAt:  key.ExpiresAt,
		LastUsedAt: key.LastUsedAt,
		Plaintext:  strings.TrimSpace(plaintext),
	}
}

func toAPIKeyMetadataResponse(key usermanagement.APIKeyMetadata, plaintext string) userAPIKeyResponse {
	return userAPIKeyResponse{
		ID:         string(key.ID),
		UserID:     string(key.UserID),
		Name:       key.Name,
		Prefix:     key.Prefix,
		Status:     string(key.Status),
		CreatedAt:  key.CreatedAt,
		UpdatedAt:  key.UpdatedAt,
		ExpiresAt:  key.ExpiresAt,
		LastUsedAt: key.LastUsedAt,
		Plaintext:  strings.TrimSpace(plaintext),
	}
}
