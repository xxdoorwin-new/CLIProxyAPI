package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/usermanagement"
)

func TestUserModelPolicyMiddlewareAllowsPermittedModelAndPreservesBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := newAPITestUserStore(t)
	user := createAPITestUser(t, store)
	if _, err := usermanagement.NewModelPolicyService(store).SetUserModels(t.Context(), user.ID, false, []string{"gpt-5"}); err != nil {
		t.Fatalf("SetUserModels() error = %v", err)
	}

	router := gin.New()
	router.POST("/v1/chat/completions", userMetadataMiddleware(user.ID, ""), UserModelPolicyMiddleware(usermanagement.NewModelPolicyService(store)), func(c *gin.Context) {
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		c.String(http.StatusOK, string(body))
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-5","messages":[]}`))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != `{"model":"gpt-5","messages":[]}` {
		t.Fatalf("body = %q, want original request body", rec.Body.String())
	}
}

func TestUserModelPolicyMiddlewareRejectsDisallowedModel(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := newAPITestUserStore(t)
	user := createAPITestUser(t, store)
	if _, err := usermanagement.NewModelPolicyService(store).SetUserModels(t.Context(), user.ID, false, []string{"gpt-5"}); err != nil {
		t.Fatalf("SetUserModels() error = %v", err)
	}

	router := gin.New()
	router.POST("/v1/chat/completions", userMetadataMiddleware(user.ID, ""), UserModelPolicyMiddleware(usermanagement.NewModelPolicyService(store)), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4"}`))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
}

func TestUserModelPolicyMiddlewareIgnoresFlatKeyRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := newAPITestUserStore(t)

	router := gin.New()
	router.POST("/v1/chat/completions", UserModelPolicyMiddleware(usermanagement.NewModelPolicyService(store)), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4"}`))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
}

func userMetadataMiddleware(userID usermanagement.UserID, keyID usermanagement.APIKeyID) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("accessMetadata", map[string]string{
			"user_id":    string(userID),
			"api_key_id": string(keyID),
		})
		c.Next()
	}
}

func newAPITestUserStore(t *testing.T) *usermanagement.SQLiteStore {
	t.Helper()
	store, err := usermanagement.OpenSQLiteStore(t.Context(), usermanagement.SQLiteConfig{Path: t.TempDir() + "/users.db"})
	if err != nil {
		t.Fatalf("OpenSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})
	return store
}

func createAPITestUser(t *testing.T, store *usermanagement.SQLiteStore) *usermanagement.User {
	t.Helper()
	hash, err := usermanagement.HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	user, err := store.CreateUser(t.Context(), usermanagement.CreateUserParams{
		Username:     "api-user",
		Email:        "api-user@example.test",
		PasswordHash: hash,
		Status:       usermanagement.UserStatusApproved,
		Role:         usermanagement.UserRoleUser,
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	return user
}
