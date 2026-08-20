package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

type exhaustedQuotaStore struct{}

func (exhaustedQuotaStore) SetQuotaPolicy(context.Context, usermanagement.SetQuotaPolicyParams) (*usermanagement.QuotaPolicy, error) {
	return nil, nil
}

func (exhaustedQuotaStore) GetQuotaPolicy(context.Context, usermanagement.UserID) (*usermanagement.QuotaPolicy, error) {
	return &usermanagement.QuotaPolicy{
		Period:       usermanagement.QuotaPeriodMonthly,
		LimitCredits: 1,
	}, nil
}

func (exhaustedQuotaStore) UpsertQuotaRollup(context.Context, usermanagement.UpsertQuotaRollupParams) (*usermanagement.QuotaRollup, error) {
	return nil, nil
}

func (exhaustedQuotaStore) GetQuotaRollup(context.Context, usermanagement.UserID, usermanagement.QuotaPeriod, time.Time) (*usermanagement.QuotaRollup, error) {
	return &usermanagement.QuotaRollup{UsedCredits: 1}, nil
}

func TestUserQuotaMiddlewareReturnsCompatibleQuotaError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	quota := usermanagement.NewQuotaService(exhaustedQuotaStore{}, exhaustedQuotaStore{})

	for _, tc := range []struct {
		name string
		path string
	}{
		{name: "Claude", path: "/v1/messages"},
		{name: "Codex", path: "/backend-api/codex/responses"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router := gin.New()
			router.POST(tc.path,
				func(c *gin.Context) {
					c.Set("accessMetadata", map[string]string{"user_id": "quota-test-user"})
					c.Set("userRequestedModel", "test-model")
				},
				UserQuotaMiddleware(quota),
				func(c *gin.Context) {
					t.Fatal("request reached the upstream handler after quota exhaustion")
				},
			)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusTooManyRequests, rec.Body.String())
			}
			var body struct {
				Type  string `json:"type"`
				Error struct {
					Type    string `json:"type"`
					Message string `json:"message"`
					Code    string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode error response: %v; body = %s", err, rec.Body.String())
			}
			if body.Type != "error" || body.Error.Type != "rate_limit_error" || body.Error.Code != "user_quota_exhausted" || body.Error.Message != userQuotaExhaustedMessage {
				t.Fatalf("unexpected quota response: %#v", body)
			}
		})
	}
}
