package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/usermanagement"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
)

func TestUserSessionRoutesRegisterLoginSessionAndLogout(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	cfg := &config.Config{}
	cfg.UserManagement.Enabled = true
	cfg.UserManagement.Registration.Enabled = true
	cfg.UserManagement.Storage.Driver = config.DefaultUserManagementStorage
	cfg.UserManagement.Storage.Path = filepath.Join(t.TempDir(), "users.db")
	cfg.UserManagement.Sessions.TTL = "1h"

	server := NewServer(cfg, nil, sdkaccess.NewManager(), configPath)
	t.Cleanup(func() {
		_ = server.Stop(context.Background())
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v0/user/register", strings.NewReader(`{
		"username":"alice",
		"email":"alice@example.test",
		"password":"secret-password",
		"display_name":"Alice"
	}`))
	server.engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v0/user/login", strings.NewReader(`{
		"identity":"alice",
		"password":"secret-password"
	}`))
	server.engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("pending login status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}

	user, err := server.userStore.FindUserByIdentity(t.Context(), "alice")
	if err != nil {
		t.Fatalf("FindUserByIdentity() error = %v", err)
	}
	if _, err = usermanagement.NewUserLifecycleService(server.userStore, server.userStore).ApproveUser(t.Context(), user.ID, usermanagement.UserRoleUser); err != nil {
		t.Fatalf("ApproveUser() error = %v", err)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v0/user/login", strings.NewReader(`{
		"identity":"alice@example.test",
		"password":"secret-password"
	}`))
	server.engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approved login status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	var loginPayload struct {
		Session struct {
			Token string `json:"token"`
			User  struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			} `json:"user"`
		} `json:"session"`
	}
	if err = json.Unmarshal(rec.Body.Bytes(), &loginPayload); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if loginPayload.Session.Token == "" || loginPayload.Session.User.ID != string(user.ID) || loginPayload.Session.User.Status != "approved" {
		t.Fatalf("login payload = %#v", loginPayload)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v0/user/session", nil)
	req.Header.Set("Authorization", "Bearer "+loginPayload.Session.Token)
	server.engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("session status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v0/user/logout", nil)
	req.Header.Set("X-User-Session", loginPayload.Session.Token)
	server.engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v0/user/session", nil)
	req.Header.Set("Authorization", "Bearer "+loginPayload.Session.Token)
	server.engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session status = %d, want 401; body = %s", rec.Code, rec.Body.String())
	}
}

func TestUserPortalRoutesReturnSelfServiceData(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	cfg := &config.Config{}
	cfg.UserManagement.Enabled = true
	cfg.UserManagement.Storage.Driver = config.DefaultUserManagementStorage
	cfg.UserManagement.Storage.Path = filepath.Join(t.TempDir(), "users.db")

	server := NewServer(cfg, nil, sdkaccess.NewManager(), configPath)
	t.Cleanup(func() {
		_ = server.Stop(context.Background())
	})
	user := createServerPolicyUser(t, server.userStore)
	credential, err := usermanagement.NewUserAPIKeyService(server.userStore, server.userStore).CreateKey(t.Context(), usermanagement.CreateUserAPIKeyRequest{
		UserID: user.ID,
		Name:   "default",
	})
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}
	if _, err = usermanagement.NewModelPolicyService(server.userStore).SetUserModels(t.Context(), user.ID, false, []string{"gpt-5"}); err != nil {
		t.Fatalf("SetUserModels() error = %v", err)
	}
	if _, err = server.userStore.SetQuotaPolicy(t.Context(), usermanagement.SetQuotaPolicyParams{
		UserID:       user.ID,
		Period:       usermanagement.QuotaPeriodMonthly,
		LimitCredits: 20,
	}); err != nil {
		t.Fatalf("SetQuotaPolicy() error = %v", err)
	}
	if _, err = usermanagement.NewUsageRecorder(server.userStore, usermanagement.UsageRecorderConfig{MissingUsageCredits: 4}).RecordUsage(t.Context(), usermanagement.RecordUsageParams{
		UserID:      user.ID,
		APIKeyID:    credential.APIKey.ID,
		RequestID:   "req-portal",
		Provider:    "openai",
		Model:       "gpt-5",
		RequestedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("RecordUsage() error = %v", err)
	}
	session, err := usermanagement.NewSessionService(server.userStore, server.userStore).CreateSession(t.Context(), user.ID, time.Hour)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	authGet := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+session.Token)
		server.engine.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want 200; body = %s", path, rec.Code, rec.Body.String())
		}
		return rec
	}

	var profile struct {
		User userResponse `json:"user"`
	}
	if err = json.Unmarshal(authGet("/v0/user/profile").Body.Bytes(), &profile); err != nil {
		t.Fatalf("decode profile: %v", err)
	}
	if profile.User.ID != string(user.ID) {
		t.Fatalf("profile = %#v", profile.User)
	}

	var keys struct {
		APIKeys []userAPIKeyResponse `json:"api_keys"`
	}
	if err = json.Unmarshal(authGet("/v0/user/api-keys").Body.Bytes(), &keys); err != nil {
		t.Fatalf("decode api keys: %v", err)
	}
	if len(keys.APIKeys) != 1 || keys.APIKeys[0].Plaintext != "" {
		t.Fatalf("api keys = %#v", keys.APIKeys)
	}

	var models struct {
		ModelPolicy modelPolicyResponse `json:"model_policy"`
	}
	if err = json.Unmarshal(authGet("/v0/user/models").Body.Bytes(), &models); err != nil {
		t.Fatalf("decode models: %v", err)
	}
	if len(models.ModelPolicy.Models) != 1 || models.ModelPolicy.Models[0] != "gpt-5" {
		t.Fatalf("models = %#v", models.ModelPolicy)
	}

	var quota struct {
		Quota quotaSummaryResponse `json:"quota"`
	}
	if err = json.Unmarshal(authGet("/v0/user/quota").Body.Bytes(), &quota); err != nil {
		t.Fatalf("decode quota: %v", err)
	}
	if quota.Quota.UsedCredits != 4 || quota.Quota.RemainingCredits != 16 {
		t.Fatalf("quota = %#v", quota.Quota)
	}

	var usage struct {
		Usage usageSummaryResponse `json:"usage"`
	}
	if err = json.Unmarshal(authGet("/v0/user/usage").Body.Bytes(), &usage); err != nil {
		t.Fatalf("decode usage: %v", err)
	}
	if len(usage.Usage.RecentUsage) != 1 || usage.Usage.RecentUsage[0].RequestID != "req-portal" {
		t.Fatalf("usage = %#v", usage.Usage)
	}
}

func TestAdminUserLifecycleRoutes(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "test-management-key")
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	cfg := &config.Config{}
	cfg.UserManagement.Enabled = true
	cfg.UserManagement.Registration.Enabled = true
	cfg.UserManagement.Storage.Driver = config.DefaultUserManagementStorage
	cfg.UserManagement.Storage.Path = filepath.Join(t.TempDir(), "users.db")

	server := NewServer(cfg, nil, sdkaccess.NewManager(), configPath)
	t.Cleanup(func() {
		_ = server.Stop(context.Background())
	})

	_, err := usermanagement.NewRegistrationService(server.userStore).Register(t.Context(), usermanagement.RegisterUserRequest{
		Username: "bob",
		Email:    "bob@example.test",
		Password: "secret-password",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	user, err := server.userStore.FindUserByIdentity(t.Context(), "bob")
	if err != nil {
		t.Fatalf("FindUserByIdentity() error = %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v0/management/users/pending", nil)
	req.Header.Set("Authorization", "Bearer test-management-key")
	server.engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("pending status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	var listPayload struct {
		Users []userResponse `json:"users"`
	}
	if err = json.Unmarshal(rec.Body.Bytes(), &listPayload); err != nil {
		t.Fatalf("decode pending response: %v", err)
	}
	if len(listPayload.Users) != 1 || listPayload.Users[0].ID != string(user.ID) {
		t.Fatalf("pending users = %#v", listPayload.Users)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v0/management/users/"+string(user.ID)+"/approve", strings.NewReader(`{"role":"admin"}`))
	req.Header.Set("Authorization", "Bearer test-management-key")
	server.engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	var userPayload struct {
		User userResponse `json:"user"`
	}
	if err = json.Unmarshal(rec.Body.Bytes(), &userPayload); err != nil {
		t.Fatalf("decode approve response: %v", err)
	}
	if userPayload.User.Status != "approved" || userPayload.User.Role != "admin" {
		t.Fatalf("approved user = %#v", userPayload.User)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v0/management/users/"+string(user.ID), nil)
	req.Header.Set("X-Management-Key", "test-management-key")
	server.engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("detail status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v0/management/users/"+string(user.ID)+"/suspend", nil)
	req.Header.Set("Authorization", "Bearer test-management-key")
	server.engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("suspend status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v0/management/users/"+string(user.ID)+"/reactivate", nil)
	req.Header.Set("Authorization", "Bearer test-management-key")
	server.engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("reactivate status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
}

func TestAdminUserAPIKeyLifecycleRoutes(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "test-management-key")
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	cfg := &config.Config{}
	cfg.UserManagement.Enabled = true
	cfg.UserManagement.Storage.Driver = config.DefaultUserManagementStorage
	cfg.UserManagement.Storage.Path = filepath.Join(t.TempDir(), "users.db")

	server := NewServer(cfg, nil, sdkaccess.NewManager(), configPath)
	t.Cleanup(func() {
		_ = server.Stop(context.Background())
	})
	user := createServerPolicyUser(t, server.userStore)

	authRequest := func(method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer test-management-key")
		server.engine.ServeHTTP(rec, req)
		return rec
	}

	rec := authRequest(http.MethodPost, "/v0/management/users/"+string(user.ID)+"/api-keys", `{"name":"default"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create key status = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}
	var keyPayload struct {
		APIKey userAPIKeyResponse `json:"api_key"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &keyPayload); err != nil {
		t.Fatalf("decode create key response: %v", err)
	}
	if keyPayload.APIKey.ID == "" || keyPayload.APIKey.Plaintext == "" || keyPayload.APIKey.Prefix == "" {
		t.Fatalf("created key = %#v", keyPayload.APIKey)
	}

	rec = authRequest(http.MethodGet, "/v0/management/users/"+string(user.ID)+"/api-keys", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list key status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	var listPayload struct {
		APIKeys []userAPIKeyResponse `json:"api_keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listPayload); err != nil {
		t.Fatalf("decode list key response: %v", err)
	}
	if len(listPayload.APIKeys) != 1 || listPayload.APIKeys[0].Plaintext != "" {
		t.Fatalf("listed keys = %#v", listPayload.APIKeys)
	}

	keyPath := "/v0/management/users/" + string(user.ID) + "/api-keys/" + keyPayload.APIKey.ID
	rec = authRequest(http.MethodPatch, keyPath, `{"name":"renamed"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("rename key status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}

	rec = authRequest(http.MethodPost, keyPath+"/disable", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("disable key status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &keyPayload); err != nil {
		t.Fatalf("decode disable key response: %v", err)
	}
	if keyPayload.APIKey.Status != "disabled" {
		t.Fatalf("disabled key = %#v", keyPayload.APIKey)
	}

	rec = authRequest(http.MethodPost, keyPath+"/rotate", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate key status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &keyPayload); err != nil {
		t.Fatalf("decode rotate key response: %v", err)
	}
	if keyPayload.APIKey.Status != "active" || keyPayload.APIKey.Plaintext == "" {
		t.Fatalf("rotated key = %#v", keyPayload.APIKey)
	}

	rec = authRequest(http.MethodPost, keyPath+"/revoke", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke key status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	keyPayload = struct {
		APIKey userAPIKeyResponse `json:"api_key"`
	}{}
	if err := json.Unmarshal(rec.Body.Bytes(), &keyPayload); err != nil {
		t.Fatalf("decode revoke key response: %v", err)
	}
	if keyPayload.APIKey.Status != "revoked" || keyPayload.APIKey.Plaintext != "" {
		t.Fatalf("revoked key = %#v", keyPayload.APIKey)
	}
}

func TestAdminPolicyQuotaAndPricingRoutes(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "test-management-key")
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	cfg := &config.Config{}
	cfg.UserManagement.Enabled = true
	cfg.UserManagement.Storage.Driver = config.DefaultUserManagementStorage
	cfg.UserManagement.Storage.Path = filepath.Join(t.TempDir(), "users.db")

	server := NewServer(cfg, nil, sdkaccess.NewManager(), configPath)
	t.Cleanup(func() {
		_ = server.Stop(context.Background())
	})
	user := createServerPolicyUser(t, server.userStore)
	credential, err := usermanagement.NewUserAPIKeyService(server.userStore, server.userStore).CreateKey(t.Context(), usermanagement.CreateUserAPIKeyRequest{
		UserID: user.ID,
		Name:   "default",
	})
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	authRequest := func(method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer test-management-key")
		server.engine.ServeHTTP(rec, req)
		return rec
	}

	rec := authRequest(http.MethodPut, "/v0/management/users/"+string(user.ID)+"/model-policy", `{"models":["gpt-5","gpt-5"],"allow_all":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("set user model policy status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	var policyPayload struct {
		ModelPolicy modelPolicyResponse `json:"model_policy"`
	}
	if err = json.Unmarshal(rec.Body.Bytes(), &policyPayload); err != nil {
		t.Fatalf("decode model policy response: %v", err)
	}
	if len(policyPayload.ModelPolicy.Models) != 1 || policyPayload.ModelPolicy.Models[0] != "gpt-5" {
		t.Fatalf("model policy = %#v", policyPayload.ModelPolicy)
	}

	keyPolicyPath := "/v0/management/users/" + string(user.ID) + "/api-keys/" + string(credential.APIKey.ID) + "/model-policy"
	rec = authRequest(http.MethodPut, keyPolicyPath, `{"allow_all":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("set key model policy status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}

	rec = authRequest(http.MethodPut, "/v0/management/users/"+string(user.ID)+"/quota-policy", `{"period":"monthly","limit_credits":123}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("set quota policy status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	var quotaPayload struct {
		QuotaPolicy quotaPolicyResponse `json:"quota_policy"`
	}
	if err = json.Unmarshal(rec.Body.Bytes(), &quotaPayload); err != nil {
		t.Fatalf("decode quota response: %v", err)
	}
	if quotaPayload.QuotaPolicy.LimitCredits != 123 {
		t.Fatalf("quota policy = %#v", quotaPayload.QuotaPolicy)
	}

	rec = authRequest(http.MethodPut, "/v0/management/pricing-rules", `{
		"model":"gpt-5",
		"input_credits_per_million_tokens":1,
		"output_credits_per_million_tokens":2,
		"request_credits":3
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("set pricing rule status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}

	rec = authRequest(http.MethodGet, "/v0/management/pricing-rules", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list pricing rules status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	var pricingPayload struct {
		PricingRules []pricingRuleResponse `json:"pricing_rules"`
	}
	if err = json.Unmarshal(rec.Body.Bytes(), &pricingPayload); err != nil {
		t.Fatalf("decode pricing response: %v", err)
	}
	if len(pricingPayload.PricingRules) != 1 || pricingPayload.PricingRules[0].RequestCredits != 3 {
		t.Fatalf("pricing rules = %#v", pricingPayload.PricingRules)
	}

	rec = authRequest(http.MethodDelete, "/v0/management/pricing-rules?model=gpt-5", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("delete pricing rule status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
}

func TestManagementRoutesAcceptAdminSessionAndRejectOrdinaryUserSession(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "test-management-key")
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	cfg := &config.Config{}
	cfg.UserManagement.Enabled = true
	cfg.UserManagement.Storage.Driver = config.DefaultUserManagementStorage
	cfg.UserManagement.Storage.Path = filepath.Join(t.TempDir(), "users.db")

	server := NewServer(cfg, nil, sdkaccess.NewManager(), configPath)
	t.Cleanup(func() {
		_ = server.Stop(context.Background())
	})
	admin := createServerPolicyUser(t, server.userStore)
	if _, err := usermanagement.NewUserLifecycleService(server.userStore, server.userStore).AssignRole(t.Context(), admin.ID, usermanagement.UserRoleAdmin); err != nil {
		t.Fatalf("AssignRole(admin) error = %v", err)
	}
	ordinary := createServerPolicyUser(t, server.userStore)
	sessionService := usermanagement.NewSessionService(server.userStore, server.userStore)
	adminSession, err := sessionService.CreateSession(t.Context(), admin.ID, time.Hour)
	if err != nil {
		t.Fatalf("CreateSession(admin) error = %v", err)
	}
	userSession, err := sessionService.CreateSession(t.Context(), ordinary.ID, time.Hour)
	if err != nil {
		t.Fatalf("CreateSession(user) error = %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v0/management/users", nil)
	req.Header.Set("Authorization", "Bearer "+adminSession.Token)
	server.engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin session status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v0/management/users", nil)
	req.Header.Set("Authorization", "Bearer "+userSession.Token)
	server.engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("ordinary session status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v0/management/users", nil)
	req.Header.Set("Authorization", "Bearer test-management-key")
	server.engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("management key status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
}

func TestServerInitializesUserManagementAndRejectsDisallowedModel(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	cfg := &config.Config{
		Port: 0,
	}
	cfg.UserManagement.Enabled = true
	cfg.UserManagement.Storage.Driver = config.DefaultUserManagementStorage
	cfg.UserManagement.Storage.Path = filepath.Join(t.TempDir(), "users.db")

	server := NewServer(cfg, nil, sdkaccess.NewManager(), configPath)
	t.Cleanup(func() {
		_ = server.Stop(context.Background())
	})
	if server.userStore == nil || server.userModelPolicy == nil {
		t.Fatal("user management store or model policy service was not initialized")
	}

	user := createServerPolicyUser(t, server.userStore)
	keyService := usermanagement.NewUserAPIKeyService(server.userStore, server.userStore)
	credential, err := keyService.CreateKey(t.Context(), usermanagement.CreateUserAPIKeyRequest{
		UserID: user.ID,
		Name:   "default",
	})
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}
	if _, err = server.userModelPolicy.SetUserModels(t.Context(), user.ID, false, []string{"gpt-5"}); err != nil {
		t.Fatalf("SetUserModels() error = %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	req.Header.Set("Authorization", "Bearer "+credential.Plaintext)
	server.engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
}

func TestResolveUserManagementSQLitePathDefaultsBesideConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	cfg := &config.Config{}
	cfg.UserManagement.Storage.Driver = config.DefaultUserManagementStorage

	got, err := resolveUserManagementSQLitePath(cfg, configPath)
	if err != nil {
		t.Fatalf("resolveUserManagementSQLitePath() error = %v", err)
	}
	want := filepath.Join(filepath.Dir(configPath), "user-management.sqlite")
	if got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
}

func TestServerFiltersModelListForUserPolicy(t *testing.T) {
	openAIModels := registry.GetGlobalRegistry().GetAvailableModels("openai")
	if len(openAIModels) == 0 {
		t.Skip("no OpenAI models registered")
	}
	allowedModel, _ := openAIModels[0]["id"].(string)
	if allowedModel == "" {
		t.Skip("first OpenAI model has no id")
	}

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	cfg := &config.Config{}
	cfg.UserManagement.Enabled = true
	cfg.UserManagement.Storage.Driver = config.DefaultUserManagementStorage
	cfg.UserManagement.Storage.Path = filepath.Join(t.TempDir(), "users.db")

	server := NewServer(cfg, nil, sdkaccess.NewManager(), configPath)
	t.Cleanup(func() {
		_ = server.Stop(context.Background())
	})
	user := createServerPolicyUser(t, server.userStore)
	keyService := usermanagement.NewUserAPIKeyService(server.userStore, server.userStore)
	credential, err := keyService.CreateKey(t.Context(), usermanagement.CreateUserAPIKeyRequest{
		UserID: user.ID,
		Name:   "default",
	})
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}
	if _, err = server.userModelPolicy.SetUserModels(t.Context(), user.ID, false, []string{allowedModel}); err != nil {
		t.Fatalf("SetUserModels() error = %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+credential.Plaintext)
	server.engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Data []map[string]any `json:"data"`
	}
	if err = json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.Data) != 1 {
		t.Fatalf("model count = %d, want 1; body = %s", len(payload.Data), rec.Body.String())
	}
	if got, _ := payload.Data[0]["id"].(string); got != allowedModel {
		t.Fatalf("model id = %q, want %q", got, allowedModel)
	}
}

func createServerPolicyUser(t *testing.T, store *usermanagement.SQLiteStore) *usermanagement.User {
	t.Helper()
	hash, err := usermanagement.HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	user, err := store.CreateUser(t.Context(), usermanagement.CreateUserParams{
		Username:     "server-user-" + time.Now().Format("150405.000000000"),
		Email:        "server-user-" + time.Now().Format("150405.000000000") + "@example.test",
		PasswordHash: hash,
		Status:       usermanagement.UserStatusApproved,
		Role:         usermanagement.UserRoleUser,
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	return user
}
