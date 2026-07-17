package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/usermanagement"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
)

func TestTrafficStatisticsRoutesRespectAdminAndSelfScopes(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "test-management-key")
	cfg := &config.Config{}
	cfg.UserManagement.Enabled = true
	cfg.UserManagement.Storage.Driver = config.DefaultUserManagementStorage
	cfg.UserManagement.Storage.Path = filepath.Join(t.TempDir(), "users.db")
	server := NewServer(cfg, nil, sdkaccess.NewManager(), filepath.Join(t.TempDir(), "config.yaml"))
	t.Cleanup(func() { _ = server.Stop(context.Background()) })

	alice := createServerPolicyUser(t, server.userStore)
	bob := createServerPolicyUser(t, server.userStore)
	createUsageKey := func(userID usermanagement.UserID) *usermanagement.APIKey {
		t.Helper()
		key, err := server.userStore.CreateAPIKey(t.Context(), usermanagement.CreateAPIKeyParams{
			UserID: userID, Name: "traffic", KeyHash: []byte(uuid.NewString()), Prefix: "traffic", Status: usermanagement.APIKeyStatusActive,
		})
		if err != nil {
			t.Fatalf("CreateAPIKey() error = %v", err)
		}
		return key
	}
	aliceKey := createUsageKey(alice.ID)
	bobKey := createUsageKey(bob.ID)
	for _, item := range []struct {
		userID  usermanagement.UserID
		keyID   usermanagement.APIKeyID
		request string
		tokens  int64
	}{
		{alice.ID, aliceKey.ID, "alice-traffic", 10},
		{bob.ID, bobKey.ID, "bob-traffic", 20},
	} {
		_, err := server.userStore.AppendUsageLedgerRow(t.Context(), usermanagement.CreateUsageLedgerRowParams{
			UserID: item.userID, APIKeyID: item.keyID, RequestID: item.request, Provider: "openai", Model: "gpt-5",
			InputTokens: item.tokens, TotalTokens: item.tokens, CreditCost: 2, Status: usermanagement.UsageStatusSucceeded,
			CreatedAt: time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC),
		})
		if err != nil {
			t.Fatalf("AppendUsageLedgerRow() error = %v", err)
		}
	}
	aliceSession, err := usermanagement.NewSessionService(server.userStore, server.userStore).CreateSession(t.Context(), alice.ID, time.Hour)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	request := func(path, header, token string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set(header, token)
		server.engine.ServeHTTP(rec, req)
		return rec
	}

	selfResponse := request("/v0/user/traffic-statistics?time_zone=UTC&from=2026-07-10&to=2026-07-10", "Authorization", "Bearer "+aliceSession.Token)
	if selfResponse.Code != http.StatusOK {
		t.Fatalf("self statistics status = %d, want 200; body = %s", selfResponse.Code, selfResponse.Body.String())
	}
	var selfPayload struct {
		Traffic usermanagement.TrafficStatistics `json:"traffic"`
	}
	if err = json.Unmarshal(selfResponse.Body.Bytes(), &selfPayload); err != nil {
		t.Fatalf("decode self statistics: %v", err)
	}
	if selfPayload.Traffic.Summary.TotalTokens != 10 || len(selfPayload.Traffic.Ranking) != 0 {
		t.Fatalf("self statistics = %#v, want only Alice without ranking", selfPayload.Traffic)
	}

	adminResponse := request("/v0/management/traffic-statistics?time_zone=UTC&from=2026-07-10&to=2026-07-10", "X-Management-Key", "test-management-key")
	if adminResponse.Code != http.StatusOK {
		t.Fatalf("admin statistics status = %d, want 200; body = %s", adminResponse.Code, adminResponse.Body.String())
	}
	var adminPayload struct {
		Traffic usermanagement.TrafficStatistics `json:"traffic"`
	}
	if err = json.Unmarshal(adminResponse.Body.Bytes(), &adminPayload); err != nil {
		t.Fatalf("decode admin statistics: %v", err)
	}
	if adminPayload.Traffic.Summary.TotalTokens != 30 || len(adminPayload.Traffic.Ranking) != 2 {
		t.Fatalf("admin statistics = %#v, want both users", adminPayload.Traffic)
	}

	forbiddenResponse := request("/v0/management/traffic-statistics?time_zone=UTC", "Authorization", "Bearer "+aliceSession.Token)
	if forbiddenResponse.Code != http.StatusForbidden {
		t.Fatalf("ordinary management statistics status = %d, want 403", forbiddenResponse.Code)
	}

	hourlyResponse := request("/v0/management/traffic-statistics?time_zone=UTC&from=2026-07-10&to=2026-07-10&granularity=hour", "X-Management-Key", "test-management-key")
	if hourlyResponse.Code != http.StatusOK {
		t.Fatalf("hourly statistics status = %d, want 200; body = %s", hourlyResponse.Code, hourlyResponse.Body.String())
	}
	var hourlyPayload struct {
		Traffic usermanagement.TrafficStatistics `json:"traffic"`
	}
	if err = json.Unmarshal(hourlyResponse.Body.Bytes(), &hourlyPayload); err != nil {
		t.Fatalf("decode hourly statistics: %v", err)
	}
	if hourlyPayload.Traffic.Granularity != "hour" || len(hourlyPayload.Traffic.Daily) != 24 {
		t.Fatalf("hourly statistics = %#v, want granularity=hour with 24 buckets", hourlyPayload.Traffic)
	}
}
