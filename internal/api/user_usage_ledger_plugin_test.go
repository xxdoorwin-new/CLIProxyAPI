package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	internallogging "github.com/router-for-me/CLIProxyAPI/v7/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/usermanagement"
	coreusage "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
)

func TestUserUsageLedgerPluginWritesUserLinkedLedger(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store, err := usermanagement.OpenSQLiteStore(t.Context(), usermanagement.SQLiteConfig{
		Path: filepath.Join(t.TempDir(), "users.db"),
	})
	if err != nil {
		t.Fatalf("OpenSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	user := createServerPolicyUser(t, store)
	key, err := store.CreateAPIKey(t.Context(), usermanagement.CreateAPIKeyParams{
		UserID:  user.ID,
		Name:    "default",
		KeyHash: []byte("key-hash"),
		Prefix:  "cpak_test",
		Status:  usermanagement.APIKeyStatusActive,
	})
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	if _, err = store.SetQuotaPolicy(t.Context(), usermanagement.SetQuotaPolicyParams{
		UserID:       user.ID,
		Period:       usermanagement.QuotaPeriodMonthly,
		LimitCredits: 100,
	}); err != nil {
		t.Fatalf("SetQuotaPolicy() error = %v", err)
	}

	ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ginCtx.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	ginCtx.Set("accessMetadata", map[string]string{
		"user_id":    string(user.ID),
		"api_key_id": string(key.ID),
	})
	ctx := context.WithValue(context.Background(), "gin", ginCtx)
	ctx = internallogging.WithRequestID(ctx, "req-plugin")
	ctx = internallogging.WithResponseStatusHolder(ctx)
	internallogging.SetResponseStatus(ctx, http.StatusOK)

	plugin := &userUsageLedgerPlugin{
		recorder: usermanagement.NewUsageRecorder(store, usermanagement.UsageRecorderConfig{MissingUsageCredits: 5}),
	}
	plugin.HandleUsage(ctx, coreusage.Record{
		Provider:    "openai",
		Model:       "gpt-5",
		Alias:       "codex-pro",
		RequestedAt: time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC),
		Latency:     2 * time.Second,
		Detail: coreusage.Detail{
			InputTokens: 1,
		},
	})

	rows, err := store.ListUsageLedgerRows(t.Context(), usermanagement.UsageLedgerFilter{UserID: user.ID})
	if err != nil {
		t.Fatalf("ListUsageLedgerRows() error = %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("ledger rows = %d, want 1", len(rows))
	}
	row := rows[0]
	if row.APIKeyID != key.ID || row.RequestID != "req-plugin" || row.ModelAlias != "codex-pro" {
		t.Fatalf("ledger row = %#v", row)
	}
	if row.LatencyMillis != 2000 || row.Status != usermanagement.UsageStatusSucceeded {
		t.Fatalf("ledger timing/status = %#v", row)
	}
}

func TestUserUsageLedgerPluginSkipsNonUserContext(t *testing.T) {
	store, err := usermanagement.OpenSQLiteStore(t.Context(), usermanagement.SQLiteConfig{
		Path: filepath.Join(t.TempDir(), "users.db"),
	})
	if err != nil {
		t.Fatalf("OpenSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	plugin := &userUsageLedgerPlugin{
		recorder: usermanagement.NewUsageRecorder(store, usermanagement.UsageRecorderConfig{MissingUsageCredits: 5}),
	}
	plugin.HandleUsage(context.Background(), coreusage.Record{
		Provider: "openai",
		Model:    "gpt-5",
	})

	rows, err := store.ListUsageLedgerRows(t.Context(), usermanagement.UsageLedgerFilter{})
	if err != nil {
		t.Fatalf("ListUsageLedgerRows() error = %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("ledger rows = %d, want 0", len(rows))
	}
}
