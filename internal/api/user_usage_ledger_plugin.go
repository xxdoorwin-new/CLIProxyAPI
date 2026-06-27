package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	internallogging "github.com/router-for-me/CLIProxyAPI/v7/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/usermanagement"
	coreusage "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
	log "github.com/sirupsen/logrus"
)

const userUsageLedgerPluginName = "user-management-ledger"

type userUsageLedgerPlugin struct {
	recorder *usermanagement.UsageRecorder
}

func registerUserUsageLedgerPlugin(store *usermanagement.SQLiteStore, missingUsageCredits int64) {
	if store == nil {
		coreusage.UnregisterNamedPlugin(userUsageLedgerPluginName)
		return
	}
	coreusage.RegisterNamedPlugin(userUsageLedgerPluginName, &userUsageLedgerPlugin{
		recorder: usermanagement.NewUsageRecorder(store, usermanagement.UsageRecorderConfig{
			MissingUsageCredits: missingUsageCredits,
		}),
	})
}

func unregisterUserUsageLedgerPlugin() {
	coreusage.UnregisterNamedPlugin(userUsageLedgerPluginName)
}

func (p *userUsageLedgerPlugin) HandleUsage(ctx context.Context, record coreusage.Record) {
	if p == nil || p.recorder == nil {
		return
	}
	userID, keyID := usagePrincipalFromContext(ctx)
	if userID == "" || keyID == "" {
		return
	}
	statusCode := internallogging.GetResponseStatus(ctx)
	_, err := p.recorder.RecordUsage(ctx, usermanagement.RecordUsageParams{
		UserID:          userID,
		APIKeyID:        keyID,
		RequestID:       internallogging.GetRequestID(ctx),
		Provider:        record.Provider,
		Model:           record.Model,
		ModelAlias:      record.Alias,
		InputTokens:     record.Detail.InputTokens,
		OutputTokens:    record.Detail.OutputTokens,
		CachedTokens:    normalizedCachedTokens(record.Detail),
		ReasoningTokens: record.Detail.ReasoningTokens,
		Failed:          record.Failed || statusCode >= http.StatusBadRequest,
		ErrorCode:       usageErrorCode(record, statusCode),
		HTTPStatusCode:  statusCode,
		Latency:         record.Latency,
		RequestedAt:     record.RequestedAt,
	})
	if err != nil {
		log.Errorf("user management usage ledger write failed: %v", err)
	}
}

func usagePrincipalFromContext(ctx context.Context) (usermanagement.UserID, usermanagement.APIKeyID) {
	if ctx == nil {
		return "", ""
	}
	ginCtx, ok := ctx.Value("gin").(*gin.Context)
	if !ok || ginCtx == nil {
		return "", ""
	}
	raw, exists := ginCtx.Get("accessMetadata")
	if !exists {
		return "", ""
	}
	metadata := stringMetadata(raw)
	userID := strings.TrimSpace(metadata["user_id"])
	keyID := strings.TrimSpace(metadata["api_key_id"])
	if userID == "" || keyID == "" {
		return "", ""
	}
	return usermanagement.UserID(userID), usermanagement.APIKeyID(keyID)
}

func stringMetadata(raw any) map[string]string {
	switch value := raw.(type) {
	case map[string]string:
		return value
	case map[string]any:
		out := make(map[string]string, len(value))
		for k, v := range value {
			out[k] = fmt.Sprintf("%v", v)
		}
		return out
	default:
		return nil
	}
}

func normalizedCachedTokens(detail coreusage.Detail) int64 {
	if detail.CachedTokens != 0 {
		return detail.CachedTokens
	}
	return detail.CacheReadTokens + detail.CacheCreationTokens
}

func usageErrorCode(record coreusage.Record, statusCode int) string {
	if record.Fail.StatusCode > 0 {
		return fmt.Sprintf("%d", record.Fail.StatusCode)
	}
	if statusCode > 0 {
		return fmt.Sprintf("%d", statusCode)
	}
	return ""
}
