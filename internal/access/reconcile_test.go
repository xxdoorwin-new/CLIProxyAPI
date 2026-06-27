package access

import (
	"context"
	"net/http"
	"testing"

	useraccess "github.com/router-for-me/CLIProxyAPI/v7/internal/access/user_access"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
)

func TestApplyAccessProvidersUserManagementDisabledPreservesFlatAPIKeys(t *testing.T) {
	sdkaccess.UnregisterProvider(useraccess.AccessProviderTypeUserAPIKey)
	sdkaccess.UnregisterProvider(sdkaccess.AccessProviderTypeConfigAPIKey)
	t.Cleanup(func() {
		sdkaccess.UnregisterProvider(useraccess.AccessProviderTypeUserAPIKey)
		sdkaccess.UnregisterProvider(sdkaccess.AccessProviderTypeConfigAPIKey)
	})

	manager := sdkaccess.NewManager()
	cfg := &config.Config{}
	cfg.APIKeys = []string{"flat-key"}
	cfg.UserManagement.Enabled = false

	_, err := ApplyAccessProviders(manager, nil, cfg)
	if err != nil {
		t.Fatalf("ApplyAccessProviders() error = %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://example.test/v1/chat/completions", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer flat-key")

	result, authErr := manager.Authenticate(context.Background(), req)
	if authErr != nil {
		t.Fatalf("Authenticate() error = %v", authErr)
	}
	if result.Provider != sdkaccess.DefaultAccessProviderName {
		t.Fatalf("Provider = %q, want %q", result.Provider, sdkaccess.DefaultAccessProviderName)
	}
	if result.Principal != "flat-key" {
		t.Fatalf("Principal = %q, want flat-key", result.Principal)
	}
}
