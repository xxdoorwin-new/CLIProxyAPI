package executor

import "testing"

func TestClaudeAPIEndpointURL(t *testing.T) {
	tests := []struct {
		name     string
		baseURL  string
		endpoint string
		want     string
	}{
		{name: "host base", baseURL: "https://api.anthropic.com", endpoint: "messages", want: "https://api.anthropic.com/v1/messages"},
		{name: "versioned base", baseURL: "https://proxy.example.com/v1", endpoint: "messages", want: "https://proxy.example.com/v1/messages"},
		{name: "trailing slash", baseURL: "https://proxy.example.com/v1/", endpoint: "/messages/count_tokens", want: "https://proxy.example.com/v1/messages/count_tokens"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := claudeAPIEndpointURL(tt.baseURL, tt.endpoint); got != tt.want {
				t.Fatalf("claudeAPIEndpointURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
