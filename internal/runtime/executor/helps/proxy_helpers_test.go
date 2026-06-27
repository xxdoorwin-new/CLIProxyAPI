package helps

import (
	"context"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func TestNewProxyAwareHTTPClientDirectBypassesGlobalProxy(t *testing.T) {
	t.Parallel()

	client := NewProxyAwareHTTPClient(
		context.Background(),
		&config.Config{
			SDKConfig: sdkconfig.SDKConfig{ProxyURL: "http://global-proxy.example.com:8080"},
			Privacy:   config.PrivacyConfig{IPMasquerade: true},
		},
		&cliproxyauth.Auth{ProxyURL: "direct"},
		0,
	)

	scrubber, ok := client.Transport.(proxyTracingScrubRoundTripper)
	if !ok {
		t.Fatalf("transport type = %T, want proxyTracingScrubRoundTripper", client.Transport)
	}
	transport, ok := scrubber.base.(*http.Transport)
	if !ok {
		t.Fatalf("base transport type = %T, want *http.Transport", scrubber.base)
	}
	if transport.Proxy != nil {
		t.Fatal("expected direct transport to disable proxy function")
	}
}

func TestProxyTracingScrubRoundTripperRemovesForwardedIPHeaders(t *testing.T) {
	t.Parallel()

	var got http.Header
	base := scrubTestRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		got = req.Header.Clone()
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       http.NoBody,
			Request:    req,
		}, nil
	})
	client := &http.Client{Transport: scrubProxyTracingTransport(base, true)}
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	req.Header.Set("X-Real-IP", "203.0.113.8")
	req.Header.Set("Forwarded", "for=203.0.113.9")
	req.Header.Set("User-Agent", "stable-client/1.0")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	_ = resp.Body.Close()

	for _, key := range []string{"X-Forwarded-For", "X-Real-IP", "Forwarded"} {
		if got.Get(key) != "" {
			t.Fatalf("%s = %q, want empty", key, got.Get(key))
		}
	}
	if got.Get("User-Agent") != "stable-client/1.0" {
		t.Fatalf("User-Agent = %q, want stable-client/1.0", got.Get("User-Agent"))
	}
}

func TestProxyTracingScrubRoundTripperDisabledPreservesForwardedIPHeaders(t *testing.T) {
	t.Parallel()

	var got http.Header
	base := scrubTestRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		got = req.Header.Clone()
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       http.NoBody,
			Request:    req,
		}, nil
	})
	client := &http.Client{Transport: scrubProxyTracingTransport(base, false)}
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("X-Forwarded-For", "203.0.113.7")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	_ = resp.Body.Close()

	if got.Get("X-Forwarded-For") != "203.0.113.7" {
		t.Fatalf("X-Forwarded-For = %q, want preserved", got.Get("X-Forwarded-For"))
	}
}

type scrubTestRoundTripFunc func(*http.Request) (*http.Response, error)

func (f scrubTestRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
