package helps

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
)

type proxyTracingScrubRoundTripper struct {
	base                  http.RoundTripper
	preserveProxyIdentity bool
}

func (t proxyTracingScrubRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// A Claude request can deliberately replace the downstream identity with the
	// proxy host's identity. Keep only those replacement fields; every other
	// tracing header is still removed below.
	var proxyIdentity http.Header
	if t.preserveProxyIdentity {
		proxyIdentity = make(http.Header, 4)
		for _, name := range []string{"X-Forwarded-For", "X-Real-IP", "Forwarded", "X-Client-IP"} {
			if value := req.Header.Get(name); value != "" {
				proxyIdentity.Set(name, value)
			}
		}
	}
	misc.ScrubProxyTracingHeaders(req.Header)
	for name, values := range proxyIdentity {
		req.Header[name] = values
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

func scrubProxyTracingTransport(base http.RoundTripper, enabled bool) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if !enabled {
		return base
	}
	return proxyTracingScrubRoundTripper{base: base}
}

// preserveProxyIdentityTransport removes untrusted tracing headers while retaining
// the proxy-owned replacement IP headers placed on a newly-created upstream request.
func preserveProxyIdentityTransport(base http.RoundTripper, enabled bool) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if !enabled {
		return base
	}
	return proxyTracingScrubRoundTripper{base: base, preserveProxyIdentity: true}
}

// NewProxyAwareHTTPClient creates an HTTP client with proper proxy configuration priority:
// 1. Use auth.ProxyURL if configured (highest priority)
// 2. Use cfg.ProxyURL if auth proxy is not configured
// 3. Use RoundTripper from context if neither are configured
//
// Parameters:
//   - ctx: The context containing optional RoundTripper
//   - cfg: The application configuration
//   - auth: The authentication information
//   - timeout: The client timeout (0 means no timeout)
//
// Returns:
//   - *http.Client: An HTTP client with configured proxy or transport
func NewProxyAwareHTTPClient(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth, timeout time.Duration) *http.Client {
	httpClient := &http.Client{}
	if timeout > 0 {
		httpClient.Timeout = timeout
	}
	ipMasquerade := config.IPMasqueradeEnabled(cfg)

	// Priority 1: Use auth.ProxyURL if configured
	var proxyURL string
	if auth != nil {
		proxyURL = strings.TrimSpace(auth.ProxyURL)
	}

	// Priority 2: Use cfg.ProxyURL if auth proxy is not configured
	if proxyURL == "" && cfg != nil {
		proxyURL = strings.TrimSpace(cfg.ProxyURL)
	}

	// If we have a proxy URL configured, set up the transport
	if proxyURL != "" {
		transport := buildProxyTransport(proxyURL)
		if transport != nil {
			httpClient.Transport = scrubProxyTracingTransport(transport, ipMasquerade)
			return httpClient
		}
		// If proxy setup failed, log and fall through to context RoundTripper
		log.Debugf("failed to setup proxy from URL: %s, falling back to context transport", proxyutil.Redact(proxyURL))
	}

	// Priority 3: Use RoundTripper from context (typically from RoundTripperFor)
	if ctx != nil {
		if rt, ok := ctx.Value("cliproxy.roundtripper").(http.RoundTripper); ok && rt != nil {
			httpClient.Transport = scrubProxyTracingTransport(rt, ipMasquerade)
		}
	}
	if httpClient.Transport == nil {
		httpClient.Transport = scrubProxyTracingTransport(http.DefaultTransport, ipMasquerade)
	}

	return httpClient
}

// buildProxyTransport creates an HTTP transport configured for the given proxy URL.
// It supports SOCKS5, HTTP, and HTTPS proxy protocols.
//
// Parameters:
//   - proxyURL: The proxy URL string (e.g., "socks5://user:pass@host:port", "http://host:port")
//
// Returns:
//   - *http.Transport: A configured transport, or nil if the proxy URL is invalid
func buildProxyTransport(proxyURL string) *http.Transport {
	transport, _, errBuild := proxyutil.BuildHTTPTransport(proxyURL)
	if errBuild != nil {
		log.Errorf("%v", errBuild)
		return nil
	}
	return transport
}
