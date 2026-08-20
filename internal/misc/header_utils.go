// Package misc provides miscellaneous utility functions for the CLI Proxy API server.
// It includes helper functions for HTTP header manipulation and other common operations
// that don't fit into more specific packages.
package misc

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
)

const (
	// GeminiCLIVersion is the version string reported in the User-Agent for upstream requests.
	GeminiCLIVersion = "0.34.0"

	// GeminiCLIApiClientHeader is the value for the X-Goog-Api-Client header sent to the Gemini CLI upstream.
	GeminiCLIApiClientHeader = "google-genai-sdk/1.41.0 gl-node/v22.19.0"
)

// geminiCLIOS maps Go runtime OS names to the Node.js-style platform strings used by Gemini CLI.
func geminiCLIOS() string {
	switch runtime.GOOS {
	case "windows":
		return "win32"
	default:
		return runtime.GOOS
	}
}

// geminiCLIArch maps Go runtime architecture names to the Node.js-style arch strings used by Gemini CLI.
func geminiCLIArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	case "386":
		return "x86"
	default:
		return runtime.GOARCH
	}
}

// GeminiCLIUserAgent returns a User-Agent string that matches the Gemini CLI format.
// The model parameter is included in the UA; pass "" or "unknown" when the model is not applicable.
func GeminiCLIUserAgent(model string) string {
	if model == "" {
		model = "unknown"
	}
	return fmt.Sprintf("GeminiCLI/%s/%s (%s; %s; terminal)", GeminiCLIVersion, model, geminiCLIOS(), geminiCLIArch())
}

// ScrubProxyAndFingerprintHeaders removes all headers that could reveal
// proxy infrastructure, client identity, or browser fingerprints from an
// outgoing request. This ensures requests to upstream services look like they
// originate directly from a native client rather than a third-party client
// behind a reverse proxy.
func ScrubProxyAndFingerprintHeaders(req *http.Request) {
	if req == nil {
		return
	}

	ScrubProxyTracingHeaders(req.Header)
	ScrubDeviceFingerprintHeaders(req.Header)
}

// ScrubDeviceFingerprintHeaders removes headers that can reveal the downstream
// client application, runtime, OS/arch, browser, or encoding fingerprint.
func ScrubDeviceFingerprintHeaders(headers http.Header) {
	if headers == nil {
		return
	}
	// --- Client identity headers ---
	headers.Del("X-Title")
	headers.Del("X-Stainless-Lang")
	headers.Del("X-Stainless-Package-Version")
	headers.Del("X-Stainless-Os")
	headers.Del("X-Stainless-Arch")
	headers.Del("X-Stainless-Runtime")
	headers.Del("X-Stainless-Runtime-Version")
	headers.Del("Http-Referer")
	headers.Del("Referer")

	// --- Browser / Chromium fingerprint headers ---
	// These are sent by Electron-based clients (e.g. CherryStudio) using the
	// Fetch API, but NOT by Node.js https module (which Antigravity uses).
	headers.Del("Sec-Ch-Ua")
	headers.Del("Sec-Ch-Ua-Mobile")
	headers.Del("Sec-Ch-Ua-Platform")
	headers.Del("Sec-Fetch-Mode")
	headers.Del("Sec-Fetch-Site")
	headers.Del("Sec-Fetch-Dest")
	headers.Del("Priority")

	// --- Encoding negotiation ---
	// Antigravity (Node.js) sends "gzip, deflate, br" by default;
	// Electron-based clients may add "zstd" which is a fingerprint mismatch.
	headers.Del("Accept-Encoding")
}

// ScrubProxyTracingHeaders removes hop-by-hop proxy tracing headers that can
// reveal the downstream client's original network address to upstream services.
func ScrubProxyTracingHeaders(headers http.Header) {
	if headers == nil {
		return
	}
	headers.Del("X-Forwarded-For")
	headers.Del("X-Forwarded-Host")
	headers.Del("X-Forwarded-Proto")
	headers.Del("X-Forwarded-Port")
	headers.Del("X-Real-IP")
	headers.Del("Forwarded")
	headers.Del("Via")
	headers.Del("CF-Connecting-IP")
	headers.Del("True-Client-IP")
	headers.Del("X-Client-IP")
	headers.Del("Fastly-Client-IP")
}

// EnsureHeader ensures that a header exists in the target header map by checking
// multiple sources in order of priority: source headers, existing target headers,
// and finally the default value. It only sets the header if it's not already present
// and the value is not empty after trimming whitespace.
//
// Parameters:
//   - target: The target header map to modify
//   - source: The source header map to check first (can be nil)
//   - key: The header key to ensure
//   - defaultValue: The default value to use if no other source provides a value
func EnsureHeader(target http.Header, source http.Header, key, defaultValue string) {
	if target == nil {
		return
	}
	if source != nil {
		if val := strings.TrimSpace(source.Get(key)); val != "" {
			target.Set(key, val)
			return
		}
	}
	if strings.TrimSpace(target.Get(key)) != "" {
		return
	}
	if val := strings.TrimSpace(defaultValue); val != "" {
		target.Set(key, val)
	}
}
