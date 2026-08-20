package handlers

import (
	"net/http"
	"testing"
)

func TestFilterUpstreamHeaders_RemovesConnectionScopedHeaders(t *testing.T) {
	src := http.Header{}
	src.Add("Connection", "keep-alive, x-hop-a, x-hop-b")
	src.Add("Connection", "x-hop-c")
	src.Set("Keep-Alive", "timeout=5")
	src.Set("X-Hop-A", "a")
	src.Set("X-Hop-B", "b")
	src.Set("X-Hop-C", "c")
	src.Set("X-Request-Id", "req-1")
	src.Set("Set-Cookie", "session=secret")

	filtered := FilterUpstreamHeaders(src)
	if filtered == nil {
		t.Fatalf("expected filtered headers, got nil")
	}

	requestID := filtered.Get("X-Request-Id")
	if requestID != "req-1" {
		t.Fatalf("expected X-Request-Id to be preserved, got %q", requestID)
	}

	blockedHeaderKeys := []string{
		"Connection",
		"Keep-Alive",
		"X-Hop-A",
		"X-Hop-B",
		"X-Hop-C",
		"Set-Cookie",
	}
	for _, key := range blockedHeaderKeys {
		value := filtered.Get(key)
		if value != "" {
			t.Fatalf("expected %s to be removed, got %q", key, value)
		}
	}
}

func TestFilterUpstreamHeaders_ReturnsNilWhenAllHeadersBlocked(t *testing.T) {
	src := http.Header{}
	src.Add("Connection", "x-hop-a")
	src.Set("X-Hop-A", "a")
	src.Set("Set-Cookie", "session=secret")

	filtered := FilterUpstreamHeaders(src)
	if filtered != nil {
		t.Fatalf("expected nil when all headers are filtered, got %#v", filtered)
	}
}

func TestFilterQuotaHeaders_PreservesUsageLimitHeaders(t *testing.T) {
	src := http.Header{}
	src.Set("X-RateLimit-Remaining-Requests", "10")
	src.Set("Anthropic-RateLimit-Requests-Reset", "2026-06-27T00:00:00Z")
	src.Set("OpenAI-Usage-Limit-Reset-Seconds", "30")
	src.Set("Retry-After", "5")
	src.Set("X-Request-Id", "req-1")
	src.Set("Set-Cookie", "session=secret")
	src.Set("Content-Encoding", "gzip")

	filtered := FilterQuotaHeaders(src)
	if filtered == nil {
		t.Fatalf("expected quota headers, got nil")
	}
	for _, key := range []string{
		"X-RateLimit-Remaining-Requests",
		"Anthropic-RateLimit-Requests-Reset",
		"OpenAI-Usage-Limit-Reset-Seconds",
		"Retry-After",
	} {
		if got := filtered.Get(key); got == "" {
			t.Fatalf("expected %s to be preserved", key)
		}
	}
	for _, key := range []string{"X-Request-Id", "Set-Cookie", "Content-Encoding"} {
		if got := filtered.Get(key); got != "" {
			t.Fatalf("expected %s to be removed, got %q", key, got)
		}
	}
}
