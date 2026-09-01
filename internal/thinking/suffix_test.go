package thinking

import "testing"

func TestNormalizeClaudeModelName_StripsContextWindowAnnotation(t *testing.T) {
	tests := []struct {
		name      string
		model     string
		modelName string
	}{
		{name: "one million", model: "claude-opus-5[1m]", modelName: "claude-opus-5"},
		{name: "case insensitive", model: "claude-opus-5[1M]", modelName: "claude-opus-5"},
		{name: "preserves surrounding whitespace", model: " claude-opus-5[1m] ", modelName: "claude-opus-5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeClaudeModelName(tt.model)
			if got != tt.modelName {
				t.Fatalf("NormalizeClaudeModelName() = %q, want %q", got, tt.modelName)
			}
			parsed := ParseSuffix(tt.model)
			if parsed.ModelName != tt.model || parsed.HasSuffix {
				t.Fatalf("ParseSuffix changed provider-specific syntax: %+v", parsed)
			}
		})
	}
}

func TestParseSuffix_StillParsesThinkingSuffix(t *testing.T) {
	got := ParseSuffix("claude-sonnet-4-6(high)")
	if got.ModelName != "claude-sonnet-4-6" || !got.HasSuffix || got.RawSuffix != "high" {
		t.Fatalf("unexpected result: %+v", got)
	}
}
