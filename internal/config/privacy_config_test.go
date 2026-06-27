package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigOptional_PrivacyConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	configYAML := []byte(`
privacy:
  ip-masquerade: true
  device-masquerade: true
`)
	if err := os.WriteFile(configPath, configYAML, 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := LoadConfigOptional(configPath, false)
	if err != nil {
		t.Fatalf("LoadConfigOptional() error = %v", err)
	}

	if !IPMasqueradeEnabled(cfg) {
		t.Fatalf("IPMasqueradeEnabled() = false, want true")
	}
	if !DeviceMasqueradeEnabled(cfg) {
		t.Fatalf("DeviceMasqueradeEnabled() = false, want true")
	}
}

func TestPrivacyConfig_DefaultDisabled(t *testing.T) {
	if IPMasqueradeEnabled(nil) {
		t.Fatalf("IPMasqueradeEnabled(nil) = true, want false")
	}
	if DeviceMasqueradeEnabled(&Config{}) {
		t.Fatalf("DeviceMasqueradeEnabled(empty config) = true, want false")
	}
}
