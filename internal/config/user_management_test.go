package config

import "testing"

func TestParseConfigBytes_UserManagementDefaults(t *testing.T) {
	cfg, errParse := ParseConfigBytes([]byte("user-management: {}\n"))
	if errParse != nil {
		t.Fatalf("ParseConfigBytes() error = %v", errParse)
	}

	if cfg.UserManagement.Enabled {
		t.Fatal("UserManagement.Enabled = true, want false")
	}
	if cfg.UserManagement.Registration.Enabled {
		t.Fatal("UserManagement.Registration.Enabled = true, want false")
	}
	if cfg.UserManagement.Storage.Driver != DefaultUserManagementStorage {
		t.Fatalf("UserManagement.Storage.Driver = %q, want %q", cfg.UserManagement.Storage.Driver, DefaultUserManagementStorage)
	}
	if cfg.UserManagement.Quota.DefaultPeriod != DefaultUserQuotaPeriod {
		t.Fatalf("UserManagement.Quota.DefaultPeriod = %q, want %q", cfg.UserManagement.Quota.DefaultPeriod, DefaultUserQuotaPeriod)
	}
	if cfg.UserManagement.Quota.DefaultMonthlyCredits != 0 {
		t.Fatalf("UserManagement.Quota.DefaultMonthlyCredits = %d, want 0", cfg.UserManagement.Quota.DefaultMonthlyCredits)
	}
	if cfg.UserManagement.Quota.MissingUsageCredits != 0 {
		t.Fatalf("UserManagement.Quota.MissingUsageCredits = %d, want 0", cfg.UserManagement.Quota.MissingUsageCredits)
	}
}

func TestParseConfigBytes_UserManagementSanitizesValues(t *testing.T) {
	cfg, errParse := ParseConfigBytes([]byte(`
user-management:
  enabled: true
  registration:
    enabled: true
  storage:
    driver: " SQLITE "
    path: " ./users.db "
  sessions:
    ttl: " 12h "
  quota:
    default-period: " MONTHLY "
    default-monthly-credits: -1
    missing-usage-credits: -5
`))
	if errParse != nil {
		t.Fatalf("ParseConfigBytes() error = %v", errParse)
	}

	if !cfg.UserManagement.Enabled {
		t.Fatal("UserManagement.Enabled = false, want true")
	}
	if !cfg.UserManagement.Registration.Enabled {
		t.Fatal("UserManagement.Registration.Enabled = false, want true")
	}
	if cfg.UserManagement.Storage.Driver != "sqlite" {
		t.Fatalf("UserManagement.Storage.Driver = %q, want sqlite", cfg.UserManagement.Storage.Driver)
	}
	if cfg.UserManagement.Storage.Path != "./users.db" {
		t.Fatalf("UserManagement.Storage.Path = %q, want ./users.db", cfg.UserManagement.Storage.Path)
	}
	if cfg.UserManagement.Sessions.TTL != "12h" {
		t.Fatalf("UserManagement.Sessions.TTL = %q, want 12h", cfg.UserManagement.Sessions.TTL)
	}
	if cfg.UserManagement.Quota.DefaultPeriod != "monthly" {
		t.Fatalf("UserManagement.Quota.DefaultPeriod = %q, want monthly", cfg.UserManagement.Quota.DefaultPeriod)
	}
	if cfg.UserManagement.Quota.DefaultMonthlyCredits != 0 {
		t.Fatalf("UserManagement.Quota.DefaultMonthlyCredits = %d, want 0", cfg.UserManagement.Quota.DefaultMonthlyCredits)
	}
	if cfg.UserManagement.Quota.MissingUsageCredits != 0 {
		t.Fatalf("UserManagement.Quota.MissingUsageCredits = %d, want 0", cfg.UserManagement.Quota.MissingUsageCredits)
	}
}
