package config

import "testing"

func TestValidateRequiresPostgres(t *testing.T) {
	if err := (Config{}).Validate(); err == nil {
		t.Fatal("missing postgres should be rejected")
	}
	if err := (Config{PostgresURL: "postgres://example"}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadIgnoresRemovedSecretConfiguration(t *testing.T) {
	t.Setenv("NEWAPI_BASE_URL", "https://ignored.example")
	t.Setenv("NEWAPI_API_KEY", "ignored")
	t.Setenv("GATEWAY_API_KEY_PEPPER", "ignored")
	t.Setenv("ADMIN_API_TOKEN", "ignored")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EncryptionKeyFile != "/var/lib/gateway/keys/encryption.key" {
		t.Fatalf("unexpected encryption key path: %q", cfg.EncryptionKeyFile)
	}
}

func TestLoadSSELimitsDefaultsAndRejectsInvalidValues(t *testing.T) {
	t.Setenv("SSE_AUDIT_WINDOW_BYTES", "")
	t.Setenv("SSE_MAX_EVENT_BYTES", "")
	cfg, err := Load()
	if err != nil || cfg.SSEAuditWindowBytes != 16<<10 || cfg.SSEMaxEventBytes != 256<<10 {
		t.Fatalf("defaults=%+v err=%v", cfg, err)
	}
	t.Setenv("SSE_AUDIT_WINDOW_BYTES", "4096")
	t.Setenv("SSE_MAX_EVENT_BYTES", "8192")
	cfg, err = Load()
	if err != nil || cfg.SSEAuditWindowBytes != 4096 || cfg.SSEMaxEventBytes != 8192 {
		t.Fatalf("configured=%+v err=%v", cfg, err)
	}
	t.Setenv("SSE_AUDIT_WINDOW_BYTES", "0")
	t.Setenv("SSE_MAX_EVENT_BYTES", "invalid")
	if _, err = Load(); err == nil {
		t.Fatal("invalid limits must fail to load instead of falling back")
	}
}

func TestLoadRejectsInvalidSecurityBooleans(t *testing.T) {
	t.Setenv("AUDIT_FAIL_CLOSED", "yes")
	if _, err := Load(); err == nil {
		t.Fatal("AUDIT_FAIL_CLOSED=yes must fail to load instead of degrading to fail-open")
	}
}

func TestValidateRejectsProductionDemoBootstrap(t *testing.T) {
	if err := (Config{Environment: "production", AllowDemoBootstrap: true, PostgresURL: "postgres://example"}).Validate(); err == nil {
		t.Fatal("production demo bootstrap should be rejected")
	}
	if err := (Config{Environment: "development", AllowDemoBootstrap: true, PostgresURL: "postgres://example"}).Validate(); err != nil {
		t.Fatal(err)
	}
}
