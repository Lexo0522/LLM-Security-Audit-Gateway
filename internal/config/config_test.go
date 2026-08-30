package config

import (
	"testing"
)

func TestValidateRequiresPepperAndPostgres(t *testing.T) {
	if err := (Config{}).Validate(); err == nil {
		t.Fatal("missing pepper and postgres should be rejected")
	}
	if err := (Config{APIKeyPepper: "0123456789abcdef0123456789abcdef"}).Validate(); err == nil {
		t.Fatal("missing postgres should be rejected")
	}
	if err := (Config{APIKeyPepper: "0123456789abcdef0123456789abcdef", PostgresURL: "postgres://example"}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsWeakAdminTokenInProduction(t *testing.T) {
	pepper := "0123456789abcdef0123456789abcdef"
	postgres := "postgres://example"
	if err := (Config{Environment: "production", AdminToken: "change-me", APIKeyPepper: pepper, PostgresURL: postgres}).Validate(); err == nil {
		t.Fatal("placeholder admin token should be rejected in production")
	}
	if err := (Config{Environment: "production", AdminToken: "short-token", APIKeyPepper: pepper, PostgresURL: postgres}).Validate(); err == nil {
		t.Fatal("short admin token should be rejected in production")
	}
	if err := (Config{Environment: "development", AdminToken: "change-me", APIKeyPepper: pepper, PostgresURL: postgres}).Validate(); err != nil {
		t.Fatal(err)
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
	pepper := "0123456789abcdef0123456789abcdef"
	if err := (Config{Environment: "production", AllowDemoBootstrap: true, APIKeyPepper: pepper, PostgresURL: "postgres://example"}).Validate(); err == nil {
		t.Fatal("production demo bootstrap should be rejected")
	}
	if err := (Config{Environment: "development", AllowDemoBootstrap: true, APIKeyPepper: pepper, PostgresURL: "postgres://example"}).Validate(); err != nil {
		t.Fatal(err)
	}
}
