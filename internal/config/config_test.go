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

func TestLoadSSELimitsDefaultsAndRejectsInvalidValues(t *testing.T) {
	t.Setenv("SSE_AUDIT_WINDOW_BYTES", "")
	t.Setenv("SSE_MAX_EVENT_BYTES", "")
	if cfg := Load(); cfg.SSEAuditWindowBytes != 16<<10 || cfg.SSEMaxEventBytes != 256<<10 {
		t.Fatalf("defaults=%+v", cfg)
	}
	t.Setenv("SSE_AUDIT_WINDOW_BYTES", "4096")
	t.Setenv("SSE_MAX_EVENT_BYTES", "8192")
	if cfg := Load(); cfg.SSEAuditWindowBytes != 4096 || cfg.SSEMaxEventBytes != 8192 {
		t.Fatalf("configured=%+v", cfg)
	}
	t.Setenv("SSE_AUDIT_WINDOW_BYTES", "0")
	t.Setenv("SSE_MAX_EVENT_BYTES", "invalid")
	if cfg := Load(); cfg.SSEAuditWindowBytes != 16<<10 || cfg.SSEMaxEventBytes != 256<<10 {
		t.Fatalf("invalid limits accepted=%+v", cfg)
	}
}
