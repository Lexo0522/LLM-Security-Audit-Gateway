package config

import "testing"

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
