package storage

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestUpstreamLifecycleProjection(t *testing.T) {
	if got := upstreamLifecycle(true); got != UpstreamLifecycleActive {
		t.Fatalf("enabled lifecycle=%q", got)
	}
	if got := upstreamLifecycle(false); got != UpstreamLifecycleDisabled {
		t.Fatalf("disabled lifecycle=%q", got)
	}
	if UpstreamLifecycleDeleting == "" || UpstreamLifecycleDeleting == UpstreamLifecycleActive || UpstreamLifecycleDeleting == UpstreamLifecycleDisabled {
		t.Fatal("lifecycle states must be distinct")
	}
}

func TestValidateUpstreamURL(t *testing.T) {
	for _, valid := range []string{"https://example.com", "http://localhost:8080/v1"} {
		if err := ValidateUpstreamURL(valid); err != nil {
			t.Fatalf("ValidateUpstreamURL(%q)=%v", valid, err)
		}
	}
	for _, invalid := range []string{"", "ftp://example.com", "https:///missing-host", "https://user:pass@example.com"} {
		if err := ValidateUpstreamURL(invalid); !errors.Is(err, ErrInvalidUpstreamURL) {
			t.Fatalf("ValidateUpstreamURL(%q)=%v, want ErrInvalidUpstreamURL", invalid, err)
		}
	}
}

func TestUpstreamNotFoundPreservesPGXSentinel(t *testing.T) {
	if !errors.Is(ErrUpstreamNotFound, pgx.ErrNoRows) || !IsNotFound(ErrUpstreamNotFound) {
		t.Fatal("upstream not found must map to the repository not-found sentinel")
	}
}
