package proxy

import (
	"net/http"
	"testing"
)

func TestCopyHeadersDoesNotForwardCallerIdentity(t *testing.T) {
	source := http.Header{"Authorization": []string{"Bearer client-key"}, "X-Tenant-ID": []string{"forged"}, "X-Request-ID": []string{"request-a"}}
	destination := http.Header{}
	copyHeaders(destination, source)
	if destination.Get("Authorization") != "" || destination.Get("X-Tenant-ID") != "" || destination.Get("X-Request-ID") != "request-a" {
		t.Fatalf("unexpected forwarded headers: %#v", destination)
	}
}
