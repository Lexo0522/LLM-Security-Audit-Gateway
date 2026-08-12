package ratelimit

import "testing"

func TestMemoryLimiterAlwaysAllows(t *testing.T) {
	ok, _, err := MemoryLimiter{}.Allow(t.Context(), "tenant:/v1/chat/completions")
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}
