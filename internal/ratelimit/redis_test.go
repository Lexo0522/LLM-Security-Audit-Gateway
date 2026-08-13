package ratelimit

import "testing"

func TestMemoryLimiterAlwaysAllows(t *testing.T) {
	ok, _, err := MemoryLimiter{}.Allow(t.Context(), "tenant:/v1/chat/completions")
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestAdaptiveLimiterUsesLocalBucketWhenRedisDisabled(t *testing.T) {
	limiter, err := NewAdaptiveRedis("", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if limiter == nil || !limiter.Degraded() {
		t.Fatal("disabled Redis should use degraded local limiter")
	}
	if allowed, _, err := limiter.Allow(t.Context(), "tenant:/v1"); err != nil || !allowed {
		t.Fatalf("first allow=%v err=%v", allowed, err)
	}
	if allowed, _, err := limiter.Allow(t.Context(), "tenant:/v1"); err != nil || allowed {
		t.Fatalf("second allow=%v err=%v", allowed, err)
	}
}
