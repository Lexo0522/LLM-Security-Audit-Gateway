package httpapi

import (
	"sync"
	"time"
)

// authThrottle tracks failed authentication attempts per client address to
// slow online guessing of admin tokens and gateway API keys. Entries expire
// with their window; the map is swept when it grows past its bound so a flood
// of spoofed addresses cannot exhaust memory.
type authThrottle struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	buckets map[string]*authBucket
	now     func() time.Time
}

type authBucket struct {
	start time.Time
	count int
}

func newAuthThrottle(limit int, window time.Duration) *authThrottle {
	return &authThrottle{limit: limit, window: window, buckets: map[string]*authBucket{}, now: time.Now}
}

func (t *authThrottle) blocked(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if len(t.buckets) > 4096 {
		for entry, bucket := range t.buckets {
			if now.Sub(bucket.start) > t.window {
				delete(t.buckets, entry)
			}
		}
	}
	bucket, ok := t.buckets[key]
	if !ok {
		return false
	}
	if now.Sub(bucket.start) > t.window {
		delete(t.buckets, key)
		return false
	}
	return bucket.count >= t.limit
}

func (t *authThrottle) fail(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	bucket, ok := t.buckets[key]
	if !ok || now.Sub(bucket.start) > t.window {
		bucket = &authBucket{start: now}
		t.buckets[key] = bucket
	}
	bucket.count++
}
