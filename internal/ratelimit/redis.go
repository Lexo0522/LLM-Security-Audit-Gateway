package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/example/ai-audit-gateway/internal/observability"
	"github.com/redis/go-redis/v9"
)

type Limiter interface {
	Allow(context.Context, string) (bool, time.Duration, error)
}

type RedisLimiter struct {
	client     redis.UniversalClient
	rps, burst int
	script     *redis.Script
	metrics    *observability.Metrics
}

func NewRedis(url string, rps, burst int, metrics ...*observability.Metrics) (*RedisLimiter, error) {
	if url == "" {
		return nil, nil
	}
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	if rps < 1 {
		rps = 60
	}
	if burst < 1 {
		burst = 120
	}
	var collector *observability.Metrics
	if len(metrics) > 0 {
		collector = metrics[0]
	}
	return &RedisLimiter{client: redis.NewClient(opts), rps: rps, burst: burst, metrics: collector, script: redis.NewScript(`
local now=tonumber(ARGV[1]); local rate=tonumber(ARGV[2]); local burst=tonumber(ARGV[3]);
local data=redis.call('HMGET',KEYS[1],'tokens','at'); local tokens=tonumber(data[1]) or burst; local at=tonumber(data[2]) or now;
tokens=math.min(burst,tokens+(now-at)*rate/1000); local ok=tokens>=1; if ok then tokens=tokens-1 end;
redis.call('HMSET',KEYS[1],'tokens',tokens,'at',now); redis.call('PEXPIRE',KEYS[1],math.ceil(burst/rate*2000));
return {ok and 1 or 0, math.ceil(math.max(0,1-tokens)/rate*1000)}
`)}, nil
}
func (l *RedisLimiter) Close() error {
	if l == nil {
		return nil
	}
	return l.client.Close()
}
func (l *RedisLimiter) Allow(ctx context.Context, key string) (bool, time.Duration, error) {
	if l == nil {
		return true, 0, nil
	}
	result, err := l.script.Run(ctx, l.client, []string{"audit-gateway:limit:" + key}, time.Now().UnixMilli(), l.rps, l.burst).Int64Slice()
	if err != nil {
		l.metrics.Inc("audit_redis_limiter_total", map[string]string{"result": "error"})
		return false, 0, err
	}
	if len(result) != 2 {
		l.metrics.Inc("audit_redis_limiter_total", map[string]string{"result": "error"})
		return false, 0, fmt.Errorf("invalid rate-limit response")
	}
	allowed := result[0] == 1
	if allowed {
		l.metrics.Inc("audit_redis_limiter_total", map[string]string{"result": "allow"})
	} else {
		l.metrics.Inc("audit_redis_limiter_total", map[string]string{"result": "deny"})
	}
	return allowed, time.Duration(result[1]) * time.Millisecond, nil
}

type MemoryLimiter struct{}                                                      // Used when Redis is deliberately disabled; it never rejects.
func (MemoryLimiter) Allow(context.Context, string) (bool, time.Duration, error) { return true, 0, nil }
