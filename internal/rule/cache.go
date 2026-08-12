package rule

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/example/ai-audit-gateway/internal/observability"
	"github.com/redis/go-redis/v9"
)

// CacheLoader caches immutable published snapshots. Cache failures fall through
// to PostgreSQL, so Redis cannot change rule correctness.
type CacheLoader struct {
	source  RuleLoader
	client  *redis.Client
	ttl     time.Duration
	metrics *observability.Metrics
}
type cachedSet struct {
	Version string       `json:"version"`
	Rules   []Definition `json:"rules"`
}

func NewCacheLoader(source RuleLoader, redisURL string, metrics ...*observability.Metrics) (*CacheLoader, error) {
	if source == nil || redisURL == "" {
		return nil, nil
	}
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}
	var collector *observability.Metrics
	if len(metrics) > 0 {
		collector = metrics[0]
	}
	return &CacheLoader{source: source, client: redis.NewClient(opts), ttl: 5 * time.Minute, metrics: collector}, nil
}
func (c *CacheLoader) Close() error {
	if c == nil {
		return nil
	}
	return c.client.Close()
}
func (c *CacheLoader) ActiveDefinitions(ctx context.Context, scope string) ([]Definition, string, error) {
	if c == nil {
		return nil, "", fmt.Errorf("rule cache disabled")
	}
	key := "audit-gateway:rules:" + scope
	if raw, err := c.client.Get(ctx, key).Bytes(); err == nil {
		var value cachedSet
		if json.Unmarshal(raw, &value) == nil && value.Version != "" {
			c.metrics.Inc("audit_redis_rule_cache_total", map[string]string{"result": "hit"})
			return value.Rules, value.Version, nil
		}
	} else if err != redis.Nil {
		c.metrics.Inc("audit_redis_rule_cache_total", map[string]string{"result": "error"})
	}
	c.metrics.Inc("audit_redis_rule_cache_total", map[string]string{"result": "miss"})
	rules, version, err := c.source.ActiveDefinitions(ctx, scope)
	if err != nil {
		return nil, "", err
	}
	if raw, marshalErr := json.Marshal(cachedSet{Version: version, Rules: rules}); marshalErr == nil {
		_ = c.client.Set(ctx, key, raw, c.ttl).Err()
	}
	return rules, version, nil
}
func (c *CacheLoader) Invalidate(ctx context.Context, scope string) {
	if c == nil {
		return
	}
	_ = c.client.Del(ctx, "audit-gateway:rules:"+scope).Err()
	_ = c.client.Publish(ctx, "audit-gateway:rules:changed", scope).Err()
}
func (c *CacheLoader) Subscribe(ctx context.Context, refresh func(string)) {
	if c == nil {
		return
	}
	sub := c.client.Subscribe(ctx, "audit-gateway:rules:changed")
	go func() {
		defer sub.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case message, ok := <-sub.Channel():
				if !ok {
					return
				}
				_ = c.client.Del(context.Background(), "audit-gateway:rules:"+message.Payload).Err()
				refresh(message.Payload)
			}
		}
	}()
}
