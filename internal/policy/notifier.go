package policy

import (
	"context"
	"github.com/redis/go-redis/v9"
)

const redisChannel = "audit-gateway:policies:changed"

type Notifier struct{ client *redis.Client }

func NewNotifier(redisURL string) (*Notifier, error) {
	if redisURL == "" {
		return nil, nil
	}
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}
	return &Notifier{client: redis.NewClient(opts)}, nil
}
func (n *Notifier) Close() error {
	if n == nil {
		return nil
	}
	return n.client.Close()
}
func (n *Notifier) Notify(ctx context.Context) {
	if n != nil {
		_ = n.client.Publish(ctx, redisChannel, "refresh").Err()
	}
}
func (n *Notifier) Subscribe(ctx context.Context, refresh func()) {
	if n == nil {
		return
	}
	sub := n.client.Subscribe(ctx, redisChannel)
	go func() {
		defer sub.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-sub.Channel():
				if !ok {
					return
				}
				refresh()
			}
		}
	}()
}
