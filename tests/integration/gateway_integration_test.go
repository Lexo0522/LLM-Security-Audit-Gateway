//go:build integration

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/example/ai-audit-gateway/internal/audit"
	"github.com/example/ai-audit-gateway/internal/events"
	"github.com/example/ai-audit-gateway/internal/ratelimit"
	"github.com/example/ai-audit-gateway/internal/storage"
	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
)

func TestPostgresMigrationAndRedisTokenBucket(t *testing.T) {
	ctx := context.Background()
	repo, err := storage.Open(ctx, os.Getenv("POSTGRES_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err := repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	limiter, err := ratelimit.NewRedis(os.Getenv("REDIS_URL"), 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer limiter.Close()
	if allowed, _, err := limiter.Allow(ctx, "integration:/v1/chat/completions"); err != nil || !allowed {
		t.Fatalf("first request allowed=%v err=%v", allowed, err)
	}
	if allowed, _, err := limiter.Allow(ctx, "integration:/v1/chat/completions"); err != nil || allowed {
		t.Fatalf("second request allowed=%v err=%v", allowed, err)
	}
}

func TestKafkaAuditEventSchemaAndTenantKey(t *testing.T) {
	topic := "audit.events.integration"
	publisher := events.NewKafka([]string{os.Getenv("KAFKA_BROKER")}, topic)
	if publisher == nil {
		t.Fatal("KAFKA_BROKER is required")
	}
	defer publisher.Close()
	event := audit.Event{SchemaVersion: "2", EventID: uuid.NewString(), TenantID: "tenant-a", Direction: audit.DirectionAdmin, Metadata: map[string]string{"operation": "publish"}}
	if err := publisher.Publish(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	reader := kafka.NewReader(kafka.ReaderConfig{Brokers: []string{os.Getenv("KAFKA_BROKER")}, Topic: topic, Partition: 0, StartOffset: kafka.FirstOffset, MaxWait: time.Second})
	defer reader.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10e9)
	defer cancel()
	message, err := reader.ReadMessage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(message.Key) != "tenant-a" {
		t.Fatalf("key=%q", message.Key)
	}
	if string(message.Value) == "" || !contains(string(message.Value), `"schema_version":"2"`) || contains(string(message.Value), `"text"`) {
		t.Fatalf("unexpected event payload: %s", message.Value)
	}
}
func contains(value, substring string) bool {
	return len(value) >= len(substring) && (value == substring || index(value, substring) >= 0)
}
func index(value, substring string) int {
	for i := 0; i+len(substring) <= len(value); i++ {
		if value[i:i+len(substring)] == substring {
			return i
		}
	}
	return -1
}
