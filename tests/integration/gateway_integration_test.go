//go:build integration

package integration

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/example/ai-audit-gateway/internal/audit"
	"github.com/example/ai-audit-gateway/internal/auth"
	"github.com/example/ai-audit-gateway/internal/events"
	"github.com/example/ai-audit-gateway/internal/policy"
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

func TestPostgresGatewayIdentityAndPolicyPersistence(t *testing.T) {
	ctx := context.Background()
	repo, err := storage.Open(ctx, os.Getenv("POSTGRES_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err = repo.EnsurePolicies(ctx); err != nil {
		t.Fatal(err)
	}
	manager, err := auth.NewManager(repo, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	record, key, err := manager.Create(ctx, "tenant-persistence")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := manager.Authenticate(ctx, "Bearer "+key)
	if err != nil || identity.TenantID != record.TenantID {
		t.Fatalf("identity=%+v err=%v", identity, err)
	}
	if _, found, err := manager.Revoke(ctx, record.ID); err != nil || !found {
		t.Fatalf("revoke found=%v err=%v", found, err)
	}
	if _, err = manager.Authenticate(ctx, "Bearer "+key); !errors.Is(err, auth.ErrInvalidKey) {
		t.Fatalf("revoked key error=%v", err)
	}
	created, err := repo.CreatePolicy(ctx, policy.Policy{Scope: "tenant:tenant-persistence", RoutePath: "/v1/chat/completions", Direction: "request", MonitorAt: 10, InterventionAt: 20, InterventionAction: policy.Redact, AuditorFailureMode: "fail_closed"})
	if err != nil {
		t.Fatal(err)
	}
	resolver := policy.NewResolver(repo)
	if err = resolver.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	resolved := resolver.Resolve("tenant-persistence", "/v1/chat/completions", "request")
	if resolved.ID != created.ID || resolved.InterventionAction != policy.Redact {
		t.Fatalf("resolved=%+v", resolved)
	}
}

func TestPostgresAuditEventPersistence(t *testing.T) {
	ctx := context.Background()
	repo, err := storage.Open(ctx, os.Getenv("POSTGRES_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	event := audit.Event{
		SchemaVersion: "2",
		EventID:       uuid.NewString(),
		EventTime:     time.Now().UTC(),
		RequestID:     "integration-audit-persistence",
		TenantID:      "tenant-persistence",
		Direction:     audit.DirectionRequest,
		Path:          "/v1/chat/completions",
		Decision:      "allow",
		RuleVersion:   "integration",
	}
	if err := repo.StoreEvents(ctx, []audit.Event{event}); err != nil {
		t.Fatalf("store audit event: %v", err)
	}
	// Retries preserve the event ID. This must work with the partial unique
	// event_id index used by pre-existing installations as well as fresh ones.
	if err := repo.StoreEvents(ctx, []audit.Event{event}); err != nil {
		t.Fatalf("store duplicate audit event: %v", err)
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
