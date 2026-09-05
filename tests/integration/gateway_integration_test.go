//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/example/ai-audit-gateway/internal/audit"
	"github.com/example/ai-audit-gateway/internal/auth"
	clickstore "github.com/example/ai-audit-gateway/internal/clickhouse"
	"github.com/example/ai-audit-gateway/internal/consumer"
	internalcrypto "github.com/example/ai-audit-gateway/internal/crypto"
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

func TestKafkaAuditEventIsAvailableInClickHouse(t *testing.T) {
	ctx := context.Background()
	destination, err := clickstore.Open(os.Getenv("CLICKHOUSE_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	if err = destination.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	topic := "audit.events.clickhouse.integration"
	group := "audit-clickhouse-integration-" + uuid.NewString()
	delivery, err := consumer.New(consumer.Config{Brokers: []string{os.Getenv("KAFKA_BROKERS")}, Topic: topic, GroupID: group}, destination, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	consumerCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- delivery.Run(consumerCtx) }()
	defer func() { cancel(); _ = delivery.Close(); <-done }()
	publisher := events.NewKafka([]string{os.Getenv("KAFKA_BROKERS")}, topic)
	defer publisher.Close()
	event := audit.Event{SchemaVersion: "2", EventID: uuid.NewString(), EventTime: time.Now().UTC(), RequestID: "clickhouse-consumer", TenantID: "tenant-clickhouse", Direction: audit.DirectionRequest, Path: "/v1/chat/completions", Model: "gpt-integration", Decision: "allow", RiskScore: 15, RuleVersion: "integration", LatencyMS: 12, Matches: []audit.Match{{RuleID: "rule-integration", Name: "integration", Action: "monitor", Weight: 15}}}
	if err = publisher.Publish(ctx, event); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		stored, queryErr := destination.GetEvent(ctx, event.EventID)
		if queryErr == nil {
			if stored.TenantID != event.TenantID {
				t.Fatalf("stored=%+v", stored)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("clickhouse event did not arrive: %v", queryErr)
		}
		time.Sleep(250 * time.Millisecond)
	}
	// Re-delivery keeps the same event ID and must collapse at query time.
	if err = destination.InsertEvents(ctx, []audit.Event{event}); err != nil {
		t.Fatal(err)
	}
	otherTenant := event
	otherTenant.EventID = uuid.NewString()
	otherTenant.RequestID = "clickhouse-other-tenant"
	otherTenant.TenantID = "tenant-other"
	if err = destination.InsertEvents(ctx, []audit.Event{otherTenant}); err != nil {
		t.Fatal(err)
	}
	filter := clickstore.EventFilter{From: event.EventTime.Add(-time.Minute), To: event.EventTime.Add(time.Minute), TenantID: event.TenantID, Model: event.Model, RuleID: "rule-integration", Limit: 10}
	page, err := destination.ListEvents(ctx, filter)
	if err != nil || len(page.Events) != 1 || page.Events[0].TenantID != event.TenantID {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	summary, err := destination.Summary(ctx, filter, "hour")
	if err != nil || summary.TotalEvents != 1 || summary.ByModel[event.Model] != 1 || summary.ByRule["rule-integration"] != 1 || summary.MaximumLatencyMS != event.LatencyMS {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}

	invalid := []byte{0xff, '{'}
	invalidWriter := &kafka.Writer{Addr: kafka.TCP(os.Getenv("KAFKA_BROKERS")), Topic: topic, RequiredAcks: kafka.RequireAll}
	if err = invalidWriter.WriteMessages(ctx, kafka.Message{Value: invalid}); err != nil {
		t.Fatal(err)
	}
	_ = invalidWriter.Close()
	dlqReader := kafka.NewReader(kafka.ReaderConfig{Brokers: []string{os.Getenv("KAFKA_BROKERS")}, Topic: topic + ".dlq", Partition: 0, StartOffset: kafka.FirstOffset})
	defer dlqReader.Close()
	dlqCtx, dlqCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dlqCancel()
	dlqMessage, err := dlqReader.ReadMessage(dlqCtx)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		PayloadBase64 string `json:"payload_base64"`
	}
	if err = json.Unmarshal(dlqMessage.Value, &envelope); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(envelope.PayloadBase64)
	if err != nil || string(decoded) != string(invalid) {
		t.Fatalf("decoded=%v err=%v payload=%s", decoded, err, dlqMessage.Value)
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
	manager, err := auth.NewManager(repo)
	if err != nil {
		t.Fatal(err)
	}
	encryptionKey, err := internalcrypto.New(make([]byte, internalcrypto.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	upstream, err := repo.CreateUpstream(ctx, "integration-upstream-"+uuid.NewString(), "http://127.0.0.1:1", "integration-upstream-key", true, encryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	record, key, err := manager.CreateForUpstream(ctx, "tenant-persistence", upstream.ID, "integration-key")
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
	publisher := events.NewKafka([]string{os.Getenv("KAFKA_BROKERS")}, topic)
	if publisher == nil {
		t.Fatal("KAFKA_BROKERS is required")
	}
	defer publisher.Close()
	event := audit.Event{SchemaVersion: "2", EventID: uuid.NewString(), TenantID: "tenant-a", Direction: audit.DirectionAdmin, Metadata: map[string]string{"operation": "publish"}}
	if err := publisher.Publish(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	reader := kafka.NewReader(kafka.ReaderConfig{Brokers: []string{os.Getenv("KAFKA_BROKERS")}, Topic: topic, Partition: 0, StartOffset: kafka.FirstOffset, MaxWait: time.Second})
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
