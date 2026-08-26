package consumer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/segmentio/kafka-go"
)

type flakyWriter struct {
	failures int
	calls    int
	message  kafka.Message
}

func (w *flakyWriter) WriteMessages(_ context.Context, messages ...kafka.Message) error {
	w.calls++
	if w.calls <= w.failures {
		return errors.New("dlq unavailable")
	}
	w.message = messages[0]
	return nil
}

func (*flakyWriter) Close() error { return nil }

func TestDeadLetterPayloadPreservesInvalidJSONBytes(t *testing.T) {
	original := []byte{0xff, '{'}
	payload, err := deadLetterPayload(kafka.Message{Topic: "audit.events", Partition: 2, Offset: 9, Value: original}, "invalid json")
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		SourceTopic   string `json:"source_topic"`
		Partition     int    `json:"partition"`
		Offset        int64  `json:"offset"`
		Reason        string `json:"reason"`
		PayloadBase64 string `json:"payload_base64"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(envelope.PayloadBase64)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(original) || envelope.SourceTopic != "audit.events" || envelope.Partition != 2 || envelope.Offset != 9 {
		t.Fatalf("envelope=%+v payload=%v", envelope, decoded)
	}
}

func TestPublishDLQRetriesBeforeReturningSuccess(t *testing.T) {
	writer := &flakyWriter{failures: 2}
	consumer := &Consumer{dlq: writer, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), retry: time.Millisecond}
	message := kafka.Message{Topic: "audit.events", Value: []byte("not-json")}
	if err := consumer.publishDLQWithRetry(context.Background(), message, "invalid"); err != nil {
		t.Fatal(err)
	}
	if writer.calls != 3 {
		t.Fatalf("calls=%d", writer.calls)
	}
	if len(writer.message.Value) == 0 {
		t.Fatal("DLQ message was not written")
	}
}
