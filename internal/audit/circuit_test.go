package audit

import (
	"context"
	"errors"
	"testing"
	"time"
)

type failingAuditor struct{ calls int }

func (a *failingAuditor) Audit(context.Context, Input) (ModelResult, error) {
	a.calls++
	return ModelResult{}, errors.New("down")
}
func (a *failingAuditor) Health(context.Context) error { return nil }
func (a *failingAuditor) Name() string                 { return "fail" }
func TestCircuitOpensAfterFiveFailures(t *testing.T) {
	inner := &failingAuditor{}
	breaker := NewCircuitBreaker(inner, 5, 1, time.Second)
	for i := 0; i < 5; i++ {
		if _, err := breaker.Audit(context.Background(), Input{}); err == nil {
			t.Fatal("expected error")
		}
	}
	if _, err := breaker.Audit(context.Background(), Input{}); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("got %v", err)
	}
	if inner.calls != 5 {
		t.Fatalf("calls=%d", inner.calls)
	}
}
