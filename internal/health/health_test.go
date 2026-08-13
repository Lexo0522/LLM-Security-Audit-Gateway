package health

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRequiredComponentControlsReadiness(t *testing.T) {
	manager := New(time.Hour, time.Second, nil)
	manager.Add("postgres", true, func(context.Context) (map[string]any, error) { return map[string]any{"identity": "ok"}, nil })
	manager.Add("redis", false, func(context.Context) (map[string]any, error) { return nil, errors.New("offline") })
	manager.ProbeNow(t.Context())
	if !manager.Ready() || manager.Report().Components["redis"].Status != "error" {
		t.Fatalf("report=%+v", manager.Report())
	}
	manager.SetRequiredFailure("postgres", "offline", nil)
	if manager.Ready() || manager.Report().Components["postgres"].Status != "error" {
		t.Fatalf("report=%+v", manager.Report())
	}
}
