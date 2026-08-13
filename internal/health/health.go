// Package health owns bounded, dependency-safe readiness state. It never puts
// a dependency probe on the public request path.
package health

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/example/ai-audit-gateway/internal/observability"
)

type Probe func(context.Context) (map[string]any, error)

var ErrDisabled = errors.New("dependency disabled")

type Component struct {
	Required  bool           `json:"required"`
	Status    string         `json:"status"`
	CheckedAt time.Time      `json:"checked_at"`
	Error     string         `json:"error,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
}

type Report struct {
	Status     string               `json:"status"`
	Components map[string]Component `json:"components"`
}

type registeredProbe struct {
	required bool
	probe    Probe
}

type Manager struct {
	mu       sync.RWMutex
	probes   map[string]registeredProbe
	states   map[string]Component
	interval time.Duration
	timeout  time.Duration
	metrics  *observability.Metrics
}

func New(interval, timeout time.Duration, metrics *observability.Metrics) *Manager {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if timeout <= 0 {
		timeout = 750 * time.Millisecond
	}
	return &Manager{probes: map[string]registeredProbe{}, states: map[string]Component{}, interval: interval, timeout: timeout, metrics: metrics}
}

func (m *Manager) Add(name string, required bool, probe Probe) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.probes[name] = registeredProbe{required: required, probe: probe}
	m.states[name] = Component{Required: required, Status: "unknown"}
}

func (m *Manager) Start(ctx context.Context) {
	m.ProbeNow(ctx)
	go func() {
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.ProbeNow(ctx)
			}
		}
	}()
}

func (m *Manager) ProbeNow(ctx context.Context) {
	m.mu.RLock()
	probes := make(map[string]registeredProbe, len(m.probes))
	for name, probe := range m.probes {
		probes[name] = probe
	}
	m.mu.RUnlock()
	for name, registered := range probes {
		probeCtx, cancel := context.WithTimeout(ctx, m.timeout)
		details, err := registered.probe(probeCtx)
		cancel()
		state := Component{Required: registered.required, Status: "ok", CheckedAt: time.Now().UTC(), Details: details}
		if errors.Is(err, ErrDisabled) {
			state.Status = "disabled"
		} else if err != nil {
			state.Status = "error"
			state.Error = err.Error()
		}
		m.mu.Lock()
		m.states[name] = state
		m.mu.Unlock()
		if m.metrics != nil {
			value := 1.0
			if err != nil && !errors.Is(err, ErrDisabled) {
				value = 0
			}
			m.metrics.Set("audit_dependency_healthy", value, map[string]string{"component": name})
		}
	}
	if m.metrics != nil {
		value := 0.0
		if m.Ready() {
			value = 1
		}
		m.metrics.Set("audit_ready", value, nil)
	}
}

// SetRequiredFailure lets hot-path capacity guards withdraw readiness without
// waiting for the next scheduled dependency probe.
func (m *Manager) SetRequiredFailure(name, message string, details map[string]any) {
	m.mu.Lock()
	registered, ok := m.probes[name]
	if ok {
		m.states[name] = Component{Required: registered.required, Status: "error", CheckedAt: time.Now().UTC(), Error: message, Details: details}
	}
	m.mu.Unlock()
	if m.metrics != nil {
		m.metrics.Set("audit_ready", 0, nil)
	}
}

func (m *Manager) Ready() bool { return m.Report().Status == "ready" }

func (m *Manager) Report() Report {
	m.mu.RLock()
	defer m.mu.RUnlock()
	report := Report{Status: "ready", Components: make(map[string]Component, len(m.states))}
	for name, state := range m.states {
		if state.Details != nil {
			copy := make(map[string]any, len(state.Details))
			for key, value := range state.Details {
				copy[key] = value
			}
			state.Details = copy
		}
		report.Components[name] = state
		if state.Required && state.Status != "ok" {
			report.Status = "not_ready"
		}
	}
	return report
}

func RequiredError(message string, details map[string]any) (map[string]any, error) {
	return details, fmt.Errorf("%s", message)
}
