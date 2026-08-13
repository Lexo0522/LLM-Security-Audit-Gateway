package rule

import (
	"context"
	"sync"

	"github.com/example/ai-audit-gateway/internal/audit"
)

// Registry keeps tenant engines separate and never falls back from one tenant to another.
type Registry struct {
	repo          RuleLoader
	mu            sync.RWMutex
	global        *Engine
	globalVersion string
	globalSource  string
	globalStale   bool
	tenants       map[string]*tenantSnapshot
	resolved      map[string]struct{}
}
type Status struct {
	Version string `json:"version"`
	Source  string `json:"source"`
	Stale   bool   `json:"stale"`
}
type RuleLoader interface {
	ActiveDefinitions(context.Context, string) ([]Definition, string, error)
}
type tenantSnapshot struct {
	engine  *Engine
	version string
}

func NewRegistry(repo RuleLoader, bootstrap []Definition) (*Registry, error) {
	e, err := New(bootstrap)
	if err != nil {
		return nil, err
	}
	return &Registry{repo: repo, global: e, globalVersion: "bootstrap", globalSource: "demo", tenants: map[string]*tenantSnapshot{}, resolved: map[string]struct{}{}}, nil
}
func (r *Registry) Ready() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.global != nil && r.globalSource == "managed" && !r.globalStale
}
func (r *Registry) Status() Status {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return Status{Version: r.globalVersion, Source: r.globalSource, Stale: r.globalStale}
}
func (r *Registry) MarkStale() { r.mu.Lock(); defer r.mu.Unlock(); r.globalStale = true }
func (r *Registry) SetGlobalSource(source string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.globalSource = source
}
func (r *Registry) Audit(ctx context.Context, tenant string, input audit.Input) (audit.Result, string) {
	r.EnsureTenant(ctx, tenant)
	r.mu.RLock()
	if t := r.tenants[tenant]; t != nil {
		e, v := t.engine, t.version
		r.mu.RUnlock()
		return e.Audit(ctx, input), v
	}
	e, v := r.global, r.globalVersion
	r.mu.RUnlock()
	return e.Audit(ctx, input), v
}

// EnsureTenant makes one best-effort database lookup for a tenant. A missing or
// unavailable override leaves the global snapshot in effect without contaminating
// another tenant's cache entry.
func (r *Registry) EnsureTenant(ctx context.Context, tenant string) {
	r.mu.RLock()
	_, done := r.resolved[tenant]
	r.mu.RUnlock()
	if done || r.repo == nil {
		return
	}
	definitions, version, err := r.repo.ActiveDefinitions(ctx, "tenant:"+tenant)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, already := r.resolved[tenant]; already {
		return
	}
	r.resolved[tenant] = struct{}{}
	if err != nil {
		return
	}
	engine, err := New(definitions)
	if err == nil {
		r.tenants[tenant] = &tenantSnapshot{engine: engine, version: version}
	}
}
func (r *Registry) Refresh(ctx context.Context, scope string) error {
	if r.repo == nil {
		return nil
	}
	definitions, version, err := r.repo.ActiveDefinitions(ctx, scope)
	if err != nil {
		return err
	}
	engine, err := New(definitions)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if scope == "global" {
		// Source is configuration metadata, not an inference from a successful
		// refresh. In particular, a development loader may serve a demo snapshot.
		r.global, r.globalVersion, r.globalStale = engine, version, false
	} else {
		tenant := scope[len("tenant:"):]
		r.tenants[tenant] = &tenantSnapshot{engine, version}
		r.resolved[tenant] = struct{}{}
	}
	return nil
}
