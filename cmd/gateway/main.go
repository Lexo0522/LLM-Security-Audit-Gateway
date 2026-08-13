package main

import (
	"context"
	"log/slog"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/example/ai-audit-gateway/internal/audit"
	"github.com/example/ai-audit-gateway/internal/auth"
	"github.com/example/ai-audit-gateway/internal/config"
	"github.com/example/ai-audit-gateway/internal/events"
	"github.com/example/ai-audit-gateway/internal/health"
	"github.com/example/ai-audit-gateway/internal/httpapi"
	"github.com/example/ai-audit-gateway/internal/observability"
	"github.com/example/ai-audit-gateway/internal/policy"
	"github.com/example/ai-audit-gateway/internal/ratelimit"
	"github.com/example/ai-audit-gateway/internal/rule"
	"github.com/example/ai-audit-gateway/internal/storage"
	"github.com/gofiber/fiber/v2"
)

var bootstrapRules = []rule.Definition{
	{ID: "secret-key", Name: "credential pattern", Pattern: "sk-[a-z0-9]", Severity: "high", Action: "block", Weight: 85, Regex: true},
	{ID: "prompt-injection", Name: "prompt injection marker", Pattern: "ignore previous instructions", Severity: "high", Action: "block", Weight: 85},
}

type managedRuleLoader struct{ repo *storage.Repository }

func (l managedRuleLoader) ActiveDefinitions(ctx context.Context, scope string) ([]rule.Definition, string, error) {
	return l.repo.ActiveManagedDefinitions(ctx, scope)
}

func main() {
	cfg := config.Load()
	logger := observability.Logger()
	if err := cfg.Validate(); err != nil {
		logger.Error("invalid gateway configuration", slog.Any("error", err))
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	metrics := observability.NewMetrics()
	repo, err := storage.Open(ctx, cfg.PostgresURL)
	if err != nil || repo == nil {
		logger.Error("postgres is required for gateway identity", slog.Any("error", err))
		return
	}
	if err = repo.Migrate(ctx); err != nil {
		logger.Error("postgres migration failed", slog.Any("error", err))
		return
	}
	if cfg.AllowDemoBootstrap {
		if _, err = repo.EnsureBootstrap(ctx, bootstrapRules); err != nil {
			logger.Error("demo bootstrap rule setup failed", slog.Any("error", err))
			return
		}
		if err = repo.EnsurePolicies(ctx); err != nil {
			logger.Error("demo bootstrap policy setup failed", slog.Any("error", err))
			return
		}
	} else if configured, configuredErr := repo.HasManagedConfiguration(ctx); configuredErr != nil || !configured {
		logger.Error("managed rules and global request/response policies are required; run cmd/seed before gateway startup", slog.Any("error", configuredErr))
		return
	}
	defer repo.Close()
	keys, err := auth.NewManager(repo, cfg.APIKeyPepper)
	if err != nil {
		logger.Error("create API key manager", slog.Any("error", err))
		return
	}
	policies := policy.NewResolver(repo)
	if err = policies.Refresh(ctx); err != nil {
		logger.Error("load policies", slog.Any("error", err))
		return
	}
	policyNotifier, err := policy.NewNotifier(cfg.RedisURL)
	if err != nil {
		logger.Warn("redis policy notifications unavailable", slog.Any("error", err))
	}
	if policyNotifier != nil {
		defer policyNotifier.Close()
		policyNotifier.Subscribe(context.Background(), func() {
			if refreshErr := policies.Refresh(context.Background()); refreshErr != nil {
				logger.Warn("policy refresh failed", slog.Any("error", refreshErr))
			}
		})
	}
	loader := rule.RuleLoader(repo)
	if !cfg.AllowDemoBootstrap {
		loader = managedRuleLoader{repo: repo}
	}
	var cachedRules *rule.CacheLoader
	if cfg.AllowDemoBootstrap {
		cachedRules, err = rule.NewCacheLoader(repo, cfg.RedisURL, metrics)
		if err != nil {
			logger.Warn("redis rule cache unavailable", slog.Any("error", err))
		}
	}
	if cachedRules != nil {
		loader = cachedRules
		defer cachedRules.Close()
	}
	registry, err := rule.NewRegistry(loader, bootstrapRules)
	if err != nil {
		logger.Error("compile bootstrap rules", slog.Any("error", err))
		return
	}
	if cfg.AllowDemoBootstrap {
		if err = registry.Refresh(ctx, "global"); err != nil {
			logger.Error("load demo rule snapshot", slog.Any("error", err))
			return
		}
		set, setErr := repo.Active(ctx, "global")
		if setErr != nil {
			logger.Error("read active rule snapshot metadata", slog.Any("error", setErr))
			return
		}
		registry.SetGlobalSource(set.Source)
	} else if err = registry.Refresh(ctx, "global"); err != nil {
		logger.Error("load managed rule snapshot", slog.Any("error", err))
		return
	}
	if cachedRules != nil {
		cachedRules.Subscribe(context.Background(), func(scope string) {
			if err := registry.Refresh(context.Background(), scope); err != nil {
				logger.Warn("rule refresh after cache invalidation failed", slog.Any("error", err))
			}
		})
	}
	limiter, err := ratelimit.NewAdaptiveRedis(cfg.RedisURL, cfg.RateLimitRPS, cfg.RateLimitBurst, metrics)
	if err != nil {
		logger.Warn("redis limiter unavailable", slog.Any("error", err))
		limiter, _ = ratelimit.NewAdaptiveRedis("", cfg.RateLimitRPS, cfg.RateLimitBurst, metrics)
	}
	if limiter != nil {
		defer limiter.Close()
	}
	var auditor audit.Auditor = audit.NoopAuditor{}
	if cfg.AuditorURL != "" {
		auditor = audit.NewCircuitBreaker(&audit.HTTPAuditor{URL: cfg.AuditorURL, Model: cfg.AuditorModel, Client: &http.Client{Timeout: time.Duration(cfg.AuditorTimeoutMS) * time.Millisecond}}, 5, cfg.AuditorConcurrency, 30*time.Second, metrics)
	}
	kafkaPublisher := events.NewKafka(cfg.KafkaBrokers, cfg.KafkaAuditTopic)
	repo.EnableOutbox(kafkaPublisher != nil)
	pipeline := events.NewPipeline(cfg.EventQueueSize, repo, nil, logger, metrics)
	defer pipeline.Close()
	dispatcher := events.NewDispatcher(repo, kafkaPublisher, logger, metrics)
	if dispatcher != nil {
		dispatcher.Start(ctx)
		defer dispatcher.Close()
	}
	readiness := health.New(time.Duration(cfg.HealthProbeIntervalMS)*time.Millisecond, time.Duration(cfg.HealthProbeTimeoutMS)*time.Millisecond, metrics)
	readiness.Add("postgres", true, func(probeCtx context.Context) (map[string]any, error) {
		if err := repo.Ready(probeCtx); err != nil {
			registry.MarkStale()
			policies.MarkStale()
			return health.RequiredError("postgres identity, snapshot, or audit store unavailable", nil)
		}
		return map[string]any{"identity": "ok", "audit": "ok"}, nil
	})
	readiness.Add("rules", true, func(context.Context) (map[string]any, error) {
		status := registry.Status()
		details := map[string]any{"version": status.Version, "source": status.Source, "stale": status.Stale}
		if !registry.Ready() {
			return health.RequiredError("managed rule snapshot unavailable", details)
		}
		return details, nil
	})
	readiness.Add("policies", true, func(context.Context) (map[string]any, error) {
		status := policies.Status()
		details := map[string]any{"hash": status.Hash, "count": status.Count, "stale": status.Stale}
		if status.Stale || status.Hash == "" || status.Count < 2 {
			return health.RequiredError("policy snapshot unavailable", details)
		}
		return details, nil
	})
	readiness.Add("audit_queue", true, func(context.Context) (map[string]any, error) {
		status := pipeline.Status()
		details := map[string]any{"capacity": status.Capacity, "pending": status.Pending, "saturated": status.Saturated}
		if !pipeline.Ready() {
			details["last_error"] = status.LastError
			return health.RequiredError("audit persistence queue unavailable", details)
		}
		return details, nil
	})
	pipeline.OnFailure(func(status events.Status) {
		readiness.SetRequiredFailure("audit_queue", "audit persistence queue unavailable", map[string]any{"capacity": status.Capacity, "pending": status.Pending, "saturated": status.Saturated, "last_error": status.LastError})
	})
	readiness.Add("redis", false, func(probeCtx context.Context) (map[string]any, error) {
		if limiter == nil {
			return map[string]any{"enabled": false}, health.ErrDisabled
		}
		details := map[string]any{"degraded": limiter.Degraded()}
		if err := limiter.Health(probeCtx); err != nil {
			return details, err
		}
		return details, nil
	})
	readiness.Add("kafka", false, func(probeCtx context.Context) (map[string]any, error) {
		if kafkaPublisher == nil {
			return map[string]any{"enabled": false}, health.ErrDisabled
		}
		details := map[string]any{"enabled": true}
		if pending, pendingErr := repo.OutboxPending(probeCtx); pendingErr == nil {
			details["pending"] = pending
		}
		if err := kafkaPublisher.Health(probeCtx); err != nil {
			return details, err
		}
		return details, nil
	})
	readiness.Add("auditor", false, func(probeCtx context.Context) (map[string]any, error) {
		if cfg.AuditorURL == "" {
			return map[string]any{"enabled": false}, health.ErrDisabled
		}
		return map[string]any{"enabled": true, "name": auditor.Name()}, auditor.Health(probeCtx)
	})
	readiness.Start(ctx)
	go refreshSnapshots(ctx, time.Duration(cfg.SnapshotRefreshIntervalMS)*time.Millisecond, registry, policies, logger, metrics)
	app := fiber.New(fiber.Config{BodyLimit: cfg.MaxBodyBytes, DisableStartupMessage: true})
	handler := httpapi.New(cfg, registry, policies, keys, limiter, auditor, pipeline, metrics)
	handler.SetReadiness(readiness)
	handler.Register(app)
	if cfg.AdminToken != "" {
		admin := fiber.New(fiber.Config{DisableStartupMessage: true})
		(&httpapi.Admin{Token: cfg.AdminToken, Repo: repo, Rules: registry, Events: pipeline, Keys: keys, Policies: policies, PolicyChanged: func(ctx context.Context) {
			if policyNotifier != nil {
				policyNotifier.Notify(ctx)
			}
		}, RuleChanged: func(ctx context.Context, scope string) {
			if cachedRules != nil {
				cachedRules.Invalidate(ctx, scope)
			}
		}}).Register(admin)
		go func() {
			logger.Info("admin API listening", slog.String("addr", cfg.AdminAddr))
			if err := admin.Listen(cfg.AdminAddr); err != nil {
				logger.Error("admin API stopped", slog.Any("error", err))
			}
		}()
	}
	logger.Info("gateway listening", slog.String("addr", cfg.ListenAddr), slog.String("upstream", cfg.UpstreamURL))
	if err := app.Listen(cfg.ListenAddr); err != nil {
		logger.Error("gateway stopped", slog.Any("error", err))
	}
}

func refreshSnapshots(ctx context.Context, interval time.Duration, registry *rule.Registry, policies *policy.Resolver, logger *slog.Logger, metrics *observability.Metrics) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			if err := registry.Refresh(refreshCtx, "global"); err != nil {
				registry.MarkStale()
				logger.Warn("rule snapshot refresh failed", slog.Any("error", err))
				metrics.Inc("audit_snapshot_refresh_total", map[string]string{"snapshot": "rules", "result": "error"})
			} else {
				metrics.Inc("audit_snapshot_refresh_total", map[string]string{"snapshot": "rules", "result": "success"})
			}
			if err := policies.Refresh(refreshCtx); err != nil {
				policies.MarkStale()
				logger.Warn("policy snapshot refresh failed", slog.Any("error", err))
				metrics.Inc("audit_snapshot_refresh_total", map[string]string{"snapshot": "policies", "result": "error"})
			} else {
				metrics.Inc("audit_snapshot_refresh_total", map[string]string{"snapshot": "policies", "result": "success"})
			}
			cancel()
		}
	}
}
