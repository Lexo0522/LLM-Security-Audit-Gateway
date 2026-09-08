package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/example/ai-audit-gateway/internal/audit"
	"github.com/example/ai-audit-gateway/internal/auth"
	clickstore "github.com/example/ai-audit-gateway/internal/clickhouse"
	"github.com/example/ai-audit-gateway/internal/config"
	internalcrypto "github.com/example/ai-audit-gateway/internal/crypto"
	"github.com/example/ai-audit-gateway/internal/events"
	"github.com/example/ai-audit-gateway/internal/health"
	"github.com/example/ai-audit-gateway/internal/httpapi"
	"github.com/example/ai-audit-gateway/internal/observability"
	"github.com/example/ai-audit-gateway/internal/policy"
	"github.com/example/ai-audit-gateway/internal/proxy"
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

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	logger := observability.Logger()
	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid gateway configuration", slog.Any("error", err))
		return
	}
	if err := cfg.Validate(); err != nil {
		logger.Error("invalid gateway configuration", slog.Any("error", err))
		return
	}
	cfg.Version = version
	logger.Info("starting gateway", slog.String("version", version))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	metrics := observability.NewMetrics()
	repo, err := storage.Open(ctx, cfg.PostgresURL, storage.PoolSettings{
		MaxConns:        int32(min(cfg.PostgresPoolMaxConns, 1024)), // #nosec G115 -- capped below int32 range
		MaxConnLifetime: time.Duration(cfg.PostgresConnMaxLifetimeMS) * time.Millisecond,
		MaxConnIdleTime: time.Duration(cfg.PostgresConnMaxIdleMS) * time.Millisecond,
	})
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
	var auditStore *clickstore.Store
	if cfg.ClickHouseDSN != "" {
		auditStore, err = clickstore.Open(cfg.ClickHouseDSN)
		if err != nil {
			logger.Warn("clickhouse audit queries disabled", slog.Any("error", err))
		} else {
			defer auditStore.Close()
		}
	}
	encryptionKey, encryptionKeyCreated, err := internalcrypto.LoadOrCreateWithStatus(cfg.EncryptionKeyFile)
	if err != nil {
		logger.Error("load encryption key", slog.Any("error", err))
		return
	}
	if encryptionKeyCreated {
		allowGenerate := false
		if raw := os.Getenv("GATEWAY_ENCRYPTION_KEY_ALLOW_GENERATE"); raw != "" {
			allowGenerate, _ = strconv.ParseBool(raw)
		}
		if cfg.Environment == "production" && !allowGenerate {
			removeGeneratedEncryptionKey(cfg.EncryptionKeyFile, logger)
			logger.Error("a new gateway encryption key was generated; production refuses implicit key generation — restore the key file into GATEWAY_ENCRYPTION_KEY_FILE or set GATEWAY_ENCRYPTION_KEY_ALLOW_GENERATE=true if no secrets exist yet")
			return
		}
		// The key file and PostgreSQL are one recovery unit: a fresh key
		// paired with existing ciphertexts means those secrets are already
		// lost. Fail loudly instead of serving 502s with no explanation.
		orphaned, secretsErr := repo.HasUpstreamSecrets(ctx)
		if secretsErr != nil {
			logger.Error("check for existing upstream secrets", slog.Any("error", secretsErr))
			return
		}
		if orphaned {
			removeGeneratedEncryptionKey(cfg.EncryptionKeyFile, logger)
			logger.Error("the gateway encryption key file was missing and has been regenerated; stored upstream API keys can no longer be decrypted. Restore the original key file (the gateway-keys volume and PostgreSQL are one recovery unit), or delete the affected upstreams and re-enter their keys")
			return
		}
	}
	keys, err := auth.NewManager(repo)
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
	// PostgreSQL is the snapshot authority. Redis only accelerates invalidation;
	// it must never be in the polling path or make a valid snapshot stale.
	loader := rule.RuleLoader(repo)
	if !cfg.AllowDemoBootstrap {
		loader = managedRuleLoader{repo: repo}
	}
	var cachedRules *rule.CacheLoader
	cachedRules, err = rule.NewCacheLoader(repo, cfg.RedisURL, metrics)
	if err != nil {
		logger.Warn("redis rule notifications unavailable", slog.Any("error", err))
	}
	if cachedRules != nil {
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
	} else {
		registry.SetGlobalSource("managed")
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
	var shadowAuditor audit.Auditor
	if cfg.AuditorURL != "" {
		upstream := &audit.HTTPAuditor{URL: cfg.AuditorURL, Model: cfg.AuditorModel, Client: &http.Client{Timeout: time.Duration(cfg.AuditorTimeoutMS) * time.Millisecond}}
		auditor = audit.NewCircuitBreaker(upstream, 5, cfg.AuditorConcurrency, 30*time.Second, metrics)
		// Shadow audits get their own breaker so they can neither consume the
		// synchronous concurrency budget nor open the synchronous circuit.
		shadowAuditor = audit.NewCircuitBreaker(upstream, 5, cfg.AuditorConcurrency, 30*time.Second, metrics)
	}
	kafkaPublisher := events.NewKafka(cfg.KafkaBrokers, cfg.KafkaAuditTopic)
	repo.EnableOutbox(kafkaPublisher != nil)
	pipeline := events.NewPipeline(cfg.EventQueueSize, repo, logger, metrics)
	defer pipeline.Close()
	dispatcher := events.NewDispatcher(repo, kafkaPublisher, logger, metrics, cfg.OutboxClaimSize)
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
	runRetentionSweeper(ctx, cfg, repo, logger, metrics)
	runUpstreamDeletionFinalizer(ctx, cfg, repo, logger, metrics)
	app := fiber.New(fiber.Config{BodyLimit: cfg.MaxBodyBytes, DisableStartupMessage: true})
	handler := httpapi.New(cfg, registry, policies, keys, limiter, auditor, pipeline, metrics)
	handler.SetShadowAuditor(shadowAuditor)
	handler.SetReadiness(readiness)
	handler.SetUpstreamResolver(repo)
	handler.SetEncryptionKey(encryptionKey)
	handler.Register(app)
	{
		admin := fiber.New(fiber.Config{DisableStartupMessage: true})
		upstreamClient := proxy.New(cfg)
		(&httpapi.Admin{
			Logger: logger, EncryptionKey: encryptionKey, Repo: repo, Rules: registry, Events: pipeline, Keys: keys, Policies: policies, Audit: auditStore,
			UpstreamClient: upstreamClient, TargetPolicy: upstreamClient.TargetPolicy(),
			SessionTTL:                  time.Duration(cfg.AdminSessionTTLMS) * time.Millisecond,
			UpstreamDeletionGracePeriod: time.Duration(cfg.UpstreamDeletionGracePeriodMS) * time.Millisecond,
			CookieSecureMode:            cfg.AdminCookieSecureMode,
			TrustedOrigins:              cfg.AdminTrustedOrigins,
			LoginMaxFailures:            cfg.AdminLoginMaxFailures,
			LoginLockout:                time.Duration(cfg.AdminLoginLockoutMS) * time.Millisecond,
			PolicyChanged: func(ctx context.Context) {
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
	logger.Info("gateway listening", slog.String("addr", cfg.ListenAddr))
	if err := app.Listen(cfg.ListenAddr); err != nil {
		logger.Error("gateway stopped", slog.Any("error", err))
	}
}

func removeGeneratedEncryptionKey(path string, logger *slog.Logger) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		logger.Error("remove rejected generated encryption key", slog.Any("error", err))
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
			// Tenant snapshots resolved on this instance must also converge
			// after publish/rollback; a failed tenant refresh never flips the
			// global readiness signal.
			for _, scope := range registry.TenantScopes() {
				if err := registry.Refresh(refreshCtx, scope); err != nil {
					logger.Warn("tenant rule snapshot refresh failed", slog.String("scope", scope), slog.Any("error", err))
					metrics.Inc("audit_snapshot_refresh_total", map[string]string{"snapshot": "rules", "result": "error"})
				}
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

// runUpstreamDeletionFinalizer periodically physically removes upstreams whose
// deletion grace period has elapsed. The repository owns selection and locking;
// this worker only supplies the bounded batch size and lifecycle context.
func runUpstreamDeletionFinalizer(ctx context.Context, cfg config.Config, repo *storage.Repository, logger *slog.Logger, metrics *observability.Metrics) {
	if cfg.UpstreamDeletionSweepIntervalMS <= 0 || repo == nil {
		return
	}
	finalized := 0.0
	updateBacklog := func(backlog storage.UpstreamDeletionBacklog) {
		metrics.Set("upstream_deletion_backlog", float64(backlog.Pending), nil)
		metrics.Set("upstream_deletion_due", float64(backlog.Due), nil)
		metrics.Set("upstream_deletion_malformed", float64(backlog.Malformed), nil)
		metrics.Set("upstream_deletion_oldest_age_seconds", backlog.OldestOverdueSeconds, nil)
	}
	go func() {
		if backlog, err := repo.GetUpstreamDeletionBacklog(ctx); err != nil {
			logger.Warn("upstream deletion backlog refresh failed", slog.Any("error", err))
		} else {
			updateBacklog(backlog)
		}
		ticker := time.NewTicker(time.Duration(cfg.UpstreamDeletionSweepIntervalMS) * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				started := time.Now()
				sweepCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
				result, err := repo.FinalizeDueUpstreamDeletionsResult(sweepCtx, cfg.UpstreamDeletionBatchSize)
				cancel()
				metrics.Observe("upstream_deletion_finalizer_duration_seconds", time.Since(started).Seconds(), nil)
				updateBacklog(result.Backlog)
				if err != nil {
					logger.Warn("upstream deletion finalization failed", slog.Any("error", err), slog.Int64("finalized", result.Finalized), slog.Int64("revoked_keys", result.RevokedKeys), slog.Int64("backlog", result.Backlog.Pending), slog.Int64("due", result.Backlog.Due))
					metrics.Set("upstream_deletion_finalizer_last_error_timestamp", float64(time.Now().Unix()), nil)
					metrics.Inc("upstream_deletion_finalizer_total", map[string]string{"result": "error"})
					metrics.Inc("upstream_deletion_finalizer_failures_total", nil)
					metrics.Inc("upstream_deletion_finalizer_retries_total", nil)
					continue
				}
				metrics.Set("upstream_deletion_finalizer_last_success_timestamp", float64(time.Now().Unix()), nil)
				if result.Finalized == 0 && result.Backlog.Due > 0 {
					metrics.Set("upstream_deletion_finalizer_zero_progress_timestamp", float64(time.Now().Unix()), nil)
				}
				finalized += float64(result.Finalized)
				metrics.Set("upstream_deletion_rows_finalized", finalized, nil)
				metrics.Add("upstream_deletion_finalized_total", uint64(result.Finalized), nil)
				metrics.Add("upstream_deletion_keys_revoked_total", uint64(result.RevokedKeys), nil)
				metrics.Inc("upstream_deletion_finalizer_total", map[string]string{"result": "success"})
				if result.Finalized > 0 {
					logger.Info("upstream deletions finalized", slog.Int64("upstreams", result.Finalized), slog.Int64("revoked_keys", result.RevokedKeys), slog.Int64("backlog", result.Backlog.Pending))
				}
			}
		}
	}()
}

// runRetentionSweeper periodically deletes expired audit records and published
// outbox rows so PostgreSQL stays bounded. A zero sweep interval disables it;
// a zero retention disables the corresponding table's cleanup.
func runRetentionSweeper(ctx context.Context, cfg config.Config, repo *storage.Repository, logger *slog.Logger, metrics *observability.Metrics) {
	if cfg.RetentionSweepIntervalMS <= 0 || repo == nil {
		return
	}
	auditDeleted, outboxDeleted, sessionsDeleted := 0.0, 0.0, 0.0
	go func() {
		ticker := time.NewTicker(time.Duration(cfg.RetentionSweepIntervalMS) * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sweepCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
				auditRows, outboxRows, err := repo.CleanupExpired(sweepCtx,
					time.Duration(cfg.AuditRecordsRetentionDays)*24*time.Hour,
					time.Duration(cfg.OutboxRetentionDays)*24*time.Hour, 1000)
				if err == nil {
					// Sessions become unusable the moment they expire or are
					// revoked; the grace only keeps recent sign-out traces.
					sessionsRows, sessionsErr := repo.CleanupExpiredAdminSessions(sweepCtx, 24*time.Hour, 1000)
					if sessionsErr != nil {
						err = sessionsErr
					}
					sessionsDeleted += float64(sessionsRows)
				}
				cancel()
				if err != nil {
					logger.Warn("retention cleanup failed", slog.Any("error", err))
					metrics.Inc("audit_retention_sweeps_total", map[string]string{"result": "error"})
					continue
				}
				auditDeleted += float64(auditRows)
				outboxDeleted += float64(outboxRows)
				metrics.Set("audit_retention_rows_deleted", auditDeleted, map[string]string{"table": "audit_records"})
				metrics.Set("audit_retention_rows_deleted", outboxDeleted, map[string]string{"table": "audit_outbox"})
				metrics.Set("audit_retention_rows_deleted", sessionsDeleted, map[string]string{"table": "admin_sessions"})
				metrics.Inc("audit_retention_sweeps_total", map[string]string{"result": "success"})
				if auditRows > 0 || outboxRows > 0 {
					logger.Info("retention cleanup", slog.Int64("audit_records", auditRows), slog.Int64("audit_outbox", outboxRows))
				}
			}
		}
	}()
}
