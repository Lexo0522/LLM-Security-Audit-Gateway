package main

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/example/ai-audit-gateway/internal/audit"
	"github.com/example/ai-audit-gateway/internal/config"
	"github.com/example/ai-audit-gateway/internal/events"
	"github.com/example/ai-audit-gateway/internal/httpapi"
	"github.com/example/ai-audit-gateway/internal/observability"
	"github.com/example/ai-audit-gateway/internal/ratelimit"
	"github.com/example/ai-audit-gateway/internal/rule"
	"github.com/example/ai-audit-gateway/internal/storage"
	"github.com/gofiber/fiber/v2"
)

var bootstrapRules = []rule.Definition{
	{ID: "secret-key", Name: "credential pattern", Pattern: "sk-[a-z0-9]", Severity: "high", Action: "block", Weight: 85, Regex: true},
	{ID: "prompt-injection", Name: "prompt injection marker", Pattern: "ignore previous instructions", Severity: "high", Action: "block", Weight: 85},
}

func main() {
	cfg := config.Load()
	logger := observability.Logger()
	ctx := context.Background()
	metrics := observability.NewMetrics()
	repo, err := storage.Open(ctx, cfg.PostgresURL)
	if err != nil {
		logger.Warn("postgres unavailable; persistence and rule management disabled", slog.Any("error", err))
		repo = nil
	}
	if repo != nil {
		if err = repo.Migrate(ctx); err != nil {
			logger.Error("postgres migration failed", slog.Any("error", err))
			return
		}
		if _, err = repo.EnsureBootstrap(ctx, bootstrapRules); err != nil {
			logger.Error("bootstrap rule setup failed", slog.Any("error", err))
			return
		}
		defer repo.Close()
	}
	var cachedRules *rule.CacheLoader
	if repo != nil {
		cachedRules, err = rule.NewCacheLoader(repo, cfg.RedisURL, metrics)
		if err != nil {
			logger.Warn("redis rule cache unavailable", slog.Any("error", err))
		}
	}
	loader := rule.RuleLoader(repo)
	if cachedRules != nil {
		loader = cachedRules
		defer cachedRules.Close()
	}
	registry, err := rule.NewRegistry(loader, bootstrapRules)
	if err != nil {
		logger.Error("compile bootstrap rules", slog.Any("error", err))
		return
	}
	if repo != nil {
		if err = registry.Refresh(ctx, "global"); err != nil {
			logger.Warn("using bootstrap rules", slog.Any("error", err))
		}
	}
	if cachedRules != nil {
		cachedRules.Subscribe(context.Background(), func(scope string) {
			if err := registry.Refresh(context.Background(), scope); err != nil {
				logger.Warn("rule refresh after cache invalidation failed", slog.Any("error", err))
			}
		})
	}
	limiter, err := ratelimit.NewRedis(cfg.RedisURL, cfg.RateLimitRPS, cfg.RateLimitBurst, metrics)
	if err != nil {
		logger.Warn("redis limiter unavailable", slog.Any("error", err))
		limiter = nil
	}
	if limiter != nil {
		defer limiter.Close()
	}
	var auditor audit.Auditor = audit.NoopAuditor{}
	if cfg.AuditorURL != "" {
		auditor = audit.NewCircuitBreaker(&audit.HTTPAuditor{URL: cfg.AuditorURL, Model: cfg.AuditorModel, Client: &http.Client{Timeout: time.Duration(cfg.AuditorTimeoutMS) * time.Millisecond}}, 5, cfg.AuditorConcurrency, 30*time.Second, metrics)
	}
	pipeline := events.NewPipeline(cfg.EventQueueSize, repo, events.NewKafka(cfg.KafkaBrokers, cfg.KafkaAuditTopic), logger, metrics)
	defer pipeline.Close()
	app := fiber.New(fiber.Config{BodyLimit: cfg.MaxBodyBytes, DisableStartupMessage: true})
	httpapi.New(cfg, registry, limiter, auditor, pipeline, metrics).Register(app)
	if cfg.AdminToken != "" && repo != nil {
		admin := fiber.New(fiber.Config{DisableStartupMessage: true})
		(&httpapi.Admin{Token: cfg.AdminToken, Repo: repo, Rules: registry, Events: pipeline, RuleChanged: func(ctx context.Context, scope string) {
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
	} else if cfg.AdminToken != "" {
		logger.Warn("admin API disabled because PostgreSQL is unavailable")
	}
	logger.Info("gateway listening", slog.String("addr", cfg.ListenAddr), slog.String("upstream", cfg.UpstreamURL))
	if err := app.Listen(cfg.ListenAddr); err != nil {
		logger.Error("gateway stopped", slog.Any("error", err))
	}
}
