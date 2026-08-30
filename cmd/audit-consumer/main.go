package main

import (
	"context"
	"log/slog"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	store "github.com/example/ai-audit-gateway/internal/clickhouse"
	"github.com/example/ai-audit-gateway/internal/config"
	"github.com/example/ai-audit-gateway/internal/consumer"
	"github.com/example/ai-audit-gateway/internal/health"
	"github.com/example/ai-audit-gateway/internal/observability"
	"github.com/gofiber/fiber/v2"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	logger, metrics := observability.Logger(), observability.NewMetrics()
	logger.Info("starting audit consumer", slog.String("version", version))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid audit consumer configuration", slog.Any("error", err))
		return
	}
	if cfg.ClickHouseDSN == "" || len(cfg.KafkaBrokers) == 0 {
		logger.Error("CLICKHOUSE_DSN and KAFKA_BROKERS are required for audit consumer")
		return
	}
	destination, err := store.Open(cfg.ClickHouseDSN)
	if err != nil {
		logger.Error("open clickhouse", slog.Any("error", err))
		return
	}
	defer destination.Close()
	dlq := cfg.KafkaAuditDLQTopic
	if dlq == "" {
		dlq = cfg.KafkaAuditTopic + ".dlq"
	}
	delivery, err := consumer.New(consumer.Config{Brokers: cfg.KafkaBrokers, Topic: cfg.KafkaAuditTopic, DLQTopic: dlq, GroupID: cfg.KafkaConsumerGroup}, destination, logger, metrics)
	if err != nil {
		logger.Error("create audit consumer", slog.Any("error", err))
		return
	}
	defer delivery.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	readiness := health.New(time.Duration(cfg.HealthProbeIntervalMS)*time.Millisecond, time.Duration(cfg.HealthProbeTimeoutMS)*time.Millisecond, metrics)
	readiness.Add("kafka", true, func(probe context.Context) (map[string]any, error) { return nil, delivery.KafkaHealth(probe) })
	readiness.Add("clickhouse", true, func(probe context.Context) (map[string]any, error) { return nil, delivery.ClickHouseHealth(probe) })
	readiness.Start(ctx)
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Get("/healthz", func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"status": "ok"}) })
	app.Get("/readyz", func(c *fiber.Ctx) error {
		report := readiness.Report()
		if report.Status != "ready" {
			return c.Status(http.StatusServiceUnavailable).JSON(report)
		}
		return c.JSON(report)
	})
	app.Get("/metrics", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, "text/plain; version=0.0.4; charset=utf-8")
		return c.SendString(metrics.Render())
	})
	go func() {
		logger.Info("audit consumer health API listening", slog.String("addr", cfg.ConsumerListenAddr))
		if err := app.Listen(cfg.ConsumerListenAddr); err != nil {
			logger.Error("audit consumer health API stopped", slog.Any("error", err))
		}
	}()
	if err := delivery.Run(ctx); err != nil {
		logger.Error("audit consumer stopped", slog.Any("error", err))
	}
}
