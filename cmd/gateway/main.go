package main

import (
	"log/slog"

	"github.com/example/ai-audit-gateway/internal/config"
	"github.com/example/ai-audit-gateway/internal/httpapi"
	"github.com/example/ai-audit-gateway/internal/observability"
	"github.com/example/ai-audit-gateway/internal/rule"
	"github.com/gofiber/fiber/v2"
)

func main() {
	cfg := config.Load()
	logger := observability.Logger()
	definitions := []rule.Definition{
		{ID: "secret-key", Name: "credential pattern", Pattern: "sk-[a-z0-9]", Severity: "high", Action: "block", Weight: 85, Regex: true},
		{ID: "prompt-injection", Name: "prompt injection marker", Pattern: "ignore previous instructions", Severity: "high", Action: "block", Weight: 85},
	}
	engine, err := rule.New(definitions)
	if err != nil {
		logger.Error("compile rules", slog.Any("error", err))
		return
	}
	app := fiber.New(fiber.Config{BodyLimit: cfg.MaxBodyBytes, DisableStartupMessage: true})
	httpapi.New(cfg, engine).Register(app)
	logger.Info("gateway listening", slog.String("addr", cfg.ListenAddr), slog.String("upstream", cfg.UpstreamURL))
	if err := app.Listen(cfg.ListenAddr); err != nil {
		logger.Error("gateway stopped", slog.Any("error", err))
	}
}
