package httpapi

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	clickstore "github.com/example/ai-audit-gateway/internal/clickhouse"
	"github.com/gofiber/fiber/v2"
)

func (a *Admin) listAuditEvents(c *fiber.Ctx) error {
	if a.Audit == nil {
		return fiber.ErrServiceUnavailable
	}
	filter, err := auditFilter(c)
	if err != nil {
		return auditQueryError(c, err)
	}
	page, err := a.Audit.ListEvents(c.UserContext(), filter)
	if err != nil {
		return auditQueryError(c, err)
	}
	return c.JSON(page)
}
func (a *Admin) getAuditEvent(c *fiber.Ctx) error {
	if a.Audit == nil {
		return fiber.ErrServiceUnavailable
	}
	event, err := a.Audit.GetEvent(c.UserContext(), c.Params("event_id"))
	if errors.Is(err, clickstore.ErrNotFound) {
		return fiber.ErrNotFound
	}
	if err != nil {
		return auditQueryError(c, err)
	}
	return c.JSON(event)
}
func (a *Admin) auditSummary(c *fiber.Ctx) error {
	if a.Audit == nil {
		return fiber.ErrServiceUnavailable
	}
	filter, err := auditFilter(c)
	if err != nil {
		return auditQueryError(c, err)
	}
	bucket := c.Query("bucket", "hour")
	result, err := a.Audit.Summary(c.UserContext(), filter, bucket)
	if err != nil {
		return auditQueryError(c, err)
	}
	return c.JSON(result)
}
func auditFilter(c *fiber.Ctx) (clickstore.EventFilter, error) {
	filter := clickstore.EventFilter{TenantID: c.Query("tenant_id"), Decision: c.Query("decision"), Direction: c.Query("direction"), Path: c.Query("path"), Model: c.Query("model"), RuleID: c.Query("rule_id"), Cursor: c.Query("cursor")}
	for _, target := range []struct {
		raw string
		set func(time.Time)
	}{{c.Query("from"), func(value time.Time) { filter.From = value }}, {c.Query("to"), func(value time.Time) { filter.To = value }}} {
		if target.raw == "" {
			continue
		}
		value, err := time.Parse(time.RFC3339, target.raw)
		if err != nil {
			return filter, fmt.Errorf("%w: timestamp: %v", clickstore.ErrInvalidFilter, err)
		}
		target.set(value)
	}
	if raw := c.Query("page_size"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil {
			return filter, fmt.Errorf("%w: page_size: %v", clickstore.ErrInvalidFilter, err)
		}
		filter.Limit = value
	}
	if raw := c.Query("min_risk_score"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil {
			return filter, fmt.Errorf("%w: min_risk_score: %v", clickstore.ErrInvalidFilter, err)
		}
		filter.MinRiskScore = &value
	}
	return filter, nil
}
func auditQueryError(c *fiber.Ctx, err error) error {
	if errors.Is(err, clickstore.ErrInvalidFilter) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fiber.Map{"message": err.Error()}})
	}
	return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": fiber.Map{"message": "audit query service unavailable"}})
}
