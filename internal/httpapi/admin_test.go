package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/example/ai-audit-gateway/internal/audit"
	"github.com/example/ai-audit-gateway/internal/auth"
	clickstore "github.com/example/ai-audit-gateway/internal/clickhouse"
	"github.com/gofiber/fiber/v2"
)

type adminKeyStore struct{ records map[string]auth.KeyRecord }

func (s *adminKeyStore) CreateGatewayAPIKey(_ context.Context, record auth.KeyRecord) (auth.KeyRecord, error) {
	if s.records == nil {
		s.records = map[string]auth.KeyRecord{}
	}
	record.CreatedAt = time.Now().UTC()
	s.records[record.ID] = record
	return record, nil
}

type auditReaderStub struct {
	page    clickstore.EventPage
	event   audit.Event
	summary clickstore.Summary
}

func (s auditReaderStub) ListEvents(_ context.Context, filter clickstore.EventFilter) (clickstore.EventPage, error) {
	if filter.TenantID != "tenant-a" || filter.Model != "gpt-test" || filter.RuleID != "rule-a" || filter.Limit != 10 {
		return clickstore.EventPage{}, errors.New("filter not forwarded")
	}
	return s.page, nil
}
func (s auditReaderStub) GetEvent(context.Context, string) (audit.Event, error) { return s.event, nil }
func (s auditReaderStub) Summary(context.Context, clickstore.EventFilter, string) (clickstore.Summary, error) {
	return s.summary, nil
}
func (s *adminKeyStore) LookupGatewayAPIKey(_ context.Context, id string) (auth.KeyRecord, bool, error) {
	value, found := s.records[id]
	return value, found, nil
}
func (s *adminKeyStore) ListGatewayAPIKeys(_ context.Context, tenant string) ([]auth.KeyRecord, error) {
	result := []auth.KeyRecord{}
	for _, value := range s.records {
		if tenant == "" || tenant == value.TenantID {
			value.KeyDigest = nil
			value.KeySalt = nil
			result = append(result, value)
		}
	}
	return result, nil
}
func (s *adminKeyStore) RevokeGatewayAPIKey(_ context.Context, id string) (auth.KeyRecord, bool, error) {
	value, found := s.records[id]
	if !found {
		return auth.KeyRecord{}, false, nil
	}
	if value.RevokedAt == nil {
		now := time.Now().UTC()
		value.RevokedAt = &now
		s.records[id] = value
	}
	value.KeyDigest = nil
	value.KeySalt = nil
	return value, true, nil
}

func TestAdminRequiresDatabaseSession(t *testing.T) {
	app := fiber.New()
	reader := auditReaderStub{page: clickstore.EventPage{Events: []audit.Event{{EventID: "event"}}}, summary: clickstore.Summary{TotalEvents: 1}}
	(&Admin{Audit: reader}).Register(app)
	request := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/events?tenant_id=tenant-a&model=gpt-test&rule_id=rule-a&page_size=10", nil)
	request.Header.Set("Authorization", "Bearer admin-token")
	response, err := app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want database-backed authentication", response.StatusCode)
	}
}

func TestAdminCSRFRejectsCrossOriginWrite(t *testing.T) {
	app := fiber.New()
	(&Admin{}).Register(app)
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/setup", strings.NewReader(`{"username":"admin","password":"a-long-enough-password"}`))
	request.Header.Set("Origin", "https://evil.example")
	request.Header.Set("Host", "localhost:3000")
	response, err := app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d, want CSRF rejection", response.StatusCode)
	}
}

func TestAdminCSRFAcceptsForwardedSameOrigin(t *testing.T) {
	app := fiber.New()
	(&Admin{}).Register(app)
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/setup", strings.NewReader(`{"username":"admin","password":"a-long-enough-password"}`))
	request.Header.Set("Origin", "http://localhost:3000")
	request.Header.Set("Host", "gateway:8081")
	request.Header.Set("X-Forwarded-Host", "localhost:3000")
	request.Header.Set("X-Forwarded-Proto", "http")
	response, err := app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusForbidden {
		t.Fatalf("same-origin request was rejected: status=%d", response.StatusCode)
	}
}
