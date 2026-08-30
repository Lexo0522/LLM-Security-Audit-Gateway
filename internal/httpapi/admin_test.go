package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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
			value.HMAC = nil
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
	value.HMAC = nil
	return value, true, nil
}

func TestAdminAPIKeyLifecycleDoesNotLeakKeyMaterial(t *testing.T) {
	keys, err := auth.NewManager(&adminKeyStore{}, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	(&Admin{Token: "admin-token", Keys: keys}).Register(app)
	create := httptest.NewRequest(http.MethodPost, "/admin/v1/api-keys", strings.NewReader(`{"tenant_id":"tenant-a"}`))
	create.Header.Set("Authorization", "Bearer admin-token")
	create.Header.Set("Content-Type", "application/json")
	response, err := app.Test(create)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("status=%d", response.StatusCode)
	}
	var created struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.Key, "agw.") {
		t.Fatalf("unexpected key %q", created.Key)
	}
	list := httptest.NewRequest(http.MethodGet, "/admin/v1/api-keys?tenant_id=tenant-a", nil)
	list.Header.Set("Authorization", "Bearer admin-token")
	response, err = app.Test(list)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if strings.Contains(string(body), created.Key) || strings.Contains(string(body), "hmac") {
		t.Fatalf("list leaked secret: %s", body)
	}
	for i := 0; i < 2; i++ {
		revoke := httptest.NewRequest(http.MethodPost, "/admin/v1/api-keys/"+created.ID+"/revoke", nil)
		revoke.Header.Set("Authorization", "Bearer admin-token")
		response, err = app.Test(revoke)
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("revoke status=%d err=%v", response.StatusCode, err)
		}
		response.Body.Close()
	}
}

func TestAdminAuditQueriesRequireTokenAndForwardFilters(t *testing.T) {
	app := fiber.New()
	reader := auditReaderStub{page: clickstore.EventPage{Events: []audit.Event{{EventID: "event"}}}, summary: clickstore.Summary{TotalEvents: 1}}
	(&Admin{Token: "admin-token", Audit: reader}).Register(app)
	request := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/events?tenant_id=tenant-a&model=gpt-test&rule_id=rule-a&page_size=10", nil)
	response, err := app.Test(request)
	if err != nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%v err=%v", response.StatusCode, err)
	}
	response.Body.Close()
	request.Header.Set("Authorization", "Bearer admin-token")
	response, err = app.Test(request)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("authorized status=%v err=%v", response.StatusCode, err)
	}
	response.Body.Close()
	invalid := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/events?min_risk_score=not-a-number", nil)
	invalid.Header.Set("Authorization", "Bearer admin-token")
	response, err = app.Test(invalid)
	if err != nil || response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid status=%v err=%v", response.StatusCode, err)
	}
	response.Body.Close()
}

func TestAdminAuthenticateThrottlesFailures(t *testing.T) {
	app := fiber.New()
	(&Admin{Token: "admin-token", Repo: nil}).Register(app)
	for i := 0; i < 30; i++ {
		request := httptest.NewRequest(http.MethodGet, "/admin/v1/rule-sets", nil)
		request.Header.Set("Authorization", "Bearer wrong")
		response, err := app.Test(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if i < 29 && response.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("throttled too early at attempt %d", i+1)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/admin/v1/rule-sets", nil)
	request.Header.Set("Authorization", "Bearer wrong")
	response, err := app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status=%d, want 429 after repeated failures", response.StatusCode)
	}
	// Even a valid token stays throttled for this address until the window passes.
	valid := httptest.NewRequest(http.MethodGet, "/admin/v1/rule-sets", nil)
	valid.Header.Set("Authorization", "Bearer admin-token")
	response, err = app.Test(valid)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("valid token status=%d, want 429 while throttled", response.StatusCode)
	}
}
