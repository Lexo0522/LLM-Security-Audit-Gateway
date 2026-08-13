package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/example/ai-audit-gateway/internal/auth"
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
