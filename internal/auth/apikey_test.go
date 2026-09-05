package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

type memoryStore struct {
	keys map[string]KeyRecord
	err  error
}

func (s *memoryStore) CreateGatewayAPIKey(_ context.Context, record KeyRecord) (KeyRecord, error) {
	if s.keys == nil {
		s.keys = map[string]KeyRecord{}
	}
	record.CreatedAt = time.Now().UTC()
	s.keys[record.ID] = record
	return record, nil
}
func (s *memoryStore) LookupGatewayAPIKey(_ context.Context, id string) (KeyRecord, bool, error) {
	if s.err != nil {
		return KeyRecord{}, false, s.err
	}
	record, found := s.keys[id]
	return record, found, nil
}
func (s *memoryStore) ListGatewayAPIKeys(_ context.Context, _ string) ([]KeyRecord, error) {
	return nil, nil
}
func (s *memoryStore) RevokeGatewayAPIKey(_ context.Context, id string) (KeyRecord, bool, error) {
	record, found := s.keys[id]
	if !found {
		return KeyRecord{}, false, nil
	}
	now := time.Now().UTC()
	record.RevokedAt = &now
	s.keys[id] = record
	return record, true, nil
}

func TestGatewayAPIKeyFormatAndDigestAuthentication(t *testing.T) {
	store := &memoryStore{}
	manager, err := NewManager(store)
	if err != nil {
		t.Fatal(err)
	}
	record, key, err := manager.CreateForUpstream(t.Context(), "tenant-a", uuid.NewString(), "test")
	if err != nil {
		t.Fatal(err)
	}
	parsed, id, err := ParseBearerKey("Bearer " + key)
	if err != nil || parsed != key || id != record.ID {
		t.Fatalf("parsed=%q id=%q err=%v", parsed, id, err)
	}
	if len(store.keys[id].KeyDigest) != 32 || string(store.keys[id].KeyDigest) == key || len(store.keys[id].KeySalt) == 0 {
		t.Fatal("key material was not persisted as a salted digest")
	}
	identity, err := manager.Authenticate(t.Context(), "Bearer "+key)
	if err != nil || identity.TenantID != "tenant-a" || identity.APIKeyID != record.ID {
		t.Fatalf("identity=%+v err=%v", identity, err)
	}
}

func TestGatewayAPIKeyRejectsRevokedAndUnavailableKeys(t *testing.T) {
	store := &memoryStore{}
	manager, _ := NewManager(store)
	record, key, err := manager.CreateForUpstream(t.Context(), "tenant-a", uuid.NewString(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = manager.Revoke(t.Context(), record.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = manager.Authenticate(t.Context(), "Bearer "+key); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("revoked key error=%v", err)
	}
	store.err = errors.New("database down")
	if _, err = manager.Authenticate(t.Context(), "Bearer "+key); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unavailable error=%v", err)
	}
}
