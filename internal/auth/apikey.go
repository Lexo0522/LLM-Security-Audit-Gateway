package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	keyPrefix        = "agw"
	secretByteLength = 32
	minimumPepperLen = 32
)

var (
	ErrInvalidKey  = errors.New("invalid gateway API key")
	ErrUnavailable = errors.New("gateway identity unavailable")
)

// KeyRecord is safe to return from management APIs. HMAC is populated only
// while authenticating and is never serialized.
type KeyRecord struct {
	ID        string     `json:"id"`
	TenantID  string     `json:"tenant_id"`
	Prefix    string     `json:"prefix"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	HMAC      []byte     `json:"-"`
}

type Identity struct {
	APIKeyID string
	TenantID string
}

type Authenticator interface {
	Authenticate(context.Context, string) (Identity, error)
}

// KeyStore is implemented by the persistent credential repository.
type KeyStore interface {
	CreateGatewayAPIKey(context.Context, KeyRecord) (KeyRecord, error)
	LookupGatewayAPIKey(context.Context, string) (KeyRecord, bool, error)
	ListGatewayAPIKeys(context.Context, string) ([]KeyRecord, error)
	RevokeGatewayAPIKey(context.Context, string) (KeyRecord, bool, error)
}

type Manager struct {
	store  KeyStore
	pepper []byte
}

func NewManager(store KeyStore, pepper string) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("API key store is required")
	}
	if len(pepper) < minimumPepperLen {
		return nil, fmt.Errorf("GATEWAY_API_KEY_PEPPER must be at least %d bytes", minimumPepperLen)
	}
	return &Manager{store: store, pepper: []byte(pepper)}, nil
}

func (m *Manager) Create(ctx context.Context, tenantID string) (KeyRecord, string, error) {
	if !ValidTenantID(tenantID) {
		return KeyRecord{}, "", fmt.Errorf("invalid tenant_id")
	}
	secret := make([]byte, secretByteLength)
	if _, err := rand.Read(secret); err != nil {
		return KeyRecord{}, "", fmt.Errorf("generate API key secret: %w", err)
	}
	id := uuid.NewString()
	key := keyPrefix + "." + id + "." + base64.RawURLEncoding.EncodeToString(secret)
	record := KeyRecord{
		ID:       id,
		TenantID: tenantID,
		Prefix:   keyPrefix + "." + id + ".",
		HMAC:     Digest(key, m.pepper),
	}
	stored, err := m.store.CreateGatewayAPIKey(ctx, record)
	if err != nil {
		return KeyRecord{}, "", err
	}
	stored.HMAC = nil
	return stored, key, nil
}

func (m *Manager) Authenticate(ctx context.Context, authorization string) (Identity, error) {
	key, id, err := ParseBearerKey(authorization)
	if err != nil {
		return Identity{}, ErrInvalidKey
	}
	record, found, err := m.store.LookupGatewayAPIKey(ctx, id)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if !found || record.RevokedAt != nil || !hmac.Equal(record.HMAC, Digest(key, m.pepper)) {
		return Identity{}, ErrInvalidKey
	}
	return Identity{APIKeyID: record.ID, TenantID: record.TenantID}, nil
}

func (m *Manager) List(ctx context.Context, tenantID string) ([]KeyRecord, error) {
	if tenantID != "" && !ValidTenantID(tenantID) {
		return nil, fmt.Errorf("invalid tenant_id")
	}
	return m.store.ListGatewayAPIKeys(ctx, tenantID)
}

func (m *Manager) Revoke(ctx context.Context, id string) (KeyRecord, bool, error) {
	if _, err := uuid.Parse(id); err != nil {
		return KeyRecord{}, false, fmt.Errorf("invalid API key id")
	}
	return m.store.RevokeGatewayAPIKey(ctx, id)
}

func Digest(key string, pepper []byte) []byte {
	mac := hmac.New(sha256.New, pepper)
	_, _ = mac.Write([]byte(key))
	return mac.Sum(nil)
}

// ParseBearerKey validates the public wire format before any storage lookup.
func ParseBearerKey(authorization string) (string, string, error) {
	if !strings.HasPrefix(authorization, "Bearer ") {
		return "", "", ErrInvalidKey
	}
	key := strings.TrimPrefix(authorization, "Bearer ")
	parts := strings.Split(key, ".")
	if len(parts) != 3 || parts[0] != keyPrefix {
		return "", "", ErrInvalidKey
	}
	if _, err := uuid.Parse(parts[1]); err != nil {
		return "", "", ErrInvalidKey
	}
	secret, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(secret) != secretByteLength {
		return "", "", ErrInvalidKey
	}
	return key, parts[1], nil
}

func ValidTenantID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for i, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '.' || char == '-' || char == '_' {
			if i == 0 && (char == '.' || char == '-' || char == '_') {
				return false
			}
			continue
		}
		return false
	}
	return true
}
