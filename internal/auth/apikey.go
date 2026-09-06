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
	digestSaltLength = 16
)

var (
	ErrInvalidKey  = errors.New("invalid gateway API key")
	ErrUnavailable = errors.New("gateway identity unavailable")
)

// KeyRecord contains safe key metadata and the verifier fields used internally.
type KeyRecord struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	UpstreamID  string     `json:"upstream_id,omitempty"`
	DisplayName string     `json:"display_name,omitempty"`
	Prefix      string     `json:"prefix"`
	CreatedAt   time.Time  `json:"created_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	KeyDigest   []byte     `json:"-"`
	KeySalt     []byte     `json:"-"`
}

type Identity struct {
	APIKeyID   string
	TenantID   string
	UpstreamID string
}

type Authenticator interface {
	Authenticate(context.Context, string) (Identity, error)
}

type KeyStore interface {
	CreateGatewayAPIKey(context.Context, KeyRecord) (KeyRecord, error)
	LookupGatewayAPIKey(context.Context, string) (KeyRecord, bool, error)
	ListGatewayAPIKeys(context.Context, string, int, int) ([]KeyRecord, int64, error)
	RevokeGatewayAPIKey(context.Context, string) (KeyRecord, bool, error)
}

type Manager struct {
	store KeyStore
}

// NewManager authenticates against per-key salted digests persisted by the KeyStore.
func NewManager(store KeyStore) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("API key store is required")
	}
	return &Manager{store: store}, nil
}

func (m *Manager) CreateForUpstream(ctx context.Context, tenantID, upstreamID, displayName string) (KeyRecord, string, error) {
	if !ValidTenantID(tenantID) {
		return KeyRecord{}, "", fmt.Errorf("invalid tenant_id")
	}
	if upstreamID == "" {
		return KeyRecord{}, "", fmt.Errorf("upstream_id is required")
	}
	if _, err := uuid.Parse(upstreamID); err != nil {
		return KeyRecord{}, "", fmt.Errorf("invalid upstream_id")
	}
	secret := make([]byte, secretByteLength)
	if _, err := rand.Read(secret); err != nil {
		return KeyRecord{}, "", fmt.Errorf("generate API key secret: %w", err)
	}
	id := uuid.NewString()
	key := keyPrefix + "." + id + "." + base64.RawURLEncoding.EncodeToString(secret)
	record := KeyRecord{ID: id, TenantID: tenantID, UpstreamID: upstreamID, DisplayName: displayName, Prefix: keyPrefix + "." + id + "."}
	record.KeySalt = make([]byte, digestSaltLength)
	if _, err := rand.Read(record.KeySalt); err != nil {
		return KeyRecord{}, "", fmt.Errorf("generate API key salt: %w", err)
	}
	record.KeyDigest = DigestSalted(key, record.KeySalt)
	stored, err := m.store.CreateGatewayAPIKey(ctx, record)
	if err != nil {
		return KeyRecord{}, "", err
	}
	stored.KeyDigest, stored.KeySalt = nil, nil
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
	valid := false
	if found && record.RevokedAt == nil && len(record.KeyDigest) > 0 && len(record.KeySalt) > 0 {
		valid = hmac.Equal(record.KeyDigest, DigestSalted(key, record.KeySalt))
	}
	if !found || !valid {
		return Identity{}, ErrInvalidKey
	}
	return Identity{APIKeyID: record.ID, TenantID: record.TenantID, UpstreamID: record.UpstreamID}, nil
}

func (m *Manager) List(ctx context.Context, tenantID string, limit, offset int) ([]KeyRecord, int64, error) {
	if tenantID != "" && !ValidTenantID(tenantID) {
		return nil, 0, fmt.Errorf("invalid tenant_id")
	}
	return m.store.ListGatewayAPIKeys(ctx, tenantID, limit, offset)
}
func (m *Manager) Revoke(ctx context.Context, id string) (KeyRecord, bool, error) {
	if _, err := uuid.Parse(id); err != nil {
		return KeyRecord{}, false, fmt.Errorf("invalid API key id")
	}
	return m.store.RevokeGatewayAPIKey(ctx, id)
}
func DigestSalted(key string, salt []byte) []byte {
	h := sha256.New()
	_, _ = h.Write(salt)
	_, _ = h.Write([]byte(key))
	return h.Sum(nil)
}

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
