package storage

import "time"

const (
	UpstreamLifecycleActive   = "active"
	UpstreamLifecycleDisabled = "disabled"
	UpstreamLifecycleDeleting = "deleting"
)

// AdminUser is the public administrator metadata model; password hashes are
// intentionally not exposed by repository reads.
type AdminUser struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type AdminSession struct {
	ID          string     `json:"id"`
	AdminUserID string     `json:"admin_user_id"`
	ExpiresAt   time.Time  `json:"expires_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

type Upstream struct {
	ID                string     `json:"id"`
	Name              string     `json:"name"`
	BaseURL           string     `json:"base_url"`
	Enabled           bool       `json:"enabled"`
	LifecycleState    string     `json:"lifecycle_state"`
	Status            string     `json:"status"`
	DeleteRequestedAt *time.Time `json:"delete_requested_at,omitempty"`
	PurgeAfter        *time.Time `json:"purge_after,omitempty"`
	HasAPIKey         bool       `json:"has_api_key"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// UpstreamSecret is returned only to trusted server-side callers. It must not
// be serialized in admin API responses.
type UpstreamSecret struct {
	Upstream
	APIKey string `json:"-"`
}

// UpstreamDeletion describes the result of a logical deletion request.
type UpstreamDeletion struct {
	Upstream
	Found        bool  `json:"found"`
	Transitioned bool  `json:"transitioned"`
	RevokedKeys  int64 `json:"revoked_keys"`
}
