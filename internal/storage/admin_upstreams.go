package storage

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	internalcrypto "github.com/example/ai-audit-gateway/internal/crypto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrDuplicateAdminUsername = errors.New("admin username already exists")
	ErrDuplicateUpstreamName  = errors.New("upstream name already exists")
	ErrInvalidUpstreamURL     = errors.New("invalid upstream URL")
	ErrUpstreamDisabled       = errors.New("upstream is disabled")
	ErrUpstreamDeleting       = errors.New("upstream is deleting")
	ErrUpstreamNotFound       = fmt.Errorf("%w: upstream not found", pgx.ErrNoRows)
)

func (r *Repository) CountAdminUsers(ctx context.Context) (int64, error) {
	if r == nil || r.pool == nil {
		return 0, fmt.Errorf("postgres disabled")
	}
	var count int64
	err := r.pool.QueryRow(ctx, `SELECT count(*) FROM admin_users`).Scan(&count)
	return count, err
}

func (r *Repository) CreateAdminUser(ctx context.Context, username string, passwordHash []byte) (AdminUser, error) {
	if r == nil || r.pool == nil {
		return AdminUser{}, fmt.Errorf("postgres disabled")
	}
	username = strings.TrimSpace(username)
	if username == "" || len(username) > 128 {
		return AdminUser{}, &ValidationError{fmt.Errorf("username must be 1..128 characters")}
	}
	var value AdminUser
	err := r.pool.QueryRow(ctx, `INSERT INTO admin_users(username,password_hash) VALUES($1,$2) RETURNING id,username,created_at,updated_at`, username, passwordHash).Scan(&value.ID, &value.Username, &value.CreatedAt, &value.UpdatedAt)
	if isUniqueViolation(err) {
		return AdminUser{}, ErrDuplicateAdminUsername
	}
	return value, err
}

func (r *Repository) GetAdminUser(ctx context.Context, username string) (AdminUser, []byte, error) {
	if r == nil || r.pool == nil {
		return AdminUser{}, nil, fmt.Errorf("postgres disabled")
	}
	var value AdminUser
	var passwordHash []byte
	err := r.pool.QueryRow(ctx, `SELECT id,username,password_hash,created_at,updated_at FROM admin_users WHERE username=$1`, username).Scan(&value.ID, &value.Username, &passwordHash, &value.CreatedAt, &value.UpdatedAt)
	return value, passwordHash, err
}

func (r *Repository) CreateAdminSession(ctx context.Context, userID string, tokenHash []byte, expiresAt time.Time) (AdminSession, error) {
	if r == nil || r.pool == nil {
		return AdminSession{}, fmt.Errorf("postgres disabled")
	}
	var value AdminSession
	err := r.pool.QueryRow(ctx, `INSERT INTO admin_sessions(admin_user_id,token_hash,expires_at) VALUES($1,$2,$3) RETURNING id,admin_user_id,expires_at,revoked_at,created_at`, userID, tokenHash, expiresAt).Scan(&value.ID, &value.AdminUserID, &value.ExpiresAt, &value.RevokedAt, &value.CreatedAt)
	return value, err
}

func (r *Repository) GetAdminSession(ctx context.Context, tokenHash []byte) (AdminSession, AdminUser, error) {
	if r == nil || r.pool == nil {
		return AdminSession{}, AdminUser{}, fmt.Errorf("postgres disabled")
	}
	var session AdminSession
	var user AdminUser
	err := r.pool.QueryRow(ctx, `SELECT s.id,s.admin_user_id,s.expires_at,s.revoked_at,s.created_at,u.id,u.username,u.created_at,u.updated_at FROM admin_sessions s JOIN admin_users u ON u.id=s.admin_user_id WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at > now()`, tokenHash).Scan(&session.ID, &session.AdminUserID, &session.ExpiresAt, &session.RevokedAt, &session.CreatedAt, &user.ID, &user.Username, &user.CreatedAt, &user.UpdatedAt)
	return session, user, err
}

func (r *Repository) RevokeAdminSession(ctx context.Context, tokenHash []byte) error {
	if r == nil || r.pool == nil {
		return fmt.Errorf("postgres disabled")
	}
	_, err := r.pool.Exec(ctx, `UPDATE admin_sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE token_hash=$1`, tokenHash)
	return err
}

// UpdateAdminPassword swaps the stored bcrypt hash for the user.
func (r *Repository) UpdateAdminPassword(ctx context.Context, userID string, passwordHash []byte) error {
	if r == nil || r.pool == nil {
		return fmt.Errorf("postgres disabled")
	}
	tag, err := r.pool.Exec(ctx, `UPDATE admin_users SET password_hash=$2, updated_at=now() WHERE id=$1`, userID, passwordHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("admin user %s not found", userID)
	}
	return nil
}

// RevokeAdminSessions revokes every live session of the user. A non-nil
// keptTokenHash spares one session — the one that issued the request, so a
// password change does not force an immediate re-login.
func (r *Repository) RevokeAdminSessions(ctx context.Context, userID string, keptTokenHash []byte) (int64, error) {
	if r == nil || r.pool == nil {
		return 0, fmt.Errorf("postgres disabled")
	}
	tag, err := r.pool.Exec(ctx, `UPDATE admin_sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE admin_user_id=$1 AND revoked_at IS NULL AND ($2::bytea IS NULL OR token_hash <> $2)`, userID, keptTokenHash)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func upstreamLifecycle(enabled bool) string {
	if enabled {
		return UpstreamLifecycleActive
	}
	return UpstreamLifecycleDisabled
}

func ValidateUpstreamURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" && parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil {
		return ErrInvalidUpstreamURL
	}
	return nil
}

func (r *Repository) CreateUpstream(ctx context.Context, name, baseURL, apiKey string, enabled bool, key *internalcrypto.Key) (Upstream, error) {
	if r == nil || r.pool == nil {
		return Upstream{}, fmt.Errorf("postgres disabled")
	}
	name = strings.TrimSpace(name)
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if name == "" || len(name) > 128 {
		return Upstream{}, &ValidationError{fmt.Errorf("upstream name must be 1..128 characters")}
	}
	if err := ValidateUpstreamURL(baseURL); err != nil {
		return Upstream{}, &ValidationError{err}
	}
	ciphertext, err := encryptSecret(apiKey, key)
	if err != nil {
		return Upstream{}, err
	}
	lifecycleState := upstreamLifecycle(enabled)
	var value Upstream
	err = r.pool.QueryRow(ctx, `INSERT INTO upstream_configs(name,base_url,api_key_ciphertext,enabled,lifecycle_state) VALUES($1,$2,$3,$4,$5) RETURNING id,name,base_url,enabled,lifecycle_state,lifecycle_state,delete_requested_at,purge_after,(api_key_ciphertext IS NOT NULL),created_at,updated_at`, name, baseURL, ciphertext, enabled, lifecycleState).Scan(&value.ID, &value.Name, &value.BaseURL, &value.Enabled, &value.LifecycleState, &value.Status, &value.DeleteRequestedAt, &value.PurgeAfter, &value.HasAPIKey, &value.CreatedAt, &value.UpdatedAt)
	if isUniqueViolation(err) {
		return Upstream{}, ErrDuplicateUpstreamName
	}
	return value, err
}

func (r *Repository) GetUpstream(ctx context.Context, id string, key *internalcrypto.Key) (UpstreamSecret, error) {
	if r == nil || r.pool == nil {
		return UpstreamSecret{}, fmt.Errorf("postgres disabled")
	}
	var value UpstreamSecret
	var ciphertext []byte
	err := r.pool.QueryRow(ctx, `SELECT id,name,base_url,enabled,lifecycle_state,lifecycle_state,delete_requested_at,purge_after,(api_key_ciphertext IS NOT NULL),api_key_ciphertext,created_at,updated_at FROM upstream_configs WHERE id=$1`, id).Scan(&value.ID, &value.Name, &value.BaseURL, &value.Enabled, &value.LifecycleState, &value.Status, &value.DeleteRequestedAt, &value.PurgeAfter, &value.HasAPIKey, &ciphertext, &value.CreatedAt, &value.UpdatedAt)
	if err != nil {
		return UpstreamSecret{}, err
	}
	if len(ciphertext) > 0 {
		if key == nil {
			return UpstreamSecret{}, fmt.Errorf("encryption key is required")
		}
		raw, decErr := key.Decrypt(ciphertext)
		if decErr != nil {
			return UpstreamSecret{}, fmt.Errorf("decrypt upstream API key: %w", decErr)
		}
		value.APIKey = string(raw)
	}
	return value, nil
}

func (r *Repository) ListUpstreams(ctx context.Context, limit, offset int) ([]Upstream, int64, error) {
	if r == nil || r.pool == nil {
		return nil, 0, fmt.Errorf("postgres disabled")
	}
	if limit < 0 {
		limit = 0
	}
	if offset < 0 {
		offset = 0
	}
	var total int64
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM upstream_configs`).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `SELECT id,name,base_url,enabled,lifecycle_state,lifecycle_state,delete_requested_at,purge_after,(api_key_ciphertext IS NOT NULL),created_at,updated_at FROM upstream_configs ORDER BY name`
	args := []any{}
	if limit > 0 {
		query += ` LIMIT $1 OFFSET $2`
		args = append(args, limit, offset)
	}
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	result := []Upstream{}
	for rows.Next() {
		var v Upstream
		if err := rows.Scan(&v.ID, &v.Name, &v.BaseURL, &v.Enabled, &v.LifecycleState, &v.Status, &v.DeleteRequestedAt, &v.PurgeAfter, &v.HasAPIKey, &v.CreatedAt, &v.UpdatedAt); err != nil {
			return nil, 0, err
		}
		result = append(result, v)
	}
	return result, total, rows.Err()
}

func (r *Repository) UpdateUpstream(ctx context.Context, id, name, baseURL, apiKey string, enabled bool, key *internalcrypto.Key) (Upstream, error) {
	if r == nil || r.pool == nil {
		return Upstream{}, fmt.Errorf("postgres disabled")
	}
	name = strings.TrimSpace(name)
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if name == "" || len(name) > 128 {
		return Upstream{}, &ValidationError{fmt.Errorf("upstream name must be 1..128 characters")}
	}
	if err := ValidateUpstreamURL(baseURL); err != nil {
		return Upstream{}, &ValidationError{err}
	}
	var value Upstream
	var err error
	if apiKey != "" {
		var ciphertext []byte
		ciphertext, err = encryptSecret(apiKey, key)
		if err != nil {
			return Upstream{}, err
		}
		err = r.pool.QueryRow(ctx, `UPDATE upstream_configs SET name=$2,base_url=$3,api_key_ciphertext=$4,enabled=$5,lifecycle_state=$6,updated_at=now() WHERE id=$1 AND lifecycle_state IN ('active','disabled') RETURNING id,name,base_url,enabled,lifecycle_state,lifecycle_state,delete_requested_at,purge_after,(api_key_ciphertext IS NOT NULL),created_at,updated_at`, id, name, baseURL, ciphertext, enabled, upstreamLifecycle(enabled)).Scan(&value.ID, &value.Name, &value.BaseURL, &value.Enabled, &value.LifecycleState, &value.Status, &value.DeleteRequestedAt, &value.PurgeAfter, &value.HasAPIKey, &value.CreatedAt, &value.UpdatedAt)
	} else {
		err = r.pool.QueryRow(ctx, `UPDATE upstream_configs SET name=$2,base_url=$3,enabled=$4,lifecycle_state=$5,updated_at=now() WHERE id=$1 AND lifecycle_state IN ('active','disabled') RETURNING id,name,base_url,enabled,lifecycle_state,lifecycle_state,delete_requested_at,purge_after,(api_key_ciphertext IS NOT NULL),created_at,updated_at`, id, name, baseURL, enabled, upstreamLifecycle(enabled)).Scan(&value.ID, &value.Name, &value.BaseURL, &value.Enabled, &value.LifecycleState, &value.Status, &value.DeleteRequestedAt, &value.PurgeAfter, &value.HasAPIKey, &value.CreatedAt, &value.UpdatedAt)
	}
	if err == pgx.ErrNoRows {
		var state string
		if stateErr := r.pool.QueryRow(ctx, `SELECT lifecycle_state FROM upstream_configs WHERE id=$1`, id).Scan(&state); stateErr == nil && state == UpstreamLifecycleDeleting {
			return Upstream{}, ErrUpstreamDeleting
		}
		return Upstream{}, ErrUpstreamNotFound
	}
	if isUniqueViolation(err) {
		return Upstream{}, ErrDuplicateUpstreamName
	}
	return value, err
}

// RequestUpstreamDeletion atomically transitions an upstream into deleting,
// revokes its gateway keys, and erases its stored secret. It is idempotent.
func (r *Repository) RequestUpstreamDeletion(ctx context.Context, id uuid.UUID, gracePeriods ...time.Duration) (UpstreamDeletion, error) {
	if r == nil || r.pool == nil {
		return UpstreamDeletion{}, fmt.Errorf("postgres disabled")
	}
	gracePeriod := 24 * time.Hour
	if len(gracePeriods) > 0 && gracePeriods[0] > 0 {
		gracePeriod = gracePeriods[0]
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return UpstreamDeletion{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var value UpstreamDeletion
	err = tx.QueryRow(ctx, `SELECT id,name,base_url,enabled,lifecycle_state,lifecycle_state,delete_requested_at,purge_after,(api_key_ciphertext IS NOT NULL),created_at,updated_at FROM upstream_configs WHERE id=$1 FOR UPDATE`, id).Scan(&value.ID, &value.Name, &value.BaseURL, &value.Enabled, &value.LifecycleState, &value.Status, &value.DeleteRequestedAt, &value.PurgeAfter, &value.HasAPIKey, &value.CreatedAt, &value.UpdatedAt)
	if err == pgx.ErrNoRows {
		return UpstreamDeletion{Found: false}, ErrUpstreamNotFound
	}
	if err != nil {
		return UpstreamDeletion{}, err
	}
	value.Found = true
	if value.LifecycleState == UpstreamLifecycleDeleting {
		value.Transitioned = false
		if err := tx.Commit(ctx); err != nil {
			return UpstreamDeletion{}, err
		}
		return value, nil
	}
	now := time.Now().UTC()
	purgeAfter := now.Add(gracePeriod)
	if _, err = tx.Exec(ctx, `UPDATE upstream_configs SET lifecycle_state='deleting',enabled=false,delete_requested_at=$2,purge_after=$3,api_key_ciphertext=NULL,updated_at=now() WHERE id=$1`, id, now, purgeAfter); err != nil {
		return UpstreamDeletion{}, err
	}
	var revoked int64
	if err = tx.QueryRow(ctx, `WITH revoked AS (UPDATE gateway_api_keys SET revoked_at=COALESCE(revoked_at,now()) WHERE upstream_id=$1 AND revoked_at IS NULL RETURNING 1) SELECT count(*) FROM revoked`, id).Scan(&revoked); err != nil {
		return UpstreamDeletion{}, err
	}
	value.Enabled = false
	value.LifecycleState = UpstreamLifecycleDeleting
	value.Status = UpstreamLifecycleDeleting
	value.DeleteRequestedAt = &now
	value.PurgeAfter = &purgeAfter
	value.HasAPIKey = false
	value.Transitioned = true
	value.RevokedKeys = revoked
	if err = tx.Commit(ctx); err != nil {
		return UpstreamDeletion{}, err
	}
	return value, nil
}

// GetUpstreamDeletionBacklog returns the authoritative deletion state from
// PostgreSQL. Malformed deleting rows are reported separately because the
// finalizer cannot safely purge them.
func (r *Repository) GetUpstreamDeletionBacklog(ctx context.Context) (UpstreamDeletionBacklog, error) {
	if r == nil || r.pool == nil {
		return UpstreamDeletionBacklog{}, fmt.Errorf("postgres disabled")
	}
	var backlog UpstreamDeletionBacklog
	var oldest *time.Time
	err := r.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE lifecycle_state='deleting'), count(*) FILTER (WHERE lifecycle_state='deleting' AND delete_requested_at IS NOT NULL AND purge_after IS NOT NULL AND purge_after >= delete_requested_at AND purge_after <= now()), count(*) FILTER (WHERE lifecycle_state='deleting' AND (delete_requested_at IS NULL OR purge_after IS NULL OR purge_after < delete_requested_at)), min(purge_after) FILTER (WHERE lifecycle_state='deleting' AND purge_after IS NOT NULL) FROM upstream_configs`).Scan(&backlog.Pending, &backlog.Due, &backlog.Malformed, &oldest)
	if err != nil {
		return UpstreamDeletionBacklog{}, err
	}
	backlog.OldestPurgeAfter = oldest
	if oldest != nil {
		backlog.OldestOverdueSeconds = time.Since(oldest.UTC()).Seconds()
		if backlog.OldestOverdueSeconds < 0 {
			backlog.OldestOverdueSeconds = 0
		}
	}
	return backlog, nil
}

// FinalizeDueUpstreamDeletionsResult reports committed work and the remaining
// database-backed backlog. Each upstream is processed in its own transaction.
func (r *Repository) FinalizeDueUpstreamDeletionsResult(ctx context.Context, limit int) (UpstreamFinalizationResult, error) {
	if r == nil || r.pool == nil {
		return UpstreamFinalizationResult{}, nil
	}
	if limit < 1 {
		limit = 100
	}
	var result UpstreamFinalizationResult
	for result.Finalized < int64(limit) {
		tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return r.finalizationResult(ctx, result, err)
		}
		var id string
		err = tx.QueryRow(ctx, `SELECT id FROM upstream_configs WHERE lifecycle_state='deleting' AND delete_requested_at IS NOT NULL AND purge_after IS NOT NULL AND purge_after >= delete_requested_at AND purge_after <= now() ORDER BY purge_after LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&id)
		if err == pgx.ErrNoRows {
			_ = tx.Rollback(ctx)
			return r.finalizationResult(ctx, result, nil)
		}
		if err != nil {
			_ = tx.Rollback(ctx)
			return r.finalizationResult(ctx, result, err)
		}
		var revokedKeys int64
		if tag, deleteErr := tx.Exec(ctx, `DELETE FROM gateway_api_keys WHERE upstream_id=$1 AND revoked_at IS NOT NULL`, id); deleteErr != nil {
			_ = tx.Rollback(ctx)
			return r.finalizationResult(ctx, result, deleteErr)
		} else {
			revokedKeys = tag.RowsAffected()
		}
		if tag, deleteErr := tx.Exec(ctx, `DELETE FROM upstream_configs WHERE id=$1 AND lifecycle_state='deleting'`, id); deleteErr != nil {
			_ = tx.Rollback(ctx)
			return r.finalizationResult(ctx, result, deleteErr)
		} else if tag.RowsAffected() != 1 {
			_ = tx.Rollback(ctx)
			return r.finalizationResult(ctx, result, fmt.Errorf("upstream finalization lost %s", id))
		}
		if err = tx.Commit(ctx); err != nil {
			return r.finalizationResult(ctx, result, err)
		}
		result.Finalized++
		result.RevokedKeys += revokedKeys
	}
	return r.finalizationResult(ctx, result, nil)
}

func (r *Repository) finalizationResult(ctx context.Context, result UpstreamFinalizationResult, cause error) (UpstreamFinalizationResult, error) {
	backlog, err := r.GetUpstreamDeletionBacklog(ctx)
	result.Backlog = backlog
	if cause != nil {
		if err != nil {
			return result, fmt.Errorf("%w; read deletion backlog: %v", cause, err)
		}
		return result, cause
	}
	return result, err
}

// GetUpstreamForGatewayKey resolves the immutable key binding and enforces the
// enabled flag in the same query, preventing a stale or disabled route.
func (r *Repository) GetUpstreamForGatewayKey(ctx context.Context, keyID string, key *internalcrypto.Key) (UpstreamSecret, error) {
	if r == nil || r.pool == nil {
		return UpstreamSecret{}, fmt.Errorf("postgres disabled")
	}
	var value UpstreamSecret
	var ciphertext []byte
	err := r.pool.QueryRow(ctx, `SELECT u.id,u.name,u.base_url,u.enabled,u.lifecycle_state,u.lifecycle_state,u.delete_requested_at,u.purge_after,(u.api_key_ciphertext IS NOT NULL),u.api_key_ciphertext,u.created_at,u.updated_at FROM gateway_api_keys k JOIN upstream_configs u ON u.id=k.upstream_id WHERE k.id=$1 AND k.revoked_at IS NULL AND u.lifecycle_state='active' AND u.enabled`, keyID).Scan(&value.ID, &value.Name, &value.BaseURL, &value.Enabled, &value.LifecycleState, &value.Status, &value.DeleteRequestedAt, &value.PurgeAfter, &value.HasAPIKey, &ciphertext, &value.CreatedAt, &value.UpdatedAt)
	if err != nil {
		return UpstreamSecret{}, err
	}
	if len(ciphertext) > 0 {
		if key == nil {
			return UpstreamSecret{}, fmt.Errorf("encryption key is required")
		}
		plain, decryptErr := key.Decrypt(ciphertext)
		if decryptErr != nil {
			return UpstreamSecret{}, fmt.Errorf("decrypt upstream API key: %w", decryptErr)
		}
		value.APIKey = string(plain)
	}
	return value, nil
}
func encryptSecret(secret string, key *internalcrypto.Key) ([]byte, error) {
	if secret == "" {
		return nil, nil
	}
	if key == nil {
		return nil, fmt.Errorf("encryption key is required")
	}
	return key.Encrypt([]byte(secret))
}

// HasUpstreamSecrets reports whether any upstream stores an encrypted API
// key. Startup uses it to refuse a freshly generated encryption key that
// would orphan existing ciphertexts.
func (r *Repository) HasUpstreamSecrets(ctx context.Context) (bool, error) {
	if r == nil || r.pool == nil {
		return false, fmt.Errorf("postgres disabled")
	}
	var count int64
	err := r.pool.QueryRow(ctx, `SELECT count(*) FROM upstream_configs WHERE api_key_ciphertext IS NOT NULL`).Scan(&count)
	return count > 0, err
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
