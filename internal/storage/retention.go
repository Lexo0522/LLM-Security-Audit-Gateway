package storage

import (
	"context"
	"time"
)

// CleanupExpired deletes audit records and published outbox rows older than
// their retention windows so PostgreSQL tables stay bounded. Deletion runs in
// id-batched chunks to keep each statement short. A zero duration disables the
// corresponding cleanup.
func (r *Repository) CleanupExpired(ctx context.Context, auditRetention, outboxRetention time.Duration, batchSize int) (auditDeleted, outboxDeleted int64, err error) {
	if r == nil || r.pool == nil {
		return 0, 0, nil
	}
	if batchSize < 1 {
		batchSize = 1000
	}
	if auditRetention > 0 {
		cutoff := time.Now().Add(-auditRetention)
		for {
			tag, execErr := r.pool.Exec(ctx, `DELETE FROM audit_records WHERE id IN (SELECT id FROM audit_records WHERE created_at < $1 LIMIT $2)`, cutoff, batchSize)
			if execErr != nil {
				return auditDeleted, outboxDeleted, execErr
			}
			auditDeleted += tag.RowsAffected()
			if tag.RowsAffected() < int64(batchSize) {
				break
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				return auditDeleted, outboxDeleted, ctxErr
			}
		}
	}
	if outboxRetention > 0 {
		cutoff := time.Now().Add(-outboxRetention)
		for {
			tag, execErr := r.pool.Exec(ctx, `DELETE FROM audit_outbox WHERE event_id IN (SELECT event_id FROM audit_outbox WHERE published_at IS NOT NULL AND published_at < $1 LIMIT $2)`, cutoff, batchSize)
			if execErr != nil {
				return auditDeleted, outboxDeleted, execErr
			}
			outboxDeleted += tag.RowsAffected()
			if tag.RowsAffected() < int64(batchSize) {
				break
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				return auditDeleted, outboxDeleted, ctxErr
			}
		}
	}
	return auditDeleted, outboxDeleted, nil
}

// CleanupExpiredAdminSessions deletes sessions that expired or were revoked
// more than graceAgo ago. Revoked rows are kept briefly so an administrator
// can still see recent sign-out activity; they are unusable the moment they
// expire or are revoked.
func (r *Repository) CleanupExpiredAdminSessions(ctx context.Context, graceAgo time.Duration, batchSize int) (int64, error) {
	if r == nil || r.pool == nil || graceAgo <= 0 {
		return 0, nil
	}
	if batchSize < 1 {
		batchSize = 1000
	}
	cutoff := time.Now().Add(-graceAgo)
	var total int64
	for {
		tag, err := r.pool.Exec(ctx, `DELETE FROM admin_sessions WHERE id IN (SELECT id FROM admin_sessions WHERE expires_at < $1 OR (revoked_at IS NOT NULL AND revoked_at < $1) LIMIT $2)`, cutoff, batchSize)
		if err != nil {
			return total, err
		}
		total += tag.RowsAffected()
		if tag.RowsAffected() < int64(batchSize) {
			return total, nil
		}
		if err := ctx.Err(); err != nil {
			return total, err
		}
	}
}
