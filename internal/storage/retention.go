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
