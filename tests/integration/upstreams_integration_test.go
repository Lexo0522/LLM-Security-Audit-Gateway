//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/ai-audit-gateway/internal/auth"
	internalcrypto "github.com/example/ai-audit-gateway/internal/crypto"
	"github.com/example/ai-audit-gateway/internal/httpapi"
	"github.com/example/ai-audit-gateway/internal/storage"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

func newStorageRepo(t *testing.T) (*storage.Repository, *internalcrypto.Key) {
	t.Helper()
	ctx := context.Background()
	repo, err := storage.Open(ctx, os.Getenv("POSTGRES_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	if err := repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := repo.Migrate(ctx); err != nil {
		t.Fatalf("migration must be idempotent: %v", err)
	}
	key, err := internalcrypto.LoadOrCreate(filepath.Join(t.TempDir(), "integration-encryption.key"))
	if err != nil {
		t.Fatal(err)
	}
	return repo, key
}

func TestUpstreamLifecycleWithRealPostgres(t *testing.T) {
	ctx := context.Background()
	repo, key := newStorageRepo(t)
	suffix := uuid.NewString()[:8]
	nameA := "it-upstream-a-" + suffix
	nameB := "it-upstream-b-" + suffix

	created, err := repo.CreateUpstream(ctx, nameA, "http://upstream-a", "it-secret-a-0001", true, key)
	if err != nil {
		t.Fatal(err)
	}
	if !created.HasAPIKey || !created.Enabled {
		t.Fatalf("created=%+v", created)
	}
	if serialized, marshalErr := json.Marshal(created); marshalErr != nil || strings.Contains(string(serialized), "it-secret-a-0001") {
		t.Fatalf("creation model leaks the api key: %s", serialized)
	}

	// Duplicate names are refused.
	if _, err = repo.CreateUpstream(ctx, nameA, "http://elsewhere", "k", true, key); !errors.Is(err, storage.ErrDuplicateUpstreamName) {
		t.Fatalf("duplicate name err=%v", err)
	}
	// Non-HTTP schemes are refused.
	var validation *storage.ValidationError
	if _, err = repo.CreateUpstream(ctx, "it-bad-"+suffix, "ftp://upstream", "", true, key); !errors.As(err, &validation) {
		t.Fatalf("invalid URL must be a validation error, got %v", err)
	}

	// An update without an api key keeps the stored one.
	if _, err = repo.UpdateUpstream(ctx, created.ID, nameA, "http://upstream-a", "", true, key); err != nil {
		t.Fatal(err)
	}
	stored, err := repo.GetUpstream(ctx, created.ID, key)
	if err != nil || stored.APIKey != "it-secret-a-0001" {
		t.Fatalf("stored=%+v err=%v", stored, err)
	}
	// An update with an api key rotates it.
	if _, err = repo.UpdateUpstream(ctx, created.ID, nameA, "http://upstream-a", "it-rotated-a-0002", true, key); err != nil {
		t.Fatal(err)
	}
	if stored, err = repo.GetUpstream(ctx, created.ID, key); err != nil || stored.APIKey != "it-rotated-a-0002" {
		t.Fatalf("stored=%+v err=%v", stored, err)
	}

	// Listing never carries secrets, and the total reflects the full set.
	list, total, err := repo.ListUpstreams(ctx, 0, 0)
	if err != nil || total < 2 {
		t.Fatalf("total=%d err=%v", total, err)
	}
	serialized, marshalErr := json.Marshal(list)
	if marshalErr != nil || strings.Contains(string(serialized), "it-rotated-a-0002") || strings.Contains(string(serialized), "it-secret-a-0001") {
		t.Fatalf("list leaks api keys: %s", serialized)
	}

	createdB, err := repo.CreateUpstream(ctx, nameB, "http://upstream-b", "it-secret-b-0001", true, key)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := auth.NewManager(repo)
	if err != nil {
		t.Fatal(err)
	}
	recordA, plaintextA, err := manager.CreateForUpstream(ctx, "it-tenant-a", created.ID, "key-a")
	if err != nil || !strings.HasPrefix(plaintextA, "agw.") {
		t.Fatalf("record=%+v key=%q err=%v", recordA, plaintextA, err)
	}
	recordB, _, err := manager.CreateForUpstream(ctx, "it-tenant-b", createdB.ID, "key-b")
	if err != nil {
		t.Fatal(err)
	}

	// Each key resolves to its own upstream with its own decrypted api key.
	routeA, err := repo.GetUpstreamForGatewayKey(ctx, recordA.ID, key)
	if err != nil || routeA.ID != created.ID || routeA.APIKey != "it-rotated-a-0002" {
		t.Fatalf("routeA=%+v err=%v", routeA, err)
	}
	routeB, err := repo.GetUpstreamForGatewayKey(ctx, recordB.ID, key)
	if err != nil || routeB.ID != createdB.ID || routeB.APIKey != "it-secret-b-0001" {
		t.Fatalf("routeB=%+v err=%v", routeB, err)
	}

	// Disabling the upstream cuts off its keys immediately.
	if _, err = repo.UpdateUpstream(ctx, created.ID, nameA, "http://upstream-a", "", false, key); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.GetUpstreamForGatewayKey(ctx, recordA.ID, key); err == nil {
		t.Fatal("a disabled upstream must not resolve for its keys")
	}
	if _, err = repo.UpdateUpstream(ctx, created.ID, nameA, "http://upstream-a", "", true, key); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.GetUpstreamForGatewayKey(ctx, recordA.ID, key); err != nil {
		t.Fatalf("re-enabled upstream must resolve again: %v", err)
	}

	// A revoked key stops resolving.
	if _, found, err := manager.Revoke(ctx, recordB.ID); err != nil || !found {
		t.Fatalf("revoke found=%v err=%v", found, err)
	}
	if _, err = repo.GetUpstreamForGatewayKey(ctx, recordB.ID, key); err == nil {
		t.Fatal("a revoked key must not resolve its upstream")
	}

	// Deletion immediately revokes the remaining key and erases the upstream secret.
	deletion, err := repo.RequestUpstreamDeletion(ctx, uuid.MustParse(created.ID), time.Millisecond)
	if err != nil || !deletion.Transitioned || deletion.RevokedKeys != 1 {
		t.Fatalf("deletion=%+v err=%v", deletion, err)
	}
	if _, err = repo.GetUpstreamForGatewayKey(ctx, recordA.ID, key); err == nil {
		t.Fatal("a deleting upstream must not resolve for its keys")
	}
	deleted, err := repo.GetUpstream(ctx, created.ID, key)
	if err != nil || deleted.HasAPIKey || deleted.APIKey != "" || deleted.LifecycleState != storage.UpstreamLifecycleDeleting {
		t.Fatalf("deleted upstream=%+v err=%v", deleted, err)
	}
	duplicate, err := repo.RequestUpstreamDeletion(ctx, uuid.MustParse(created.ID), time.Hour)
	if err != nil || duplicate.Transitioned || duplicate.PurgeAfter == nil {
		t.Fatalf("duplicate deletion=%+v err=%v", duplicate, err)
	}
	time.Sleep(10 * time.Millisecond)
	result, err := repo.FinalizeDueUpstreamDeletionsResult(ctx, 10)
	if err != nil || result.Finalized != 1 {
		t.Fatalf("finalization result=%+v err=%v", result, err)
	}
	if _, err = repo.GetUpstream(ctx, created.ID, key); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("purged upstream err=%v", err)
	}
}

func TestAdminUpstreamDeletionHTTPContract(t *testing.T) {
	ctx := context.Background()
	repo, key := newStorageRepo(t)
	username := "it-delete-admin-" + uuid.NewString()[:8]
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("integration-delete-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	user, err := repo.CreateAdminUser(ctx, username, passwordHash)
	if err != nil {
		t.Fatal(err)
	}
	token := uuid.NewString()
	tokenHash := sha256.Sum256([]byte(token))
	if _, err = repo.CreateAdminSession(ctx, user.ID, tokenHash[:], time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	upstream, err := repo.CreateUpstream(ctx, "it-http-delete-"+uuid.NewString()[:8], "http://upstream-delete", "delete-secret", true, key)
	if err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	(&httpapi.Admin{
		Repo: repo, EncryptionKey: key, CookieSecureMode: "never",
		UpstreamDeletionGracePeriod: time.Millisecond,
	}).Register(app)
	call := func(method, path string) (*http.Response, string) {
		t.Helper()
		req := httptest.NewRequest(method, path, nil)
		req.Host = "localhost:3000"
		req.Header.Set("Origin", "http://localhost:3000")
		req.AddCookie(&http.Cookie{Name: "gateway_admin_session", Value: token})
		resp, callErr := app.Test(req)
		if callErr != nil {
			t.Fatal(callErr)
		}
		raw, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		return resp, string(raw)
	}

	invalid, _ := call(http.MethodDelete, "/admin/v1/upstreams/not-a-uuid")
	if invalid.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid delete status=%d", invalid.StatusCode)
	}
	first, body := call(http.MethodDelete, "/admin/v1/upstreams/"+upstream.ID)
	if first.StatusCode != http.StatusAccepted || !strings.Contains(body, `"lifecycle_state":"deleting"`) {
		t.Fatalf("first delete status=%d body=%s", first.StatusCode, body)
	}
	second, body := call(http.MethodDelete, "/admin/v1/upstreams/"+upstream.ID)
	if second.StatusCode != http.StatusAccepted || !strings.Contains(body, `"transitioned":false`) {
		t.Fatalf("second delete status=%d body=%s", second.StatusCode, body)
	}
	backlogResponse, backlogBody := call(http.MethodGet, "/admin/v1/upstreams/deletion-backlog")
	if backlogResponse.StatusCode != http.StatusOK || !strings.Contains(backlogBody, `"pending":1`) {
		t.Fatalf("backlog status=%d body=%s", backlogResponse.StatusCode, backlogBody)
	}
	time.Sleep(10 * time.Millisecond)
	result, err := repo.FinalizeDueUpstreamDeletionsResult(ctx, 10)
	if err != nil || result.Finalized != 1 || result.Backlog.Pending != 0 {
		t.Fatalf("finalization result=%+v err=%v", result, err)
	}

	missing, _ := call(http.MethodDelete, "/admin/v1/upstreams/"+upstream.ID)
	if missing.StatusCode != http.StatusNotFound {
		t.Fatalf("purged delete status=%d", missing.StatusCode)
	}
}

func newIntegrationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, os.Getenv("POSTGRES_URL"))
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func waitForUpstreamDue(t *testing.T, pool *pgxpool.Pool, id string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var due bool
		err := pool.QueryRow(context.Background(), `SELECT purge_after <= now() FROM upstream_configs WHERE id=$1`, id).Scan(&due)
		if errors.Is(err, pgx.ErrNoRows) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if due {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("upstream %s did not become due", id)
}

func cleanupTestUpstream(repo *storage.Repository, pool *pgxpool.Pool, id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var due bool
		err := pool.QueryRow(ctx, `SELECT purge_after <= now() FROM upstream_configs WHERE id=$1 AND lifecycle_state='deleting'`, id).Scan(&due)
		if errors.Is(err, pgx.ErrNoRows) {
			return
		}
		if err != nil {
			return
		}
		if due {
			_, _ = repo.FinalizeDueUpstreamDeletionsResult(ctx, 100)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestConcurrentCreateKeyAndUpstreamDelete(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	repo, key := newStorageRepo(t)
	manager, err := auth.NewManager(repo)
	if err != nil {
		t.Fatal(err)
	}
	tenant := "it-concurrent-create-delete-" + uuid.NewString()[:8]
	upstream, err := repo.CreateUpstream(ctx, tenant, "http://upstream-create-delete", "create-delete-secret", true, key)
	if err != nil {
		t.Fatal(err)
	}
	pool := newIntegrationPool(t)
	t.Cleanup(func() { cleanupTestUpstream(repo, pool, upstream.ID) })

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	createResult := make(chan struct {
		record auth.KeyRecord
		err    error
	}, 1)
	deleteResult := make(chan struct {
		value storage.UpstreamDeletion
		err   error
	}, 1)
	go func() {
		defer wg.Done()
		<-start
		record, _, createErr := manager.CreateForUpstream(ctx, tenant, upstream.ID, "race")
		createResult <- struct {
			record auth.KeyRecord
			err    error
		}{record: record, err: createErr}
	}()
	go func() {
		defer wg.Done()
		<-start
		value, deleteErr := repo.RequestUpstreamDeletion(ctx, uuid.MustParse(upstream.ID), time.Millisecond)
		deleteResult <- struct {
			value storage.UpstreamDeletion
			err   error
		}{value: value, err: deleteErr}
	}()
	close(start)
	wg.Wait()
	created := <-createResult
	deleted := <-deleteResult
	if deleted.err != nil || !deleted.value.Transitioned {
		t.Fatalf("deletion=%+v err=%v", deleted.value, deleted.err)
	}
	if created.err != nil && !errors.Is(created.err, storage.ErrUpstreamDeleting) {
		t.Fatalf("create err=%v", created.err)
	}

	stored, err := repo.GetUpstream(ctx, upstream.ID, key)
	if err != nil || stored.LifecycleState != storage.UpstreamLifecycleDeleting || stored.HasAPIKey || stored.APIKey != "" {
		t.Fatalf("stored=%+v err=%v", stored, err)
	}
	keys, total, err := manager.List(ctx, tenant, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if created.err != nil {
		if total != 0 {
			t.Fatalf("failed create left keys=%+v total=%d", keys, total)
		}
		return
	}
	if total != 1 || len(keys) != 1 || keys[0].ID != created.record.ID || keys[0].RevokedAt == nil {
		t.Fatalf("created key was not revoked: keys=%+v total=%d", keys, total)
	}
	if _, err := repo.GetUpstreamForGatewayKey(ctx, created.record.ID, key); err == nil {
		t.Fatal("a key created before deletion must not route after deletion commits")
	}
}

func TestConcurrentUpdateAndUpstreamDelete(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	repo, key := newStorageRepo(t)
	upstream, err := repo.CreateUpstream(ctx, "it-concurrent-update-delete-"+uuid.NewString()[:8], "http://upstream-update-delete", "update-delete-secret", true, key)
	if err != nil {
		t.Fatal(err)
	}
	pool := newIntegrationPool(t)
	t.Cleanup(func() { cleanupTestUpstream(repo, pool, upstream.ID) })
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	updateResult := make(chan error, 1)
	deleteResult := make(chan struct {
		value storage.UpstreamDeletion
		err   error
	}, 1)
	go func() {
		defer wg.Done()
		<-start
		_, updateErr := repo.UpdateUpstream(ctx, upstream.ID, upstream.Name+"-updated", "http://upstream-update-delete-v2", "rotated-after-race", true, key)
		updateResult <- updateErr
	}()
	go func() {
		defer wg.Done()
		<-start
		value, deleteErr := repo.RequestUpstreamDeletion(ctx, uuid.MustParse(upstream.ID), time.Millisecond)
		deleteResult <- struct {
			value storage.UpstreamDeletion
			err   error
		}{value: value, err: deleteErr}
	}()
	close(start)
	wg.Wait()
	updateErr := <-updateResult
	deleted := <-deleteResult
	if deleted.err != nil || !deleted.value.Transitioned {
		t.Fatalf("deletion=%+v err=%v", deleted.value, deleted.err)
	}
	if updateErr != nil && !errors.Is(updateErr, storage.ErrUpstreamDeleting) {
		t.Fatalf("update err=%v", updateErr)
	}
	stored, err := repo.GetUpstream(ctx, upstream.ID, key)
	if err != nil || stored.LifecycleState != storage.UpstreamLifecycleDeleting || stored.Enabled || stored.HasAPIKey || stored.APIKey != "" {
		t.Fatalf("deleting upstream was not terminal: %+v err=%v", stored, err)
	}
	duplicate, err := repo.RequestUpstreamDeletion(ctx, uuid.MustParse(upstream.ID), time.Nanosecond)
	if err != nil || duplicate.Transitioned || duplicate.PurgeAfter == nil || deleted.value.PurgeAfter == nil || duplicate.PurgeAfter.Sub(*deleted.value.PurgeAfter) > time.Microsecond || duplicate.PurgeAfter.Sub(*deleted.value.PurgeAfter) < -time.Microsecond {
		t.Fatalf("duplicate deletion=%+v first=%+v err=%v", duplicate, deleted.value, err)
	}
	if _, err := repo.UpdateUpstream(ctx, upstream.ID, "it-should-not-revive", "http://revive.invalid", "", true, key); !errors.Is(err, storage.ErrUpstreamDeleting) {
		t.Fatalf("update after deletion err=%v, want ErrUpstreamDeleting", err)
	}
}

func TestConcurrentUpstreamFinalizers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	repo, key := newStorageRepo(t)
	manager, err := auth.NewManager(repo)
	if err != nil {
		t.Fatal(err)
	}
	tenant := "it-concurrent-finalizer-" + uuid.NewString()[:8]
	upstream, err := repo.CreateUpstream(ctx, "it-concurrent-finalizer-one-"+uuid.NewString()[:8], "http://finalizer-one", "finalizer-one-secret", true, key)
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := manager.CreateForUpstream(ctx, tenant, upstream.ID, "one")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.RequestUpstreamDeletion(ctx, uuid.MustParse(upstream.ID), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	pool := newIntegrationPool(t)
	waitForUpstreamDue(t, pool, upstream.ID)

	start := make(chan struct{})
	results := make(chan struct {
		value storage.UpstreamFinalizationResult
		err   error
	}, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			value, finalizeErr := repo.FinalizeDueUpstreamDeletionsResult(ctx, 1)
			results <- struct {
				value storage.UpstreamFinalizationResult
				err   error
			}{value: value, err: finalizeErr}
		}()
	}
	close(start)
	wg.Wait()
	first, second := <-results, <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("finalizer errors: first=%v second=%v", first.err, second.err)
	}
	if first.value.Finalized+second.value.Finalized != 1 || first.value.RevokedKeys+second.value.RevokedKeys != 1 {
		t.Fatalf("duplicate finalization: first=%+v second=%+v", first.value, second.value)
	}
	if _, err := repo.GetUpstream(ctx, upstream.ID, key); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("upstream finalization err=%v", err)
	}
	if _, found, err := repo.LookupGatewayAPIKey(ctx, record.ID); err != nil || found {
		t.Fatalf("gateway key after finalization found=%v err=%v", found, err)
	}

	batchTenant := "it-concurrent-finalizer-batch-" + uuid.NewString()[:8]
	ids := make([]string, 0, 4)
	for i := 0; i < 4; i++ {
		value, createErr := repo.CreateUpstream(ctx, fmt.Sprintf("it-concurrent-finalizer-batch-%d-%s", i, uuid.NewString()[:8]), "http://finalizer-batch", "batch-secret", true, key)
		if createErr != nil {
			t.Fatal(createErr)
		}
		if _, _, createErr = manager.CreateForUpstream(ctx, batchTenant, value.ID, fmt.Sprintf("batch-%d", i)); createErr != nil {
			t.Fatal(createErr)
		}
		if _, deleteErr := repo.RequestUpstreamDeletion(ctx, uuid.MustParse(value.ID), time.Millisecond); deleteErr != nil {
			t.Fatal(deleteErr)
		}
		waitForUpstreamDue(t, pool, value.ID)
		ids = append(ids, value.ID)
	}
	batchResults := make(chan struct {
		value storage.UpstreamFinalizationResult
		err   error
	}, 2)
	start = make(chan struct{})
	wg = sync.WaitGroup{}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			value, finalizeErr := repo.FinalizeDueUpstreamDeletionsResult(ctx, len(ids))
			batchResults <- struct {
				value storage.UpstreamFinalizationResult
				err   error
			}{value: value, err: finalizeErr}
		}()
	}
	close(start)
	wg.Wait()
	var finalized, revokedKeys int64
	for i := 0; i < 2; i++ {
		result := <-batchResults
		if result.err != nil {
			t.Fatalf("batch finalizer err=%v result=%+v", result.err, result.value)
		}
		finalized += result.value.Finalized
		revokedKeys += result.value.RevokedKeys
	}
	if finalized != int64(len(ids)) || revokedKeys != int64(len(ids)) {
		t.Fatalf("batch finalized=%d revoked_keys=%d want=%d", finalized, revokedKeys, len(ids))
	}
	for _, id := range ids {
		if _, err := repo.GetUpstream(ctx, id, key); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("batch upstream %s err=%v", id, err)
		}
	}
}

func TestUpstreamFinalizerPartialFailureRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	repo, key := newStorageRepo(t)
	manager, err := auth.NewManager(repo)
	if err != nil {
		t.Fatal(err)
	}
	pool := newIntegrationPool(t)
	triggerName := "it_fail_finalizer_delete_trigger"
	functionName := "it_fail_finalizer_delete"
	_, _ = pool.Exec(ctx, `DROP TRIGGER IF EXISTS `+triggerName+` ON upstream_configs`)
	_, _ = pool.Exec(ctx, `DROP FUNCTION IF EXISTS `+functionName+`()`)
	_, err = pool.Exec(ctx, `CREATE FUNCTION `+functionName+`() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.name LIKE 'it-fault-finalizer-fail-%' THEN RAISE EXCEPTION 'injected finalizer delete failure'; END IF; RETURN OLD; END; $$`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `CREATE TRIGGER `+triggerName+` BEFORE DELETE ON upstream_configs FOR EACH ROW EXECUTE FUNCTION `+functionName+`()`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS `+triggerName+` ON upstream_configs`)
		_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+functionName+`()`)
	}()

	first, err := repo.CreateUpstream(ctx, "it-fault-finalizer-ok-"+uuid.NewString()[:8], "http://fault-finalizer-ok", "first-secret", true, key)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := repo.CreateUpstream(ctx, "it-fault-finalizer-fail-"+uuid.NewString()[:8], "http://fault-finalizer-fail", "second-secret", true, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []struct {
		id     string
		tenant string
		name   string
	}{
		{id: first.ID, tenant: "it-fault-finalizer-ok", name: "first"},
		{id: failed.ID, tenant: "it-fault-finalizer-fail", name: "second"},
	} {
		if _, _, err := manager.CreateForUpstream(ctx, value.tenant, value.id, value.name); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.RequestUpstreamDeletion(ctx, uuid.MustParse(value.id), time.Millisecond); err != nil {
			t.Fatal(err)
		}
	}
	waitForUpstreamDue(t, pool, first.ID)
	waitForUpstreamDue(t, pool, failed.ID)

	result, err := repo.FinalizeDueUpstreamDeletionsResult(ctx, 10)
	if err == nil || result.Finalized != 1 || result.RevokedKeys != 1 {
		t.Fatalf("partial result=%+v err=%v", result, err)
	}
	if _, err := repo.GetUpstream(ctx, first.ID, key); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("successful upstream was not finalized: %v", err)
	}
	remaining, err := repo.GetUpstream(ctx, failed.ID, key)
	if err != nil || remaining.LifecycleState != storage.UpstreamLifecycleDeleting || remaining.HasAPIKey {
		t.Fatalf("failed upstream state=%+v err=%v", remaining, err)
	}
	backlog, err := repo.GetUpstreamDeletionBacklog(ctx)
	if err != nil || backlog.Pending != 1 || backlog.Due != 1 {
		t.Fatalf("partial backlog=%+v err=%v", backlog, err)
	}
	keys, total, err := manager.List(ctx, "it-fault-finalizer-fail", 0, 0)
	if err != nil || total != 1 || len(keys) != 1 || keys[0].RevokedAt == nil {
		t.Fatalf("failed key state=%+v total=%d err=%v", keys, total, err)
	}

	if _, err := pool.Exec(ctx, `DROP TRIGGER IF EXISTS `+triggerName+` ON upstream_configs`); err != nil {
		t.Fatal(err)
	}
	result, err = repo.FinalizeDueUpstreamDeletionsResult(ctx, 10)
	if err != nil || result.Finalized != 1 || result.RevokedKeys != 1 || result.Backlog.Pending != 0 {
		t.Fatalf("recovery result=%+v err=%v", result, err)
	}
	if _, err := repo.GetUpstream(ctx, failed.ID, key); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("failed upstream was not recovered: %v", err)
	}
}

func TestAdminSessionLifecycleWithRealPostgres(t *testing.T) {
	ctx := context.Background()
	repo, key := newStorageRepo(t)
	manager, err := auth.NewManager(repo)
	if err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	admin := &httpapi.Admin{Repo: repo, EncryptionKey: key, Keys: manager, CookieSecureMode: "never"}
	admin.Register(app)

	var bodyOf func(*http.Response) string
	call := func(method, path, body string, cookies []*http.Cookie, set func(*http.Request)) *http.Response {
		t.Helper()
		var reader io.Reader
		if body != "" {
			reader = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, path, reader)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		if set != nil {
			set(req)
		}
		resp, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}
	bodyOf = func(resp *http.Response) string {
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	sameOrigin := func(req *http.Request) {
		req.Header.Set("Origin", "http://localhost:3000")
		req.Header.Set("X-Forwarded-Host", "localhost:3000")
		req.Header.Set("X-Forwarded-Proto", "http")
	}
	decodeUser := func(resp *http.Response) storage.AdminUser {
		var user storage.AdminUser
		if err := json.Unmarshal([]byte(bodyOf(resp)), &user); err != nil {
			t.Fatalf("decode user: %v", err)
		}
		return user
	}

	username := "it-admin-" + uuid.NewString()[:8]
	password := "it-password-one-000"
	newPassword := "it-password-two-000"

	// First-run setup. Skip when this database already has an administrator
	// (a previous run against a persistent volume). Browsers always attach an
	// Origin header to writes, so every write below does too.
	status := call(http.MethodGet, "/admin/v1/setup/status", "", nil, nil)
	var state struct {
		Initialized bool `json:"initialized"`
	}
	if err := json.Unmarshal([]byte(bodyOf(status)), &state); err != nil {
		t.Fatal(err)
	}
	if state.Initialized {
		t.Skip("database already has an administrator; recreate the integration volume for a clean run")
	}
	setup := call(http.MethodPost, "/admin/v1/setup", fmt.Sprintf(`{"username":%q,"password":%q}`, username, password), nil, sameOrigin)
	if setup.StatusCode != http.StatusCreated {
		t.Fatalf("setup status=%d body=%s", setup.StatusCode, bodyOf(setup))
	}

	// Login sets the session and CSRF cookies; Secure stays off for "never".
	login := call(http.MethodPost, "/admin/v1/auth/login", fmt.Sprintf(`{"username":%q,"password":%q}`, username, password), nil, sameOrigin)
	if login.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d body=%s", login.StatusCode, bodyOf(login))
	}
	sessionCookies := login.Cookies()
	for _, cookie := range sessionCookies {
		if cookie.Name == "gateway_admin_session" && cookie.Secure {
			t.Fatal("session cookie must not be Secure under the never mode")
		}
	}
	me := call(http.MethodGet, "/admin/v1/auth/me", "", sessionCookies, nil)
	if me.StatusCode != http.StatusOK {
		t.Fatalf("me status=%d", me.StatusCode)
	}
	if user := decodeUser(me); user.Username != username {
		t.Fatalf("me returned %q", user.Username)
	}

	// A session-cookie write goes through the same-origin CSRF path and hits
	// the real database.
	upstreamPayload := fmt.Sprintf(`{"name":"it-admin-upstream-%s","base_url":"http://upstream-a","api_key":"it-admin-key-1"}`, uuid.NewString()[:8])
	created := call(http.MethodPost, "/admin/v1/upstreams", upstreamPayload, sessionCookies, sameOrigin)
	if created.StatusCode != http.StatusCreated {
		t.Fatalf("upstream create status=%d body=%s", created.StatusCode, bodyOf(created))
	}
	var createdUpstream struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(bodyOf(created)), &createdUpstream); err != nil || createdUpstream.ID == "" {
		t.Fatalf("created=%s err=%v", bodyOf(created), err)
	}
	if hasSecrets, err := repo.HasUpstreamSecrets(ctx); err != nil || !hasSecrets {
		t.Fatalf("hasSecrets=%v err=%v", hasSecrets, err)
	}
	// The same session with a hostile origin is rejected.
	hostile := call(http.MethodPost, "/admin/v1/upstreams", upstreamPayload, sessionCookies, func(req *http.Request) {
		req.Header.Set("Origin", "http://evil.test")
	})
	if hostile.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin write status=%d, want 403", hostile.StatusCode)
	}

	// Batch revocation is idempotent and reports unknown ids.
	keyCreate := call(http.MethodPost, "/admin/v1/api-keys",
		fmt.Sprintf(`{"tenant_id":"it-tenant-batch","upstream_id":%q,"display_name":"batch"}`, createdUpstream.ID),
		sessionCookies, sameOrigin)
	if keyCreate.StatusCode != http.StatusCreated {
		t.Fatalf("key create status=%d body=%s", keyCreate.StatusCode, bodyOf(keyCreate))
	}
	var createdKey struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(bodyOf(keyCreate)), &createdKey); err != nil || createdKey.ID == "" {
		t.Fatalf("key=%s err=%v", bodyOf(keyCreate), err)
	}
	batchBody := fmt.Sprintf(`{"ids":[%q,"00000000-0000-0000-0000-000000000000"]}`, createdKey.ID)
	batch := call(http.MethodPost, "/admin/v1/api-keys/revoke", batchBody, sessionCookies, sameOrigin)
	if batch.StatusCode != http.StatusOK {
		t.Fatalf("batch revoke status=%d body=%s", batch.StatusCode, bodyOf(batch))
	}
	var batchResult struct {
		Revoked int      `json:"revoked"`
		Missing []string `json:"missing"`
	}
	if err := json.Unmarshal([]byte(bodyOf(batch)), &batchResult); err != nil {
		t.Fatal(err)
	}
	if batchResult.Revoked != 1 || len(batchResult.Missing) != 1 {
		t.Fatalf("batch result=%+v", batchResult)
	}
	retry := call(http.MethodPost, "/admin/v1/api-keys/revoke", batchBody, sessionCookies, sameOrigin)
	var retryResult struct {
		Revoked int `json:"revoked"`
	}
	if err := json.Unmarshal([]byte(bodyOf(retry)), &retryResult); err != nil || retryResult.Revoked != 1 {
		t.Fatalf("retry must return a stable count, result=%s err=%v", bodyOf(retry), err)
	}

	// A second login coexists until the password rotation revokes it.
	login2 := call(http.MethodPost, "/admin/v1/auth/login", fmt.Sprintf(`{"username":%q,"password":%q}`, username, password), nil, sameOrigin)
	if login2.StatusCode != http.StatusOK {
		t.Fatalf("second login status=%d", login2.StatusCode)
	}

	// Rotating the password keeps the current session and kills the other.
	change := call(http.MethodPost, "/admin/v1/auth/password",
		fmt.Sprintf(`{"current_password":%q,"new_password":%q}`, password, newPassword),
		sessionCookies, sameOrigin)
	if change.StatusCode != http.StatusNoContent {
		t.Fatalf("password change status=%d body=%s", change.StatusCode, bodyOf(change))
	}
	if me2 := call(http.MethodGet, "/admin/v1/auth/me", "", login2.Cookies(), nil); me2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("other session must be revoked, got status=%d", me2.StatusCode)
	}
	if me1 := call(http.MethodGet, "/admin/v1/auth/me", "", sessionCookies, nil); me1.StatusCode != http.StatusOK {
		t.Fatalf("current session must survive the rotation, got status=%d", me1.StatusCode)
	}

	// Logout-all revokes the remaining session too.
	logoutAll := call(http.MethodPost, "/admin/v1/auth/sessions/logout-all", "", sessionCookies, sameOrigin)
	if logoutAll.StatusCode != http.StatusNoContent {
		t.Fatalf("logout-all status=%d", logoutAll.StatusCode)
	}
	if me3 := call(http.MethodGet, "/admin/v1/auth/me", "", sessionCookies, nil); me3.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session must be revoked after logout-all, got status=%d", me3.StatusCode)
	}

	// The old password no longer works; the new one does.
	if bad := call(http.MethodPost, "/admin/v1/auth/login", fmt.Sprintf(`{"username":%q,"password":%q}`, username, password), nil, sameOrigin); bad.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old password must fail, got status=%d", bad.StatusCode)
	}
	fresh := call(http.MethodPost, "/admin/v1/auth/login", fmt.Sprintf(`{"username":%q,"password":%q}`, username, newPassword), nil, sameOrigin)
	if fresh.StatusCode != http.StatusOK {
		t.Fatalf("new password must work, got status=%d body=%s", fresh.StatusCode, bodyOf(fresh))
	}
	user := decodeUser(fresh)

	// Expired sessions are unusable and the sweeper removes them.
	deadHash := []byte("integration-dead-session-hash")
	if _, err := repo.CreateAdminSession(ctx, user.ID, deadHash, time.Now().Add(-25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.GetAdminSession(ctx, deadHash); err == nil {
		t.Fatal("an expired session must not authenticate")
	}
	deleted, err := repo.CleanupExpiredAdminSessions(ctx, 24*time.Hour, 100)
	if err != nil || deleted < 1 {
		t.Fatalf("deleted=%d err=%v", deleted, err)
	}
}
