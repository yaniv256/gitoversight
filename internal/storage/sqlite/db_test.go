package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/storage"
)

func TestOpenMigratesAndEnforcesSafeRuntime(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "gitoversight.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	status, err := db.Readiness(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.SchemaVersion != CurrentSchemaVersion {
		t.Fatalf("schema version = %d, want %d", status.SchemaVersion, CurrentSchemaVersion)
	}
	if status.SQLiteVersion.LessThan(MinimumSQLiteVersion) {
		t.Fatalf("SQLite runtime %s is older than %s", status.SQLiteVersion, MinimumSQLiteVersion)
	}
	if status.JournalMode != "wal" {
		t.Fatalf("journal_mode = %q, want wal", status.JournalMode)
	}
	if status.Synchronous != "full" {
		t.Fatalf("synchronous = %q, want full", status.Synchronous)
	}
	if !status.ForeignKeys {
		t.Fatal("foreign keys are disabled")
	}

	wantTables := []string{
		"tenants", "humans", "agents", "agent_credentials", "repositories",
		"repository_owners", "branch_grants", "standing_exceptions", "policy_generations",
		"operation_packets", "approvals", "execution_grants", "reconciliations",
		"audit_events", "audit_checkpoints", "notification_subscriptions",
		"outbox_deliveries", "notification_deliveries", "webhook_receipts", "request_nonces",
		"oauth_clients", "oauth_client_redirect_uris", "oauth_authorization_codes",
		"oauth_authorization_code_repositories", "oauth_token_families",
		"oauth_token_family_repositories", "oauth_access_tokens", "oauth_refresh_tokens",
		"change_drafts",
		"change_draft_publications",
	}
	for _, table := range wantTables {
		if !hasTable(t, db, table) {
			t.Errorf("missing migrated table %q", table)
		}
	}
}

func TestWithTxRollsBackOperationAuditAndOutboxTogether(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openTestDB(t)
	seedTenant(t, db, "tenant-a")
	seedCredential(t, db, "tenant-a", "zara-key")

	wantErr := errors.New("checkpoint unavailable")
	err := db.WithTx(ctx, func(tx *Tx) error {
		if err := tx.PutOperation(ctx, storage.Operation{
			TenantID: "tenant-a", ID: "op-1", AgentID: "zara", Repository: "yaniv256/private",
			Kind: "branch.push", PacketHash: "packet-1", State: "authorized", PolicyGeneration: 7,
			CreatedAt: time.Unix(1_720_000_000, 0).UTC(), ExpiresAt: time.Unix(1_720_000_300, 0).UTC(),
		}); err != nil {
			return err
		}
		if err := tx.AppendAudit(ctx, storage.AuditEvent{
			TenantID: "tenant-a", ID: "audit-1", Kind: "operation.authorized", SubjectID: "op-1",
			PayloadJSON: []byte(`{"operation":"op-1"}`), PreviousHash: "genesis", Hash: "hash-1",
			CreatedAt: time.Unix(1_720_000_000, 0).UTC(),
		}); err != nil {
			return err
		}
		if err := tx.AppendOutbox(ctx, storage.OutboxEvent{
			TenantID: "tenant-a", ID: "outbox-1", Kind: "operation.authorized", AudienceAgentID: "agent-a",
			PayloadJSON: []byte(`{"operation":"op-1"}`), State: "pending",
			CreatedAt: time.Unix(1_720_000_000, 0).UTC(),
		}); err != nil {
			return err
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("WithTx error = %v, want %v", err, wantErr)
	}

	for _, table := range []string{"operation_packets", "audit_events", "outbox_deliveries"} {
		if got := countTenantRows(t, db, table, "tenant-a"); got != 0 {
			t.Fatalf("%s rows = %d after rollback, want 0", table, got)
		}
	}
}

func TestVerifyAuthorityAuditChainRejectsStoredTampering(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	seedTenant(t, db, "tenant-a")
	now := time.Unix(1_720_000_000, 0).UTC()
	if err := db.WithTx(ctx, func(tx *Tx) error {
		return tx.AppendAuthorityTransition(ctx, "tenant-a", "event-1", "operation_submitted", "op-1", map[string]string{"state": "authorized"}, now)
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.VerifyAuthorityAuditChain(ctx, "tenant-a"); err != nil {
		t.Fatalf("valid audit chain rejected: %v", err)
	}
	if _, err := db.sql.ExecContext(ctx, `UPDATE audit_events SET payload_json = '{"state":"denied"}' WHERE tenant_id = 'tenant-a' AND id = 'event-1'`); err != nil {
		t.Fatal(err)
	}
	if err := db.VerifyAuthorityAuditChain(ctx, "tenant-a"); err == nil {
		t.Fatal("tampered audit chain was accepted")
	}
}

func TestConsumeNonceAllowsOneConcurrentWinner(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openTestDB(t)
	seedTenant(t, db, "tenant-a")
	seedCredential(t, db, "tenant-a", "zara-key")

	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- db.WithTx(ctx, func(tx *Tx) error {
				return tx.ConsumeNonce(ctx, "tenant-a", "zara-key", "nonce-1", time.Now().Add(time.Minute))
			})
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var successes, duplicates int
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, storage.ErrDuplicateNonce):
			duplicates++
		default:
			t.Fatalf("unexpected nonce result: %v", err)
		}
	}
	if successes != 1 || duplicates != 1 {
		t.Fatalf("successes=%d duplicates=%d, want 1 and 1", successes, duplicates)
	}
}

func TestBackupRestoresTenantStateAndIntegrity(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openTestDB(t)
	seedTenant(t, db, "tenant-a")

	backupPath := filepath.Join(t.TempDir(), "backup.db")
	if err := db.Backup(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	restored, err := Open(ctx, Config{Path: backupPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restored.Close() })

	status, err := restored.Readiness(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !status.IntegrityOK {
		t.Fatal("restored database integrity check failed")
	}
	if got := countTenantRows(t, restored, "tenants", "tenant-a"); got != 1 {
		t.Fatalf("restored tenant rows = %d, want 1", got)
	}
}

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(context.Background(), Config{Path: filepath.Join(t.TempDir(), "gitoversight.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func seedTenant(t *testing.T, db *DB, tenantID string) {
	t.Helper()
	err := db.WithTx(context.Background(), func(tx *Tx) error {
		return tx.EnsureTenant(context.Background(), tenantID, time.Unix(1_720_000_000, 0).UTC())
	})
	if err != nil {
		t.Fatal(err)
	}
}

func seedCredential(t *testing.T, db *DB, tenantID, credentialID string) {
	t.Helper()
	err := db.WithTx(context.Background(), func(tx *Tx) error {
		return tx.PutAgentCredential(context.Background(), storage.AgentCredential{
			TenantID: tenantID, AgentID: "zara", ID: credentialID, PublicKey: []byte("public-key"),
			CreatedAt: time.Unix(1_720_000_000, 0).UTC(),
		})
	})
	if err != nil {
		t.Fatal(err)
	}
}

func hasTable(t *testing.T, db *DB, table string) bool {
	t.Helper()
	var count int
	if err := db.sql.QueryRowContext(context.Background(), `SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count == 1
}

func countTenantRows(t *testing.T, db *DB, table, tenantID string) int {
	t.Helper()
	allowed := map[string]bool{"tenants": true, "operation_packets": true, "audit_events": true, "outbox_deliveries": true}
	if !allowed[table] {
		t.Fatalf("test helper does not allow table %q", table)
	}
	column := "tenant_id"
	if table == "tenants" {
		column = "id"
	}
	var count int
	query := `SELECT count(*) FROM ` + table + ` WHERE ` + column + ` = ?`
	if err := db.sql.QueryRowContext(context.Background(), query, tenantID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestReadinessIntegrityStalenessBound(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "stale.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if status, err := db.Readiness(ctx); err != nil || !status.IntegrityOK {
		t.Fatalf("fresh open should be ready with integrity ok: %+v err=%v", status, err)
	}
	// A wedged refresher must not let the cached proof outlive maxIntegrityAge.
	db.integrityMu.Lock()
	db.integrityAt = time.Now().Add(-maxIntegrityAge - time.Minute)
	db.integrityMu.Unlock()
	status, err := db.Readiness(ctx)
	if err == nil || status.IntegrityOK {
		t.Fatalf("stale integrity cache must fail readiness: %+v err=%v", status, err)
	}
	// A refresh restores readiness.
	if err := db.runIntegrityCheck(ctx); err != nil {
		t.Fatal(err)
	}
	if status, err := db.Readiness(ctx); err != nil || !status.IntegrityOK {
		t.Fatalf("refreshed integrity should restore readiness: %+v err=%v", status, err)
	}
}
