package sqlite

import (
	"context"
	"testing"
	"time"
)

func TestRegisterDerivedRepositoryIsIdempotentAndConflictSafe(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	seedTenant(t, db, "tenant-a")
	if _, err := db.sql.ExecContext(ctx, `INSERT INTO policy_generations (tenant_id, generation, policy_hash, activated_at, snapshot_json) VALUES ('tenant-a', 1, 'hash-1', 1, '{"generation":1,"agents":{},"repositories":{},"branch_grants":[]}')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.ExecContext(ctx, `INSERT INTO agents (tenant_id, id, created_at) VALUES ('tenant-a', 'tomas', 1), ('tenant-a', 'zara', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.ExecContext(ctx, `INSERT INTO operation_packets (tenant_id, id, agent_id, repository, operation, packet_hash, state, policy_generation, actor_subject, created_at, expires_at, payload_json)
		VALUES ('tenant-a', 'create-1', 'tomas', 'yaniv256/new-private', 'repository.create', 'packet-1', 'executing', 1, 'yaniv', 1, 2, '{"visibility":"private"}')`); err != nil {
		t.Fatal(err)
	}
	at := time.Unix(100, 0).UTC()
	for range 2 {
		if err := db.WithTx(ctx, func(tx *Tx) error { return registerDerivedRepository(ctx, tx.tx, "tenant-a", "create-1", at) }); err != nil {
			t.Fatal(err)
		}
	}
	repositories, err := db.DerivedRepositories(ctx, "tenant-a")
	if err != nil || len(repositories) != 1 || repositories[0].OwnerAgentID != "tomas" || repositories[0].Repository != "yaniv256/new-private" || repositories[0].ActorSubject != "yaniv" {
		t.Fatalf("repositories=%#v err=%v", repositories, err)
	}
	if _, err := db.sql.ExecContext(ctx, `INSERT INTO operation_packets (tenant_id, id, agent_id, repository, operation, packet_hash, state, policy_generation, actor_subject, created_at, expires_at, payload_json)
		VALUES ('tenant-a', 'create-2', 'zara', 'yaniv256/new-private', 'repository.create', 'packet-2', 'executing', 1, 'yaniv', 1, 2, '{"visibility":"private"}')`); err != nil {
		t.Fatal(err)
	}
	if err := db.WithTx(ctx, func(tx *Tx) error { return registerDerivedRepository(ctx, tx.tx, "tenant-a", "create-2", at) }); err == nil {
		t.Fatal("conflicting creator was accepted")
	}
}

func TestRegisterDerivedRepositoryIgnoresPublicCreate(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	seedTenant(t, db, "tenant-a")
	if _, err := db.sql.ExecContext(ctx, `INSERT INTO policy_generations (tenant_id, generation, policy_hash, activated_at, snapshot_json) VALUES ('tenant-a', 1, 'hash-1', 1, '{"generation":1,"agents":{},"repositories":{},"branch_grants":[]}')`); err != nil {
		t.Fatal(err)
	}
	_, _ = db.sql.ExecContext(ctx, `INSERT INTO agents (tenant_id, id, created_at) VALUES ('tenant-a', 'tomas', 1)`)
	_, err := db.sql.ExecContext(ctx, `INSERT INTO operation_packets (tenant_id, id, agent_id, repository, operation, packet_hash, state, policy_generation, created_at, expires_at, payload_json)
		VALUES ('tenant-a', 'create-public', 'tomas', 'yaniv256/public', 'repository.create', 'packet-public', 'executing', 1, 1, 2, '{"visibility":"public"}')`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.WithTx(ctx, func(tx *Tx) error {
		return registerDerivedRepository(ctx, tx.tx, "tenant-a", "create-public", time.Unix(100, 0))
	}); err != nil {
		t.Fatal(err)
	}
	repositories, err := db.DerivedRepositories(ctx, "tenant-a")
	if err != nil || len(repositories) != 0 {
		t.Fatalf("repositories=%#v err=%v", repositories, err)
	}
}

func TestRegisterDerivedRepositoryRejectsConcurrentPolicyRegistration(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	seedTenant(t, db, "tenant-a")
	_, _ = db.sql.ExecContext(ctx, `INSERT INTO agents (tenant_id, id, created_at) VALUES ('tenant-a', 'tomas', 1)`)
	_, err := db.sql.ExecContext(ctx, `INSERT INTO policy_generations (tenant_id, generation, policy_hash, activated_at, snapshot_json) VALUES ('tenant-a', 1, 'hash-1', 1, '{"generation":1,"agents":{},"repositories":{"yaniv256/new-private":{"visibility":"private","owners":["zara"]}},"branch_grants":[]}')`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.sql.ExecContext(ctx, `INSERT INTO operation_packets (tenant_id, id, agent_id, repository, operation, packet_hash, state, policy_generation, actor_subject, created_at, expires_at, payload_json)
		VALUES ('tenant-a', 'create-1', 'tomas', 'yaniv256/new-private', 'repository.create', 'packet-1', 'executing', 1, 'yaniv', 1, 2, '{"visibility":"private"}')`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.WithTx(ctx, func(tx *Tx) error {
		return registerDerivedRepository(ctx, tx.tx, "tenant-a", "create-1", time.Unix(100, 0))
	}); err == nil {
		t.Fatal("configured-policy conflict was accepted")
	}
}
