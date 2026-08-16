package authorityrpc_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/authorityrpc"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/server"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
	"github.com/yaniv256/gitoversight.dev/internal/worker"
)

type openGate struct{}

func (openGate) Verify() error                        { return nil }
func (openGate) Commit(context.Context, string) error { return nil }

type committedExecutor struct{}

func (committedExecutor) Execute(worker.Request) (worker.Result, error) {
	return worker.Result{ResourceID: "untrusted"}, nil
}
func (committedExecutor) Reconcile(worker.Request) (worker.Reconciliation, error) {
	return worker.Reconciliation{State: worker.ReconciliationCommitted, ResourceID: "verified"}, nil
}

func TestWorkerUsesNarrowAuthorityRPCWithoutDatabaseAccess(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, sqlite.Config{Path: filepath.Join(t.TempDir(), "gitoversight.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	broker := server.NewDurableBroker(db)
	broker.SetWriteGate(openGate{})
	if err := broker.InstallPolicy(ctx, "tenant-a", policy.Snapshot{
		Generation: 1, Agents: map[string]policy.Agent{"zara": {UID: uint32(os.Getuid()), FirstName: "Zara"}},
		Repositories: map[string]policy.Repository{"yaniv256/private": {Visibility: "private", Owners: []string{"zara"}}},
	}); err != nil {
		t.Fatal(err)
	}
	request := server.DurableOperationRequest{ID: "operation-1", Repository: "yaniv256/private", Operation: "branch.push", Branch: "feat/rpc", ManifestHash: "manifest", Payload: map[string]any{"sha": "abc123"}}
	if _, err := broker.Submit(ctx, server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, request); err != nil {
		t.Fatal(err)
	}
	packet, err := broker.PrepareExecutionPacket(ctx, server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, request.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service := authorityrpc.NewServer(filepath.Join(t.TempDir(), "authority.sock"), broker, uint32(os.Getuid()), "worker-a", "tenant-a", os.Getgid())
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() { _ = service.Serve(listener) }()

	privilegedWorker := worker.New(authorityrpc.NewClient(listener.Addr().String()), committedExecutor{})
	result, err := privilegedWorker.Handle(worker.Request{
		TenantID: packet.TenantID, Capability: packet.Capability, RequestID: packet.RequestID, Repository: packet.Repository,
		Operation: packet.Operation, Payload: packet.Payload, Branch: packet.Branch, Title: packet.Title,
		Body: packet.Body, ManifestHash: packet.ManifestHash, ActorMode: packet.ActorMode, ActorSubject: packet.ActorSubject,
	}, time.Now().UTC())
	if err != nil || result.ResourceID != "verified" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestAuthorityRPCRejectsWorkerIDDifferentFromGrantBinding(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, sqlite.Config{Path: filepath.Join(t.TempDir(), "gitoversight.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	broker := server.NewDurableBroker(db)
	broker.SetWriteGate(openGate{})
	if err := broker.InstallPolicy(ctx, "tenant-a", policy.Snapshot{
		Generation: 1, Agents: map[string]policy.Agent{"zara": {UID: uint32(os.Getuid()), FirstName: "Zara"}},
		Repositories: map[string]policy.Repository{"yaniv256/private": {Visibility: "private", Owners: []string{"zara"}}},
	}); err != nil {
		t.Fatal(err)
	}
	request := server.DurableOperationRequest{ID: "operation-worker-binding", Repository: "yaniv256/private", Operation: "branch.push", Branch: "feat/rpc", ManifestHash: "manifest", Payload: map[string]any{"sha": "abc123"}}
	identity := server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}
	if _, err := broker.Submit(ctx, identity, request); err != nil {
		t.Fatal(err)
	}
	packet, err := broker.PrepareExecutionPacket(ctx, identity, request.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service := authorityrpc.NewServer(filepath.Join(t.TempDir(), "authority.sock"), broker, uint32(os.Getuid()), "worker-b", "tenant-a", os.Getgid())
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() { _ = service.Serve(listener) }()

	_, err = worker.New(authorityrpc.NewClient(listener.Addr().String()), committedExecutor{}).Handle(worker.Request{
		TenantID: packet.TenantID, Capability: packet.Capability, RequestID: packet.RequestID, Repository: packet.Repository,
		Operation: packet.Operation, Payload: packet.Payload, Branch: packet.Branch, Title: packet.Title,
		Body: packet.Body, ManifestHash: packet.ManifestHash, ActorMode: packet.ActorMode, ActorSubject: packet.ActorSubject,
	}, time.Now().UTC())
	if err == nil || !strings.Contains(err.Error(), "capability_rejected") {
		t.Fatalf("worker mismatch error = %v", err)
	}
}

func TestAuthorityRPCSocketPermissionDriftFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authority.sock")
	service := authorityrpc.NewServer(path, server.NewDurableBroker(nil), uint32(os.Getuid()), "worker-a", "tenant-a", os.Getgid())
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() { _ = service.Serve(listener) }()
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	_, err = authorityrpc.NewClient(path).ConsumeCapability("token", "yaniv256/private", "branch.push", "mutation", time.Now().UTC())
	if err == nil || !strings.Contains(err.Error(), "authority_socket_permissions_invalid") {
		t.Fatalf("permission drift error = %v", err)
	}
}
