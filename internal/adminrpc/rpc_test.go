package adminrpc_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/adminrpc"
	"github.com/yaniv256/gitoversight.dev/internal/approval"
)

func TestRootWorkerCanRegisterVerifiedApproval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.sock")
	store := approval.NewStore()
	service := adminrpc.NewServer(path, uint32(os.Getuid()), store)
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go service.Serve(listener)
	packet := approval.Packet{ID: "approval-1", ManifestHash: "manifest-1", Repository: "yaniv256/public", Operations: []string{"pull_request.create"}, Approver: "yaniv", Nonce: "nonce-1", ExpiresAt: time.Now().Add(time.Minute), PolicyGeneration: 1}
	if err := adminrpc.NewClient(path).Put(packet); err != nil {
		t.Fatal(err)
	}
	if err := store.Reserve(packet.ID, "request-1", packet.ManifestHash, packet.Repository, packet.Operations[0], packet.PolicyGeneration, []string{"yaniv"}, time.Now()); err != nil {
		t.Fatalf("registered approval was not consumable: %v", err)
	}
}

func TestAdminSocketRejectsUnexpectedUnixCaller(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.sock")
	store := approval.NewStore()
	service := adminrpc.NewServer(path, uint32(os.Getuid()+1), store)
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go service.Serve(listener)
	packet := approval.Packet{ID: "approval-1", ManifestHash: "manifest-1", Repository: "yaniv256/public", Operations: []string{"pull_request.create"}, Approver: "yaniv", Nonce: "nonce-1", ExpiresAt: time.Now().Add(time.Minute), PolicyGeneration: 1}
	if err := adminrpc.NewClient(path).Put(packet); err == nil {
		t.Fatal("unexpected Unix caller registered approval")
	}
}

func TestAdminSocketIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.sock")
	service := adminrpc.NewServer(path, uint32(os.Getuid()), approval.NewStore())
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %o", info.Mode().Perm())
	}
}
