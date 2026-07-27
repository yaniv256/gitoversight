package identity_test

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/identity"
)

func TestUnixPeerIdentityComesFromKernel(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "broker.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	result := make(chan identity.Peer, 1)
	errs := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			errs <- acceptErr
			return
		}
		defer conn.Close()
		peer, peerErr := identity.FromUnixConn(conn)
		if peerErr != nil {
			errs <- peerErr
			return
		}
		result <- peer
	}()

	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case err := <-errs:
		t.Fatal(err)
	case peer := <-result:
		if peer.UID != uint32(os.Getuid()) {
			t.Fatalf("uid = %d, want %d", peer.UID, os.Getuid())
		}
	}
}

func TestRegistryRejectsDuplicateUIDAndResolvesCanonicalName(t *testing.T) {
	t.Parallel()
	registry, err := identity.NewRegistry(map[string]uint32{"zara": 1002, "tomas": 1005})
	if err != nil {
		t.Fatal(err)
	}
	name, ok := registry.AgentForUID(1005)
	if !ok || name != "tomas" {
		t.Fatalf("resolution = %q, %v", name, ok)
	}
	if _, err := identity.NewRegistry(map[string]uint32{"zara": 1002, "tomas": 1002}); err == nil {
		t.Fatal("expected duplicate UID rejection")
	}
}
