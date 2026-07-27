package checkpoint_test

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/checkpoint"
)

func TestCheckpointUnixServiceExtendsAndVerifiesState(t *testing.T) {
	t.Parallel()
	client, cleanup := startCheckpointService(t, uint32(os.Getuid()))
	defer cleanup()

	state, err := client.Extend(checkpoint.Extension{NewTail: "tail-1", PolicyGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	current, err := client.State()
	if err != nil {
		t.Fatal(err)
	}
	if current != state {
		t.Fatalf("state = %#v, want %#v", current, state)
	}
	if err := client.Verify(state); err != nil {
		t.Fatalf("verify: %v", err)
	}
	state.Tail = "forged"
	if err := client.Verify(state); err == nil {
		t.Fatal("expected forged state rejection")
	}
}

func TestCheckpointUnixServiceRejectsUnauthorizedPeer(t *testing.T) {
	t.Parallel()
	client, cleanup := startCheckpointService(t, uint32(os.Getuid()+1))
	defer cleanup()
	if _, err := client.State(); err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("state error = %v", err)
	}
}

func TestCheckpointUnixServiceHasNoArbitrarySignOrResetOperation(t *testing.T) {
	t.Parallel()
	client, cleanup := startCheckpointService(t, uint32(os.Getuid()))
	defer cleanup()
	conn, err := net.DialTimeout("unix", client.SocketPath(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(map[string]any{"operation": "sign", "state": checkpoint.State{Tail: "replacement"}}); err != nil {
		t.Fatal(err)
	}
	var response struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(response.Error, "unsupported") {
		t.Fatalf("response = %#v", response)
	}
}

func TestCheckpointSocketPermissionDriftFailsClosed(t *testing.T) {
	t.Parallel()
	client, cleanup := startCheckpointService(t, uint32(os.Getuid()))
	defer cleanup()
	if err := os.Chmod(client.SocketPath(), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := client.State(); err == nil || !strings.Contains(err.Error(), "socket permissions invalid") {
		t.Fatalf("state error = %v", err)
	}
}

func startCheckpointService(t *testing.T, allowedUID uint32) (*checkpoint.Client, func()) {
	t.Helper()
	dir := t.TempDir()
	signer, err := checkpoint.Open(filepath.Join(dir, "state.json"), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	server := checkpoint.NewServer(filepath.Join(dir, "checkpoint.sock"), signer, allowedUID)
	listener, err := server.Listen()
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	client, err := checkpoint.NewClient(server.SocketPath(), time.Second)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	return client, func() { _ = listener.Close() }
}
