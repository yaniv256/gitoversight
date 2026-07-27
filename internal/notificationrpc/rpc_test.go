package notificationrpc_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/notificationrpc"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

func TestNotifierCanOnlyUseDeliveryLeaseRPC(t *testing.T) {
	db, err := sqlite.Open(context.Background(), sqlite.Config{Path: filepath.Join(t.TempDir(), "gitoversight.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	service := notificationrpc.NewServer(filepath.Join(t.TempDir(), "notifications.sock"), db, uint32(os.Getuid()), os.Getgid())
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() { _ = service.Serve(listener) }()
	client := notificationrpc.NewClient(listener.Addr().String())
	if _, worked, err := client.ClaimNotificationDelivery(context.Background(), "notify-a", time.Now().UTC(), time.Minute); err != nil || worked {
		t.Fatalf("worked=%v err=%v", worked, err)
	}
}

func TestNotificationRPCSocketPermissionDriftFailsClosed(t *testing.T) {
	db, err := sqlite.Open(context.Background(), sqlite.Config{Path: filepath.Join(t.TempDir(), "gitoversight.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	path := filepath.Join(t.TempDir(), "notifications.sock")
	service := notificationrpc.NewServer(path, db, uint32(os.Getuid()), os.Getgid())
	listener, err := service.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() { _ = service.Serve(listener) }()
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	_, err = notificationrpc.NewClient(path).ExpandNotificationOutbox(context.Background(), time.Now().UTC())
	if err == nil || !strings.Contains(err.Error(), "notification_socket_permissions_invalid") {
		t.Fatalf("permission drift error = %v", err)
	}
}
