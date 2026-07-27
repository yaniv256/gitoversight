package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/commitpacket"
)

func TestAPIListenMustBeExplicitLoopback(t *testing.T) {
	for _, address := range []string{"0.0.0.0:17445", ":17445", "192.0.2.1:17445"} {
		if requireLoopback(address) == nil {
			t.Errorf("accepted %q", address)
		}
	}
	for _, address := range []string{"127.0.0.1:17445", "[::1]:17445"} {
		if err := requireLoopback(address); err != nil {
			t.Errorf("rejected %q: %v", address, err)
		}
	}
}

func TestNotificationRPCConfigurationIsOptionalButCannotBePartial(t *testing.T) {
	base := config{
		Listen: "127.0.0.1:17445", DatabasePath: "/var/lib/gitoversight/gitoversight.db",
		TenantID: "tenant-a", PolicyFile: "/etc/gitoversight/policy.json",
		WorkerSocket: "/run/gitoversight/worker.sock", GitReadSocket: "/run/gitoversight/git-read.sock",
		GitReadBaseURL: "https://gitoversight.example/git", ReadSessionTTL: "10m", AuthoritySocket: "/run/gitoversight/authority.sock",
		WorkerUID: 1001, AuthoritySocketGID: 1001, WorkerID: "worker-a",
		CheckpointSocket: "/run/gitoversight/checkpoint.sock", WebhookSecretFile: "/etc/gitoversight/webhook-secret",
		HumanApprovers: map[string]string{"yaniv": "Yaniv256"}, MaxBodyBytes: commitpacket.MaxRequestBodyBytes,
		MaxConcurrent: 8, RateLimitRequests: 20, MinimumFreeBytes: 1024,
	}
	if _, err := loadConfig(writeConfig(t, base)); err != nil {
		t.Fatalf("optional notification configuration was required: %v", err)
	}
	base.NotificationSocket = "/run/gitoversight/notification.sock"
	if _, err := loadConfig(writeConfig(t, base)); err == nil {
		t.Fatal("partial notification configuration was accepted")
	}
	base.NotificationUID, base.NotificationSocketGID = 1002, 1002
	if _, err := loadConfig(writeConfig(t, base)); err != nil {
		t.Fatalf("complete notification configuration was rejected: %v", err)
	}
}

func TestSearchDBPathIsOptional(t *testing.T) {
	base := config{
		Listen: "127.0.0.1:17445", DatabasePath: "/var/lib/gitoversight/gitoversight.db",
		TenantID: "tenant-a", PolicyFile: "/etc/gitoversight/policy.json",
		WorkerSocket: "/run/gitoversight/worker.sock", GitReadSocket: "/run/gitoversight/git-read.sock",
		GitReadBaseURL: "https://gitoversight.example/git", ReadSessionTTL: "10m", AuthoritySocket: "/run/gitoversight/authority.sock",
		WorkerUID: 1001, AuthoritySocketGID: 1001, WorkerID: "worker-a",
		CheckpointSocket: "/run/gitoversight/checkpoint.sock", WebhookSecretFile: "/etc/gitoversight/webhook-secret",
		HumanApprovers: map[string]string{"yaniv": "Yaniv256"}, MaxBodyBytes: commitpacket.MaxRequestBodyBytes,
		MaxConcurrent: 8, RateLimitRequests: 20, MinimumFreeBytes: 1024,
	}
	if _, err := loadConfig(writeConfig(t, base)); err != nil {
		t.Fatalf("empty search_db_path was rejected: %v", err)
	}
	base.SearchDBPath = "/var/lib/gitoversight/search.db"
	cfg, err := loadConfig(writeConfig(t, base))
	if err != nil {
		t.Fatalf("search_db_path was rejected: %v", err)
	}
	if cfg.SearchDBPath != "/var/lib/gitoversight/search.db" {
		t.Fatalf("search_db_path = %q", cfg.SearchDBPath)
	}
}

func TestAPIConfigurationRejectsRequestLimitBelowCommitEnvelope(t *testing.T) {
	cfg := config{
		Listen: "127.0.0.1:17445", DatabasePath: "/var/lib/gitoversight/gitoversight.db",
		TenantID: "tenant-a", PolicyFile: "/etc/gitoversight/policy.json",
		WorkerSocket: "/run/gitoversight/worker.sock", GitReadSocket: "/run/gitoversight/git-read.sock",
		GitReadBaseURL: "https://gitoversight.example/git", ReadSessionTTL: "10m", AuthoritySocket: "/run/gitoversight/authority.sock",
		WorkerUID: 1001, AuthoritySocketGID: 1001, WorkerID: "worker-a",
		CheckpointSocket: "/run/gitoversight/checkpoint.sock", WebhookSecretFile: "/etc/gitoversight/webhook-secret",
		HumanApprovers: map[string]string{"yaniv": "Yaniv256"}, MaxBodyBytes: commitpacket.MaxRequestBodyBytes - 1,
		MaxConcurrent: 8, RateLimitRequests: 20, MinimumFreeBytes: 1024,
	}
	if _, err := loadConfig(writeConfig(t, cfg)); err == nil {
		t.Fatal("API accepted a body limit smaller than the commit publication envelope")
	}
}

func writeConfig(t *testing.T, cfg config) string {
	t.Helper()
	payload, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
