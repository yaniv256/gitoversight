package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/commitpacket"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/releaseasset"
	"github.com/yaniv256/gitoversight.dev/internal/server"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

type apiTestWriteGate struct{}

func (apiTestWriteGate) Verify() error                        { return nil }
func (apiTestWriteGate) Commit(context.Context, string) error { return nil }

func TestEnsurePolicyUsesNewerDurableEnrollmentAcrossRestart(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, sqlite.Config{Path: filepath.Join(t.TempDir(), "gitoversight.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	broker := server.NewDurableBroker(db)
	broker.SetWriteGate(apiTestWriteGate{})
	configured := policy.Snapshot{
		Generation: 1,
		Agents:     map[string]policy.Agent{"zara": {UID: 1000, FirstName: "Zara"}},
		Repositories: map[string]policy.Repository{
			"yaniv256/private": {Visibility: "private", Owners: []string{"zara"}, Approvers: []string{"yaniv"}},
		},
	}
	active, err := ensurePolicy(ctx, broker, "tenant-a", configured)
	if err != nil || active.Generation != 1 {
		t.Fatalf("initial policy = %+v, %v", active, err)
	}
	status, err := broker.PolicyStatus(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.EnrollWorkAgent(ctx, "tenant-a", "yaniv", server.WorkAgentEnrollment{
		AgentID: "chatgpt-work", DisplayName: "ChatGPT Work", AllPrivate: true,
		ExpectedGeneration: status.Generation, ExpectedPolicyHash: status.PolicyHash,
	}); err != nil {
		t.Fatal(err)
	}
	if err := policyReady(ctx, broker, "tenant-a", configured); err != nil {
		t.Fatalf("readiness rejected durable enrollment: %v", err)
	}
	restarted := server.NewDurableBroker(db)
	restarted.SetWriteGate(apiTestWriteGate{})
	active, err = ensurePolicy(ctx, restarted, "tenant-a", configured)
	if err != nil {
		t.Fatalf("restart rejected newer durable policy: %v", err)
	}
	if active.Generation != 2 || !active.Agents["chatgpt-work"].IsRemote() {
		t.Fatalf("restart did not preserve remote enrollment: %+v", active)
	}
}

func TestReleaseAssetProtocolAgreementFailsClosed(t *testing.T) {
	rootID := strings.Repeat("a", 64)
	for _, test := range []struct {
		name   string
		status workerrpc.ReleaseAssetReadiness
		ok     bool
	}{
		{"exact", workerrpc.ReleaseAssetReadiness{ProtocolVersion: releaseasset.ProtocolVersion, RootID: rootID, Readable: true}, true},
		{"old protocol", workerrpc.ReleaseAssetReadiness{ProtocolVersion: releaseasset.ProtocolVersion - 1, RootID: rootID, Readable: true}, false},
		{"wrong root", workerrpc.ReleaseAssetReadiness{ProtocolVersion: releaseasset.ProtocolVersion, RootID: strings.Repeat("b", 64), Readable: true}, false},
		{"unreadable", workerrpc.ReleaseAssetReadiness{ProtocolVersion: releaseasset.ProtocolVersion, RootID: rootID}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateReleaseAssetProtocol(rootID, test.status)
			if (err == nil) != test.ok {
				t.Fatalf("error = %v, want ok=%v", err, test.ok)
			}
		})
	}
}

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
