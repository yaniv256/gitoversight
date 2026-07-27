package security_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/adminrpc"
	"github.com/yaniv256/gitoversight.dev/internal/approval"
	"github.com/yaniv256/gitoversight.dev/internal/approvalflow"
	"github.com/yaniv256/gitoversight.dev/internal/audit"
	"github.com/yaniv256/gitoversight.dev/internal/daemon"
	"github.com/yaniv256/gitoversight.dev/internal/identity"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/server"
	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

func TestSignedHumanReviewFlowsAcrossPrivilegedBoundaryIntoExactApproval(t *testing.T) {
	directory := t.TempDir()
	now := time.Now().UTC()
	secret := []byte("0123456789abcdef0123456789abcdef")
	approvals, err := approval.OpenStore(filepath.Join(directory, "approvals.json"))
	if err != nil {
		t.Fatal(err)
	}
	journal, err := audit.Open(filepath.Join(directory, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := policy.Snapshot{
		Generation: 1,
		Agents: map[string]policy.Agent{
			"zara": {UID: uint32(os.Getuid()), FirstName: "Zara"},
		},
		Repositories: map[string]policy.Repository{
			"yaniv256/public": {Visibility: "public", Owners: []string{"zara"}, Approvers: []string{"yaniv"}},
		},
	}
	broker := server.New(snapshot, approvals, journal, time.Minute)
	registry, err := identity.NewRegistry(map[string]uint32{"zara": uint32(os.Getuid())})
	if err != nil {
		t.Fatal(err)
	}

	adminPath := filepath.Join(directory, "admin.sock")
	adminService := adminrpc.NewServer(adminPath, uint32(os.Getuid()), approvals)
	adminListener, err := adminService.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer adminListener.Close()
	go adminService.Serve(adminListener)

	coordinator, err := approvalflow.Open(secret, 4096, 2, filepath.Join(directory, "expectations.json"))
	if err != nil {
		t.Fatal(err)
	}
	workerPath := filepath.Join(directory, "worker.sock")
	workerService := workerrpc.NewServer(workerPath, uint32(os.Getuid()), workerrpc.WithApprovalExpecter(coordinator))
	workerListener, err := workerService.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer workerListener.Close()
	go workerService.Serve(workerListener)

	brokerPath := filepath.Join(directory, "broker.sock")
	brokerService := daemon.New(brokerPath, registry, broker, daemon.WithApprovalRequester(workerrpc.NewClient(workerPath)))
	brokerListener, err := brokerService.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer brokerListener.Close()
	go brokerService.Serve(brokerListener)

	expectation := daemon.Request{
		SchemaVersion: 1, Action: "approval.expect", RequestID: "expect-1",
		Repository: "yaniv256/public", Operation: "pull_request.create", Branch: "export",
		Title: "Public change", Body: "Exact public body", ManifestHash: "manifest-1",
		ApprovalID: "approval-1", Approver: "yaniv", HeadSHA: "abc123", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}
	response := sendBrokerRequest(t, brokerPath, expectation)
	if response.Error != "" || response.Approval == nil || response.Approval.Nonce == "" {
		t.Fatalf("expectation response = %#v", response)
	}

	webhook := coordinator.Handler(adminrpc.NewClient(adminPath))
	wrongBody := []byte(`{"action":"submitted","repository":{"full_name":"yaniv256/public"},"pull_request":{"head":{"sha":"changed"}},"review":{"state":"approved","user":{"login":"yaniv"}}}`)
	if status := sendSignedWebhook(webhook, secret, wrongBody); status != http.StatusForbidden {
		t.Fatalf("changed head status = %d", status)
	}
	body := []byte(`{"action":"submitted","repository":{"full_name":"yaniv256/public"},"pull_request":{"head":{"sha":"abc123"}},"review":{"state":"approved","user":{"login":"yaniv"}}}`)
	if status := sendSignedWebhook(webhook, secret, body); status != http.StatusAccepted {
		t.Fatalf("approval status = %d", status)
	}
	if status := sendSignedWebhook(webhook, secret, body); status != http.StatusConflict {
		t.Fatalf("replay status = %d", status)
	}

	authorized := broker.Authorize("zara", server.MutationRequest{
		RequestID: "execute-1", Repository: "yaniv256/public", Operation: "pull_request.create", Branch: "export", Title: "Public change", Body: "Exact public body", ApprovalID: "approval-1",
	}, "manifest-1", now.Add(time.Second))
	if authorized.Code != server.AllowedByApproval || authorized.Capability == "" {
		t.Fatalf("authorization = %#v", authorized)
	}
	changed := broker.Authorize("zara", server.MutationRequest{
		RequestID: "execute-2", Repository: "yaniv256/public", Operation: "pull_request.create", Branch: "export", Title: "Changed", Body: "Exact public body", ApprovalID: "approval-1",
	}, "changed-manifest", now.Add(2*time.Second))
	if changed.Code != policy.ApprovalRequired || changed.Capability != "" {
		t.Fatalf("changed authorization = %#v", changed)
	}
}

func sendBrokerRequest(t *testing.T, path string, request daemon.Request) daemon.Response {
	t.Helper()
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		t.Fatal(err)
	}
	var response daemon.Response
	if err := json.NewDecoder(connection).Decode(&response); err != nil {
		t.Fatal(err)
	}
	return response
}

func sendSignedWebhook(handler http.Handler, secret, body []byte) int {
	request := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(body))
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	request.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response.Code
}
