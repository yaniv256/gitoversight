package contract_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/api"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/server"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

func TestGitHubWebhookIsAuthenticatedReceiptNotApprovalAuthority(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, sqlite.Config{Path: filepath.Join(t.TempDir(), "gitoversight.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.WithTx(ctx, func(tx *sqlite.Tx) error { return tx.EnsureTenant(ctx, "tenant-a", time.Now().UTC()) }); err != nil {
		t.Fatal(err)
	}
	broker := server.NewDurableBroker(db)
	broker.SetWriteGate(contractWriteGate{})
	snapshot := policy.Snapshot{
		Generation: 1,
		Agents:     map[string]policy.Agent{"zara": {UID: 1000, FirstName: "Zara"}},
		Repositories: map[string]policy.Repository{
			"yaniv256/public": {Visibility: "public", Owners: []string{"zara"}, Approvers: []string{"yaniv"}},
		},
	}
	if err := broker.InstallPolicy(ctx, "tenant-a", snapshot); err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().UTC().Add(time.Hour)
	request := server.DurableOperationRequest{
		ID: "webhook-operation", Repository: "yaniv256/public", Operation: "pull_request.create",
		Branch: "feat/reviewed", Title: "Reviewed public change", Body: "Exact body", HeadSHA: "abc123",
		ManifestHash: "manifest-1", ApprovalID: "approval-1", ApprovalNonce: "nonce-1",
		ApprovalExpiresAt: expiresAt, Approver: "yaniv", Payload: map[string]any{"base": "main", "head_sha": "abc123"},
	}
	pending, err := broker.Submit(ctx, server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, request)
	if err != nil || pending.State != server.DurableAwaitingApproval {
		t.Fatalf("pending = %+v, err = %v", pending, err)
	}

	secret := []byte("0123456789abcdef0123456789abcdef")
	handler := api.NewGitHubWebhookHandler(db, api.GitHubWebhookConfig{TenantID: "tenant-a", Secret: secret, MaxBodyBytes: 1 << 20})
	body := []byte(`{"action":"submitted","repository":{"full_name":"yaniv256/public"},"pull_request":{"head":{"sha":"abc123"}},"review":{"state":"approved","user":{"login":"yaniv"}}}`)

	first := sendGitHubWebhook(handler, secret, "delivery-1", body)
	if first.Code != http.StatusAccepted {
		t.Fatalf("first status = %d, body = %q", first.Code, first.Body.String())
	}
	status, err := broker.Status(ctx, server.DurableIdentity{TenantID: "tenant-a", AgentID: "zara"}, request.ID)
	if err != nil || status.State != server.DurableAwaitingApproval {
		t.Fatalf("status = %+v, err = %v", status, err)
	}

	replay := sendGitHubWebhook(handler, secret, "delivery-1", body)
	if replay.Code != http.StatusConflict {
		t.Fatalf("replay status = %d, body = %q", replay.Code, replay.Body.String())
	}

	transformed := httptest.NewRequest(http.MethodPost, "/webhooks/github", strings.NewReader(string(body)+"\n"))
	transformed.Header.Set("X-Hub-Signature-256", githubSignature(secret, body))
	transformed.Header.Set("X-GitHub-Delivery", "delivery-2")
	transformed.Header.Set("X-GitHub-Event", "pull_request_review")
	transformedResponse := httptest.NewRecorder()
	handler.ServeHTTP(transformedResponse, transformed)
	if transformedResponse.Code != http.StatusForbidden {
		t.Fatalf("transformed status = %d", transformedResponse.Code)
	}

	pingBody := []byte(`{"zen":"Keep it logically awesome."}`)
	pingRequest := httptest.NewRequest(http.MethodPost, "/webhooks/github", strings.NewReader(string(pingBody)))
	pingRequest.Header.Set("X-Hub-Signature-256", githubSignature(secret, pingBody))
	pingRequest.Header.Set("X-GitHub-Delivery", "delivery-ping")
	pingRequest.Header.Set("X-GitHub-Event", "ping")
	pingResponse := httptest.NewRecorder()
	handler.ServeHTTP(pingResponse, pingRequest)
	if pingResponse.Code != http.StatusAccepted {
		t.Fatalf("signed ping status = %d: %s", pingResponse.Code, pingResponse.Body.String())
	}
}

func sendGitHubWebhook(handler http.Handler, secret []byte, deliveryID string, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/webhooks/github", strings.NewReader(string(body)))
	request.Header.Set("X-Hub-Signature-256", githubSignature(secret, body))
	request.Header.Set("X-GitHub-Delivery", deliveryID)
	request.Header.Set("X-GitHub-Event", "pull_request_review")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func githubSignature(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
