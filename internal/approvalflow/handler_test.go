package approvalflow_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/approval"
	"github.com/yaniv256/gitoversight.dev/internal/approvalflow"
)

type sink struct {
	packets []approval.Packet
	err     error
}

func (s *sink) Put(packet approval.Packet) error {
	if s.err != nil {
		return s.err
	}
	s.packets = append(s.packets, packet)
	return nil
}

func TestWebhookRegistersExactExpectedApprovalOnce(t *testing.T) {
	secret := []byte("webhook-secret")
	coordinator := approvalflow.New(secret, 4096, 2)
	packet := approval.Packet{ID: "approval-1", ManifestHash: "manifest-1", Repository: "yaniv256/public", Operations: []string{"pull_request.create"}, Approver: "yaniv", Nonce: "nonce-1", ExpiresAt: time.Now().Add(time.Minute), PolicyGeneration: 1}
	if err := coordinator.Expect(packet, "abc123"); err != nil {
		t.Fatal(err)
	}
	store := &sink{}
	handler := coordinator.Handler(store)
	body := []byte(`{"action":"submitted","repository":{"full_name":"yaniv256/public"},"pull_request":{"head":{"sha":"abc123"}},"review":{"state":"approved","user":{"login":"yaniv"}}}`)
	request := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(body))
	request.Header.Set("X-Hub-Signature-256", signature(secret, body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || len(store.packets) != 1 || store.packets[0].ID != packet.ID {
		t.Fatalf("status = %d, packets = %#v", response.Code, store.packets)
	}
	replayRequest := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(body))
	replayRequest.Header.Set("X-Hub-Signature-256", signature(secret, body))
	replay := httptest.NewRecorder()
	handler.ServeHTTP(replay, replayRequest)
	if replay.Code != http.StatusConflict || len(store.packets) != 1 {
		t.Fatalf("replay status = %d, packets = %#v", replay.Code, store.packets)
	}
}

func TestWebhookSinkFailureDoesNotConsumeHumanApproval(t *testing.T) {
	secret := []byte("webhook-secret")
	coordinator := approvalflow.New(secret, 4096, 1)
	packet := approval.Packet{ID: "approval-1", ManifestHash: "manifest-1", Repository: "yaniv256/public", Operations: []string{"pull_request.create"}, Approver: "yaniv", Nonce: "nonce-1", ExpiresAt: time.Now().Add(time.Minute), PolicyGeneration: 1}
	if err := coordinator.Expect(packet, "abc123"); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"action":"submitted","repository":{"full_name":"yaniv256/public"},"pull_request":{"head":{"sha":"abc123"}},"review":{"state":"approved","user":{"login":"yaniv"}}}`)
	failed := &sink{err: errors.New("broker unavailable")}
	request := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(body))
	request.Header.Set("X-Hub-Signature-256", signature(secret, body))
	response := httptest.NewRecorder()
	coordinator.Handler(failed).ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", response.Code)
	}
	working := &sink{}
	retry := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(body))
	retry.Header.Set("X-Hub-Signature-256", signature(secret, body))
	retryResponse := httptest.NewRecorder()
	coordinator.Handler(working).ServeHTTP(retryResponse, retry)
	if retryResponse.Code != http.StatusAccepted || len(working.packets) != 1 {
		t.Fatalf("retry status = %d, packets = %#v", retryResponse.Code, working.packets)
	}
}

func TestWebhookRejectsOversizeBeforeApprovalStore(t *testing.T) {
	coordinator := approvalflow.New([]byte("secret"), 8, 1)
	store := &sink{}
	request := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewBufferString("0123456789"))
	response := httptest.NewRecorder()
	coordinator.Handler(store).ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge || len(store.packets) != 0 {
		t.Fatalf("status = %d, packets = %#v", response.Code, store.packets)
	}
}

func TestApprovalExpectationSurvivesRestartAndIsRemovedAfterUse(t *testing.T) {
	secret := []byte("webhook-secret")
	path := t.TempDir() + "/expectations.json"
	coordinator, err := approvalflow.Open(secret, 4096, 1, path)
	if err != nil {
		t.Fatal(err)
	}
	packet := approval.Packet{ID: "approval-1", ManifestHash: "manifest-1", Repository: "yaniv256/public", Operations: []string{"pull_request.create"}, Approver: "yaniv", Nonce: "nonce-1", ExpiresAt: time.Now().Add(time.Minute), PolicyGeneration: 1}
	if err := coordinator.Expect(packet, "abc123"); err != nil {
		t.Fatal(err)
	}
	reopened, err := approvalflow.Open(secret, 4096, 1, path)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"action":"submitted","repository":{"full_name":"yaniv256/public"},"pull_request":{"head":{"sha":"abc123"}},"review":{"state":"approved","user":{"login":"yaniv"}}}`)
	request := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(body))
	request.Header.Set("X-Hub-Signature-256", signature(secret, body))
	response := httptest.NewRecorder()
	reopened.Handler(&sink{}).ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d", response.Code)
	}
	afterUse, err := approvalflow.Open(secret, 4096, 1, path)
	if err != nil {
		t.Fatal(err)
	}
	replay := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(body))
	replay.Header.Set("X-Hub-Signature-256", signature(secret, body))
	replayResponse := httptest.NewRecorder()
	afterUse.Handler(&sink{}).ServeHTTP(replayResponse, replay)
	if replayResponse.Code == http.StatusAccepted {
		t.Fatal("consumed expectation survived restart")
	}
}

func signature(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

var _ approvalflow.Sink = (*sink)(nil)
