package ingress_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/ingress"
)

func signature(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestWebhookRequiresSignatureAndConsumesApprovalTupleOnce(t *testing.T) {
	t.Parallel()
	secret := []byte("webhook-secret")
	handler := ingress.NewWebhookVerifier(secret, 1024)
	tuple := ingress.ApprovalTuple{Nonce: "nonce", Repository: "yaniv256/public", Head: "head", Manifest: "manifest", Approver: "yaniv"}
	if err := handler.Expect(tuple, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"action":"submitted","nonce":"nonce","manifest_hash":"manifest","repository":{"full_name":"yaniv256/public"},"pull_request":{"head":{"sha":"head"}},"review":{"state":"approved","user":{"login":"yaniv"}}}`)
	if err := handler.Consume(signature(secret, body), body, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := handler.Consume(signature(secret, body), body, time.Now()); err != ingress.ErrReplay {
		t.Fatalf("replay = %v", err)
	}
}

func TestStandardGitHubReviewWebhookResolvesServerSideApprovalTuple(t *testing.T) {
	secret := []byte("secret")
	verifier := ingress.NewWebhookVerifier(secret, 4096)
	expected := ingress.ApprovalTuple{Nonce: "nonce-standard", Repository: "yaniv256/public", Head: "abc123", Manifest: "manifest-hash", Approver: "yaniv"}
	if err := verifier.Expect(expected, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"action":"submitted","repository":{"full_name":"yaniv256/public"},"pull_request":{"head":{"sha":"abc123"}},"review":{"state":"approved","user":{"login":"yaniv"}}}`)
	actual, err := verifier.ConsumeTuple(signature(secret, body), body, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("tuple = %#v", actual)
	}
}

func TestWebhookRejectsOversizeBadSignatureAndChangedTuple(t *testing.T) {
	t.Parallel()
	secret := []byte("webhook-secret")
	handler := ingress.NewWebhookVerifier(secret, 1024)
	tuple := ingress.ApprovalTuple{Nonce: "nonce", Repository: "yaniv256/public", Head: "head", Manifest: "manifest", Approver: "yaniv"}
	if err := handler.Expect(tuple, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := handler.Consume("sha256=bad", []byte("body"), time.Now()); err != ingress.ErrSignature {
		t.Fatalf("bad signature = %v", err)
	}
	big := []byte(strings.Repeat("x", 1025))
	if err := handler.Consume(signature(secret, big), big, time.Now()); err != ingress.ErrOversize {
		t.Fatalf("oversize = %v", err)
	}
	body := []byte(`{"action":"submitted","nonce":"nonce","manifest_hash":"manifest","repository":{"full_name":"yaniv256/public"},"pull_request":{"head":{"sha":"other"}},"review":{"state":"approved","user":{"login":"yaniv"}}}`)
	if err := handler.Consume(signature(secret, body), body, time.Now()); err != ingress.ErrUnsolicited {
		t.Fatalf("changed tuple = %v", err)
	}
}

func TestOAuthTransactionIsStatePKCEAccountAndSessionBound(t *testing.T) {
	t.Parallel()
	store := ingress.NewOAuthStore()
	now := time.Now()
	tx := ingress.OAuthTransaction{State: "state", Session: "session", Approver: "yaniv", Installation: 42, RedirectURI: "https://app.gitoversight.com/callback", PKCEChallenge: ingress.PKCEChallenge("verifier"), ExpiresAt: now.Add(time.Minute)}
	if err := store.Put(tx); err != nil {
		t.Fatal(err)
	}
	if err := store.Consume("state", "session", "yaniv", 42, tx.RedirectURI, "wrong", now); err != ingress.ErrOAuthBinding {
		t.Fatalf("wrong verifier = %v", err)
	}
	if err := store.Consume("state", "session", "yaniv", 42, tx.RedirectURI, "verifier", now); err != nil {
		t.Fatal(err)
	}
	if err := store.Consume("state", "session", "yaniv", 42, tx.RedirectURI, "verifier", now); err != ingress.ErrReplay {
		t.Fatalf("oauth replay = %v", err)
	}
}
