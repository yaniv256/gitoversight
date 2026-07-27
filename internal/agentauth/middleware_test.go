package agentauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMiddlewareAuthenticatesSignedRequestAndRejectsReplay(t *testing.T) {
	t.Parallel()

	service := NewCredentialService(openCredentialDB(t), CredentialServiceConfig{ChallengeTTL: time.Minute, WriteGate: credentialTestWriteGate{}})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credential := enrollKnownKey(t, service, "zara-key-1", publicKey, privateKey)
	middleware, err := NewMiddleware(service, MiddlewareConfig{MaxBodyBytes: 1024, SignatureTTL: time.Minute, ClockSkew: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}

	var seen Identity
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		seen, _ = IdentityFromContext(request.Context())
		body, _ := io.ReadAll(request.Body)
		if string(body) != `{"caller":"mallory","value":1}` {
			t.Fatalf("handler body = %q", body)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	request := signedRequest(t, privateKey, credential, "nonce-1", []byte(`{"caller":"mallory","value":1}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("signed response = %d: %s", response.Code, response.Body.String())
	}
	if seen.AgentID != "zara" || seen.CredentialID != "zara-key-1" || seen.TenantID != "tenant-a" {
		t.Fatalf("identity = %+v", seen)
	}

	replay := cloneSignedRequest(t, request)
	replayResponse := httptest.NewRecorder()
	handler.ServeHTTP(replayResponse, replay)
	if replayResponse.Code != http.StatusUnauthorized {
		t.Fatalf("replay response = %d, want 401", replayResponse.Code)
	}
}

func TestMiddlewareRejectsBodyTargetTenantAndForwardingDrift(t *testing.T) {
	t.Parallel()

	service := NewCredentialService(openCredentialDB(t), CredentialServiceConfig{ChallengeTTL: time.Minute, WriteGate: credentialTestWriteGate{}})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credential := enrollKnownKey(t, service, "zara-key-1", publicKey, privateKey)
	middleware, err := NewMiddleware(service, MiddlewareConfig{MaxBodyBytes: 1024, SignatureTTL: time.Minute, ClockSkew: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))

	tests := map[string]func(*http.Request){
		"body": func(request *http.Request) {
			request.Body = io.NopCloser(bytes.NewReader([]byte(`{"value":2}`)))
			request.ContentLength = int64(len(`{"value":2}`))
		},
		"path":       func(request *http.Request) { request.URL.Path = "/v1/other" },
		"tenant":     func(request *http.Request) { request.Header.Set(HeaderTenant, "tenant-b") },
		"agent":      func(request *http.Request) { request.Header.Set(HeaderAgent, "mallory") },
		"credential": func(request *http.Request) { request.Header.Set(HeaderCredential, "another-key") },
		"forwarded":  func(request *http.Request) { request.Header.Set("Forwarded", "host=evil.example") },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := signedRequest(t, privateKey, credential, "nonce-"+name, []byte(`{"value":1}`))
			mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("response = %d, want 401", response.Code)
			}
		})
	}

	wrongAgent, err := http.NewRequest(http.MethodPost, "https://gitoversight.test/v1/operations", bytes.NewReader([]byte(`{"value":1}`)))
	if err != nil {
		t.Fatal(err)
	}
	wrongAgent.Header.Set("Content-Type", "application/json")
	if err := SignRequest(wrongAgent, privateKey, Identity{TenantID: credential.TenantID, AgentID: "mallory", CredentialID: credential.ID}, "nonce-wrong-agent", time.Minute); err != nil {
		t.Fatal(err)
	}
	wrongAgentResponse := httptest.NewRecorder()
	handler.ServeHTTP(wrongAgentResponse, wrongAgent)
	if wrongAgentResponse.Code != http.StatusUnauthorized {
		t.Fatalf("wrong signed agent response = %d, want 401", wrongAgentResponse.Code)
	}
}

func TestMiddlewareRejectsRevokedCredentialAndOversizedBody(t *testing.T) {
	t.Parallel()

	service := NewCredentialService(openCredentialDB(t), CredentialServiceConfig{ChallengeTTL: time.Minute, WriteGate: credentialTestWriteGate{}})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credential := enrollKnownKey(t, service, "zara-key-1", publicKey, privateKey)
	middleware, err := NewMiddleware(service, MiddlewareConfig{MaxBodyBytes: 16, SignatureTTL: time.Minute, ClockSkew: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))

	oversized := signedRequest(t, privateKey, credential, "nonce-large", []byte(`{"value":"this is too large"}`))
	oversizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(oversizedResponse, oversized)
	if oversizedResponse.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized response = %d, want 413", oversizedResponse.Code)
	}

	if err := service.Revoke(context.Background(), credential.TenantID, credential.ID, "yaniv"); err != nil {
		t.Fatal(err)
	}
	revoked := signedRequest(t, privateKey, credential, "nonce-revoked", []byte(`{}`))
	revokedResponse := httptest.NewRecorder()
	handler.ServeHTTP(revokedResponse, revoked)
	if revokedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("revoked response = %d, want 401", revokedResponse.Code)
	}
}

func TestMiddlewareRejectsMissingDuplicateConflictingAndExpiredSignatures(t *testing.T) {
	t.Parallel()

	service := NewCredentialService(openCredentialDB(t), CredentialServiceConfig{ChallengeTTL: time.Minute, WriteGate: credentialTestWriteGate{}})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credential := enrollKnownKey(t, service, "zara-key-1", publicKey, privateKey)
	middleware, err := NewMiddleware(service, MiddlewareConfig{MaxBodyBytes: 1024, SignatureTTL: time.Minute, ClockSkew: 0})
	if err != nil {
		t.Fatal(err)
	}
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))

	unsigned := httptest.NewRequest(http.MethodPost, "https://gitoversight.example/v1/operations", bytes.NewReader([]byte(`{}`)))
	unsigned.Header.Set(HeaderTenant, "tenant-a")
	unsigned.Header.Set(HeaderCredential, "zara-key-1")

	duplicate := signedRequest(t, privateKey, credential, "nonce-duplicate", []byte(`{}`))
	duplicate.Header.Add(HeaderTenant, "tenant-a")

	conflicting := signedRequest(t, privateKey, credential, "nonce-conflicting", []byte(`{}`))
	conflicting.Header.Add("Signature", conflicting.Header.Get("Signature"))

	expired := httptest.NewRequest(http.MethodPost, "https://gitoversight.example/v1/operations?dry_run=false", bytes.NewReader([]byte(`{}`)))
	expired.Header.Set("Content-Type", "application/json")
	if err := SignRequest(expired, privateKey, Identity{TenantID: credential.TenantID, AgentID: credential.AgentID, CredentialID: credential.ID}, "nonce-expired", time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)

	for name, request := range map[string]*http.Request{
		"unsigned": unsigned, "duplicate": duplicate, "conflicting": conflicting, "expired": expired,
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("response = %d, want 401", response.Code)
			}
		})
	}
}

func TestMiddlewareRateLimitsVerifiedCredentialBeforeNonceConsumption(t *testing.T) {
	t.Parallel()

	service := NewCredentialService(openCredentialDB(t), CredentialServiceConfig{ChallengeTTL: time.Minute, WriteGate: credentialTestWriteGate{}})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credential := enrollKnownKey(t, service, "zara-key-1", publicKey, privateKey)
	now := time.Unix(1000, 0)
	limiter, err := NewFixedWindowLimiter(1, time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	middleware, err := NewMiddleware(service, MiddlewareConfig{MaxBodyBytes: 1024, SignatureTTL: time.Minute, SourceLimiter: limiter})
	if err != nil {
		t.Fatal(err)
	}
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))

	first := signedRequest(t, privateKey, credential, "nonce-first", []byte(`{}`))
	first.RemoteAddr = "192.0.2.10:1234"
	firstResponse := httptest.NewRecorder()
	handler.ServeHTTP(firstResponse, first)
	if firstResponse.Code != http.StatusNoContent {
		t.Fatalf("first response = %d", firstResponse.Code)
	}

	limited := signedRequest(t, privateKey, credential, "nonce-not-consumed", []byte(`{}`))
	limited.RemoteAddr = "192.0.2.10:5678"
	limitedResponse := httptest.NewRecorder()
	handler.ServeHTTP(limitedResponse, limited)
	if limitedResponse.Code != http.StatusTooManyRequests {
		t.Fatalf("limited response = %d, want 429", limitedResponse.Code)
	}

	retryElsewhere := cloneSignedRequest(t, limited)
	retryElsewhere.RemoteAddr = "198.51.100.7:5678"
	retryResponse := httptest.NewRecorder()
	handler.ServeHTTP(retryResponse, retryElsewhere)
	if retryResponse.Code != http.StatusTooManyRequests {
		t.Fatalf("credential limit was bypassed by changing source IP: %d", retryResponse.Code)
	}
	now = now.Add(time.Minute)
	retryAfterWindow := cloneSignedRequest(t, limited)
	retryAfterWindowResponse := httptest.NewRecorder()
	handler.ServeHTTP(retryAfterWindowResponse, retryAfterWindow)
	if retryAfterWindowResponse.Code != http.StatusNoContent {
		t.Fatalf("nonce was consumed by rate-limit denial: %d", retryAfterWindowResponse.Code)
	}
}

func enrollKnownKey(t *testing.T, service *CredentialService, credentialID string, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) Credential {
	t.Helper()
	challenge, err := service.Begin(context.Background(), EnrollmentRequest{TenantID: "tenant-a", AgentID: "zara", CredentialID: credentialID, PublicKey: publicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Complete(context.Background(), "tenant-a", challenge.ID, ed25519.Sign(privateKey, challenge.ProofMessage)); err != nil {
		t.Fatal(err)
	}
	credential, err := service.Approve(context.Background(), "tenant-a", challenge.ID, "yaniv")
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func signedRequest(t *testing.T, privateKey ed25519.PrivateKey, credential Credential, nonce string, body []byte) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "https://gitoversight.example/v1/operations?dry_run=false", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := SignRequest(request, privateKey, Identity{TenantID: credential.TenantID, AgentID: credential.AgentID, CredentialID: credential.ID}, nonce, time.Minute); err != nil {
		t.Fatal(err)
	}
	return request
}

func cloneSignedRequest(t *testing.T, source *http.Request) *http.Request {
	t.Helper()
	body, err := source.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	clone := source.Clone(context.Background())
	clone.Body = body
	clone.Header = source.Header.Clone()
	return clone
}
