package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/agentauth"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/server"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

func TestEnrollmentHTTPRequiresProofAndProtectedHumanApproval(t *testing.T) {
	db, err := sqlite.Open(context.Background(), sqlite.Config{Path: filepath.Join(t.TempDir(), "gitoversight.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.WithTx(context.Background(), func(tx *sqlite.Tx) error {
		return tx.EnsureTenant(context.Background(), "tenant-a", time.Now().UTC())
	}); err != nil {
		t.Fatal(err)
	}
	broker := server.NewDurableBroker(db)
	broker.SetWriteGate(apiTestWriteGate{})
	if err := broker.InstallPolicy(context.Background(), "tenant-a", policy.Snapshot{
		Generation: 1, Agents: map[string]policy.Agent{"zara": {UID: 1000, FirstName: "Zara"}},
		Repositories: map[string]policy.Repository{"yaniv256/private": {Visibility: "private", Owners: []string{"zara"}}},
	}); err != nil {
		t.Fatal(err)
	}
	service := agentauth.NewCredentialService(db, agentauth.CredentialServiceConfig{ChallengeTTL: time.Minute, WriteGate: apiTestWriteGate{}})
	handler := NewEnrollmentHandler(service, EnrollmentHandlerConfig{MaxBodyBytes: 2048})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	challengeResponse := postJSON(t, handler, "/v1/enrollments/challenge", map[string]any{
		"tenant_id": "tenant-a", "agent_id": "zara", "credential_id": "zara-key-1",
		"public_key": base64.RawURLEncoding.EncodeToString(publicKey),
	}, nil)
	if challengeResponse.Code != http.StatusCreated {
		t.Fatalf("challenge = %d: %s", challengeResponse.Code, challengeResponse.Body.String())
	}
	var challenge struct {
		ID           string `json:"id"`
		ProofMessage string `json:"proof_message"`
	}
	if err := json.Unmarshal(challengeResponse.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	proofMessage, err := base64.RawURLEncoding.DecodeString(challenge.ProofMessage)
	if err != nil {
		t.Fatal(err)
	}

	proofResponse := postJSON(t, handler, "/v1/enrollments/"+challenge.ID+"/proof", map[string]any{
		"tenant_id": "tenant-a", "proof": base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, proofMessage)),
	}, nil)
	if proofResponse.Code != http.StatusNoContent {
		t.Fatalf("proof = %d: %s", proofResponse.Code, proofResponse.Body.String())
	}

	unauthorized := postJSON(t, handler, "/v1/enrollments/"+challenge.ID+"/approve", map[string]any{"tenant_id": "tenant-a"}, nil)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized approval = %d, want 401", unauthorized.Code)
	}

	humanContext := func(ctx context.Context) context.Context {
		return WithHumanApprover(ctx, HumanApprover{TenantID: "tenant-a", ID: "yaniv"})
	}
	approved := postJSON(t, handler, "/v1/enrollments/"+challenge.ID+"/approve", map[string]any{"tenant_id": "tenant-a"}, humanContext)
	if approved.Code != http.StatusCreated {
		t.Fatalf("approval = %d: %s", approved.Code, approved.Body.String())
	}
	credential, err := service.Resolve(context.Background(), "tenant-a", "zara-key-1")
	if err != nil || credential.ApprovedBy != "yaniv" {
		t.Fatalf("approved credential = %+v, %v", credential, err)
	}
}

func postJSON(t *testing.T, handler http.Handler, path string, body any, contextDecorator func(context.Context) context.Context) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	if contextDecorator != nil {
		request = request.WithContext(contextDecorator(request.Context()))
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
