package agentauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/server"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

type credentialTestWriteGate struct{}

func (credentialTestWriteGate) Verify() error                        { return nil }
func (credentialTestWriteGate) Commit(context.Context, string) error { return nil }

func TestEnrollmentRequiresProofOfPossessionAndHumanApproval(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openCredentialDB(t)
	service := NewCredentialService(db, CredentialServiceConfig{ChallengeTTL: time.Minute, WriteGate: credentialTestWriteGate{}})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := service.Begin(ctx, EnrollmentRequest{
		TenantID: "tenant-a", AgentID: "zara", CredentialID: "zara-key-1", PublicKey: publicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Resolve(ctx, "tenant-a", "zara-key-1"); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("unapproved enrollment resolved as credential: %v", err)
	}
	if err := service.Complete(ctx, challenge.TenantID, challenge.ID, ed25519.Sign(privateKey, []byte("wrong message"))); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("wrong proof error = %v, want ErrInvalidProof", err)
	}
	if err := service.Complete(ctx, challenge.TenantID, challenge.ID, ed25519.Sign(privateKey, challenge.ProofMessage)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Resolve(ctx, "tenant-a", "zara-key-1"); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("proved but unapproved enrollment resolved as credential: %v", err)
	}

	credential, err := service.Approve(ctx, challenge.TenantID, challenge.ID, "yaniv")
	if err != nil {
		t.Fatal(err)
	}
	if credential.AgentID != "zara" || credential.ID != "zara-key-1" || credential.ApprovedBy != "yaniv" {
		t.Fatalf("unexpected credential: %+v", credential)
	}
	resolved, err := service.Resolve(ctx, "tenant-a", "zara-key-1")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.AgentID != "zara" || string(resolved.PublicKey) != string(publicKey) {
		t.Fatalf("resolved credential drift: %+v", resolved)
	}
	events, err := db.AuthorityAuditTrail(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	wantKinds := []string{"policy_generation_installed", "agent_enrollment_created", "agent_enrollment_proved", "agent_credential_approved"}
	if len(events) != len(wantKinds) {
		t.Fatalf("audit events = %d, want %d", len(events), len(wantKinds))
	}
	for index, want := range wantKinds {
		if events[index].Kind != want {
			t.Fatalf("audit[%d] = %q, want %q", index, events[index].Kind, want)
		}
	}
}

type rejectingCredentialGate struct{}

func (rejectingCredentialGate) Verify() error { return errors.New("checkpoint unavailable") }
func (rejectingCredentialGate) Commit(context.Context, string) error {
	return errors.New("checkpoint unavailable")
}

func TestEnrollmentFailsClosedWhenCheckpointGateIsUnavailable(t *testing.T) {
	service := NewCredentialService(openCredentialDB(t), CredentialServiceConfig{ChallengeTTL: time.Minute, WriteGate: rejectingCredentialGate{}})
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Begin(context.Background(), EnrollmentRequest{TenantID: "tenant-a", AgentID: "zara", CredentialID: "blocked", PublicKey: publicKey})
	if err == nil || !strings.Contains(err.Error(), "checkpoint unavailable") {
		t.Fatalf("checkpoint outage error = %v", err)
	}
}

func TestRotationApprovalAtomicallyRevokesOldCredential(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openCredentialDB(t)
	service := NewCredentialService(db, CredentialServiceConfig{ChallengeTTL: time.Minute, WriteGate: credentialTestWriteGate{}})
	old := enrollApprovedCredential(t, service, "zara-key-1", "")
	newCredential := enrollApprovedCredential(t, service, "zara-key-2", old.ID)

	if _, err := service.Resolve(ctx, "tenant-a", old.ID); !errors.Is(err, ErrCredentialRevoked) {
		t.Fatalf("old credential error = %v, want ErrCredentialRevoked", err)
	}
	if _, err := service.Resolve(ctx, "tenant-a", newCredential.ID); err != nil {
		t.Fatalf("new credential did not resolve: %v", err)
	}
}

func TestEnrollmentRejectsAgentAbsentFromPolicy(t *testing.T) {
	ctx := context.Background()
	service := NewCredentialService(openCredentialDB(t), CredentialServiceConfig{ChallengeTTL: time.Minute, WriteGate: credentialTestWriteGate{}})
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Begin(ctx, EnrollmentRequest{TenantID: "tenant-a", AgentID: "unknown", CredentialID: "unknown-key-1", PublicKey: publicKey})
	if err == nil || !strings.Contains(err.Error(), "not registered by policy") {
		t.Fatalf("unknown-agent enrollment error = %v", err)
	}
}

func TestEnrollmentPendingQuotaFailsClosed(t *testing.T) {
	ctx := context.Background()
	service := NewCredentialService(openCredentialDB(t), CredentialServiceConfig{ChallengeTTL: time.Hour, WriteGate: credentialTestWriteGate{}})
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 100; index++ {
		if _, err := service.Begin(ctx, EnrollmentRequest{
			TenantID: "tenant-a", AgentID: "zara", CredentialID: fmt.Sprintf("pending-key-%03d", index), PublicKey: publicKey,
		}); err != nil {
			t.Fatalf("enrollment %d: %v", index, err)
		}
	}
	_, err = service.Begin(ctx, EnrollmentRequest{TenantID: "tenant-a", AgentID: "zara", CredentialID: "pending-key-overflow", PublicKey: publicKey})
	if err == nil || !strings.Contains(err.Error(), "quota exceeded") {
		t.Fatalf("quota error = %v", err)
	}
}

func openCredentialDB(t *testing.T) *sqlite.DB {
	t.Helper()
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
	broker.SetWriteGate(credentialTestWriteGate{})
	if err := broker.InstallPolicy(context.Background(), "tenant-a", policy.Snapshot{
		Generation: 1, Agents: map[string]policy.Agent{"zara": {UID: 1000, FirstName: "Zara"}},
		Repositories: map[string]policy.Repository{"yaniv256/private": {Visibility: "private", Owners: []string{"zara"}}},
	}); err != nil {
		t.Fatal(err)
	}
	return db
}

func enrollApprovedCredential(t *testing.T, service *CredentialService, credentialID, supersedesID string) Credential {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := service.Begin(context.Background(), EnrollmentRequest{
		TenantID: "tenant-a", AgentID: "zara", CredentialID: credentialID,
		PublicKey: publicKey, SupersedesCredentialID: supersedesID,
	})
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
