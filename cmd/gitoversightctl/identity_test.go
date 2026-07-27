package main

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/agentauth"
)

func TestGenerateIdentityStoresOwnerOnlyPrivateKeyAndCanSign(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.key")
	publicKey, err := generateIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode = %o, want 600", info.Mode().Perm())
	}
	privateKey, err := loadIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if !publicKey.Equal(privateKey.Public()) {
		t.Fatal("loaded private key does not match generated public key")
	}
	request := httptest.NewRequest(http.MethodPost, "https://gitoversight.example/v1/operations", nil)
	if err := signAgentRequest(request, privateKey, agentauth.Identity{TenantID: "tenant-a", AgentID: "zara", CredentialID: "zara-key-1"}, "nonce-1", time.Minute); err != nil {
		t.Fatal(err)
	}
	if request.Header.Get("Signature") == "" || len(privateKey) != ed25519.PrivateKeySize {
		t.Fatal("signed request or private key is invalid")
	}
}

func TestLoadIdentityRejectsBroadPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.key")
	if _, err := generateIdentity(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentity(path); err == nil {
		t.Fatal("load accepted group-readable private key")
	}
}
