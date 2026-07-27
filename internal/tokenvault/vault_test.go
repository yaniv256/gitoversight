package tokenvault_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/tokenvault"
)

func TestVaultEncryptsTokensAtRest(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "tokens.enc")
	vault, err := tokenvault.Open(path, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	secret := "github_pat_never_plaintext"
	if err := vault.Put("yaniv", secret); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("token persisted in plaintext")
	}
	got, err := vault.Get("yaniv")
	if err != nil || got != secret {
		t.Fatalf("get = %q, %v", got, err)
	}
}

func TestVaultAtomicallyStoresRotatingUserCredential(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "tokens.enc")
	vault, err := tokenvault.Open(path, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	want := tokenvault.UserCredential{AccessToken: "ghu_access", AccessExpiresAt: time.Now().Add(8 * time.Hour), RefreshToken: "ghr_refresh", RefreshExpiresAt: time.Now().Add(180 * 24 * time.Hour)}
	if err := vault.PutUserCredential("human_user:yaniv256", want); err != nil {
		t.Fatal(err)
	}
	got, err := vault.GetUserCredential("human_user:yaniv256")
	if err != nil || got.AccessToken != want.AccessToken || got.RefreshToken != want.RefreshToken {
		t.Fatalf("credential = %#v, err = %v", got, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(want.AccessToken)) || bytes.Contains(raw, []byte(want.RefreshToken)) {
		t.Fatal("rotating user credential persisted in plaintext")
	}
}

func TestVaultRoundTripsSealedJSONState(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "tokens.enc")
	vault, err := tokenvault.Open(path, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	type transaction struct {
		State    string `json:"state"`
		Verifier string `json:"verifier"`
		Used     bool   `json:"used"`
	}
	want := transaction{State: "opaque-state", Verifier: "secret-verifier"}
	if err := vault.PutJSON("oauth_state:"+want.State, want); err != nil {
		t.Fatal(err)
	}
	var got transaction
	if err := vault.GetJSON("oauth_state:"+want.State, &got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("transaction = %#v", got)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(want.Verifier)) {
		t.Fatal("sealed JSON state persisted in plaintext")
	}
}

func TestVaultRejectsWrongKey(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "tokens.enc")
	vault, err := tokenvault.Open(path, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.Put("yaniv", "secret"); err != nil {
		t.Fatal(err)
	}
	wrong, err := tokenvault.Open(path, bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Get("yaniv"); err == nil {
		t.Fatal("expected authentication failure")
	}
}
