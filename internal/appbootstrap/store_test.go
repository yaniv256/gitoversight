package appbootstrap

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretDirectoryStorePublishesCompleteOwnerOnlyBundle(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "github-app")
	store, err := NewSecretDirectoryStore(path)
	if err != nil {
		t.Fatal(err)
	}
	registration := validRegistration()
	if err := store.Store(context.Background(), registration); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode = %o", info.Mode().Perm())
	}
	want := map[string]string{
		AppPrivateKeyFilename:   registration.PEM,
		AppClientSecretFilename: registration.ClientSecret,
		WebhookSecretFilename:   registration.WebhookSecret,
	}
	for name, content := range want {
		payload, err := os.ReadFile(filepath.Join(path, name))
		if err != nil {
			t.Fatal(err)
		}
		fileInfo, err := os.Stat(filepath.Join(path, name))
		if err != nil {
			t.Fatal(err)
		}
		if fileInfo.Mode().Perm() != 0o600 || string(payload) != content {
			t.Fatalf("%s mode/content mismatch", name)
		}
	}
	metadata, err := os.ReadFile(filepath.Join(path, AppMetadataFilename))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{registration.PEM, registration.ClientSecret, registration.WebhookSecret} {
		if strings.Contains(string(metadata), secret) {
			t.Fatal("metadata contains secret material")
		}
	}
}

func TestSecretDirectoryStoreFailsClosedWithoutPartialFinalDirectory(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "github-app")
	store, err := NewSecretDirectoryStore(path)
	if err != nil {
		t.Fatal(err)
	}
	invalid := validRegistration()
	invalid.ClientSecret = ""
	if err := store.Store(context.Background(), invalid); err == nil {
		t.Fatal("accepted incomplete registration")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("partial final directory exists: %v", err)
	}
	if err := store.Store(context.Background(), validRegistration()); err != nil {
		t.Fatal(err)
	}
	if err := store.Store(context.Background(), validRegistration()); err == nil {
		t.Fatal("overwrote existing secret bundle")
	}
}

func validRegistration() Registration {
	return Registration{
		ID:            42,
		Slug:          "yaniv-gitoversight-broker",
		ClientID:      "Iv23f8doAlphaNumer1c",
		ClientSecret:  "client-secret-value",
		WebhookSecret: "webhook-secret-value",
		PEM:           "-----BEGIN RSA PRIVATE KEY-----\nprivate-key-value\n-----END RSA PRIVATE KEY-----\n",
		HTMLURL:       "https://github.com/apps/yaniv-gitoversight-broker",
		Name:          ApprovedAppName,
		Owner:         ApprovedOwner,
	}
}
