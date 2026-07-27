package appbootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	AppPrivateKeyFilename   = "github-app.pem"
	AppClientSecretFilename = "github-app-client.secret"
	WebhookSecretFilename   = "webhook.secret"
	AppMetadataFilename     = "app.json"
)

type RegistrationStore interface {
	Store(context.Context, Registration) error
}

type SecretDirectoryStore struct {
	path string
}

type AppMetadata struct {
	SchemaVersion int    `json:"schema_version"`
	AppID         int64  `json:"app_id"`
	Slug          string `json:"slug"`
	ClientID      string `json:"client_id"`
	HTMLURL       string `json:"html_url"`
	Name          string `json:"name"`
	Owner         string `json:"owner"`
}

func NewSecretDirectoryStore(path string) (*SecretDirectoryStore, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) == "/" {
		return nil, errors.New("GitHub App secret directory must be an absolute non-root path")
	}
	return &SecretDirectoryStore{path: filepath.Clean(path)}, nil
}

func (store *SecretDirectoryStore) Store(ctx context.Context, registration Registration) error {
	if err := validateRegistration(registration); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	parent := filepath.Dir(store.path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return errors.New("create GitHub App secret parent directory")
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		return errors.New("secure GitHub App secret parent directory")
	}
	parentInfo, err := os.Stat(parent)
	if err != nil {
		return errors.New("inspect GitHub App secret parent directory")
	}
	if !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("GitHub App secret parent directory is not owner-only")
	}
	if _, err := os.Lstat(store.path); err == nil {
		return errors.New("GitHub App secret bundle already exists")
	} else if !os.IsNotExist(err) {
		return errors.New("inspect GitHub App secret bundle")
	}
	temporary, err := os.MkdirTemp(parent, ".github-app-bootstrap-*")
	if err != nil {
		return errors.New("create GitHub App secret staging directory")
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := os.Chmod(temporary, 0o700); err != nil {
		return errors.New("secure GitHub App secret staging directory")
	}
	metadata, err := json.MarshalIndent(AppMetadata{
		SchemaVersion: 1,
		AppID:         registration.ID,
		Slug:          registration.Slug,
		ClientID:      registration.ClientID,
		HTMLURL:       registration.HTMLURL,
		Name:          registration.Name,
		Owner:         ApprovedOwner,
	}, "", "  ")
	if err != nil {
		return errors.New("encode GitHub App metadata")
	}
	files := []struct {
		name    string
		payload []byte
	}{
		{name: AppPrivateKeyFilename, payload: []byte(registration.PEM)},
		{name: AppClientSecretFilename, payload: []byte(registration.ClientSecret)},
		{name: WebhookSecretFilename, payload: []byte(registration.WebhookSecret)},
		{name: AppMetadataFilename, payload: append(metadata, '\n')},
	}
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := writeSecretFile(filepath.Join(temporary, file.name), file.payload); err != nil {
			return fmt.Errorf("write GitHub App bootstrap file %s", file.name)
		}
	}
	if err := syncDirectory(temporary); err != nil {
		return errors.New("sync GitHub App secret staging directory")
	}
	if err := os.Rename(temporary, store.path); err != nil {
		return errors.New("publish GitHub App secret bundle")
	}
	published = true
	if err := syncDirectory(parent); err != nil {
		return errors.New("sync GitHub App secret parent directory")
	}
	return nil
}

func writeSecretFile(path string, payload []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(payload); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
