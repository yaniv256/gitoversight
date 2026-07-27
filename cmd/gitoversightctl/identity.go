package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/agentauth"
)

func generateIdentity(path string) (ed25519.PublicKey, error) {
	if path == "" {
		return nil, errors.New("identity path is required")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create identity directory: %w", err)
	}
	encoded := []byte(base64.RawURLEncoding.EncodeToString(privateKey) + "\n")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create identity: %w", err)
	}
	if _, err = file.Write(encoded); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("write identity: %w", err)
	}
	if err = file.Close(); err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("close identity: %w", err)
	}
	return publicKey, nil
}

func loadIdentity(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat identity: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, errors.New("identity private key must be a regular owner-only file (0600)")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity: %w", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(string(bytesTrimSpace(payload)))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("identity private key is invalid")
	}
	return ed25519.PrivateKey(decoded), nil
}

func signAgentRequest(request *http.Request, key ed25519.PrivateKey, identity agentauth.Identity, nonce string, ttl time.Duration) error {
	return agentauth.SignRequest(request, key, identity, nonce, ttl)
}

func bytesTrimSpace(value []byte) []byte {
	start, end := 0, len(value)
	for start < end && (value[start] == ' ' || value[start] == '\n' || value[start] == '\r' || value[start] == '\t') {
		start++
	}
	for end > start && (value[end-1] == ' ' || value[end-1] == '\n' || value[end-1] == '\r' || value[end-1] == '\t') {
		end--
	}
	return value[start:end]
}
