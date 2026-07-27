package tokenvault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/durable"
)

type Vault struct {
	mu   sync.Mutex
	path string
	key  []byte
}

type UserCredential struct {
	AccessToken      string    `json:"access_token"`
	AccessExpiresAt  time.Time `json:"access_expires_at"`
	RefreshToken     string    `json:"refresh_token"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}

func Open(path string, key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, errors.New("vault key must be 32 bytes")
	}
	return &Vault{path: path, key: append([]byte(nil), key...)}, nil
}

func (v *Vault) Put(subject, token string) error {
	payload, err := json.Marshal(token)
	if err != nil {
		return err
	}
	return v.put(subject, payload)
}

func (v *Vault) PutUserCredential(subject string, credential UserCredential) error {
	if subject == "" || credential.AccessToken == "" || credential.AccessExpiresAt.IsZero() || credential.RefreshToken == "" || credential.RefreshExpiresAt.IsZero() {
		return errors.New("user credential is incomplete")
	}
	payload, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	return v.put(subject, payload)
}

// PutJSON seals small privileged-service state alongside credentials. Callers
// provide a namespaced subject so unrelated state cannot collide.
func (v *Vault) PutJSON(subject string, value any) error {
	if subject == "" || value == nil {
		return errors.New("sealed JSON entry is incomplete")
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return v.put(subject, payload)
}

func (v *Vault) put(subject string, value json.RawMessage) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	values, err := v.load()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if values == nil {
		values = make(map[string]json.RawMessage)
	}
	values[subject] = value
	payload, err := json.Marshal(values)
	if err != nil {
		return err
	}
	sealed, err := v.encrypt(payload)
	if err != nil {
		return err
	}
	return durable.Replace(v.path, sealed, 0o600)
}

func (v *Vault) Get(subject string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	values, err := v.load()
	if err != nil {
		return "", err
	}
	raw, ok := values[subject]
	if !ok {
		return "", errors.New("token not found")
	}
	var token string
	if err := json.Unmarshal(raw, &token); err != nil {
		return "", errors.New("vault entry is not a token")
	}
	return token, nil
}

func (v *Vault) GetUserCredential(subject string) (UserCredential, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	values, err := v.load()
	if err != nil {
		return UserCredential{}, err
	}
	raw, ok := values[subject]
	if !ok {
		return UserCredential{}, errors.New("user credential not found")
	}
	var credential UserCredential
	if err := json.Unmarshal(raw, &credential); err != nil || credential.AccessToken == "" {
		return UserCredential{}, errors.New("user credential is invalid")
	}
	return credential, nil
}

func (v *Vault) GetJSON(subject string, destination any) error {
	if subject == "" || destination == nil {
		return errors.New("sealed JSON destination is incomplete")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	values, err := v.load()
	if err != nil {
		return err
	}
	raw, ok := values[subject]
	if !ok {
		return errors.New("sealed JSON entry not found")
	}
	if err := json.Unmarshal(raw, destination); err != nil {
		return errors.New("sealed JSON entry is invalid")
	}
	return nil
}

func (v *Vault) load() (map[string]json.RawMessage, error) {
	payload, err := os.ReadFile(v.path)
	if err != nil {
		return nil, err
	}
	plaintext, err := v.decrypt(payload)
	if err != nil {
		return nil, err
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(plaintext, &values); err != nil {
		return nil, err
	}
	return values, nil
}

func (v *Vault) encrypt(plaintext []byte) ([]byte, error) {
	aead, err := v.aead()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return append(nonce, aead.Seal(nil, nonce, plaintext, []byte("gitoversight-v1"))...), nil
}

func (v *Vault) decrypt(payload []byte) ([]byte, error) {
	aead, err := v.aead()
	if err != nil {
		return nil, err
	}
	if len(payload) < aead.NonceSize() {
		return nil, errors.New("encrypted vault is truncated")
	}
	nonce, ciphertext := payload[:aead.NonceSize()], payload[aead.NonceSize():]
	return aead.Open(nil, nonce, ciphertext, []byte("gitoversight-v1"))
}

func (v *Vault) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
