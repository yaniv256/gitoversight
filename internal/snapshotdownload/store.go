package snapshotdownload

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	maxActiveDownloads = 128
	maxActiveBytes     = 256 << 20
)

type Metadata struct {
	URL, SHA256 string
	ExpiresAt   time.Time
	Size        int64
}

type Store struct {
	baseURL string
	ttl     time.Duration
	now     func() time.Time
	random  func([]byte) (int, error)
	mu      sync.Mutex
	items   map[[sha256.Size]byte]item
	bytes   int64
}

type item struct {
	content             []byte
	contentType, sha256 string
	expiresAt           time.Time
}

func New(baseURL string, ttl time.Duration, now func() time.Time) (*Store, error) {
	if !strings.HasPrefix(baseURL, "https://") || ttl <= 0 || ttl > 15*time.Minute {
		return nil, errors.New("snapshot download store configuration is invalid")
	}
	if now == nil {
		now = time.Now
	}
	return &Store{baseURL: strings.TrimRight(baseURL, "/"), ttl: ttl, now: now, random: rand.Read, items: make(map[[sha256.Size]byte]item)}, nil
}

func (store *Store) Put(content []byte, contentType, expectedSHA256 string, maxBytes int64) (Metadata, error) {
	if len(content) == 0 || int64(len(content)) > maxBytes || contentType != "application/gzip" {
		return Metadata{}, errors.New("snapshot download content is invalid")
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != expectedSHA256 {
		return Metadata{}, errors.New("snapshot download digest mismatch")
	}
	secret := make([]byte, 32)
	if count, err := store.random(secret); err != nil || count != len(secret) {
		return Metadata{}, errors.New("snapshot capability generation failed")
	}
	token := base64.RawURLEncoding.EncodeToString(secret)
	key := sha256.Sum256([]byte(token))
	expires := store.now().UTC().Add(store.ttl)
	store.mu.Lock()
	defer store.mu.Unlock()
	store.pruneLocked()
	if len(store.items) >= maxActiveDownloads || store.bytes+int64(len(content)) > maxActiveBytes {
		return Metadata{}, errors.New("too many active snapshot downloads")
	}
	if _, collision := store.items[key]; collision {
		return Metadata{}, errors.New("snapshot capability collision")
	}
	store.items[key] = item{content: append([]byte(nil), content...), contentType: contentType, sha256: expectedSHA256, expiresAt: expires}
	store.bytes += int64(len(content))
	return Metadata{URL: store.baseURL + "/v1/repository-snapshots/" + token, SHA256: expectedSHA256, ExpiresAt: expires, Size: int64(len(content))}, nil
}

func (store *Store) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.NotFound(response, request)
		return
	}
	token := strings.TrimPrefix(request.URL.Path, "/v1/repository-snapshots/")
	if token == request.URL.Path || token == "" || strings.Contains(token, "/") {
		http.NotFound(response, request)
		return
	}
	key := sha256.Sum256([]byte(token))
	now := store.now().UTC()
	store.mu.Lock()
	value, ok := store.items[key]
	if ok {
		delete(store.items, key)
		store.bytes -= int64(len(value.content))
	}
	store.mu.Unlock()
	if !ok || !now.Before(value.expiresAt) {
		http.Error(response, "snapshot download unavailable", http.StatusGone)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", value.contentType)
	response.Header().Set("X-GitOversight-SHA256", value.sha256)
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(value.content)
}

func (store *Store) pruneLocked() {
	now := store.now().UTC()
	for key, value := range store.items {
		if !now.Before(value.expiresAt) {
			delete(store.items, key)
			store.bytes -= int64(len(value.content))
		}
	}
}

// DeleteExpired promptly releases unredeemed private archive bytes. Put also
// calls the same pruning path so capacity cannot be held by expired entries.
func (store *Store) DeleteExpired() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	before := len(store.items)
	store.pruneLocked()
	return before - len(store.items)
}
