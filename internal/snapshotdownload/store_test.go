package snapshotdownload

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStoreIssuesHTTPSSingleUseBoundedDownload(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	store, err := New("https://gitoversight.test", time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	store.random = func(value []byte) (int, error) {
		for i := range value {
			value[i] = byte(i + 1)
		}
		return len(value), nil
	}
	content := []byte("archive")
	digest := sha256.Sum256(content)
	metadata, err := store.Put(content, "application/gzip", hex.EncodeToString(digest[:]), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(metadata.URL, "https://") || metadata.Size != int64(len(content)) {
		t.Fatalf("metadata = %#v", metadata)
	}
	request := httptest.NewRequest(http.MethodGet, metadata.URL, nil)
	first := httptest.NewRecorder()
	store.ServeHTTP(first, request)
	if first.Code != http.StatusOK || first.Body.String() != "archive" || first.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("first = %d %#v %q", first.Code, first.Header(), first.Body.String())
	}
	second := httptest.NewRecorder()
	store.ServeHTTP(second, request)
	if second.Code != http.StatusGone {
		t.Fatalf("second status = %d", second.Code)
	}
}

func TestStoreRejectsDigestSizeAndExpiredRedemption(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	store, _ := New("https://gitoversight.test", time.Minute, func() time.Time { return now })
	store.random = func(value []byte) (int, error) {
		for i := range value {
			value[i] = 7
		}
		return len(value), nil
	}
	if _, err := store.Put([]byte("x"), "application/gzip", strings.Repeat("0", 64), 1); err == nil {
		t.Fatal("digest mismatch accepted")
	}
	digest := sha256.Sum256([]byte("xx"))
	if _, err := store.Put([]byte("xx"), "application/gzip", hex.EncodeToString(digest[:]), 1); err == nil {
		t.Fatal("oversize accepted")
	}
	metadata, _ := store.Put([]byte("xx"), "application/gzip", hex.EncodeToString(digest[:]), 2)
	now = now.Add(2 * time.Minute)
	response := httptest.NewRecorder()
	store.ServeHTTP(response, httptest.NewRequest(http.MethodGet, metadata.URL, nil))
	if response.Code != http.StatusGone {
		t.Fatalf("expired status = %d", response.Code)
	}
}
