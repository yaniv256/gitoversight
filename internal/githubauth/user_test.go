package githubauth_test

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/githubauth"
	"github.com/yaniv256/gitoversight.dev/internal/tokenvault"
)

type credentialStore struct {
	mu    sync.Mutex
	value tokenvault.UserCredential
}

func (s *credentialStore) GetUserCredential(string) (tokenvault.UserCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.value, nil
}

func (s *credentialStore) PutUserCredential(_ string, value tokenvault.UserCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.value = value
	return nil
}

func TestUserTokenProviderAtomicallyRotatesExpiredCredential(t *testing.T) {
	store := &credentialStore{value: tokenvault.UserCredential{AccessToken: "ghu_old", AccessExpiresAt: time.Now().Add(-time.Minute), RefreshToken: "ghr_old", RefreshExpiresAt: time.Now().Add(time.Hour)}}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Method != http.MethodPost || request.URL.Path != "/login/oauth/access_token" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		if err := request.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if request.Form.Get("client_id") != "Iv1.client" || request.Form.Get("client_secret") != "client-secret" || request.Form.Get("grant_type") != "refresh_token" || request.Form.Get("refresh_token") != "ghr_old" {
			t.Fatalf("form = %#v", request.Form)
		}
		response.Header().Set("Content-Type", "application/json")
		response.Write([]byte(`{"access_token":"ghu_new","expires_in":28800,"refresh_token":"ghr_new","refresh_token_expires_in":15897600,"token_type":"bearer"}`))
	}))
	defer server.Close()
	httpClient := server.Client()
	httpClient.Timeout = time.Second
	provider, err := githubauth.NewUserTokenProvider(server.URL, "Iv1.client", "client-secret", httpClient, store)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		token, err := provider.Token("yaniv256")
		if err != nil || token != "ghu_new" {
			t.Fatalf("token = %q, err = %v", token, err)
		}
	}
	if calls.Load() != 1 || store.value.RefreshToken != "ghr_new" {
		t.Fatalf("calls = %d, credential = %#v", calls.Load(), store.value)
	}
}

func TestUserTokenProviderFailsClosedAfterRefreshExpiry(t *testing.T) {
	store := &credentialStore{value: tokenvault.UserCredential{AccessToken: "ghu_old", AccessExpiresAt: time.Now().Add(-time.Minute), RefreshToken: "ghr_old", RefreshExpiresAt: time.Now().Add(-time.Minute)}}
	httpClient := &http.Client{Timeout: time.Second}
	provider, err := githubauth.NewUserTokenProvider("https://github.test", "client", "secret", httpClient, store)
	if err != nil {
		t.Fatal(err)
	}
	if token, err := provider.Token("yaniv256"); err == nil || token != "" {
		t.Fatalf("token = %q, err = %v", token, err)
	}
}
