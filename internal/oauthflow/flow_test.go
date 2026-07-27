package oauthflow_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/oauthflow"
	"github.com/yaniv256/gitoversight.dev/internal/tokenvault"
)

type sealedStore struct {
	mu         sync.Mutex
	values     map[string]json.RawMessage
	credential tokenvault.UserCredential
	subject    string
}

func newSealedStore() *sealedStore { return &sealedStore{values: make(map[string]json.RawMessage)} }

func (s *sealedStore) PutJSON(subject string, value any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	payload, err := json.Marshal(value)
	if err == nil {
		s.values[subject] = payload
	}
	return err
}

func (s *sealedStore) GetJSON(subject string, destination any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.Unmarshal(s.values[subject], destination)
}

func (s *sealedStore) PutUserCredential(subject string, credential tokenvault.UserCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subject = subject
	s.credential = credential
	return nil
}

func TestOAuthCallbackIsStatePKCEAccountInstallationAndReplayBound(t *testing.T) {
	store := newSealedStore()
	var exchanges atomic.Int32
	var expectedChallenge string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/login/oauth/access_token":
			exchanges.Add(1)
			if err := request.ParseForm(); err != nil {
				t.Fatal(err)
			}
			verifier := request.Form.Get("code_verifier")
			digest := sha256.Sum256([]byte(verifier))
			if request.Method != http.MethodPost || request.Form.Get("client_id") != "Iv1.client" || request.Form.Get("client_secret") != "client-secret" || request.Form.Get("code") != "one-time-code" || request.Form.Get("redirect_uri") == "" || base64.RawURLEncoding.EncodeToString(digest[:]) != expectedChallenge {
				t.Fatalf("exchange form = %#v", request.Form)
			}
			response.Header().Set("Content-Type", "application/json")
			io.WriteString(response, `{"access_token":"ghu_access","expires_in":28800,"refresh_token":"ghr_refresh","refresh_token_expires_in":15897600,"token_type":"bearer"}`)
		case "/user":
			if request.Header.Get("Authorization") != "Bearer ghu_access" {
				t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
			}
			io.WriteString(response, `{"login":"Yaniv256"}`)
		case "/user/installations/42/repositories":
			if request.Header.Get("Authorization") != "Bearer ghu_access" {
				t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
			}
			if request.URL.Query().Get("per_page") != "1" {
				t.Fatalf("query = %q", request.URL.RawQuery)
			}
			io.WriteString(response, `{"total_count":3,"repositories":[{"id":1}]}`)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	httpClient := server.Client()
	httpClient.Timeout = time.Second

	callbackURL := server.URL + "/oauth/github/callback"
	config := oauthflow.Config{OAuthBaseURL: server.URL, APIBaseURL: server.URL, ClientID: "Iv1.client", ClientSecret: "client-secret", RedirectURI: callbackURL}
	coordinator, err := oauthflow.New(config, httpClient, store)
	if err != nil {
		t.Fatal(err)
	}
	authorizationURL, err := coordinator.Begin(oauthflow.BeginRequest{Purpose: "human_login", Session: "owner-session", Subject: "yaniv", GitHubLogin: "Yaniv256", Installation: 42, ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	expectedChallenge = query.Get("code_challenge")
	if parsed.Path != "/login/oauth/authorize" || query.Get("client_id") != "Iv1.client" || query.Get("redirect_uri") != callbackURL || query.Get("state") == "" || expectedChallenge == "" || query.Get("code_challenge_method") != "S256" {
		t.Fatalf("authorization URL = %s", authorizationURL)
	}

	// Recreate the coordinator before the callback to prove the sealed
	// transaction, including its verifier, survives a worker restart.
	coordinator, err = oauthflow.New(config, httpClient, store)
	if err != nil {
		t.Fatal(err)
	}
	completion, err := coordinator.Complete(query.Get("state"), "one-time-code")
	if err != nil {
		t.Fatal(err)
	}
	if completion.Purpose != "human_login" || completion.Session != "owner-session" || completion.Subject != "yaniv" {
		t.Fatalf("completion = %#v", completion)
	}
	if store.subject != "human_user:yaniv" || store.credential.AccessToken != "ghu_access" || store.credential.RefreshToken != "ghr_refresh" {
		t.Fatalf("subject = %q, credential = %#v", store.subject, store.credential)
	}

	if _, err := coordinator.Complete(query.Get("state"), "one-time-code"); err == nil || exchanges.Load() != 1 {
		t.Fatalf("replay error = %v, exchanges = %d", err, exchanges.Load())
	}
}

func TestOAuthCallbackRejectsWrongHumanWithoutPersistingCredential(t *testing.T) {
	store := newSealedStore()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/login/oauth/access_token":
			response.Header().Set("Content-Type", "application/json")
			io.WriteString(response, `{"access_token":"ghu_access","expires_in":28800,"refresh_token":"ghr_refresh","refresh_token_expires_in":15897600,"token_type":"bearer"}`)
		case "/user":
			io.WriteString(response, `{"login":"attacker"}`)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	httpClient := server.Client()
	httpClient.Timeout = time.Second
	coordinator, err := oauthflow.New(oauthflow.Config{OAuthBaseURL: server.URL, APIBaseURL: server.URL, ClientID: "Iv1.client", ClientSecret: "client-secret", RedirectURI: server.URL + "/oauth/github/callback"}, httpClient, store)
	if err != nil {
		t.Fatal(err)
	}
	authorizationURL, err := coordinator.Begin(oauthflow.BeginRequest{Purpose: "human_login", Session: "owner-session", Subject: "yaniv", GitHubLogin: "Yaniv256", Installation: 42, ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(authorizationURL)
	if _, err := coordinator.Complete(parsed.Query().Get("state"), "one-time-code"); err == nil || store.subject != "" {
		t.Fatalf("error = %v, persisted subject = %q", err, store.subject)
	}
}

func TestOAuthCallbackRejectsInstallationResponseWithoutProof(t *testing.T) {
	store := newSealedStore()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/login/oauth/access_token":
			response.Header().Set("Content-Type", "application/json")
			io.WriteString(response, `{"access_token":"ghu_access","expires_in":28800,"refresh_token":"ghr_refresh","refresh_token_expires_in":15897600,"token_type":"bearer"}`)
		case "/user":
			io.WriteString(response, `{"login":"Yaniv256"}`)
		case "/user/installations/42/repositories":
			io.WriteString(response, `{}`)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	httpClient := server.Client()
	httpClient.Timeout = time.Second
	coordinator, err := oauthflow.New(oauthflow.Config{OAuthBaseURL: server.URL, APIBaseURL: server.URL, ClientID: "Iv1.client", ClientSecret: "client-secret", RedirectURI: server.URL + "/oauth/github/callback"}, httpClient, store)
	if err != nil {
		t.Fatal(err)
	}
	authorizationURL, err := coordinator.Begin(oauthflow.BeginRequest{Purpose: "human_login", Session: "owner-session", Subject: "yaniv", GitHubLogin: "Yaniv256", Installation: 42, ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(authorizationURL)
	if _, err := coordinator.Complete(parsed.Query().Get("state"), "one-time-code"); err == nil || store.subject != "" {
		t.Fatalf("error = %v, persisted subject = %q", err, store.subject)
	}
}
