package appbootstrap

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGitHubConverterUsesExactBoundedManifestEndpoint(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/app-manifests/temporary-code/conversions" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
			t.Fatalf("headers = %#v", r.Header)
		}
		if r.Header.Get("Authorization") != "" {
			t.Fatal("manifest conversion unexpectedly carried ambient authentication")
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":42,"slug":"yaniv-gitoversight-broker","client_id":"Iv23f8doAlphaNumer1c","client_secret":"secret-client","webhook_secret":"secret-hook","pem":"-----BEGIN RSA PRIVATE KEY-----\nsecret-key\n-----END RSA PRIVATE KEY-----","html_url":"https://github.com/apps/yaniv-gitoversight-broker","name":"Yaniv Git Oversight Broker","owner":{"login":"yaniv256"}}`)
	}))
	defer server.Close()

	converter, err := NewGitHubConverter(server.URL, &http.Client{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	registration, err := converter.Convert(context.Background(), "temporary-code")
	if err != nil {
		t.Fatal(err)
	}
	if registration.ID != 42 || registration.ClientID != "Iv23f8doAlphaNumer1c" || registration.ClientSecret != "secret-client" || registration.WebhookSecret != "secret-hook" || registration.PEM == "" {
		t.Fatalf("registration = %#v", registration.Redacted())
	}
}

func TestGitHubConverterRejectsInvalidCodeBeforeNetwork(t *testing.T) {
	t.Parallel()
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer server.Close()
	converter, err := NewGitHubConverter(server.URL, &http.Client{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"", "../escape", strings.Repeat("x", 257), "white space"} {
		if _, err := converter.Convert(context.Background(), code); err == nil {
			t.Fatalf("accepted code %q", code)
		}
	}
	if hits != 0 {
		t.Fatalf("invalid codes reached network %d times", hits)
	}
}

func TestGitHubConverterNeverLeaksSecretResponseOrBody(t *testing.T) {
	t.Parallel()
	secret := "ghp_response_body_must_never_escape"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		fmt.Fprint(w, `{"message":"`+secret+`"}`)
	}))
	defer server.Close()
	converter, err := NewGitHubConverter(server.URL, &http.Client{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = converter.Convert(context.Background(), "temporary-code")
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe error = %v", err)
	}
}

func TestGitHubConverterRejectsOversizedAndTrailingResponses(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		strings.Repeat("x", MaxConversionResponseBytes+1),
		`{"id":42} {"client_secret":"trailing"}`,
	} {
		body := body
		t.Run(fmt.Sprintf("bytes-%d", len(body)), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
				fmt.Fprint(w, body)
			}))
			defer server.Close()
			converter, err := NewGitHubConverter(server.URL, &http.Client{Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := converter.Convert(context.Background(), "temporary-code"); err == nil {
				t.Fatal("accepted invalid response")
			}
		})
	}
}
