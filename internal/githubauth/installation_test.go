package githubauth_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/githubauth"
)

func TestInstallationMinterUsesRS256AndExactRepositoryOperationScope(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, key)})
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Method != http.MethodPost || request.URL.Path != "/app/installations/42/access_tokens" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		verifyJWT(t, strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer "), &key.PublicKey)
		var body struct {
			Repositories []string          `json:"repositories"`
			Permissions  map[string]string `json:"permissions"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		// pull_request.create is scoped to pull_requests:write PLUS contents:read
		// (GitHub must read the base/head refs to open the PR — without contents:read
		// it 422s "not all refs are readable").
		if len(body.Repositories) != 1 || body.Repositories[0] != "private" || body.Permissions["pull_requests"] != "write" || body.Permissions["contents"] != "read" || len(body.Permissions) != 2 {
			t.Fatalf("scope = %#v", body)
		}
		io.WriteString(response, `{"token":"ghs_short_lived","expires_at":"2030-01-01T01:00:00Z"}`)
	}))
	defer server.Close()
	httpClient := server.Client()
	httpClient.Timeout = time.Second
	minter, err := githubauth.NewInstallationMinter(server.URL, "Iv1.client", pemKey, httpClient, map[string]int64{"yaniv256/private": 42})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		token, err := minter.Token("yaniv256/private\x00pull_request.create")
		if err != nil || token != "ghs_short_lived" {
			t.Fatalf("token = %q, err = %v", token, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("mint calls = %d", calls.Load())
	}
}

func TestInstallationMinterRejectsUnregisteredOrUnsupportedScopeBeforeNetwork(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("network reached") }))
	defer server.Close()
	httpClient := server.Client()
	httpClient.Timeout = time.Second
	minter, err := githubauth.NewInstallationMinter(server.URL, "app", pemKey, httpClient, map[string]int64{"yaniv256/private": 42})
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"other/private\x00branch.push", "yaniv256/private\x00unknown", "yaniv256/private"} {
		if _, err := minter.Token(scope); err == nil {
			t.Fatalf("scope %q accepted", scope)
		}
	}
}

// TestInstallationMinterSupportsPullRequestListAndClose guards that the read op
// pull_request.list (needs pull_requests:read) and pull_request.close (needs
// pull_requests:write) are recognized scopes — without a permissionsFor case the
// minter refuses the token before any network call, which surfaced live as a 502
// on pull-list even though the op was fully registered/routed/authorized.
func TestInstallationMinterSupportsPullRequestListAndClose(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	reached := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	httpClient := server.Client()
	httpClient.Timeout = time.Second
	minter, err := githubauth.NewInstallationMinter(server.URL, "app", pemKey, httpClient, map[string]int64{"yaniv256/private": 42})
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"yaniv256/private\x00pull_request.list", "yaniv256/private\x00pull_request.close"} {
		reached = false
		// The token fetch fails at the network stub, but that proves the scope
		// PASSED permissionsFor and reached the mint call (the pre-network reject
		// path from the sibling test would never touch the server).
		_, _ = minter.Token(scope)
		if !reached {
			t.Fatalf("scope %q was rejected before the network — permissionsFor is missing a case", scope)
		}
	}
}

func TestResolveInstallationSupportsOwnerWideFallbackWithExactPrecedence(t *testing.T) {
	installations := map[string]int64{
		"ActionsJson/*":                147756788,
		"ActionsJson/actions.json.dev": 99,
		"ActionsJson/disabled":         0,
		"ActionsJson/revoked":          -1,
	}
	for _, test := range []struct {
		repository string
		want       int64
		ok         bool
	}{
		{repository: "ActionsJson/actions.json.dev", want: 99, ok: true},
		{repository: "ActionsJson/future-private-repo", want: 147756788, ok: true},
		{repository: "ActionsJson/disabled", ok: false},
		{repository: "ActionsJson/revoked", want: -1, ok: false},
		{repository: "actionsjson/future-private-repo", ok: false},
		{repository: "ActionsJson", ok: false},
		{repository: "ActionsJson/one/two", ok: false},
	} {
		got, ok := githubauth.ResolveInstallation(installations, test.repository)
		if got != test.want || ok != test.ok {
			t.Fatalf("ResolveInstallation(%q) = (%d, %t), want (%d, %t)", test.repository, got, ok, test.want, test.ok)
		}
	}
}

func TestInstallationMinterUsesOwnerWideInstallationForRepositoryScopedToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/app/installations/147756788/access_tokens" {
			t.Fatalf("path = %q", request.URL.Path)
		}
		var body struct {
			Repositories []string `json:"repositories"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body.Repositories) != 1 || body.Repositories[0] != "actions.json.dev" {
			t.Fatalf("repositories = %#v", body.Repositories)
		}
		io.WriteString(response, `{"token":"ghs_org_scoped","expires_at":"2030-01-01T01:00:00Z"}`)
	}))
	defer server.Close()
	httpClient := server.Client()
	httpClient.Timeout = time.Second
	minter, err := githubauth.NewInstallationMinter(server.URL, "app", pemKey, httpClient, map[string]int64{"ActionsJson/*": 147756788})
	if err != nil {
		t.Fatal(err)
	}
	token, err := minter.Token("ActionsJson/actions.json.dev\x00repository.read")
	if err != nil || token != "ghs_org_scoped" {
		t.Fatalf("token = %q, err = %v", token, err)
	}
}

// TestInstallationWideTokenRequestsReadPermissionsWithoutRepositoryScope guards
// the repo-search sync credential: the mint request must ask for read-only
// metadata+contents permissions and must NOT carry a "repositories" key, so the
// token spans every repository the installation can see.
func TestInstallationWideTokenRequestsReadPermissionsWithoutRepositoryScope(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, key)})
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Method != http.MethodPost || request.URL.Path != "/app/installations/42/access_tokens" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		verifyJWT(t, strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer "), &key.PublicKey)
		var body map[string]json.RawMessage
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if _, present := body["repositories"]; present {
			t.Fatalf("installation-wide mint must not scope repositories: %s", body["repositories"])
		}
		var permissions map[string]string
		if err := json.Unmarshal(body["permissions"], &permissions); err != nil {
			t.Fatal(err)
		}
		if len(permissions) != 2 || permissions["metadata"] != "read" || permissions["contents"] != "read" {
			t.Fatalf("permissions = %#v", permissions)
		}
		io.WriteString(response, `{"token":"ghs_installation_wide","expires_at":"2030-01-01T01:00:00Z"}`)
	}))
	defer server.Close()
	httpClient := server.Client()
	httpClient.Timeout = time.Second
	minter, err := githubauth.NewInstallationMinter(server.URL, "Iv1.client", pemKey, httpClient, map[string]int64{"yaniv256/private": 42})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		token, err := minter.InstallationToken(42)
		if err != nil || token != "ghs_installation_wide" {
			t.Fatalf("token = %q, err = %v", token, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("mint calls = %d — the installation-wide token must be cached per installation", calls.Load())
	}
}

// TestInstallationWideTokenRejectsUnregisteredInstallationBeforeNetwork keeps
// the minter fail-closed: only installation IDs present in the configured
// installations map may mint installation-wide read tokens.
func TestInstallationWideTokenRejectsUnregisteredInstallationBeforeNetwork(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("network reached") }))
	defer server.Close()
	httpClient := server.Client()
	httpClient.Timeout = time.Second
	minter, err := githubauth.NewInstallationMinter(server.URL, "app", pemKey, httpClient, map[string]int64{"yaniv256/private": 42})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{0, -1, 999} {
		if _, err := minter.InstallationToken(id); err == nil {
			t.Fatalf("installation id %d accepted", id)
		}
	}
}

func mustPKCS8(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	value, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func verifyJWT(t *testing.T, token string, key *rsa.PublicKey) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT parts = %d", len(parts))
	}
	header, _ := base64.RawURLEncoding.DecodeString(parts[0])
	claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var headerValue map[string]any
	var claimValue map[string]any
	if json.Unmarshal(header, &headerValue) != nil || json.Unmarshal(claims, &claimValue) != nil || headerValue["alg"] != "RS256" || claimValue["iss"] != "Iv1.client" {
		t.Fatalf("header = %s, claims = %s", header, claims)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatal(err)
	}
}
