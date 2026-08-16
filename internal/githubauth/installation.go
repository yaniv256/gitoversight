package githubauth

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"
)

type cachedToken struct {
	value     string
	expiresAt time.Time
}

type InstallationMinter struct {
	mu            sync.Mutex
	baseURL       string
	clientID      string
	key           *rsa.PrivateKey
	http          *http.Client
	installations map[string]int64
	cache         map[string]cachedToken
	now           func() time.Time
}

func NewInstallationMinter(baseURL, clientID string, privateKeyPEM []byte, httpClient *http.Client, installations map[string]int64) (*InstallationMinter, error) {
	if clientID == "" || httpClient == nil || httpClient.Timeout <= 0 || len(installations) == 0 {
		return nil, errors.New("installation minter configuration is incomplete")
	}
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, errors.New("GitHub App private key is not PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		if legacy, legacyErr := x509.ParsePKCS1PrivateKey(block.Bytes); legacyErr == nil {
			key = legacy
		} else {
			return nil, errors.New("GitHub App private key is invalid")
		}
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("GitHub App private key must be RSA")
	}
	return &InstallationMinter{baseURL: strings.TrimRight(baseURL, "/"), clientID: clientID, key: rsaKey, http: httpClient, installations: installations, cache: make(map[string]cachedToken), now: time.Now}, nil
}

// ResolveInstallation returns the exact repository installation when present,
// otherwise an owner-wide installation registered as "owner/*". Repository
// identity remains case-sensitive and malformed repository names fail closed.
func ResolveInstallation(installations map[string]int64, repository string) (int64, bool) {
	if strings.Count(repository, "/") != 1 || strings.ContainsAny(repository, "*?[]") || strings.Contains(repository, "..") {
		return 0, false
	}
	owner, name, ok := strings.Cut(repository, "/")
	if !ok || owner == "" || name == "" {
		return 0, false
	}
	if installation, registered := installations[repository]; registered {
		return installation, installation > 0
	}
	installation, registered := installations[owner+"/*"]
	return installation, registered && installation > 0
}

// Token mints a repository- and operation-scoped installation token. The
// subject wire format is exact repository, NUL, exact operation.
func (m *InstallationMinter) Token(subject string) (string, error) {
	repository, operation, ok := strings.Cut(subject, "\x00")
	installationID, registered := ResolveInstallation(m.installations, repository)
	permissions, supported := permissionsFor(operation)
	if !ok || !registered || !supported {
		return "", errors.New("installation token scope is not registered")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now().UTC()
	if cached, exists := m.cache[subject]; exists && now.Add(time.Minute).Before(cached.expiresAt) {
		return cached.value, nil
	}
	_, repositoryName := path.Split(repository)
	minted, err := m.mint(now, installationID, map[string]any{"repositories": []string{repositoryName}, "permissions": permissions})
	if err != nil {
		return "", err
	}
	m.cache[subject] = minted
	return minted.value, nil
}

// InstallationToken mints an installation-WIDE token carrying read-only
// metadata and contents permissions across every repository the installation
// can see — the credential the repo-search sync job uses to enumerate
// repositories and fetch READMEs. It deliberately omits the "repositories"
// scoping field. The token can only read, and only installations registered in
// the configured installations map may mint one. Never hand it to a mutation
// path; those stay on the repository- and operation-scoped Token above.
func (m *InstallationMinter) InstallationToken(installationID int64) (string, error) {
	if installationID <= 0 || !m.registeredInstallation(installationID) {
		return "", errors.New("installation id is not registered")
	}
	// The NUL-led key cannot collide with a Token subject: subjects start with
	// an "owner/name" repository, which ResolveInstallation rejects when empty.
	key := fmt.Sprintf("\x00installation-wide\x00%d", installationID)
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now().UTC()
	if cached, exists := m.cache[key]; exists && now.Add(time.Minute).Before(cached.expiresAt) {
		return cached.value, nil
	}
	minted, err := m.mint(now, installationID, map[string]any{"permissions": map[string]string{"metadata": "read", "contents": "read"}})
	if err != nil {
		return "", err
	}
	m.cache[key] = minted
	return minted.value, nil
}

func (m *InstallationMinter) registeredInstallation(installationID int64) bool {
	for _, registered := range m.installations {
		if registered == installationID {
			return true
		}
	}
	return false
}

// mint exchanges the app JWT for an installation access token. Callers hold
// m.mu and own caching; payload decides the token's scope.
func (m *InstallationMinter) mint(now time.Time, installationID int64, payload map[string]any) (cachedToken, error) {
	jwt, err := m.jwt(now)
	if err != nil {
		return cachedToken{}, err
	}
	body, _ := json.Marshal(payload)
	request, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/app/installations/%d/access_tokens", m.baseURL, installationID), bytes.NewReader(body))
	if err != nil {
		return cachedToken{}, errors.New("installation token request failed")
	}
	request.Header.Set("Authorization", "Bearer "+jwt)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("Content-Type", "application/json")
	response, err := m.http.Do(request)
	if err != nil {
		return cachedToken{}, errors.New("installation token request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return cachedToken{}, fmt.Errorf("installation token endpoint returned status %d", response.StatusCode)
	}
	var result struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result); err != nil || result.Token == "" || !result.ExpiresAt.After(now.Add(time.Minute)) {
		return cachedToken{}, errors.New("installation token response is invalid")
	}
	return cachedToken{value: result.Token, expiresAt: result.ExpiresAt}, nil
}

func (m *InstallationMinter) jwt(now time.Time) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{"iat": now.Add(-60 * time.Second).Unix(), "exp": now.Add(9 * time.Minute).Unix(), "iss": m.clientID})
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, m.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", errors.New("GitHub App JWT signing failed")
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func permissionsFor(operation string) (map[string]string, bool) {
	switch operation {
	case "repository.read":
		return map[string]string{"contents": "read"}, true
	case "pull_request.list":
		return map[string]string{"pull_requests": "read"}, true
	case "branch.push":
		// workflows:write is requested here and NOWHERE else, because branch.push
		// is the only operation whose payload can carry a .github/workflows/ file.
		//
		// It must be named explicitly: the access_tokens endpoint treats this map
		// as a DOWN-SCOPE, so the minted token holds only what is listed even when
		// the installation was granted more. Granting the scope on GitHub is
		// therefore necessary but NOT sufficient — a push carrying a workflow file
		// still drew `403 Resource not accessible by integration` at POST
		// /git/trees, indistinguishable from the ungranted case, until this line
		// existed (2026-07-27).
		return map[string]string{"contents": "write", "workflows": "write"}, true
	case "branch.delete", "policy.promote", "release.publish", "release.asset.upload", "release.assets.upload":
		return map[string]string{"contents": "write"}, true
	case "pull_request.create", "pull_request.update", "pull_request.review", "pull_request.reply", "pull_request.close":
		// pull_requests:write alone is scoped too narrow — opening/updating a PR
		// requires GitHub to READ the base and head refs, so the token also needs
		// contents:read. Without it GitHub 422s "not all refs are readable" even
		// though base/head/diff are all valid. (Least-privilege: read, not write.)
		return map[string]string{"pull_requests": "write", "contents": "read"}, true
	case "pull_request.merge":
		return map[string]string{"contents": "write", "pull_requests": "write"}, true
	case "issue.create", "issue.comment":
		return map[string]string{"issues": "write"}, true
	case "repository.settings.update":
		return map[string]string{"administration": "write"}, true
	default:
		return nil, false
	}
}
