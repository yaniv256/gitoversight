package oauthflow

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/tokenvault"
)

const (
	maxResponseBytes = 1 << 20
	apiVersion       = "2022-11-28"
)

type Config struct {
	OAuthBaseURL  string
	APIBaseURL    string
	ClientID      string
	ClientSecret  string
	RedirectURI   string
	MaxConcurrent int
}

type BeginRequest struct {
	Session      string
	Purpose      string
	Subject      string
	GitHubLogin  string
	Installation int64
	ExpiresAt    time.Time
}

type Completion struct {
	Purpose string
	Session string
	Subject string
}

type sealedStore interface {
	PutJSON(string, any) error
	GetJSON(string, any) error
	PutUserCredential(string, tokenvault.UserCredential) error
}

type transaction struct {
	State        string    `json:"state"`
	Session      string    `json:"session"`
	Purpose      string    `json:"purpose"`
	Subject      string    `json:"subject"`
	GitHubLogin  string    `json:"github_login"`
	Installation int64     `json:"installation"`
	RedirectURI  string    `json:"redirect_uri"`
	Verifier     string    `json:"verifier"`
	ExpiresAt    time.Time `json:"expires_at"`
	Used         bool      `json:"used"`
}

type Coordinator struct {
	mu           sync.Mutex
	oauthBaseURL string
	apiBaseURL   string
	clientID     string
	clientSecret string
	redirectURI  string
	callbackPath string
	http         *http.Client
	store        sealedStore
	concurrency  chan struct{}
	now          func() time.Time
}

func New(config Config, httpClient *http.Client, store sealedStore) (*Coordinator, error) {
	if config.OAuthBaseURL == "" || config.APIBaseURL == "" || config.ClientID == "" || config.ClientSecret == "" || config.RedirectURI == "" || httpClient == nil || httpClient.Timeout <= 0 || store == nil {
		return nil, errors.New("oauth coordinator configuration is incomplete")
	}
	redirect, err := url.Parse(config.RedirectURI)
	if err != nil || redirect.Scheme == "" || redirect.Host == "" || redirect.Path == "" || redirect.RawQuery != "" || redirect.Fragment != "" {
		return nil, errors.New("oauth redirect URI is invalid")
	}
	if config.MaxConcurrent <= 0 {
		config.MaxConcurrent = 4
	}
	if config.MaxConcurrent > 64 {
		return nil, errors.New("oauth callback concurrency is invalid")
	}
	for _, raw := range []string{config.OAuthBaseURL, config.APIBaseURL} {
		parsed, parseErr := url.Parse(raw)
		if parseErr != nil || parsed.Scheme == "" || parsed.Host == "" {
			return nil, errors.New("oauth service URL is invalid")
		}
	}
	return &Coordinator{
		oauthBaseURL: strings.TrimRight(config.OAuthBaseURL, "/"),
		apiBaseURL:   strings.TrimRight(config.APIBaseURL, "/"),
		clientID:     config.ClientID,
		clientSecret: config.ClientSecret,
		redirectURI:  config.RedirectURI,
		callbackPath: redirect.Path,
		http:         httpClient,
		store:        store,
		concurrency:  make(chan struct{}, config.MaxConcurrent),
		now:          time.Now,
	}, nil
}

func (c *Coordinator) Begin(request BeginRequest) (string, error) {
	now := c.now().UTC()
	if request.Session == "" || request.Purpose == "" || request.Subject == "" || request.GitHubLogin == "" || request.Installation <= 0 || !request.ExpiresAt.After(now) || request.ExpiresAt.After(now.Add(10*time.Minute)) {
		return "", errors.New("oauth begin request is invalid")
	}
	state, err := randomOpaque(32)
	if err != nil {
		return "", errors.New("oauth state generation failed")
	}
	verifier, err := randomOpaque(48)
	if err != nil {
		return "", errors.New("oauth verifier generation failed")
	}
	value := transaction{
		State: state, Session: request.Session, Purpose: request.Purpose, Subject: request.Subject, GitHubLogin: request.GitHubLogin, Installation: request.Installation,
		RedirectURI: c.redirectURI, Verifier: verifier, ExpiresAt: request.ExpiresAt.UTC(),
	}
	if err := c.store.PutJSON(transactionKey(state), value); err != nil {
		return "", errors.New("oauth transaction persistence failed")
	}
	digest := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"client_id":             []string{c.clientID},
		"redirect_uri":          []string{c.redirectURI},
		"state":                 []string{state},
		"code_challenge":        []string{base64.RawURLEncoding.EncodeToString(digest[:])},
		"code_challenge_method": []string{"S256"},
	}
	return c.oauthBaseURL + "/login/oauth/authorize?" + query.Encode(), nil
}

func (c *Coordinator) Handler() http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		if request.Method != http.MethodGet || request.URL.Path != c.callbackPath {
			http.NotFound(response, request)
			return
		}
		state, code := request.URL.Query().Get("state"), request.URL.Query().Get("code")
		if state == "" || code == "" || len(state) > 512 || len(code) > 512 {
			http.Error(response, "authorization rejected", http.StatusBadRequest)
			return
		}
		_, err := c.Complete(state, code)
		if err != nil {
			status := http.StatusForbidden
			if errors.Is(err, errReplay) {
				status = http.StatusConflict
			}
			http.Error(response, "authorization rejected", status)
			return
		}
		response.Header().Set("Content-Type", "text/plain; charset=utf-8")
		response.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(response, "GitHub authorization complete. You may close this window.\n")
	})
}

func (c *Coordinator) Complete(state, code string) (Completion, error) {
	if state == "" || code == "" || len(state) > 512 || len(code) > 512 {
		return Completion{}, errors.New("oauth callback rejected")
	}
	select {
	case c.concurrency <- struct{}{}:
		defer func() { <-c.concurrency }()
	default:
		return Completion{}, errors.New("oauth callback overloaded")
	}
	value, err := c.consume(state)
	if err != nil {
		return Completion{}, err
	}
	credential, err := c.exchange(code, value)
	if err != nil {
		return Completion{}, err
	}
	if err := c.validateIdentity(credential.AccessToken, value); err != nil {
		return Completion{}, err
	}
	if err := c.store.PutUserCredential("human_user:"+value.Subject, credential); err != nil {
		return Completion{}, errors.New("authorization persistence failed")
	}
	return Completion{Purpose: value.Purpose, Session: value.Session, Subject: value.Subject}, nil
}

var errReplay = errors.New("oauth transaction already used")

func (c *Coordinator) consume(state string) (transaction, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var value transaction
	if err := c.store.GetJSON(transactionKey(state), &value); err != nil || value.State != state {
		return transaction{}, errors.New("oauth transaction unavailable")
	}
	if value.Used {
		return transaction{}, errReplay
	}
	if !c.now().UTC().Before(value.ExpiresAt) {
		return transaction{}, errors.New("oauth transaction expired")
	}
	value.Used = true
	if err := c.store.PutJSON(transactionKey(state), value); err != nil {
		return transaction{}, errors.New("oauth transaction consumption failed")
	}
	return value, nil
}

func (c *Coordinator) exchange(code string, value transaction) (tokenvault.UserCredential, error) {
	form := url.Values{
		"client_id":     []string{c.clientID},
		"client_secret": []string{c.clientSecret},
		"code":          []string{code},
		"redirect_uri":  []string{value.RedirectURI},
		"code_verifier": []string{value.Verifier},
	}
	request, err := http.NewRequest(http.MethodPost, c.oauthBaseURL+"/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return tokenvault.UserCredential{}, errors.New("oauth exchange failed")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := c.http.Do(request)
	if err != nil {
		return tokenvault.UserCredential{}, errors.New("oauth exchange failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return tokenvault.UserCredential{}, errors.New("oauth exchange rejected")
	}
	var result struct {
		AccessToken           string `json:"access_token"`
		ExpiresIn             int64  `json:"expires_in"`
		RefreshToken          string `json:"refresh_token"`
		RefreshTokenExpiresIn int64  `json:"refresh_token_expires_in"`
		TokenType             string `json:"token_type"`
		Error                 string `json:"error"`
	}
	if err := decodeJSON(response.Body, &result); err != nil || result.Error != "" || result.AccessToken == "" || result.RefreshToken == "" || !strings.EqualFold(result.TokenType, "bearer") || result.ExpiresIn <= 60 || result.RefreshTokenExpiresIn <= 60 {
		return tokenvault.UserCredential{}, errors.New("oauth exchange response is invalid")
	}
	now := c.now().UTC()
	return tokenvault.UserCredential{
		AccessToken: result.AccessToken, AccessExpiresAt: now.Add(time.Duration(result.ExpiresIn) * time.Second),
		RefreshToken: result.RefreshToken, RefreshExpiresAt: now.Add(time.Duration(result.RefreshTokenExpiresIn) * time.Second),
	}, nil
}

func (c *Coordinator) validateIdentity(token string, value transaction) error {
	var user struct {
		Login string `json:"login"`
	}
	if err := c.get(token, c.apiBaseURL+"/user", &user); err != nil || !strings.EqualFold(user.Login, value.GitHubLogin) {
		return errors.New("oauth human identity mismatch")
	}
	var repositories struct {
		TotalCount *int `json:"total_count"`
	}
	endpoint := c.apiBaseURL + "/user/installations/" + strconv.FormatInt(value.Installation, 10) + "/repositories?per_page=1"
	if err := c.get(token, endpoint, &repositories); err != nil || repositories.TotalCount == nil || *repositories.TotalCount < 0 {
		return errors.New("oauth installation mismatch")
	}
	return nil
}

func (c *Coordinator) get(token, endpoint string, destination any) error {
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-GitHub-Api-Version", apiVersion)
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("GitHub identity read returned status %d", response.StatusCode)
	}
	return decodeJSON(response.Body, destination)
}

func decodeJSON(reader io.Reader, destination any) error {
	decoder := json.NewDecoder(io.LimitReader(reader, maxResponseBytes))
	return decoder.Decode(destination)
}

func randomOpaque(size int) (string, error) {
	payload := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, payload); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func transactionKey(state string) string { return "oauth_state:" + state }
