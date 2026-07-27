package githubauth

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/tokenvault"
)

type userCredentialStore interface {
	GetUserCredential(string) (tokenvault.UserCredential, error)
	PutUserCredential(string, tokenvault.UserCredential) error
}

type UserTokenProvider struct {
	mu           sync.Mutex
	baseURL      string
	clientID     string
	clientSecret string
	http         *http.Client
	vault        userCredentialStore
	now          func() time.Time
}

func NewUserTokenProvider(baseURL, clientID, clientSecret string, httpClient *http.Client, vault userCredentialStore) (*UserTokenProvider, error) {
	if baseURL == "" || clientID == "" || clientSecret == "" || httpClient == nil || httpClient.Timeout <= 0 || vault == nil {
		return nil, errors.New("user token provider configuration is incomplete")
	}
	return &UserTokenProvider{baseURL: strings.TrimRight(baseURL, "/"), clientID: clientID, clientSecret: clientSecret, http: httpClient, vault: vault, now: time.Now}, nil
}

func (p *UserTokenProvider) Token(subject string) (string, error) {
	if subject == "" {
		return "", errors.New("human token subject is required")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	key := "human_user:" + subject
	credential, err := p.vault.GetUserCredential(key)
	if err != nil {
		return "", errors.New("human credential unavailable")
	}
	now := p.now().UTC()
	if now.Add(time.Minute).Before(credential.AccessExpiresAt) {
		return credential.AccessToken, nil
	}
	if credential.RefreshToken == "" || !now.Add(time.Minute).Before(credential.RefreshExpiresAt) {
		return "", errors.New("human refresh authority expired")
	}
	form := url.Values{
		"client_id":     []string{p.clientID},
		"client_secret": []string{p.clientSecret},
		"grant_type":    []string{"refresh_token"},
		"refresh_token": []string{credential.RefreshToken},
	}
	request, err := http.NewRequest(http.MethodPost, p.baseURL+"/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", errors.New("human token refresh failed")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := p.http.Do(request)
	if err != nil {
		return "", errors.New("human token refresh failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", errors.New("human token refresh rejected")
	}
	var result struct {
		AccessToken           string `json:"access_token"`
		ExpiresIn             int64  `json:"expires_in"`
		RefreshToken          string `json:"refresh_token"`
		RefreshTokenExpiresIn int64  `json:"refresh_token_expires_in"`
		TokenType             string `json:"token_type"`
		Error                 string `json:"error"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if err := decoder.Decode(&result); err != nil || result.Error != "" || result.AccessToken == "" || result.RefreshToken == "" || result.TokenType != "bearer" || result.ExpiresIn <= 60 || result.RefreshTokenExpiresIn <= 60 {
		return "", errors.New("human token refresh response is invalid")
	}
	rotated := tokenvault.UserCredential{
		AccessToken: result.AccessToken, AccessExpiresAt: now.Add(time.Duration(result.ExpiresIn) * time.Second),
		RefreshToken: result.RefreshToken, RefreshExpiresAt: now.Add(time.Duration(result.RefreshTokenExpiresIn) * time.Second),
	}
	if err := p.vault.PutUserCredential(key, rotated); err != nil {
		return "", errors.New("human token rotation persistence failed")
	}
	return rotated.AccessToken, nil
}
