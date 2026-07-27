package appbootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const MaxConversionResponseBytes = 64 << 10

var manifestCodePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)
var appSlugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,99}$`)
var clientIDPattern = regexp.MustCompile(`^Iv(?:1\.[A-Za-z0-9]{16}|[A-Za-z0-9]{18})$`)

type Registration struct {
	ID            int64  `json:"id"`
	Slug          string `json:"slug"`
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	WebhookSecret string `json:"webhook_secret"`
	PEM           string `json:"pem"`
	HTMLURL       string `json:"html_url"`
	Name          string `json:"name"`
	Owner         string `json:"-"`
	OwnerRecord   struct {
		Login string `json:"login"`
	} `json:"owner"`
}

type RedactedRegistration struct {
	ID       int64
	Slug     string
	ClientID string
	HTMLURL  string
	Name     string
	Owner    string
}

func (registration Registration) Redacted() RedactedRegistration {
	owner := registration.Owner
	if owner == "" {
		owner = registration.OwnerRecord.Login
	}
	return RedactedRegistration{ID: registration.ID, Slug: registration.Slug, ClientID: registration.ClientID, HTMLURL: registration.HTMLURL, Name: registration.Name, Owner: owner}
}

type GitHubConverter struct {
	baseURL string
	http    *http.Client
}

func NewGitHubConverter(baseURL string, httpClient *http.Client) (*GitHubConverter, error) {
	if httpClient == nil || httpClient.Timeout <= 0 {
		return nil, errors.New("manifest conversion HTTP client requires a positive timeout")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("manifest conversion base URL is invalid")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "localhost")) {
		return nil, errors.New("manifest conversion base URL must use HTTPS")
	}
	return &GitHubConverter{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient}, nil
}

func (converter *GitHubConverter) Convert(ctx context.Context, code string) (Registration, error) {
	if !manifestCodePattern.MatchString(code) {
		return Registration{}, errors.New("manifest conversion code is invalid")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, converter.baseURL+"/app-manifests/"+url.PathEscape(code)+"/conversions", nil)
	if err != nil {
		return Registration{}, errors.New("build manifest conversion request")
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("User-Agent", "gitoversight-broker-bootstrap")
	response, err := converter.http.Do(request)
	if err != nil {
		return Registration{}, errors.New("GitHub manifest conversion outcome is indeterminate")
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, MaxConversionResponseBytes+1))
	if err != nil {
		return Registration{}, errors.New("read GitHub manifest conversion response")
	}
	if len(payload) > MaxConversionResponseBytes {
		return Registration{}, errors.New("GitHub manifest conversion response exceeds limit")
	}
	if response.StatusCode != http.StatusCreated {
		return Registration{}, fmt.Errorf("GitHub manifest conversion returned status %d", response.StatusCode)
	}
	var registration Registration
	if err := json.Unmarshal(payload, &registration); err != nil {
		return Registration{}, errors.New("decode GitHub manifest conversion response")
	}
	registration.Owner = registration.OwnerRecord.Login
	if err := validateRegistration(registration); err != nil {
		return Registration{}, err
	}
	return registration, nil
}

func validateRegistration(registration Registration) error {
	owner := registration.Owner
	if owner == "" {
		owner = registration.OwnerRecord.Login
	}
	wantHTMLURL := "https://github.com/apps/" + registration.Slug
	if registration.ID <= 0 || registration.Name != ApprovedAppName || owner != ApprovedOwner || !appSlugPattern.MatchString(registration.Slug) || registration.HTMLURL != wantHTMLURL {
		return errors.New("GitHub manifest conversion returned an unexpected App identity")
	}
	if !clientIDPattern.MatchString(registration.ClientID) || len(registration.ClientSecret) < 8 || len(registration.WebhookSecret) < 8 {
		return errors.New("GitHub manifest conversion returned incomplete credentials")
	}
	if !strings.Contains(registration.PEM, "-----BEGIN RSA PRIVATE KEY-----") || !strings.Contains(registration.PEM, "-----END RSA PRIVATE KEY-----") {
		return errors.New("GitHub manifest conversion returned an invalid private key")
	}
	return nil
}
