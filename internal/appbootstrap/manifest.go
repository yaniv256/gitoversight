package appbootstrap

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/url"
	"slices"
	"strings"
)

const (
	ApprovedOwner        = "yaniv256"
	ApprovedAppName      = "Yaniv Git Oversight Broker"
	ApprovedHomepageURL  = "https://github.com/yaniv256/gitoversight.dev"
	manifestCallbackPath = "/bootstrap/github-app/callback"
	webhookPath          = "/webhooks/github"
	oauthCallbackPath    = "/oauth/github/callback"
)

type HookAttributes struct {
	URL    string `json:"url"`
	Active bool   `json:"active"`
}

type Manifest struct {
	Name               string            `json:"name"`
	URL                string            `json:"url"`
	HookAttributes     HookAttributes    `json:"hook_attributes"`
	RedirectURL        string            `json:"redirect_url"`
	CallbackURLs       []string          `json:"callback_urls"`
	Description        string            `json:"description"`
	Public             bool              `json:"public"`
	DefaultPermissions map[string]string `json:"default_permissions"`
	DefaultEvents      []string          `json:"default_events"`
}

type ManifestPacket struct {
	SchemaVersion int      `json:"schema_version"`
	Owner         string   `json:"owner"`
	State         string   `json:"state"`
	Manifest      Manifest `json:"manifest"`
}

func PrepareManifestPacket(redirectURL string, randomness io.Reader) (ManifestPacket, error) {
	if err := validateRedirectURL(redirectURL); err != nil {
		return ManifestPacket{}, err
	}
	if randomness == nil {
		return ManifestPacket{}, errors.New("manifest state randomness is required")
	}
	stateBytes := make([]byte, 32)
	if _, err := io.ReadFull(randomness, stateBytes); err != nil {
		return ManifestPacket{}, errors.New("generate manifest state")
	}
	return ManifestPacket{
		SchemaVersion: 1,
		Owner:         ApprovedOwner,
		State:         base64.RawURLEncoding.EncodeToString(stateBytes),
		Manifest:      approvedManifest(redirectURL),
	}, nil
}

func ManifestPacketDigest(packet ManifestPacket) (string, error) {
	payload, err := json.Marshal(packet)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func ValidateManifestPacket(packet ManifestPacket, expectedDigest string) error {
	if len(expectedDigest) != 64 {
		return errors.New("manifest packet digest must be a SHA-256 hex digest")
	}
	if packet.SchemaVersion != 1 || packet.Owner != ApprovedOwner || !validState(packet.State) {
		return errors.New("manifest packet identity is not approved")
	}
	if err := validateManifest(packet.Manifest); err != nil {
		return err
	}
	digest, err := ManifestPacketDigest(packet)
	if err != nil {
		return err
	}
	if digest != strings.ToLower(expectedDigest) {
		return errors.New("manifest packet digest mismatch")
	}
	return nil
}

func RenderRegistrationHTML(packet ManifestPacket) ([]byte, error) {
	if packet.SchemaVersion != 1 || packet.Owner != ApprovedOwner || !validState(packet.State) {
		return nil, errors.New("manifest packet is not renderable")
	}
	if err := validateManifest(packet.Manifest); err != nil {
		return nil, err
	}
	manifestJSON, err := json.Marshal(packet.Manifest)
	if err != nil {
		return nil, err
	}
	action := "https://github.com/settings/apps/new?state=" + url.QueryEscape(packet.State)
	data := struct {
		Action       string
		ManifestJSON string
		AppName      string
	}{Action: action, ManifestJSON: string(manifestJSON), AppName: ApprovedAppName}
	const page = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Git Oversight App bootstrap</title>
<style>
  :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
  body { margin: 0; background: #f6f8fa; color: #1f2328; }
  main { max-width: 42rem; margin: 3rem auto; padding: 2rem; background: #fff; border: 1px solid #d0d7de; border-radius: 12px; box-shadow: 0 4px 18px rgba(31,35,40,.08); }
  h1 { margin-top: 0; }
  p { line-height: 1.55; }
  button { margin-top: 1rem; padding: .75rem 1rem; border: 1px solid #1f883d; border-radius: 7px; background: #1f883d; color: #fff; font: inherit; font-weight: 650; cursor: pointer; }
  button:hover { background: #1a7f37; }
  @media (prefers-color-scheme: dark) {
    body { background: #0d1117; color: #f0f6fc; }
    main { background: #161b22; border-color: #30363d; box-shadow: none; }
    button { background: #238636; border-color: #2ea043; color: #fff; }
    button:hover { background: #2ea043; }
  }
</style></head><body>
<main><h1>Create the private GitHub App</h1>
<p>This one-time form registers {{.AppName}} with the reviewed private manifest. GitHub will show the exact permissions before creation.</p>
<form action="{{.Action}}" method="post">
<textarea name="manifest" hidden>{{.ManifestJSON}}</textarea>
<button type="submit">Create the private GitHub App</button>
</form></main></body></html>`
	tmpl, err := template.New("registration").Parse(page)
	if err != nil {
		return nil, err
	}
	var output strings.Builder
	if err := tmpl.Execute(&output, data); err != nil {
		return nil, err
	}
	return []byte(output.String()), nil
}

func approvedManifest(redirectURL string) Manifest {
	parsed, _ := url.Parse(redirectURL)
	origin := parsed.Scheme + "://" + parsed.Host
	return Manifest{
		Name:           ApprovedAppName,
		URL:            ApprovedHomepageURL,
		RedirectURL:    redirectURL,
		CallbackURLs:   []string{origin + oauthCallbackPath},
		Description:    "Brokered, human-governed GitHub operations for Yaniv Ben-Ami's repositories.",
		Public:         false,
		HookAttributes: HookAttributes{URL: origin + webhookPath, Active: true},
		DefaultPermissions: map[string]string{
			"administration": "write",
			"contents":       "write",
			"issues":         "write",
			"pull_requests":  "write",
			// GitHub gates .github/workflows/ behind its own scope; contents:write
			// does not imply it, on private repositories either. Without this the
			// App cannot write CI ANYWHERE — the denial is global, fires as a
			// generic 403 at POST /git/trees, and cannot distinguish an agent's own
			// private repo from a public one.
			//
			// Withholding it does not buy a governance boundary, because the
			// boundary already exists one layer up and is per-repository: a public
			// repository reaches GitHub only through the human-approved sync flow
			// (policy/evaluator.go:284 gates every public mutation on approval,
			// whatever files it carries). The intended path for CI is exactly that
			// — an agent edits the workflow on its private repo, proposes a sync,
			// and a human approves the publication (2026-07-27).
			"workflows": "write",
		},
		DefaultEvents: []string{
			"issue_comment",
			"pull_request",
			"pull_request_review",
			"pull_request_review_comment",
		},
	}
}

func validateManifest(manifest Manifest) error {
	if err := validateRedirectURL(manifest.RedirectURL); err != nil {
		return err
	}
	want := approvedManifest(manifest.RedirectURL)
	gotJSON, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		return err
	}
	if string(gotJSON) != string(wantJSON) {
		return errors.New("manifest does not match the approved private App contract")
	}
	return nil
}

func validateRedirectURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Port() != "" || parsed.Path != manifestCallbackPath {
		return errors.New("manifest redirect URL is not an approved HTTPS callback")
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "localhost" || net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return fmt.Errorf("manifest redirect host %q is not a public DNS name", host)
	}
	return nil
}

func validState(state string) bool {
	if len(state) != 43 {
		return false
	}
	for _, char := range state {
		if !slices.Contains([]rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"), char) {
			return false
		}
	}
	return true
}
