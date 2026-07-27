package appbootstrap

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestPrepareManifestPacketBuildsExactPrivateAppContract(t *testing.T) {
	t.Parallel()
	redirect := "https://gitoversight.example.test/bootstrap/github-app/callback"
	packet, err := PrepareManifestPacket(redirect, bytes.NewReader(bytes.Repeat([]byte{0x2a}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	if packet.SchemaVersion != 1 || packet.Owner != ApprovedOwner || packet.State == "" {
		t.Fatalf("packet identity = %#v", packet)
	}
	wantPermissions := map[string]string{
		"administration": "write",
		"contents":       "write",
		"issues":         "write",
		"pull_requests":  "write",
	}
	if packet.Manifest.Name != ApprovedAppName || packet.Manifest.URL != ApprovedHomepageURL || packet.Manifest.Public {
		t.Fatalf("manifest identity = %#v", packet.Manifest)
	}
	if packet.Manifest.RedirectURL != redirect || len(packet.Manifest.CallbackURLs) != 1 || packet.Manifest.CallbackURLs[0] != "https://gitoversight.example.test/oauth/github/callback" {
		t.Fatalf("manifest callbacks = %#v", packet.Manifest)
	}
	if packet.Manifest.HookAttributes.URL != "https://gitoversight.example.test/webhooks/github" || !packet.Manifest.HookAttributes.Active {
		t.Fatalf("manifest hook = %#v", packet.Manifest.HookAttributes)
	}
	if !mapsEqual(packet.Manifest.DefaultPermissions, wantPermissions) {
		t.Fatalf("permissions = %#v", packet.Manifest.DefaultPermissions)
	}
	wantEvents := []string{"issue_comment", "pull_request", "pull_request_review", "pull_request_review_comment"}
	if strings.Join(packet.Manifest.DefaultEvents, ",") != strings.Join(wantEvents, ",") {
		t.Fatalf("events = %#v", packet.Manifest.DefaultEvents)
	}
	digest, err := ManifestPacketDigest(packet)
	if err != nil || len(digest) != 64 {
		t.Fatalf("digest = %q, err = %v", digest, err)
	}
	if err := ValidateManifestPacket(packet, digest); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareManifestPacketBindsEveryPublicEndpointToReviewedOrigin(t *testing.T) {
	t.Parallel()
	redirect := "https://broker.customer.example/bootstrap/github-app/callback"
	packet, err := PrepareManifestPacket(redirect, bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	if packet.Manifest.RedirectURL != redirect {
		t.Fatalf("redirect = %q", packet.Manifest.RedirectURL)
	}
	if got := packet.Manifest.HookAttributes.URL; got != "https://broker.customer.example/webhooks/github" {
		t.Fatalf("webhook = %q", got)
	}
	if got := packet.Manifest.CallbackURLs; len(got) != 1 || got[0] != "https://broker.customer.example/oauth/github/callback" {
		t.Fatalf("OAuth callbacks = %#v", got)
	}
}

func TestPrepareManifestPacketRejectsUntrustedRedirects(t *testing.T) {
	t.Parallel()
	for _, redirect := range []string{
		"http://app.gitoversight.com/bootstrap/github-app/callback",
		"https://localhost/bootstrap/github-app/callback",
		"https://127.0.0.1/bootstrap/github-app/callback",
		"https://single-label/bootstrap/github-app/callback",
		"https://app.gitoversight.com/other",
		"https://app.gitoversight.com/bootstrap/github-app/callback?code=stolen",
		"https://user@app.gitoversight.com/bootstrap/github-app/callback",
	} {
		if _, err := PrepareManifestPacket(redirect, bytes.NewReader(bytes.Repeat([]byte{1}, 64))); err == nil {
			t.Fatalf("accepted redirect %q", redirect)
		}
	}
}

func TestValidateManifestPacketRejectsAnyAuthorityDrift(t *testing.T) {
	t.Parallel()
	packet, err := PrepareManifestPacket("https://app.gitoversight.com/bootstrap/github-app/callback", bytes.NewReader(bytes.Repeat([]byte{3}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := ManifestPacketDigest(packet)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*ManifestPacket){
		func(p *ManifestPacket) { p.Owner = "someone-else" },
		func(p *ManifestPacket) { p.State = p.State + "x" },
		func(p *ManifestPacket) { p.Manifest.Name = "Different App" },
		func(p *ManifestPacket) { p.Manifest.Public = true },
		func(p *ManifestPacket) { p.Manifest.DefaultPermissions["workflows"] = "write" },
		func(p *ManifestPacket) {
			p.Manifest.CallbackURLs = append(p.Manifest.CallbackURLs, "https://example.com")
		},
		func(p *ManifestPacket) { p.Manifest.HookAttributes.URL = "https://other.example/webhooks/github" },
	}
	for i, mutate := range mutations {
		candidate := clonePacket(t, packet)
		mutate(&candidate)
		if err := ValidateManifestPacket(candidate, digest); err == nil {
			t.Fatalf("mutation %d accepted", i)
		}
	}
}

func TestRenderRegistrationHTMLContainsOnlyExactManifestAndState(t *testing.T) {
	t.Parallel()
	packet, err := PrepareManifestPacket("https://app.gitoversight.com/bootstrap/github-app/callback", bytes.NewReader(bytes.Repeat([]byte{4}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	html, err := RenderRegistrationHTML(packet)
	if err != nil {
		t.Fatal(err)
	}
	text := string(html)
	for _, want := range []string{
		`action="https://github.com/settings/apps/new?state=`,
		`name="manifest"`,
		ApprovedAppName,
		packet.State,
		"Create the private GitHub App",
		"color-scheme: light dark",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("HTML missing %q", want)
		}
	}
	for _, forbidden := range []string{"agent-zara", "Zara", "client_secret", "webhook_secret", "PRIVATE KEY"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("HTML contains forbidden %q", forbidden)
		}
	}
}

func mapsEqual(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for key, value := range want {
		if got[key] != value {
			return false
		}
	}
	return true
}

func clonePacket(t *testing.T, packet ManifestPacket) ManifestPacket {
	t.Helper()
	payload, err := json.Marshal(packet)
	if err != nil {
		t.Fatal(err)
	}
	var clone ManifestPacket
	if err := json.Unmarshal(payload, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}
