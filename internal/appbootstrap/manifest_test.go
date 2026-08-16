package appbootstrap

import (
	"bytes"
	"encoding/json"
	"maps"
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
		"workflows":      "write",
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

// TestManifestContractRejectsPermissionDriftWithoutTheDigest exercises
// validateManifest DIRECTLY, and it exists because the digest was hiding it.
//
// TestValidateManifestPacketRejectsAnyAuthorityDrift below goes through
// ValidateManifestPacket, which hashes the whole packet BEFORE comparing the
// manifest to the approved contract. Every mutation there breaks the digest
// first, so the drift assertion never reaches the permission comparison:
// replacing validateManifest's contract check with `if false && ...` leaves
// that test GREEN (verified 2026-07-27). It proves the digest rejects
// tampering — a real property, but not the one its name claims.
//
// The gap matters because a digest cannot defend approvedManifest() from
// itself: the digest is computed FROM whatever that function returns, so
// drift authored INTO the contract hashes cleanly and ships. Only a direct
// comparison catches it. Same shape as the `Code == 401` blindness in
// agentauth — an assertion that passes for a reason other than the one it
// names.
func TestManifestContractRejectsPermissionDriftWithoutTheDigest(t *testing.T) {
	t.Parallel()
	const redirect = "https://app.gitoversight.com/bootstrap/github-app/callback"
	approved := approvedManifest(redirect)

	if err := validateManifest(approved); err != nil {
		t.Fatalf("the approved manifest must validate against itself: %v", err)
	}
	// The permission set the App is actually granted. Spelled out here rather
	// than derived, so a change to approvedManifest must be made deliberately
	// in two places instead of silently agreeing with itself.
	want := map[string]string{
		"administration": "write",
		"contents":       "write",
		"issues":         "write",
		"pull_requests":  "write",
		// Added 2026-07-27. Withholding it blocked EVERY .github/workflows/
		// write, on private repositories too, as a generic 403 at
		// POST /git/trees. The governance boundary lives one layer up and is
		// per-repository: public publication is gated on human approval.
		"workflows": "write",
	}
	if !mapsEqual(approved.DefaultPermissions, want) {
		t.Fatalf("granted permissions = %#v, want %#v — a permission change must be a deliberate edit to BOTH the contract and this test", approved.DefaultPermissions, want)
	}

	for _, drift := range []struct {
		name   string
		mutate func(*Manifest)
	}{
		{"an extra permission the App has no business holding", func(m *Manifest) { m.DefaultPermissions["members"] = "write" }},
		{"a granted permission silently removed", func(m *Manifest) { delete(m.DefaultPermissions, "workflows") }},
		{"a write narrowed to read", func(m *Manifest) { m.DefaultPermissions["contents"] = "read" }},
		{"the App made public", func(m *Manifest) { m.Public = true }},
	} {
		candidate := approvedManifest(redirect)
		candidate.DefaultPermissions = maps.Clone(candidate.DefaultPermissions)
		drift.mutate(&candidate)
		if err := validateManifest(candidate); err == nil {
			t.Fatalf("validateManifest accepted %s — the contract check is not defending the manifest, and no digest will catch drift authored INTO approvedManifest", drift.name)
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
		// Any permission outside the approved set is drift. `workflows` was the
		// mutation here until 2026-07-27, when it was ADDED to the contract —
		// withholding it blocked CI writes on an agent's own private repository
		// while buying no boundary, since public publication is gated on human
		// approval one layer up. `members` stands in as a permission the App has
		// no business holding, so the drift assertion keeps its teeth.
		func(p *ManifestPacket) { p.Manifest.DefaultPermissions["members"] = "write" },
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
	for _, forbidden := range []string{"private-agent-id", "Private Agent", "client_secret", "webhook_secret", "PRIVATE KEY"} {
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
