package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestExampleConfigIsSecretFreeAndNamesOnlyApprovedUsers(t *testing.T) {
	t.Parallel()
	payload, err := os.ReadFile("config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var config Config
	if err := json.Unmarshal(payload, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Agents) != 2 || config.Agents["zara"].UnixUser != "agent-zara" || config.Agents["tomas"].UnixUser != "agent-tomas" {
		t.Fatalf("unexpected example agents: %#v", config.Agents)
	}
	lower := strings.ToLower(string(payload))
	for _, forbidden := range []string{"private_key", "github_pat_", "authorization:", "bearer "} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("example config contains secret-bearing material %q", forbidden)
		}
	}
}

func TestLoadConfigRejectsTrailingJSON(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "crossuser.json")
	payload := `{"broker_url":"https://gitoversight.example"} {"unexpected":true}`
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path, false); err == nil {
		t.Fatal("trailing JSON was accepted")
	}
}

func TestEmbeddedScenariosExposeOnlyNamedGovernanceActions(t *testing.T) {
	t.Parallel()
	scenarios, err := loadScenarios()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"zara-private-owner-allow", "tomas-private-nonowner-deny", "tomas-exact-branch-allow", "tomas-wrong-branch-deny", "zara-unapproved-public-deny"}
	got := make([]string, 0, len(scenarios))
	for _, scenario := range scenarios {
		got = append(got, scenario.ID)
		if scenario.UnixUser != "agent-zara" && scenario.UnixUser != "agent-tomas" {
			t.Fatalf("scenario %q has unapproved unix user %q", scenario.ID, scenario.UnixUser)
		}
		if scenario.ExpectedState == "" || scenario.ExpectedDecision == "" {
			t.Fatalf("scenario %q lacks an exact expected state/decision", scenario.ID)
		}
		for _, argument := range scenario.Arguments {
			if strings.ContainsAny(argument, ";|`\n\r") {
				t.Fatalf("scenario %q contains shell syntax in %q", scenario.ID, argument)
			}
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scenario ids = %#v, want %#v", got, want)
	}
}

func TestPrepareInvocationPinsClientHashAndUsesNoShell(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	client := filepath.Join(directory, "gitoversightctl")
	if err := os.WriteFile(client, []byte("verified-client"), 0o755); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("verified-client"))
	config := Config{
		BrokerURL:    "https://gitoversight.example",
		TenantID:     "tenant-a",
		Client:       client,
		ClientSHA256: hex.EncodeToString(digest[:]),
		Agents: map[string]AgentConfig{
			"zara":  {UnixUser: "agent-zara", IdentityPath: "/home/agent-zara/.config/gitoversight/identity.key", CredentialID: "zara-key-1"},
			"tomas": {UnixUser: "agent-tomas", IdentityPath: "/home/agent-tomas/.config/gitoversight/identity.key", CredentialID: "tomas-key-1"},
		},
		Values: map[string]string{"private_head_sha": strings.Repeat("a", 40), "manifest_hash": strings.Repeat("b", 64)},
	}
	invocation, err := prepareInvocation(config, "zara-private-owner-allow", "run-12345678")
	if err != nil {
		t.Fatal(err)
	}
	if invocation.Program != "/usr/bin/sudo" || invocation.Args[0] != "-n" || invocation.Args[1] != "-u" || invocation.Args[2] != "agent-zara" || invocation.Args[3] != "--" || invocation.Args[4] != client {
		t.Fatalf("unsafe invocation = %#v", invocation)
	}
	if invocation.State != "verified" || invocation.Decision != "allowed_private_owner" || invocation.RequestID != "crossuser-run-12345678-zara-owner" {
		t.Fatalf("exact result contract = %#v", invocation)
	}
	joined := strings.Join(invocation.Args, " ")
	for _, value := range []string{"https://gitoversight.example", "tenant-a", "zara-key-1", "run-12345678"} {
		if !strings.Contains(joined, value) {
			t.Errorf("invocation missing %q: %s", value, joined)
		}
	}
}

func TestPrepareInvocationRejectsChangedClientAndUnknownScenario(t *testing.T) {
	t.Parallel()
	client := filepath.Join(t.TempDir(), "gitoversightctl")
	if err := os.WriteFile(client, []byte("changed"), 0o755); err != nil {
		t.Fatal(err)
	}
	config := Config{BrokerURL: "https://gitoversight.example", TenantID: "tenant-a", Client: client, ClientSHA256: strings.Repeat("0", 64), Agents: map[string]AgentConfig{"zara": {UnixUser: "agent-zara", IdentityPath: "/home/agent-zara/key", CredentialID: "zara-key"}}}
	if _, err := prepareInvocation(config, "zara-private-owner-allow", "run-12345678"); err == nil {
		t.Fatal("changed client hash was accepted")
	}
	if _, err := prepareInvocation(config, "not-a-scenario", "run-12345678"); err == nil {
		t.Fatal("unknown scenario was accepted")
	}
}

func TestPrepareInvocationRejectsBrokerURLWithPath(t *testing.T) {
	t.Parallel()
	config := Config{BrokerURL: "https://gitoversight.example/not-an-origin", TenantID: "tenant-a"}
	if _, err := prepareInvocation(config, "zara-private-owner-allow", "run-12345678"); err == nil {
		t.Fatal("broker URL with a path was accepted as an origin")
	}
}

func TestVerifyClientRejectsSymlinkAndWritableTrustedAncestor(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "bin")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	client := filepath.Join(directory, "gitoversightctl")
	payload := []byte("verified-client")
	if err := os.WriteFile(client, payload, 0o755); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	wantHash := hex.EncodeToString(digest[:])
	uid := uint32(os.Geteuid())
	if err := verifyClient(client, wantHash, &uid); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "gitoversightctl-link")
	if err := os.Symlink(client, link); err != nil {
		t.Fatal(err)
	}
	if err := verifyClient(link, wantHash, &uid); err == nil {
		t.Fatal("symlinked client was accepted")
	}
	if err := os.Chmod(directory, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := verifyClient(client, wantHash, &uid); err == nil {
		t.Fatal("client beneath writable trusted ancestor was accepted")
	}
}

func TestSafeResultNeverReturnsRawClientOutput(t *testing.T) {
	t.Parallel()
	result := summarizeResult("case", "agent-zara", 2, []byte(`{"id":"request-1","state":"denied","decision":"branch_grant_required","code":"wrong_branch","token":"github_pat_secret"}`), []byte("Authorization: bearer secret"), false)
	encoded := result.String()
	if strings.Contains(encoded, "github_pat_secret") || strings.Contains(encoded, "bearer secret") || strings.Contains(encoded, "Authorization") {
		t.Fatalf("unsafe result = %s", encoded)
	}
	for _, value := range []string{"request-1", "denied", "branch_grant_required", "wrong_branch", "agent-zara"} {
		if !strings.Contains(encoded, value) {
			t.Errorf("safe result missing %q: %s", value, encoded)
		}
	}
}

func TestResultMatchesRequiresExactExitStateDecisionAndRequestID(t *testing.T) {
	t.Parallel()
	invocation := Invocation{Want: []int{2}, State: "denied", Decision: "branch_grant_required", RequestID: "request-1"}
	valid := SafeResult{ExitCode: 2, State: "denied", Decision: "branch_grant_required", RequestID: "request-1"}
	if err := validateResult(invocation, valid); err != nil {
		t.Fatal(err)
	}
	for name, changed := range map[string]SafeResult{
		"wrong exit":     {ExitCode: 1, State: valid.State, Decision: valid.Decision, RequestID: valid.RequestID},
		"wrong state":    {ExitCode: 2, State: "awaiting_approval", Decision: valid.Decision, RequestID: valid.RequestID},
		"wrong decision": {ExitCode: 2, State: valid.State, Decision: "caller_unknown", RequestID: valid.RequestID},
		"wrong request":  {ExitCode: 2, State: valid.State, Decision: valid.Decision, RequestID: "request-2"},
		"timed out":      {ExitCode: 2, State: valid.State, Decision: valid.Decision, RequestID: valid.RequestID, TimedOut: true},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateResult(invocation, changed); err == nil {
				t.Fatal("mismatched result was accepted")
			}
		})
	}
}
