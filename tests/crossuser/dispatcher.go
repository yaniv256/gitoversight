package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

//go:embed scenarios.json
var scenarioFiles embed.FS

var (
	runIDPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{7,63}$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

type scenario struct {
	ID                string   `json:"id"`
	Agent             string   `json:"agent"`
	UnixUser          string   `json:"unix_user"`
	Arguments         []string `json:"arguments"`
	ExpectedExitCodes []int    `json:"expected_exit_codes"`
	ExpectedState     string   `json:"expected_state"`
	ExpectedDecision  string   `json:"expected_decision"`
}

type AgentConfig struct {
	UnixUser     string `json:"unix_user"`
	IdentityPath string `json:"identity_path"`
	CredentialID string `json:"credential_id"`
}

type Config struct {
	BrokerURL    string                 `json:"broker_url"`
	TenantID     string                 `json:"tenant_id"`
	Client       string                 `json:"client"`
	ClientSHA256 string                 `json:"client_sha256"`
	Agents       map[string]AgentConfig `json:"agents"`
	Values       map[string]string      `json:"values"`
	TrustedUID   *uint32                `json:"-"`
}

type Invocation struct {
	Program   string
	Args      []string
	Env       []string
	Want      []int
	ID        string
	User      string
	State     string
	Decision  string
	RequestID string
}

type SafeResult struct {
	ScenarioID     string `json:"scenario_id"`
	UnixUser       string `json:"unix_user"`
	ExitCode       int    `json:"exit_code"`
	State          string `json:"state,omitempty"`
	Code           string `json:"code,omitempty"`
	Decision       string `json:"decision,omitempty"`
	OperationID    string `json:"operation_id,omitempty"`
	RequestID      string `json:"request_id,omitempty"`
	ResponseSHA256 string `json:"response_sha256"`
	TimedOut       bool   `json:"timed_out"`
}

func (result SafeResult) String() string {
	payload, _ := json.Marshal(result)
	return string(payload)
}

func main() {
	configPath := flag.String("config", "/etc/gitoversight/crossuser.json", "root-owned dispatcher configuration")
	scenarioID := flag.String("scenario", "", "embedded scenario id")
	runID := flag.String("run-id", "", "unique lowercase acceptance run id")
	flag.Parse()
	if *scenarioID == "" || *runID == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "config, scenario, and run-id are required; positional arguments are forbidden")
		os.Exit(2)
	}
	config, err := loadConfig(*configPath, true)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	invocation, err := prepareInvocation(config, *scenarioID, *runID)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	result, err := runInvocation(invocation, 30*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(result.String())
	if err := validateResult(invocation, result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func loadScenarios() ([]scenario, error) {
	payload, err := scenarioFiles.ReadFile("scenarios.json")
	if err != nil {
		return nil, err
	}
	var scenarios []scenario
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&scenarios); err != nil {
		return nil, fmt.Errorf("decode embedded scenarios: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("embedded scenarios contain trailing JSON")
	}
	if len(scenarios) == 0 {
		return nil, errors.New("embedded scenario set is empty")
	}
	seen := map[string]struct{}{}
	for _, item := range scenarios {
		if !runIDPattern.MatchString(item.ID) || !identifierPattern.MatchString(item.Agent) || (item.UnixUser != "agent-zara" && item.UnixUser != "agent-tomas") || len(item.Arguments) == 0 || len(item.ExpectedExitCodes) == 0 || !identifierPattern.MatchString(item.ExpectedState) || !identifierPattern.MatchString(item.ExpectedDecision) {
			return nil, fmt.Errorf("embedded scenario %q is invalid", item.ID)
		}
		if _, exists := seen[item.ID]; exists {
			return nil, fmt.Errorf("duplicate embedded scenario %q", item.ID)
		}
		seen[item.ID] = struct{}{}
		for _, argument := range item.Arguments {
			if strings.ContainsAny(argument, ";|`\n\r") {
				return nil, fmt.Errorf("embedded scenario %q contains forbidden shell syntax", item.ID)
			}
		}
		for _, exitCode := range item.ExpectedExitCodes {
			if exitCode < 0 || exitCode > 255 {
				return nil, fmt.Errorf("embedded scenario %q contains an invalid exit code", item.ID)
			}
		}
	}
	return scenarios, nil
}

func loadConfig(path string, requireRoot bool) (Config, error) {
	if !filepath.IsAbs(path) {
		return Config{}, errors.New("dispatcher config path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return Config{}, fmt.Errorf("stat dispatcher config: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return Config{}, errors.New("dispatcher config must be a regular file not writable by group or world")
	}
	if requireRoot {
		if os.Geteuid() != 0 {
			return Config{}, errors.New("cross-user dispatcher must run as root")
		}
		if err := validateTrustedPath(path, 0, false); err != nil {
			return Config{}, fmt.Errorf("dispatcher config trust boundary: %w", err)
		}
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read dispatcher config: %w", err)
	}
	var config Config
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode dispatcher config: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("dispatcher config contains trailing JSON")
	}
	if requireRoot {
		rootUID := uint32(0)
		config.TrustedUID = &rootUID
	}
	return config, nil
}

func prepareInvocation(config Config, scenarioID, runID string) (Invocation, error) {
	if !runIDPattern.MatchString(runID) {
		return Invocation{}, errors.New("run-id must be 8-64 lowercase letters, digits, or hyphens")
	}
	parsedURL, err := url.Parse(config.BrokerURL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" || parsedURL.User != nil || (parsedURL.Path != "" && parsedURL.Path != "/") || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return Invocation{}, errors.New("broker_url must be an HTTPS origin")
	}
	if !identifierPattern.MatchString(config.TenantID) {
		return Invocation{}, errors.New("tenant_id is invalid")
	}
	if err := verifyClient(config.Client, config.ClientSHA256, config.TrustedUID); err != nil {
		return Invocation{}, err
	}
	scenarios, err := loadScenarios()
	if err != nil {
		return Invocation{}, err
	}
	var selected *scenario
	for index := range scenarios {
		if scenarios[index].ID == scenarioID {
			selected = &scenarios[index]
			break
		}
	}
	if selected == nil {
		return Invocation{}, fmt.Errorf("unknown embedded scenario %q", scenarioID)
	}
	agent, exists := config.Agents[selected.Agent]
	if !exists || agent.UnixUser != selected.UnixUser || !filepath.IsAbs(agent.IdentityPath) || !identifierPattern.MatchString(agent.CredentialID) {
		return Invocation{}, fmt.Errorf("agent configuration for scenario %q is invalid", scenarioID)
	}
	values := map[string]string{"run_id": runID, "broker_url": config.BrokerURL, "tenant_id": config.TenantID, "identity_path": agent.IdentityPath, "credential_id": agent.CredentialID}
	for key, value := range config.Values {
		if !identifierPattern.MatchString(key) || strings.ContainsAny(value, "\n\r") {
			return Invocation{}, fmt.Errorf("dispatcher value %q is invalid", key)
		}
		values[key] = value
	}
	arguments := make([]string, 0, len(selected.Arguments)+10)
	for _, argument := range selected.Arguments {
		rendered, err := render(argument, values)
		if err != nil {
			return Invocation{}, fmt.Errorf("render scenario %q: %w", scenarioID, err)
		}
		arguments = append(arguments, rendered)
	}
	requestID, err := exactFlagValue(arguments, "--request-id")
	if err != nil {
		return Invocation{}, fmt.Errorf("scenario %q: %w", scenarioID, err)
	}
	arguments = append(arguments, "--url", config.BrokerURL, "--identity", agent.IdentityPath, "--tenant", config.TenantID, "--agent", selected.Agent, "--credential", agent.CredentialID)
	programArguments := []string{"-n", "-u", selected.UnixUser, "--", config.Client}
	programArguments = append(programArguments, arguments...)
	return Invocation{Program: "/usr/bin/sudo", Args: programArguments, Env: []string{"PATH=/usr/bin:/bin", "LANG=C", "HOME=/home/" + selected.UnixUser}, Want: append([]int(nil), selected.ExpectedExitCodes...), ID: selected.ID, User: selected.UnixUser, State: selected.ExpectedState, Decision: selected.ExpectedDecision, RequestID: requestID}, nil
}

func exactFlagValue(arguments []string, name string) (string, error) {
	value := ""
	for index := 0; index < len(arguments); index++ {
		if arguments[index] != name {
			continue
		}
		if value != "" || index+1 >= len(arguments) || arguments[index+1] == "" {
			return "", fmt.Errorf("%s must appear exactly once with a value", name)
		}
		value = arguments[index+1]
		index++
	}
	if value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}

func verifyClient(path, wantHash string, trustedUID *uint32) error {
	if !filepath.IsAbs(path) || len(wantHash) != sha256.Size*2 {
		return errors.New("client path and SHA-256 must be exact")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat Git Oversight client: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o111 == 0 {
		return errors.New("Git Oversight client must be executable and not writable by group or world")
	}
	if trustedUID != nil {
		if err := validateTrustedPath(path, *trustedUID, true); err != nil {
			return fmt.Errorf("Git Oversight client trust boundary: %w", err)
		}
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read Git Oversight client: %w", err)
	}
	digest := sha256.Sum256(payload)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), wantHash) {
		return errors.New("Git Oversight client hash mismatch")
	}
	return nil
}

func validateTrustedPath(path string, trustedUID uint32, executable bool) error {
	current := filepath.Clean(path)
	first := true
	for {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("stat trusted path %s: %w", current, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("trusted path ownership is unavailable")
		}
		if stat.Uid != trustedUID {
			if trustedUID != 0 {
				break
			}
			return fmt.Errorf("trusted path %s is not root-owned", current)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("trusted path %s is a symlink", current)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("trusted path %s is writable by group or world", current)
		}
		if first {
			if !info.Mode().IsRegular() || (executable && info.Mode().Perm()&0o111 == 0) {
				return errors.New("trusted file type or mode is invalid")
			}
		} else if !info.IsDir() {
			return fmt.Errorf("trusted path ancestor %s is not a directory", current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
		first = false
	}
	return nil
}

func render(value string, values map[string]string) (string, error) {
	rendered := value
	for key, replacement := range values {
		rendered = strings.ReplaceAll(rendered, "{{"+key+"}}", replacement)
	}
	if strings.Contains(rendered, "{{") || strings.Contains(rendered, "}}") {
		return "", errors.New("scenario contains an unresolved placeholder")
	}
	return rendered, nil
}

func runInvocation(invocation Invocation, timeout time.Duration) (SafeResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, invocation.Program, invocation.Args...)
	command.Env = invocation.Env
	var stdout, stderr bytes.Buffer
	command.Stdout = &limitedWriter{target: &stdout, remaining: 1 << 20}
	command.Stderr = &limitedWriter{target: &stderr, remaining: 1 << 20}
	err := command.Run()
	exitCode := 0
	if err != nil {
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) && ctx.Err() == nil {
			return SafeResult{}, errors.New("cross-user client could not start")
		}
		if exitError != nil {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = 124
		}
	}
	return summarizeResult(invocation.ID, invocation.User, exitCode, stdout.Bytes(), stderr.Bytes(), ctx.Err() != nil), nil
}

func summarizeResult(scenarioID, unixUser string, exitCode int, stdout, stderr []byte, timedOut bool) SafeResult {
	digestInput := append(append([]byte(nil), stdout...), stderr...)
	digest := sha256.Sum256(digestInput)
	result := SafeResult{ScenarioID: scenarioID, UnixUser: unixUser, ExitCode: exitCode, ResponseSHA256: hex.EncodeToString(digest[:]), TimedOut: timedOut}
	var payload map[string]any
	if json.Unmarshal(stdout, &payload) == nil {
		result.State = safeString(payload, "state")
		result.Code = safeString(payload, "code")
		result.Decision = safeString(payload, "decision")
		result.OperationID = safeString(payload, "operation_id")
		result.RequestID = safeString(payload, "id")
		if result.RequestID == "" {
			result.RequestID = safeString(payload, "request_id")
		}
	}
	return result
}

func validateResult(invocation Invocation, result SafeResult) error {
	if result.TimedOut {
		return errors.New("cross-user scenario timed out")
	}
	if !containsExit(invocation.Want, result.ExitCode) {
		return fmt.Errorf("cross-user scenario exit code %d was not expected", result.ExitCode)
	}
	if result.State != invocation.State || result.Decision != invocation.Decision || result.RequestID != invocation.RequestID {
		return errors.New("cross-user scenario result did not match the exact reviewed state, decision, and request id")
	}
	return nil
}

func safeString(payload map[string]any, key string) string {
	value, _ := payload[key].(string)
	if len(value) > 256 || !identifierPattern.MatchString(value) {
		return ""
	}
	return value
}

func containsExit(values []int, candidate int) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

type limitedWriter struct {
	target    io.Writer
	remaining int64
}

func (writer *limitedWriter) Write(payload []byte) (int, error) {
	if writer.remaining <= 0 {
		return len(payload), nil
	}
	toWrite := payload
	if int64(len(toWrite)) > writer.remaining {
		toWrite = toWrite[:writer.remaining]
	}
	written, err := writer.target.Write(toWrite)
	writer.remaining -= int64(written)
	if err != nil {
		return written, err
	}
	return len(payload), nil
}
