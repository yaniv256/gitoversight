package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

type GHCommandRunner interface {
	Run(context.Context, ...string) (stdout []byte, stderr []byte, exitCode int, err error)
}

type ExecGHRunner struct {
	Path string
}

func (r ExecGHRunner) Run(ctx context.Context, args ...string) ([]byte, []byte, int, error) {
	if r.Path == "" {
		return nil, nil, -1, errors.New("gh executable path is required")
	}
	cmd := exec.CommandContext(ctx, r.Path, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return stdout.Bytes(), stderr.Bytes(), 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return stdout.Bytes(), stderr.Bytes(), exitErr.ExitCode(), nil
	}
	return stdout.Bytes(), stderr.Bytes(), -1, fmt.Errorf("execute gh: %w", err)
}

type GHRemote struct {
	runner GHCommandRunner
}

func NewGHRemote(runner GHCommandRunner) *GHRemote {
	return &GHRemote{runner: runner}
}

func (r *GHRemote) AuthenticatedLogin(ctx context.Context) (string, error) {
	stdout, stderr, exitCode, err := r.run(ctx, "api", "user")
	if err != nil {
		return "", err
	}
	if exitCode != 0 {
		return "", commandFailure("read authenticated GitHub identity", exitCode, stderr)
	}
	var response struct {
		Login string `json:"login"`
	}
	if err := json.Unmarshal(stdout, &response); err != nil {
		return "", fmt.Errorf("decode authenticated GitHub identity: %w", err)
	}
	if response.Login == "" {
		return "", errors.New("authenticated GitHub identity omitted login")
	}
	return response.Login, nil
}

func (r *GHRemote) ReadRepository(ctx context.Context, fullName string) (RepositoryState, bool, error) {
	if _, ok := approvedRepository(fullName); !ok {
		return RepositoryState{}, false, fmt.Errorf("repository %q is outside the approved bootstrap packet", fullName)
	}
	stdout, stderr, exitCode, err := r.run(ctx, "api", "repos/"+fullName)
	if err != nil {
		return RepositoryState{}, false, err
	}
	if exitCode != 0 {
		if strings.Contains(string(stderr), "HTTP 404") {
			return RepositoryState{}, false, nil
		}
		return RepositoryState{}, false, commandFailure("read repository "+fullName, exitCode, stderr)
	}
	var response struct {
		FullName   string `json:"full_name"`
		Visibility string `json:"visibility"`
	}
	if err := json.Unmarshal(stdout, &response); err != nil {
		return RepositoryState{}, false, fmt.Errorf("decode repository %s: %w", fullName, err)
	}
	if response.FullName == "" || response.Visibility == "" {
		return RepositoryState{}, false, fmt.Errorf("repository %s response omitted identity or visibility", fullName)
	}
	return RepositoryState{NameWithOwner: response.FullName, Visibility: response.Visibility}, true, nil
}

func (r *GHRemote) CreateRepository(ctx context.Context, owner string, spec RepositorySpec) error {
	if owner != approvedRepositoryPacket.Owner {
		return fmt.Errorf("repository owner %q is outside the approved bootstrap packet", owner)
	}
	fullName := owner + "/" + spec.Name
	approved, ok := approvedRepository(fullName)
	if !ok || approved != spec {
		return fmt.Errorf("repository %q differs from the approved bootstrap packet", fullName)
	}
	private := "false"
	if spec.Visibility == "private" {
		private = "true"
	} else if spec.Visibility != "public" {
		return fmt.Errorf("unsupported repository visibility %q", spec.Visibility)
	}
	_, stderr, exitCode, err := r.run(
		ctx,
		"api", "--method", "POST", "user/repos",
		"--raw-field", "name="+spec.Name,
		"--raw-field", "description="+spec.Purpose,
		"--field", "private="+private,
	)
	if err != nil {
		return err
	}
	if exitCode != 0 {
		return commandFailure("create repository "+fullName, exitCode, stderr)
	}
	return nil
}

func (r *GHRemote) run(ctx context.Context, args ...string) ([]byte, []byte, int, error) {
	if r == nil || r.runner == nil {
		return nil, nil, -1, errors.New("gh command runner is required")
	}
	return r.runner.Run(ctx, args...)
}

func approvedRepository(fullName string) (RepositorySpec, bool) {
	for _, spec := range approvedRepositoryPacket.Repositories {
		if approvedRepositoryPacket.Owner+"/"+spec.Name == fullName {
			return spec, true
		}
	}
	return RepositorySpec{}, false
}

func commandFailure(action string, exitCode int, stderr []byte) error {
	detail := strings.TrimSpace(string(stderr))
	if len(detail) > 512 {
		detail = detail[:512]
	}
	if detail == "" {
		detail = "no diagnostic"
	}
	return fmt.Errorf("%s failed (exit %d): %s", action, exitCode, detail)
}
