package bootstrap_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/bootstrap"
)

type commandResult struct {
	stdout   string
	stderr   string
	exitCode int
}

type commandRunner struct {
	results []commandResult
	calls   [][]string
}

func (r *commandRunner) Run(_ context.Context, args ...string) ([]byte, []byte, int, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	result := r.results[0]
	r.results = r.results[1:]
	return []byte(result.stdout), []byte(result.stderr), result.exitCode, nil
}

func TestGHRemoteReadsAuthenticatedLoginWithoutTokenArguments(t *testing.T) {
	t.Parallel()
	runner := &commandRunner{results: []commandResult{{stdout: `{"login":"yaniv256"}`}}}
	remote := bootstrap.NewGHRemote(runner)
	login, err := remote.AuthenticatedLogin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if login != "yaniv256" || !reflect.DeepEqual(runner.calls, [][]string{{"api", "user"}}) {
		t.Fatalf("login = %q, calls = %#v", login, runner.calls)
	}
}

func TestGHRemoteTreatsOnlyHTTP404AsAbsent(t *testing.T) {
	t.Parallel()
	runner := &commandRunner{results: []commandResult{
		{stderr: "gh: Not Found (HTTP 404)", exitCode: 1},
		{stderr: "gh: authentication failed (HTTP 401)", exitCode: 1},
	}}
	remote := bootstrap.NewGHRemote(runner)
	packet := bootstrap.ApprovedRepositoryPacket()
	first := packet.Owner + "/" + packet.Repositories[0].Name
	second := packet.Owner + "/" + packet.Repositories[1].Name
	_, exists, err := remote.ReadRepository(context.Background(), first)
	if err != nil || exists {
		t.Fatalf("exists = %v, err = %v", exists, err)
	}
	_, _, err = remote.ReadRepository(context.Background(), second)
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("err = %v", err)
	}
}

func TestGHRemoteParsesRepositoryIdentityAndVisibility(t *testing.T) {
	t.Parallel()
	packet := bootstrap.ApprovedRepositoryPacket()
	fullName := packet.Owner + "/" + packet.Repositories[0].Name
	runner := &commandRunner{results: []commandResult{{stdout: `{"full_name":"yaniv256/gitoversight.dev","visibility":"private"}`}}}
	remote := bootstrap.NewGHRemote(runner)
	state, exists, err := remote.ReadRepository(context.Background(), fullName)
	if err != nil || !exists {
		t.Fatalf("exists = %v, err = %v", exists, err)
	}
	want := bootstrap.RepositoryState{NameWithOwner: fullName, Visibility: "private"}
	if !reflect.DeepEqual(state, want) {
		t.Fatalf("state = %#v", state)
	}
}

func TestGHRemoteCreatesOnlyExactUserOwnedRepository(t *testing.T) {
	t.Parallel()
	packet := bootstrap.ApprovedRepositoryPacket()
	tests := []struct {
		spec    bootstrap.RepositorySpec
		private string
	}{
		{spec: packet.Repositories[0], private: "true"},
		{spec: packet.Repositories[3], private: "false"},
	}
	for _, test := range tests {
		t.Run(test.spec.Visibility, func(t *testing.T) {
			runner := &commandRunner{results: []commandResult{{}}}
			remote := bootstrap.NewGHRemote(runner)
			if err := remote.CreateRepository(context.Background(), packet.Owner, test.spec); err != nil {
				t.Fatal(err)
			}
			want := []string{"api", "--method", "POST", "user/repos", "--raw-field", "name=" + test.spec.Name, "--raw-field", "description=" + test.spec.Purpose, "--field", "private=" + test.private}
			if !reflect.DeepEqual(runner.calls, [][]string{want}) {
				t.Fatalf("calls = %#v", runner.calls)
			}
		})
	}
}

func TestGHRemoteRejectsOwnerAndVisibilityDriftBeforeNetwork(t *testing.T) {
	t.Parallel()
	runner := &commandRunner{}
	remote := bootstrap.NewGHRemote(runner)
	approved := bootstrap.ApprovedRepositoryPacket().Repositories[0]
	for _, test := range []struct {
		owner      string
		visibility string
	}{
		{owner: "other", visibility: "private"},
		{owner: "yaniv256", visibility: "internal"},
	} {
		spec := approved
		spec.Visibility = test.visibility
		err := remote.CreateRepository(context.Background(), test.owner, spec)
		if err == nil {
			t.Fatalf("owner = %q, visibility = %q accepted", test.owner, test.visibility)
		}
	}
	if len(runner.calls) != 0 {
		t.Fatalf("calls = %#v", runner.calls)
	}
}
