package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/bootstrap"
)

type bootstrapRemote struct {
	login       string
	states      map[string]bootstrap.RepositoryState
	identityHit int
	creates     int
}

func (r *bootstrapRemote) AuthenticatedLogin(context.Context) (string, error) {
	r.identityHit++
	return r.login, nil
}

func (r *bootstrapRemote) ReadRepository(_ context.Context, fullName string) (bootstrap.RepositoryState, bool, error) {
	state, ok := r.states[fullName]
	return state, ok, nil
}

func (r *bootstrapRemote) CreateRepository(_ context.Context, owner string, spec bootstrap.RepositorySpec) error {
	r.creates++
	fullName := owner + "/" + spec.Name
	r.states[fullName] = bootstrap.RepositoryState{NameWithOwner: fullName, Visibility: spec.Visibility}
	return nil
}

func TestRunRequiresApplyAndExactPacketDigestBeforeIdentityOrMutation(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		nil,
		{"--apply-repositories"},
		{"--apply-repositories", "--packet-digest", strings.Repeat("0", 64)},
	} {
		remote := &bootstrapRemote{login: "yaniv256", states: map[string]bootstrap.RepositoryState{}}
		if err := run(context.Background(), args, remote, &bytes.Buffer{}); err == nil {
			t.Fatalf("args %#v accepted", args)
		}
		if remote.identityHit != 0 || remote.creates != 0 {
			t.Fatalf("args %#v reached identity=%d creates=%d", args, remote.identityHit, remote.creates)
		}
	}
}

func TestRunPrintsApprovedPacketDigestWithoutIdentityOrMutation(t *testing.T) {
	t.Parallel()
	remote := &bootstrapRemote{login: "yaniv256", states: map[string]bootstrap.RepositoryState{}}
	var output bytes.Buffer
	if err := run(context.Background(), []string{"--print-packet-digest"}, remote, &output); err != nil {
		t.Fatal(err)
	}
	digest, err := bootstrap.RepositoryPacketDigest(bootstrap.ApprovedRepositoryPacket())
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(output.String()) != digest {
		t.Fatalf("output = %q, want %q", output.String(), digest)
	}
	if remote.identityHit != 0 || remote.creates != 0 {
		t.Fatalf("identity=%d creates=%d", remote.identityHit, remote.creates)
	}
}

func TestRunRejectsWrongAuthenticatedAccountBeforeMutation(t *testing.T) {
	t.Parallel()
	digest, err := bootstrap.RepositoryPacketDigest(bootstrap.ApprovedRepositoryPacket())
	if err != nil {
		t.Fatal(err)
	}
	remote := &bootstrapRemote{login: "someone-else", states: map[string]bootstrap.RepositoryState{}}
	err = run(context.Background(), []string{"--apply-repositories", "--packet-digest", digest}, remote, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "authenticated account") || remote.creates != 0 {
		t.Fatalf("creates = %d, err = %v", remote.creates, err)
	}
}

func TestRunAppliesExactPacketAndWritesReceipt(t *testing.T) {
	t.Parallel()
	digest, err := bootstrap.RepositoryPacketDigest(bootstrap.ApprovedRepositoryPacket())
	if err != nil {
		t.Fatal(err)
	}
	remote := &bootstrapRemote{login: "yaniv256", states: map[string]bootstrap.RepositoryState{}}
	var output bytes.Buffer
	if err := run(context.Background(), []string{"--apply-repositories", "--packet-digest", digest}, remote, &output); err != nil {
		t.Fatal(err)
	}
	if remote.creates != 6 || !strings.Contains(output.String(), digest) || !strings.Contains(output.String(), "verified_created") {
		t.Fatalf("creates = %d, output = %s", remote.creates, output.String())
	}
}
