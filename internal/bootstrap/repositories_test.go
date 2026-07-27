package bootstrap_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/bootstrap"
)

func TestApprovedRepositoryPacketIsExactAndStable(t *testing.T) {
	t.Parallel()
	packet := bootstrap.ApprovedRepositoryPacket()
	if err := bootstrap.ValidateRepositoryPacket(packet); err != nil {
		t.Fatal(err)
	}
	if packet.Owner != "yaniv256" || len(packet.Repositories) != 6 {
		t.Fatalf("packet = %#v", packet)
	}
	digest, err := bootstrap.RepositoryPacketDigest(packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(digest) != 64 {
		t.Fatalf("digest = %q", digest)
	}
	if second, _ := bootstrap.RepositoryPacketDigest(bootstrap.ApprovedRepositoryPacket()); second != digest {
		t.Fatalf("digest changed: %s != %s", second, digest)
	}
}

func TestRepositoryPacketRejectsAnyAuthorityDrift(t *testing.T) {
	t.Parallel()
	approved := bootstrap.ApprovedRepositoryPacket()
	tests := []struct {
		name   string
		mutate func(*bootstrap.RepositoryPacket)
	}{
		{"owner", func(packet *bootstrap.RepositoryPacket) { packet.Owner = "other" }},
		{"missing", func(packet *bootstrap.RepositoryPacket) { packet.Repositories = packet.Repositories[:5] }},
		{"unexpected", func(packet *bootstrap.RepositoryPacket) { packet.Repositories[0].Name = "gitoversight" }},
		{"visibility", func(packet *bootstrap.RepositoryPacket) { packet.Repositories[0].Visibility = "public" }},
		{"order", func(packet *bootstrap.RepositoryPacket) {
			packet.Repositories[0], packet.Repositories[1] = packet.Repositories[1], packet.Repositories[0]
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packet := approved
			packet.Repositories = append([]bootstrap.RepositorySpec(nil), approved.Repositories...)
			test.mutate(&packet)
			if err := bootstrap.ValidateRepositoryPacket(packet); err == nil {
				t.Fatal("drifted packet was accepted")
			}
		})
	}
}

type remote struct {
	states       map[string]bootstrap.RepositoryState
	reads        []string
	creates      []bootstrap.RepositorySpec
	createErr    error
	afterReadErr error
}

func (r *remote) ReadRepository(_ context.Context, fullName string) (bootstrap.RepositoryState, bool, error) {
	r.reads = append(r.reads, fullName)
	if r.afterReadErr != nil && len(r.creates) > 0 {
		return bootstrap.RepositoryState{}, false, r.afterReadErr
	}
	state, ok := r.states[fullName]
	return state, ok, nil
}

func (r *remote) CreateRepository(_ context.Context, owner string, spec bootstrap.RepositorySpec) error {
	r.creates = append(r.creates, spec)
	if r.createErr == nil || errors.Is(r.createErr, errCommittedResponseLost) {
		r.states[owner+"/"+spec.Name] = bootstrap.RepositoryState{NameWithOwner: owner + "/" + spec.Name, Visibility: spec.Visibility}
	}
	return r.createErr
}

var errCommittedResponseLost = errors.New("response lost after commit")

func TestRepositoryBootstrapSerializesCreationAndIndependentlyReadsEveryResult(t *testing.T) {
	t.Parallel()
	packet := bootstrap.ApprovedRepositoryPacket()
	api := &remote{states: map[string]bootstrap.RepositoryState{}}
	receipts, err := bootstrap.ApplyRepositories(context.Background(), api, packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 6 || len(api.creates) != 6 || len(api.reads) != 12 {
		t.Fatalf("receipts = %d, creates = %d, reads = %d", len(receipts), len(api.creates), len(api.reads))
	}
	if !reflect.DeepEqual(api.creates, packet.Repositories) {
		t.Fatalf("creation order = %#v", api.creates)
	}
	for _, receipt := range receipts {
		if receipt.Outcome != bootstrap.OutcomeVerifiedCreated || receipt.Repository == "" {
			t.Fatalf("receipt = %#v", receipt)
		}
	}
}

func TestRepositoryBootstrapReconcilesLostMutationResponseWithoutRetry(t *testing.T) {
	t.Parallel()
	packet := bootstrap.ApprovedRepositoryPacket()
	api := &remote{states: map[string]bootstrap.RepositoryState{}, createErr: errCommittedResponseLost}
	receipts, err := bootstrap.ApplyRepositories(context.Background(), api, packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(api.creates) != 6 || len(api.reads) != 12 || receipts[0].Outcome != bootstrap.OutcomeVerifiedCreated {
		t.Fatalf("receipts = %#v, creates = %d, reads = %d", receipts, len(api.creates), len(api.reads))
	}
}

func TestRepositoryBootstrapStopsIndeterminateAndNeverBlindlyRetries(t *testing.T) {
	t.Parallel()
	packet := bootstrap.ApprovedRepositoryPacket()
	api := &remote{states: map[string]bootstrap.RepositoryState{}, createErr: errors.New("timeout"), afterReadErr: errors.New("read unavailable")}
	receipts, err := bootstrap.ApplyRepositories(context.Background(), api, packet)
	if err == nil || !strings.Contains(err.Error(), "indeterminate") {
		t.Fatalf("receipts = %#v, err = %v", receipts, err)
	}
	if len(api.creates) != 1 || len(api.reads) != 2 {
		t.Fatalf("creates = %d, reads = %d", len(api.creates), len(api.reads))
	}
}

func TestRepositoryBootstrapRefusesExistingVisibilityMismatch(t *testing.T) {
	t.Parallel()
	packet := bootstrap.ApprovedRepositoryPacket()
	fullName := packet.Owner + "/" + packet.Repositories[0].Name
	api := &remote{states: map[string]bootstrap.RepositoryState{fullName: {NameWithOwner: fullName, Visibility: "public"}}}
	_, err := bootstrap.ApplyRepositories(context.Background(), api, packet)
	if err == nil || len(api.creates) != 0 {
		t.Fatalf("creates = %d, err = %v", len(api.creates), err)
	}
}
