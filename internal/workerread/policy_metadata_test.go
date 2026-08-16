package workerread_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/brokerapp"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/workerread"
)

type policySourceStub struct{ snapshot policy.Snapshot }

func (stub policySourceStub) PolicySnapshot(context.Context, string) (policy.Snapshot, error) {
	return stub.snapshot, nil
}

func TestPolicyRepositoryAdapterDiscoversOnlyReadablePrivateRepositories(t *testing.T) {
	snapshot := policy.Snapshot{Generation: 1, Agents: map[string]policy.Agent{"work": {Kind: policy.AgentKindRemote, FirstName: "Work"}}, Repositories: map[string]policy.Repository{
		"org/alpha":  {Visibility: "private", Permissions: &policy.PermissionSet{Read: true}},
		"org/public": {Visibility: "public", Permissions: &policy.PermissionSet{Read: true}},
	}}
	adapter, err := workerread.NewPolicyRepositoryAdapter(policySourceStub{snapshot: snapshot})
	if err != nil {
		t.Fatal(err)
	}
	identity := brokerapp.Identity{TenantID: "tenant", AgentID: "work"}
	repositories, err := adapter.ReadableRepositories(context.Background(), identity)
	if err != nil || !reflect.DeepEqual(repositories, []string{"org/alpha"}) {
		t.Fatalf("repositories=%v err=%v", repositories, err)
	}
	hits, err := adapter.Search(context.Background(), identity, repositories, "alpha", 5)
	if err != nil || len(hits) != 1 || hits[0].Repository != "org/alpha" || hits[0].Path != "@repository" {
		t.Fatalf("hits=%#v err=%v", hits, err)
	}
	if _, err := adapter.Inspect(context.Background(), identity, "org/public"); err == nil {
		t.Fatal("public repository inspection was allowed")
	}
}
