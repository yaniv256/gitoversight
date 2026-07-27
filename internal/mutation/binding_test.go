package mutation_test

import (
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/mutation"
)

func FuzzMutationHashNeverPanics(f *testing.F) {
	f.Add("request-1", "yaniv256/private", "pull_request.create", "feature", "Title", "Body")
	f.Add("", "", "", "", "", "")
	f.Fuzz(func(t *testing.T, requestID, repository, operation, branch, title, body string) {
		_, _ = mutation.Hash(mutation.Packet{RequestID: requestID, Repository: repository, Operation: operation, Branch: branch, Title: title, Body: body})
	})
}

func TestMutationHashBindsActorAuthority(t *testing.T) {
	base := mutation.Packet{RequestID: "request-1", Repository: "yaniv256/public", Operation: "pull_request.create", ActorMode: "human_user", ActorSubject: "yaniv"}
	want, err := mutation.Hash(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range []mutation.Packet{
		{RequestID: base.RequestID, Repository: base.Repository, Operation: base.Operation, ActorMode: "app_installation"},
		{RequestID: base.RequestID, Repository: base.Repository, Operation: base.Operation, ActorMode: "human_user", ActorSubject: "other"},
	} {
		got, err := mutation.Hash(changed)
		if err != nil {
			t.Fatal(err)
		}
		if got == want {
			t.Fatalf("actor change did not change mutation hash: %#v", changed)
		}
	}
}
