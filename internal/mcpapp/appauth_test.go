package mcpapp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/appauth"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
)

type accessResolverStub struct {
	grant appauth.AccessGrant
	err   error
}

func (stub accessResolverStub) ResolveAccessToken(context.Context, string) (appauth.AccessGrant, error) {
	return stub.grant, stub.err
}

type policySourceStub struct{ snapshot policy.Snapshot }

func (stub policySourceStub) PolicySnapshot(context.Context, string) (policy.Snapshot, error) {
	return stub.snapshot, nil
}

func TestOAuthAccessAdapterPreservesSelectedScopeAndCurrentPrivateBoundary(t *testing.T) {
	grant := appauth.AccessGrant{TokenFamily: appauth.TokenFamily{Binding: appauth.Binding{
		Issuer: "https://gitoversight.test", Audience: "https://gitoversight.test/mcp", ClientID: "chatgpt",
		TenantID: "tenant-a", AgentID: "work", Repositories: []string{"org/selected", "org/became-public"},
	}, ID: "family-1"}, ExpiresAt: time.Now().Add(time.Hour)}
	snapshot := policy.Snapshot{Generation: 1, Agents: map[string]policy.Agent{"work": {Kind: policy.AgentKindRemote, FirstName: "Work"}}, Repositories: map[string]policy.Repository{
		"org/selected":      {Visibility: "private", Owners: []string{"work"}},
		"org/not-selected":  {Visibility: "private", Owners: []string{"work"}},
		"org/became-public": {Visibility: "public", Owners: []string{"work"}},
	}}
	adapter, err := NewOAuthAccessAdapter(accessResolverStub{grant: grant}, policySourceStub{snapshot}, grant.Issuer, grant.Audience)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := adapter.ResolveBearer(context.Background(), "access")
	if err != nil || principal.Identity.CredentialID != "family-1" || principal.AllPrivate {
		t.Fatalf("principal = %+v, %v", principal, err)
	}
	repositories, err := adapter.ListAuthorized(context.Background(), principal)
	if err != nil || len(repositories) != 1 || repositories[0].Key != "org/selected" {
		t.Fatalf("selected repositories = %+v, %v", repositories, err)
	}
	if err := adapter.Authorize(context.Background(), principal, "org/not-selected"); !errors.Is(err, ErrRepositoryDenied) {
		t.Fatalf("out-of-scope authorization = %v", err)
	}
}

func TestOAuthAccessAdapterAllPrivateIsDynamicAndRejectsWrongBinding(t *testing.T) {
	grant := appauth.AccessGrant{TokenFamily: appauth.TokenFamily{Binding: appauth.Binding{
		Issuer: "https://gitoversight.test", Audience: "https://gitoversight.test/mcp", ClientID: "chatgpt",
		TenantID: "tenant-a", AgentID: "work", AllPrivate: true,
	}, ID: "family-2"}}
	snapshot := policy.Snapshot{Generation: 1, Repositories: map[string]policy.Repository{
		"org/one": {Visibility: "private", Owners: []string{"work"}},
		"org/two": {Visibility: "private", Owners: []string{"work"}},
		"org/pub": {Visibility: "public", Owners: []string{"work"}},
	}}
	adapter, _ := NewOAuthAccessAdapter(accessResolverStub{grant: grant}, policySourceStub{snapshot}, grant.Issuer, grant.Audience)
	principal, err := adapter.ResolveBearer(context.Background(), "access")
	if err != nil {
		t.Fatal(err)
	}
	repositories, err := adapter.ListAuthorized(context.Background(), principal)
	if err != nil || len(repositories) != 2 || repositories[0].Key != "org/one" || repositories[1].Key != "org/two" {
		t.Fatalf("all-private repositories = %+v, %v", repositories, err)
	}
	wrong, _ := NewOAuthAccessAdapter(accessResolverStub{grant: grant}, policySourceStub{snapshot}, "https://other.test", grant.Audience)
	if _, err := wrong.ResolveBearer(context.Background(), "access"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("wrong issuer resolver = %v", err)
	}
}
