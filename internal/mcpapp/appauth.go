package mcpapp

import (
	"context"
	"errors"
	"sort"

	"github.com/yaniv256/gitoversight.dev/internal/appauth"
	"github.com/yaniv256/gitoversight.dev/internal/brokerapp"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
)

type AccessTokenResolver interface {
	ResolveAccessToken(context.Context, string) (appauth.AccessGrant, error)
}

type PolicySource interface {
	PolicySnapshot(context.Context, string) (policy.Snapshot, error)
}

// OAuthAccessAdapter resolves OAuth access tokens and enforces their immutable
// repository scope against current policy. The current-policy intersection is
// essential: a repository that later becomes public must not remain reachable
// through an older private-only grant.
type OAuthAccessAdapter struct {
	resolver AccessTokenResolver
	policies PolicySource
	issuer   string
	audience string
}

func NewOAuthAccessAdapter(resolver AccessTokenResolver, policies PolicySource, issuer, audience string) (*OAuthAccessAdapter, error) {
	if resolver == nil || policies == nil || issuer == "" || audience == "" {
		return nil, errors.New("oauth access adapter configuration is incomplete")
	}
	return &OAuthAccessAdapter{resolver: resolver, policies: policies, issuer: issuer, audience: audience}, nil
}

func (adapter *OAuthAccessAdapter) ResolveBearer(ctx context.Context, raw string) (Principal, error) {
	grant, err := adapter.resolver.ResolveAccessToken(ctx, raw)
	if err != nil || grant.Issuer != adapter.issuer || grant.Audience != adapter.audience || grant.ClientID == "" || grant.TenantID == "" || grant.AgentID == "" {
		return Principal{}, ErrUnauthenticated
	}
	return Principal{
		Identity: brokerapp.Identity{TenantID: grant.TenantID, AgentID: grant.AgentID, CredentialID: grant.ID},
		ClientID: grant.ClientID, Repositories: append([]string(nil), grant.Repositories...), AllPrivate: grant.AllPrivate,
	}, nil
}

func (adapter *OAuthAccessAdapter) ListAuthorized(ctx context.Context, principal Principal) ([]Repository, error) {
	snapshot, err := adapter.policies.PolicySnapshot(ctx, principal.Identity.TenantID)
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]struct{}, len(principal.Repositories))
	for _, name := range principal.Repositories {
		allowed[name] = struct{}{}
	}
	repositories := make([]Repository, 0)
	for name, repository := range snapshot.Repositories {
		if repository.Visibility != "private" {
			continue
		}
		if !principal.AllPrivate {
			if _, ok := allowed[name]; !ok {
				continue
			}
		}
		repositories = append(repositories, Repository{Key: name, Visibility: repository.Visibility})
	}
	sort.Slice(repositories, func(i, j int) bool { return repositories[i].Key < repositories[j].Key })
	return repositories, nil
}

func (adapter *OAuthAccessAdapter) Authorize(ctx context.Context, principal Principal, repository string) error {
	repositories, err := adapter.ListAuthorized(ctx, principal)
	if err != nil {
		return err
	}
	for _, candidate := range repositories {
		if candidate.Key == repository {
			return nil
		}
	}
	return ErrRepositoryDenied
}
