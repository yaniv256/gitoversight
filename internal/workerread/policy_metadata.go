package workerread

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/yaniv256/gitoversight.dev/internal/brokerapp"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
)

type PolicySnapshotSource interface {
	PolicySnapshot(context.Context, string) (policy.Snapshot, error)
}

// PolicyRepositoryAdapter supplies compact repository discovery without
// exposing GitHub credentials or fetching repository contents. Search is a
// lexical projection over the exact caller-scoped repository names.
type PolicyRepositoryAdapter struct{ source PolicySnapshotSource }

func NewPolicyRepositoryAdapter(source PolicySnapshotSource) (*PolicyRepositoryAdapter, error) {
	if source == nil {
		return nil, errors.New("policy repository adapter requires a snapshot source")
	}
	return &PolicyRepositoryAdapter{source: source}, nil
}

func (adapter *PolicyRepositoryAdapter) ReadableRepositories(ctx context.Context, identity brokerapp.Identity) ([]string, error) {
	snapshot, err := adapter.source.PolicySnapshot(ctx, identity.TenantID)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0)
	for name, repository := range snapshot.Repositories {
		if repository.Visibility != "private" {
			continue
		}
		decision := policy.Evaluate(snapshot, policy.Request{Caller: identity.AgentID, Repository: name, Operation: "repository.read"})
		if decision.Code == policy.AllowedRead {
			result = append(result, name)
		}
	}
	sort.Strings(result)
	return result, nil
}

func (adapter *PolicyRepositoryAdapter) AuthorizeRepositoryRead(ctx context.Context, identity brokerapp.Identity, repository string) error {
	snapshot, err := adapter.source.PolicySnapshot(ctx, identity.TenantID)
	if err != nil {
		return err
	}
	entry, exists := snapshot.Repositories[repository]
	if !exists || entry.Visibility != "private" {
		return brokerapp.ErrRepositoryReadDenied
	}
	decision := policy.Evaluate(snapshot, policy.Request{Caller: identity.AgentID, Repository: repository, Operation: "repository.read"})
	if decision.Code != policy.AllowedRead {
		return brokerapp.ErrRepositoryReadDenied
	}
	return nil
}

func (adapter *PolicyRepositoryAdapter) Inspect(ctx context.Context, identity brokerapp.Identity, repository string) (brokerapp.RepositoryReadMetadata, error) {
	if err := adapter.AuthorizeRepositoryRead(ctx, identity, repository); err != nil {
		return brokerapp.RepositoryReadMetadata{}, err
	}
	return brokerapp.RepositoryReadMetadata{Repository: repository, Visibility: "private", DefaultBranch: "main"}, nil
}

func (adapter *PolicyRepositoryAdapter) Search(_ context.Context, _ brokerapp.Identity, repositories []string, query string, limit int) ([]brokerapp.RepositorySearchHit, error) {
	needle := strings.ToLower(strings.TrimSpace(query))
	hits := make([]brokerapp.RepositorySearchHit, 0, min(limit, len(repositories)))
	for _, repository := range repositories {
		name := strings.ToLower(repository)
		position := strings.Index(name, needle)
		if position < 0 {
			continue
		}
		score := 0.75
		if name == needle {
			score = 1
		} else if position == 0 || strings.HasPrefix(name, needle) {
			score = 0.9
		}
		hits = append(hits, brokerapp.RepositorySearchHit{Repository: repository, Path: "@repository", Snippet: repository, Score: score})
		if len(hits) == limit {
			break
		}
	}
	return hits, nil
}
