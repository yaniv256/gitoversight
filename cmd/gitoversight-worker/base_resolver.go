package main

import (
	"errors"
	"strconv"

	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

// baseResolver answers "what does this public repository look like right now?"
// — the base half of a pre-PR's cross-repository diff.
//
// It lives in the worker rather than the API because the API process holds no
// GitHub credentials by design; the worker is where tokens are minted. It is
// wired as a workerrpc option so the API reaches it over the same unix socket
// it already uses for pull reads.
type baseResolver struct {
	reader         *githubapp.Reader
	installationID int64
	visibility     func(string) (string, error)
}

func newBaseResolver(reader *githubapp.Reader, installationID int64, visibility func(string) (string, error)) (*baseResolver, error) {
	if reader == nil || installationID <= 0 || visibility == nil {
		return nil, errors.New("base resolver configuration is incomplete")
	}
	return &baseResolver{reader: reader, installationID: installationID, visibility: visibility}, nil
}

// ReadBase resolves a public repository's HEAD commit, its tree, and every leaf
// in that tree.
//
// A repository with no commits (or no such branch) yields Empty rather than an
// error: publishing into an empty public repository is a legitimate
// root-commit pre-PR, and refusing it would block the first sync a project
// ever makes.
//
// Private repositories are refused — not because reading one is exposure (it is
// not), but because a pre-PR whose base is private is incoherent: the diff a
// human approves must be measured against the repository the change will
// actually land in.
func (r *baseResolver) ReadBase(request workerrpc.BaseReadRequest) (workerrpc.BaseRead, error) {
	if request.Repository == "" || request.Branch == "" {
		return workerrpc.BaseRead{}, errors.New("base read requires a repository and branch")
	}
	visibility, err := r.visibility(request.Repository)
	if err != nil {
		return workerrpc.BaseRead{}, errors.New("base repository visibility is unknown")
	}
	if visibility != "public" {
		return workerrpc.BaseRead{}, errors.New("a pre-PR base must be a public repository")
	}
	subject := strconv.FormatInt(r.installationID, 10)

	commitSHA, err := r.reader.ReadBranchHead(request.Repository, request.Branch, subject)
	switch {
	case errors.Is(err, githubapp.ErrGitHubNotFound), errors.Is(err, githubapp.ErrGitHubRepositoryEmpty):
		return workerrpc.BaseRead{Empty: true}, nil
	case err != nil:
		return workerrpc.BaseRead{}, err
	}
	treeSHA, err := r.reader.ReadCommitTree(request.Repository, commitSHA, subject)
	if err != nil {
		return workerrpc.BaseRead{}, err
	}
	entries, err := r.reader.ReadTree(request.Repository, treeSHA, subject)
	if err != nil {
		return workerrpc.BaseRead{}, err
	}
	return workerrpc.BaseRead{CommitSHA: commitSHA, TreeSHA: treeSHA, Entries: entries}, nil
}

// ReadBlob fetches one object's content from a public repository, verifying the
// returned hash against the requested SHA.
func (r *baseResolver) ReadBlob(repository, sha string) ([]byte, error) {
	if repository == "" || sha == "" {
		return nil, errors.New("blob read requires a repository and sha")
	}
	visibility, err := r.visibility(repository)
	if err != nil || visibility != "public" {
		return nil, errors.New("a pre-PR base must be a public repository")
	}
	return r.reader.ReadBlob(repository, sha, strconv.FormatInt(r.installationID, 10))
}
