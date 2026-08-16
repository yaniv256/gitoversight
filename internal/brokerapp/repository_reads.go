package brokerapp

import (
	"context"
	"errors"
	"math"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrRepositoryReadInvalid   = errors.New("repository read request is invalid")
	ErrRepositoryReadDenied    = errors.New("repository read is outside the caller scope")
	ErrRepositoryReadLimit     = errors.New("repository read exceeds a configured limit")
	ErrRepositoryReadBinding   = errors.New("repository read backend returned mismatched metadata")
	ErrRepositoryReadStaleBase = errors.New("repository snapshot base is stale")
	ErrRepositoryReadBackend   = errors.New("repository read backend unavailable")
)

const (
	UntrustedRepositoryContent = "untrusted_repository_content"
	defaultMaxSearchResults    = 10
	maximumMaxSearchResults    = 50
	defaultMaxQueryBytes       = 512
	defaultMaxSnapshotBytes    = int64(64 << 20)
	defaultMaxSnapshotTTL      = 5 * time.Minute
	maxRepositoryTextBytes     = 4096
	maxRepositoryNameBytes     = 256
	maxRepositoryPathBytes     = 4096
	maxRepositoryURLBytes      = 2048
	maxReadableRepositories    = 4096
)

// RepositoryReadScope is supplied by the caller adapter. Its implementation
// must intersect the authenticated tenant/agent grant with current policy.
// The service never accepts a caller-provided list of readable repositories.
type RepositoryReadScope interface {
	ReadableRepositories(context.Context, Identity) ([]string, error)
	AuthorizeRepositoryRead(context.Context, Identity, string) error
}

// RepositoryReadBackend supplies repository projections and one-time snapshot
// metadata. It must not perform a GitHub mutation. Search receives only the
// already-authorized repository set and every returned hit is re-authorized.
type RepositoryReadBackend interface {
	Inspect(context.Context, Identity, string) (RepositoryReadMetadata, error)
	Search(context.Context, Identity, []string, string, int) ([]RepositorySearchHit, error)
	CurrentBase(context.Context, Identity, string, string) (RepositoryBase, error)
	IssueSnapshot(context.Context, Identity, string, RepositoryBase, int64) (SnapshotDownload, error)
}

type RepositoryReadConfig struct {
	MaxSearchResults int
	MaxQueryBytes    int
	MaxSnapshotBytes int64
	MaxSnapshotTTL   time.Duration
	Now              func() time.Time
}

type RepositoryReadMetadata struct {
	Repository    string
	Visibility    string
	DefaultBranch string
	Description   string
	HTMLURL       string
	ContentTrust  string
}

type RepositorySearchRequest struct {
	Query        string
	Limit        int
	Repositories []string
}

type RepositorySearchHit struct {
	Repository   string
	Path         string
	Snippet      string
	Score        float64
	ContentTrust string
}

type RepositorySearchResult struct {
	Query string
	Limit int
	Hits  []RepositorySearchHit
}

type RepositoryBase struct {
	Repository string
	Ref        string
	CommitSHA  string
	TreeSHA    string
}

type SnapshotRequest struct {
	Repository     string
	Ref            string
	ExactCommitSHA string
}

// SnapshotDownload is intentionally metadata, not repository bytes. The
// backend owns redemption and must make DownloadURL single-use and bounded by
// MaxBytes. Base binds the download to the exact commit and tree inspected.
type SnapshotDownload struct {
	Repository   string
	Base         RepositoryBase
	DownloadURL  string
	SHA256       string
	ExpiresAt    time.Time
	MaxBytes     int64
	OneTime      bool
	ContentTrust string
}

type RepositoryReadService struct {
	scope            RepositoryReadScope
	backend          RepositoryReadBackend
	maxSearchResults int
	maxQueryBytes    int
	maxSnapshotBytes int64
	maxSnapshotTTL   time.Duration
	now              func() time.Time
}

func NewRepositoryReadService(scope RepositoryReadScope, backend RepositoryReadBackend, config RepositoryReadConfig) *RepositoryReadService {
	maxResults := config.MaxSearchResults
	if maxResults <= 0 {
		maxResults = defaultMaxSearchResults
	}
	if maxResults > maximumMaxSearchResults {
		maxResults = maximumMaxSearchResults
	}
	maxQueryBytes := config.MaxQueryBytes
	if maxQueryBytes <= 0 {
		maxQueryBytes = defaultMaxQueryBytes
	}
	maxSnapshotBytes := config.MaxSnapshotBytes
	if maxSnapshotBytes <= 0 {
		maxSnapshotBytes = defaultMaxSnapshotBytes
	}
	maxSnapshotTTL := config.MaxSnapshotTTL
	if maxSnapshotTTL <= 0 {
		maxSnapshotTTL = defaultMaxSnapshotTTL
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &RepositoryReadService{scope: scope, backend: backend, maxSearchResults: maxResults, maxQueryBytes: maxQueryBytes, maxSnapshotBytes: maxSnapshotBytes, maxSnapshotTTL: maxSnapshotTTL, now: now}
}

func (service *RepositoryReadService) Inspect(ctx context.Context, identity Identity, repository string) (RepositoryReadMetadata, error) {
	if err := service.authorize(ctx, identity, repository); err != nil {
		return RepositoryReadMetadata{}, err
	}
	metadata, err := service.backend.Inspect(ctx, identity, repository)
	if err != nil {
		return RepositoryReadMetadata{}, errors.Join(ErrRepositoryReadBackend, err)
	}
	if metadata.Repository != repository || !validMetadata(metadata) {
		return RepositoryReadMetadata{}, ErrRepositoryReadBinding
	}
	metadata.ContentTrust = UntrustedRepositoryContent
	return metadata, nil
}

func (service *RepositoryReadService) Search(ctx context.Context, identity Identity, request RepositorySearchRequest) (RepositorySearchResult, error) {
	if err := validIdentity(identity); err != nil || strings.TrimSpace(request.Query) == "" || !utf8.ValidString(request.Query) {
		return RepositorySearchResult{}, ErrRepositoryReadInvalid
	}
	if len(request.Query) > service.maxQueryBytes {
		return RepositorySearchResult{}, ErrRepositoryReadLimit
	}
	if service.scope == nil || service.backend == nil {
		return RepositorySearchResult{}, ErrRepositoryReadBackend
	}
	repositories := request.Repositories
	if len(repositories) > maxReadableRepositories {
		return RepositorySearchResult{}, ErrRepositoryReadLimit
	}
	repositories, ok := canonicalRepositories(repositories)
	if !ok {
		return RepositorySearchResult{}, ErrRepositoryReadBinding
	}
	for _, repository := range repositories {
		if err := service.scope.AuthorizeRepositoryRead(ctx, identity, repository); err != nil {
			return RepositorySearchResult{}, errors.Join(ErrRepositoryReadDenied, err)
		}
	}
	limit := request.Limit
	if limit <= 0 || limit > service.maxSearchResults {
		limit = service.maxSearchResults
	}
	hits, err := service.backend.Search(ctx, identity, repositories, request.Query, limit)
	if err != nil {
		return RepositorySearchResult{}, errors.Join(ErrRepositoryReadBackend, err)
	}
	if len(hits) > limit {
		return RepositorySearchResult{}, ErrRepositoryReadBinding
	}
	for index := range hits {
		hit := &hits[index]
		if !validRepository(hit.Repository) || !validResultPath(hit.Path) || len(hit.Snippet) > maxRepositoryTextBytes || !utf8.ValidString(hit.Snippet) || math.IsNaN(hit.Score) || math.IsInf(hit.Score, 0) || hit.Score < 0 || hit.Score > 1 {
			return RepositorySearchResult{}, ErrRepositoryReadBinding
		}
		if err := service.scope.AuthorizeRepositoryRead(ctx, identity, hit.Repository); err != nil {
			return RepositorySearchResult{}, ErrRepositoryReadBinding
		}
		hit.ContentTrust = UntrustedRepositoryContent
	}
	return RepositorySearchResult{Query: request.Query, Limit: limit, Hits: hits}, nil
}

func (service *RepositoryReadService) Snapshot(ctx context.Context, identity Identity, request SnapshotRequest) (SnapshotDownload, error) {
	if err := service.authorize(ctx, identity, request.Repository); err != nil {
		return SnapshotDownload{}, err
	}
	if !validRef(request.Ref) || !validObjectID(request.ExactCommitSHA) {
		return SnapshotDownload{}, ErrRepositoryReadInvalid
	}
	base, err := service.backend.CurrentBase(ctx, identity, request.Repository, request.Ref)
	if err != nil {
		return SnapshotDownload{}, errors.Join(ErrRepositoryReadBackend, err)
	}
	if !validBase(base) || base.Repository != request.Repository || base.Ref != request.Ref {
		return SnapshotDownload{}, ErrRepositoryReadBinding
	}
	if base.CommitSHA != request.ExactCommitSHA {
		return SnapshotDownload{}, ErrRepositoryReadStaleBase
	}
	download, err := service.backend.IssueSnapshot(ctx, identity, request.Repository, base, service.maxSnapshotBytes)
	if err != nil {
		return SnapshotDownload{}, errors.Join(ErrRepositoryReadBackend, err)
	}
	if !service.validDownload(download, base) {
		return SnapshotDownload{}, ErrRepositoryReadBinding
	}
	download.ContentTrust = UntrustedRepositoryContent
	return download, nil
}

func (service *RepositoryReadService) authorize(ctx context.Context, identity Identity, repository string) error {
	if err := validIdentity(identity); err != nil || !validRepository(repository) {
		return ErrRepositoryReadInvalid
	}
	if service.scope == nil || service.backend == nil {
		return ErrRepositoryReadBackend
	}
	if err := service.scope.AuthorizeRepositoryRead(ctx, identity, repository); err != nil {
		return errors.Join(ErrRepositoryReadDenied, err)
	}
	return nil
}

func (service *RepositoryReadService) validDownload(download SnapshotDownload, base RepositoryBase) bool {
	now := service.now().UTC()
	parsed, err := url.Parse(download.DownloadURL)
	return len(download.DownloadURL) <= maxRepositoryURLBytes && err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Fragment == "" &&
		download.Repository == base.Repository && download.Base == base && download.OneTime && validSHA256(download.SHA256) &&
		download.MaxBytes > 0 && download.MaxBytes <= service.maxSnapshotBytes &&
		download.ExpiresAt.After(now) && !download.ExpiresAt.After(now.Add(service.maxSnapshotTTL))
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func validIdentity(identity Identity) error {
	if strings.TrimSpace(identity.TenantID) == "" || strings.TrimSpace(identity.AgentID) == "" {
		return ErrRepositoryReadInvalid
	}
	return nil
}

func validRepository(repository string) bool {
	parts := strings.Split(repository, "/")
	return len(repository) <= maxRepositoryNameBytes && len(parts) == 2 && parts[0] != "" && parts[1] != "" && repository == strings.TrimSpace(repository) && !strings.ContainsAny(repository, "*?[]\\\x00") && !strings.Contains(repository, "..")
}

func canonicalRepositories(repositories []string) ([]string, bool) {
	result := append([]string(nil), repositories...)
	sort.Strings(result)
	for index, repository := range result {
		if !validRepository(repository) || index > 0 && repository == result[index-1] {
			return nil, false
		}
	}
	return result, true
}

func validMetadata(metadata RepositoryReadMetadata) bool {
	return validRepository(metadata.Repository) && (metadata.Visibility == "private" || metadata.Visibility == "public") &&
		len(metadata.DefaultBranch) <= 255 && len(metadata.Description) <= maxRepositoryTextBytes &&
		len(metadata.HTMLURL) <= maxRepositoryURLBytes && utf8.ValidString(metadata.DefaultBranch) &&
		utf8.ValidString(metadata.Description) && utf8.ValidString(metadata.HTMLURL)
}

func validObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func validRef(ref string) bool {
	return strings.HasPrefix(ref, "refs/") && len(ref) <= 1024 && !strings.ContainsAny(ref, " ~^:?*[\\\x00") && !strings.Contains(ref, "..") && !strings.HasSuffix(ref, "/")
}

func validBase(base RepositoryBase) bool {
	return validRepository(base.Repository) && validRef(base.Ref) && validObjectID(base.CommitSHA) && validObjectID(base.TreeSHA)
}

func validResultPath(value string) bool {
	return value != "" && len(value) <= maxRepositoryPathBytes && value == path.Clean(value) && !strings.HasPrefix(value, "/") && value != "." && !strings.HasPrefix(value, "../") && !strings.Contains(value, "\\") && utf8.ValidString(value)
}
