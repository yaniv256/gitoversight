package api

import (
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/yaniv256/gitoversight.dev/internal/agentauth"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/searchembed"
	"github.com/yaniv256/gitoversight.dev/internal/searchstore"
)

const (
	searchDefaultLimit  = 10
	searchMaxLimit      = 50
	searchMaxQueryBytes = 512
	// searchLastSyncKey is the sync_meta key the sync job writes after each
	// dataset refresh (see internal/searchstore).
	searchLastSyncKey = "last_sync"
	// searchRankingCap asks searchembed.Query for effectively the FULL
	// ranking (the corpus is hundreds of repos). Ranking must not be
	// truncated before the policy filter runs: a bounded over-fetch lets
	// denied repos crowd allowed ones out of the candidate window, and the
	// window's cutoff doubles as a coarse existence oracle for repos the
	// caller cannot read.
	searchRankingCap = 10000
)

type SearchHandlerConfig struct {
	Policy policy.Snapshot
	// DBPath locates the searchstore database. The handler opens it lazily:
	// the file legitimately does not exist until the first sync run completes.
	DBPath string
}

// SearchHandler serves GET /v1/search: agent-authenticated semantic search
// over the repo dataset. Every candidate row is re-gated through the policy
// snapshot with repository.read — exactly the gate /v1/pulls applies — so an
// agent can never discover a repository it is not allowed to read.
type SearchHandler struct {
	policy policy.Snapshot
	reader *searchstore.LazyReader
}

func NewSearchHandler(config SearchHandlerConfig) (*SearchHandler, error) {
	if strings.TrimSpace(config.DBPath) == "" {
		return nil, errors.New("search handler configuration is incomplete")
	}
	if err := config.Policy.Validate(); err != nil {
		return nil, err
	}
	return &SearchHandler{policy: config.Policy, reader: searchstore.NewLazyReader(config.DBPath)}, nil
}

// SearchResult is one policy-visible search hit.
type SearchResult struct {
	FullName    string  `json:"full_name"`
	Description string  `json:"description"`
	Snippet     string  `json:"snippet"`
	Score       float64 `json:"score"`
	HTMLURL     string  `json:"html_url"`
	LastSynced  string  `json:"last_synced"`
}

func (handler *SearchHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || request.URL.Path != "/v1/search" {
		http.NotFound(response, request)
		return
	}
	identity, ok := agentauth.IdentityFromContext(request.Context())
	if !ok || identity.AgentID == "" {
		writeError(response, http.StatusUnauthorized, "agent_authentication_required")
		return
	}
	values := request.URL.Query()
	q := values.Get("q")
	if len(q) > searchMaxQueryBytes {
		writeError(response, http.StatusBadRequest, "query_exceeds_512_bytes")
		return
	}
	keywords := values["keyword"]
	hasKeyword := false
	for _, keyword := range keywords {
		if strings.TrimSpace(keyword) != "" {
			hasKeyword = true
			break
		}
	}
	if strings.TrimSpace(q) == "" && !hasKeyword {
		writeError(response, http.StatusBadRequest, "query_or_keyword_required")
		return
	}
	limit := searchDefaultLimit
	if raw := values.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			writeError(response, http.StatusBadRequest, "limit_must_be_a_positive_integer")
			return
		}
		limit = min(parsed, searchMaxLimit)
	}

	store, err := handler.reader.Open(request.Context())
	if searchstore.IndexNotBuilt(err) {
		writeJSON(response, http.StatusOK, map[string]string{"status": "index_not_built"})
		return
	}
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "search_unavailable")
		return
	}

	// Rank the full corpus (filter-before-truncate): the walk below applies
	// the policy filter and collects until `limit` allowed rows, so denied
	// repos can never crowd allowed ones out of a bounded candidate window.
	// The raw q never reaches FTS MATCH — searchembed.Query tokenizes it into
	// quoted phrase terms.
	ranked, err := searchembed.Query(store.EmbedIndex(request.Context()), q, keywords, searchRankingCap)
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "search_unavailable")
		return
	}
	lastSynced, _, err := store.GetMeta(request.Context(), searchLastSyncKey)
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "search_unavailable")
		return
	}
	results := make([]SearchResult, 0, limit)
	for _, hit := range ranked {
		if len(results) == limit {
			break
		}
		decision := policy.Evaluate(handler.policy, policy.Request{
			Caller: identity.AgentID, Repository: hit.FullName, Operation: "repository.read",
		})
		if decision.Code != policy.AllowedRead {
			continue // denied reads AND repos absent from policy
		}
		repo, found, err := store.GetRepo(request.Context(), hit.FullName)
		if err != nil {
			writeError(response, http.StatusServiceUnavailable, "search_unavailable")
			return
		}
		if !found || repo.TombstonedAt != "" {
			continue
		}
		results = append(results, SearchResult{
			FullName:    repo.FullName,
			Description: repo.Description,
			Snippet:     searchstore.Snippet(repo),
			// Rounded to 2 decimals to blunt differential score probing:
			// exact cosines leak more about unreadable neighbors than a
			// coarse relevance signal needs to.
			Score:      math.Round(hit.Score*100) / 100,
			HTMLURL:    repo.HTMLURL,
			LastSynced: lastSynced,
		})
	}
	response.Header().Set("Cache-Control", "no-store")
	writeJSON(response, http.StatusOK, map[string]any{"results": results})
}
