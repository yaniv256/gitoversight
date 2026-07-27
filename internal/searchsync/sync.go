// Package searchsync builds and refreshes the repo-search dataset: a periodic
// pass enumerates every repository visible to the configured GitHub App
// installations, mirrors metadata/READMEs/open-PR summaries into the
// searchstore, and rebuilds the embedding corpus when content changed.
//
// The pass is deliberately incremental: READMEs and pull summaries are only
// refetched for repositories whose pushed_at moved since the last pass (a
// README edit is a push, so pushed_at is a sound change signal), and the
// corpus is only rebuilt when searchable content actually changed.
package searchsync

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
	"github.com/yaniv256/gitoversight.dev/internal/searchembed"
	"github.com/yaniv256/gitoversight.dev/internal/searchstore"
)

const (
	defaultInterval           = time.Hour
	defaultCooldown           = 10 * time.Minute
	defaultTombstoneRetention = 7 * 24 * time.Hour
)

// Reader is the read-only GitHub view the syncer consumes. The production
// implementation is githubapp.Reader.
type Reader interface {
	ListInstallationRepositories(installationIDs []int64) ([]githubapp.RepoInfo, error)
	FetchReadme(repository string) (text, changeKey string, err error)
}

// PullLister returns the open pull requests of one repository, already shaped
// for the store. The production seam wraps githubapp.Client.ListPullRequests.
type PullLister func(repository string) ([]searchstore.Pull, error)

// CorpusBuilder trains the search corpus over the live documents. The
// production seam is searchembed.BuildCorpus.
type CorpusBuilder func([]searchembed.Document) *searchembed.Corpus

// Options configures a Syncer. Store, Reader, and Pulls are required;
// everything else has a default.
type Options struct {
	Store  *searchstore.Store
	Reader Reader
	Pulls  PullLister
	// BuildCorpus defaults to searchembed.BuildCorpus.
	BuildCorpus CorpusBuilder
	// Now defaults to time.Now.
	Now func() time.Time
	// Logf defaults to log.Printf.
	Logf func(format string, args ...any)
	// Interval is the periodic pass spacing (default 1h).
	Interval time.Duration
	// Cooldown is the minimum spacing a trigger keeps from the previous pass;
	// triggers inside the window coalesce into one delayed pass (default 10m).
	Cooldown time.Duration
	// TombstoneRetention is how long a tombstoned repo row survives before it
	// is purged (default 7 days).
	TombstoneRetention time.Duration
	// InstallationIDs are the GitHub App installations to enumerate.
	InstallationIDs []int64
	// ConfiguredRepoCount is the size of the worker's repositories map, logged
	// against the enumerated count so drift between the two is visible (A1).
	ConfiguredRepoCount int
}

type Syncer struct {
	store               *searchstore.Store
	reader              Reader
	pulls               PullLister
	buildCorpus         CorpusBuilder
	now                 func() time.Time
	logf                func(format string, args ...any)
	interval            time.Duration
	cooldown            time.Duration
	tombstoneRetention  time.Duration
	installationIDs     []int64
	configuredRepoCount int
	trigger             chan struct{}
}

func New(options Options) (*Syncer, error) {
	if options.Store == nil || options.Reader == nil || options.Pulls == nil {
		return nil, errors.New("searchsync: store, reader, and pull lister are required")
	}
	if len(options.InstallationIDs) == 0 {
		return nil, errors.New("searchsync: at least one installation id is required")
	}
	syncer := &Syncer{
		store:               options.Store,
		reader:              options.Reader,
		pulls:               options.Pulls,
		buildCorpus:         options.BuildCorpus,
		now:                 options.Now,
		logf:                options.Logf,
		interval:            options.Interval,
		cooldown:            options.Cooldown,
		tombstoneRetention:  options.TombstoneRetention,
		installationIDs:     append([]int64(nil), options.InstallationIDs...),
		configuredRepoCount: options.ConfiguredRepoCount,
		trigger:             make(chan struct{}, 1),
	}
	if syncer.buildCorpus == nil {
		syncer.buildCorpus = searchembed.BuildCorpus
	}
	if syncer.now == nil {
		syncer.now = time.Now
	}
	if syncer.logf == nil {
		syncer.logf = log.Printf
	}
	if syncer.interval <= 0 {
		syncer.interval = defaultInterval
	}
	if syncer.cooldown <= 0 {
		syncer.cooldown = defaultCooldown
	}
	if syncer.tombstoneRetention <= 0 {
		syncer.tombstoneRetention = defaultTombstoneRetention
	}
	return syncer, nil
}

// Trigger requests an on-demand pass. It never blocks: when a pass is already
// pending (running, queued, or waiting out the cooldown) the trigger coalesces
// into it.
func (s *Syncer) Trigger() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

// Run executes a startup pass, then loops on the periodic ticker and the
// on-demand trigger until ctx is cancelled. A trigger arriving within the
// cooldown window of the previous pass is delayed until the window closes;
// triggers arriving during a pass or during that delay coalesce into the one
// delayed pass.
func (s *Syncer) Run(ctx context.Context) {
	runPass := func() {
		if err := s.SyncOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			s.logf("searchsync: pass failed: %v", err)
		}
	}
	runPass()
	lastPass := s.now()
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runPass()
			lastPass = s.now()
		case <-s.trigger:
			if wait := s.cooldown - s.now().Sub(lastPass); wait > 0 {
				delay := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					delay.Stop()
					return
				case <-delay.C:
				}
			}
			// Coalesce any trigger that arrived while waiting or while the
			// previous pass ran: this pass serves them all.
			select {
			case <-s.trigger:
			default:
			}
			runPass()
			lastPass = s.now()
			// Drain a tick that queued while we waited out the cooldown or
			// ran the pass — without this, that stale tick would fire an
			// immediate second pass right after the triggered one. (No
			// deterministic test: time.Ticker cannot be driven by the
			// injectable clock, so this drain is covered by review + comment.)
			select {
			case <-ticker.C:
			default:
			}
		}
	}
}

// SyncOnce runs a single sync pass. On enumeration failure it aborts without
// touching the dataset. A per-repository README fetch failure is logged and
// skipped, keeping the previous pushed_at so the next pass retries it. A pull
// refresh failure is logged but still advances pushed_at — retrying it every
// pass would re-fetch the README over HTTP forever when the failure is
// persistent; the cached pulls simply stay stale until the next push.
func (s *Syncer) SyncOnce(ctx context.Context) error {
	started := s.now()
	repos, err := s.reader.ListInstallationRepositories(s.installationIDs)
	if err != nil {
		s.logf("searchsync: repository enumeration failed, dataset left intact: %v", err)
		return err
	}

	contentChanged := false
	readmeFetches := 0
	pullRefreshes := 0
	names := make([]string, 0, len(repos))
	for _, info := range repos {
		names = append(names, info.FullName)
		existing, exists, err := s.store.GetRepo(ctx, info.FullName)
		if err != nil {
			return err
		}
		pushedAt := info.PushedAt.UTC().Format(time.RFC3339)
		changed := !exists || existing.PushedAt != pushedAt
		row := searchstore.Repo{
			FullName:      info.FullName,
			Description:   info.Description,
			HTMLURL:       info.HTMLURL,
			DefaultBranch: info.DefaultBranch,
			PushedAt:      pushedAt,
			ReadmeSHA:     existing.ReadmeSHA,
			ReadmeText:    existing.ReadmeText,
		}
		if !exists || existing.Description != info.Description {
			contentChanged = true
		}
		if changed {
			text, changeKey, err := s.reader.FetchReadme(info.FullName)
			if err != nil {
				// Keep the previous pushed_at so the next pass retries both
				// the README and the pull refresh for this repository.
				s.logf("searchsync: readme fetch for %s failed, will retry next pass: %v", info.FullName, err)
				row.PushedAt = existing.PushedAt
				if err := s.store.UpsertRepo(ctx, row); err != nil {
					return err
				}
				continue
			}
			readmeFetches++
			if changeKey != existing.ReadmeSHA {
				row.ReadmeSHA = changeKey
				row.ReadmeText = text
				contentChanged = true
			}
			pulls, err := s.pulls(info.FullName)
			if err != nil {
				// Store the NEW pushed_at anyway. Holding it back would make
				// every subsequent pass re-detect change and re-fetch the
				// README over HTTP forever when the failure is persistent
				// (e.g. the repo is not in the installations map). The cached
				// pull chips just stay stale until the next push.
				s.logf("searchsync: pull refresh for %s failed, cached pulls stay stale until the next push: %v", info.FullName, err)
				if err := s.store.UpsertRepo(ctx, row); err != nil {
					return err
				}
				continue
			}
			pullRefreshes++
			if err := s.store.UpsertRepo(ctx, row); err != nil {
				return err
			}
			if err := s.store.ReplacePulls(ctx, info.FullName, pulls); err != nil {
				return err
			}
			continue
		}
		if err := s.store.UpsertRepo(ctx, row); err != nil {
			return err
		}
	}

	now := s.now().UTC()
	tombstoned, err := s.store.TombstoneMissing(ctx, names, now)
	if err != nil {
		return err
	}
	purged, err := s.store.PurgeTombstonedBefore(ctx, now.Add(-s.tombstoneRetention))
	if err != nil {
		return err
	}
	if tombstoned > 0 || purged > 0 {
		contentChanged = true
	}

	if contentChanged {
		if err := s.rebuildCorpus(ctx); err != nil {
			return err
		}
	}

	if err := s.store.SetMeta(ctx, "last_sync", now.Format(time.RFC3339)); err != nil {
		return err
	}
	s.logf("searchsync: pass complete enumerated=%d configured=%d readme_fetches=%d pull_refreshes=%d tombstoned=%d purged=%d corpus_rebuilt=%v elapsed=%s",
		len(repos), s.configuredRepoCount, readmeFetches, pullRefreshes, tombstoned, purged, contentChanged, s.now().Sub(started))
	return nil
}

func (s *Syncer) rebuildCorpus(ctx context.Context) error {
	live, err := s.store.ListRepos(ctx, false)
	if err != nil {
		return err
	}
	documents := make([]searchembed.Document, 0, len(live))
	for _, repo := range live {
		documents = append(documents, searchembed.NewDocument(repo.FullName, repo.FullName, repo.Description, repo.ReadmeText))
	}
	corpus := s.buildCorpus(documents)
	tokens := make(map[string]searchstore.TokenVector, len(corpus.Tokens))
	for token, entry := range corpus.Tokens {
		tokens[token] = searchstore.TokenVector{Vector: entry.Vector, IDF: entry.IDF}
	}
	if err := s.store.ReplaceTokenVectors(ctx, tokens); err != nil {
		return err
	}
	return s.store.ReplaceVectors(ctx, corpus.Docs)
}
