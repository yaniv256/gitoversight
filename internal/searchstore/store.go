// Package searchstore is a self-contained sqlite store for the repo-search
// dataset. It lives in its own database file, separate from the governance
// authority DB: everything in it is a rebuildable cache of upstream GitHub
// state plus derived search artifacts (FTS index, quantized vectors).
package searchstore

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const CurrentSchemaVersion = 1

// ErrNotExist is returned by OpenReadOnly when the database file does not
// exist yet. Callers lazily open the store and treat this as "no corpus
// built yet" rather than a failure.
var ErrNotExist = errors.New("searchstore: database file does not exist")

// ErrSchemaMismatch is returned by OpenReadOnly when the on-disk schema
// version does not match this build. Like ErrNotExist it means "the index
// for this build is not there yet" and resolves on the next sync, so
// IndexNotBuilt treats both as the not-built state.
var ErrSchemaMismatch = errors.New("searchstore: schema version does not match current build")

// timeFormat is the canonical encoding for timestamps stored as TEXT
// (tombstoned_at). RFC3339 at second precision in UTC compares correctly as
// a plain string, which PurgeTombstonedBefore relies on.
const timeFormat = time.RFC3339

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct {
	sql *sql.DB
}

// Repo is one row of the repos table. An empty TombstonedAt means live.
type Repo struct {
	FullName      string
	Description   string
	HTMLURL       string
	DefaultBranch string
	PushedAt      string
	ReadmeSHA     string
	ReadmeText    string
	TombstonedAt  string
}

// Pull is one row of the repo_pulls table. FullName is populated on reads;
// on ReplacePulls it is taken from the fullName argument.
type Pull struct {
	FullName string
	Number   int
	Title    string
	Author   string
	HTMLURL  string
	HeadRef  string
}

// TokenVector is a quantized token embedding with its inverse document
// frequency weight.
type TokenVector struct {
	Vector []byte
	IDF    float64
}

// Open creates (if needed) and migrates the search database at path.
//
// The directory is created with mode 0o750 — deliberately NOT the 0o700 used
// by the authority DB: a second OS user in a shared group reads this database
// cross-process via WAL and needs group traversal into the directory (the
// -wal and -shm sidecar files live next to the main file).
func Open(ctx context.Context, path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("searchstore: path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create searchstore directory: %w", err)
	}
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(FULL)&_pragma=foreign_keys(1)"
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open searchstore: %w", err)
	}
	conn.SetMaxOpenConns(8)
	store := &Store{sql: conn}
	if err := store.migrate(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return store, nil
}

// OpenReadOnly opens an existing search database without creating one. When
// the file does not exist it returns an error wrapping ErrNotExist so that
// lazy-opening callers can distinguish "not built yet" from real failures.
func OpenReadOnly(ctx context.Context, path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("searchstore: path is required")
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("searchstore %q: %w", path, ErrNotExist)
		}
		return nil, fmt.Errorf("stat searchstore: %w", err)
	}
	// No journal_mode/synchronous pragmas: those are writer concerns and a
	// read-only connection cannot change the journal mode anyway.
	dsn := "file:" + path + "?mode=ro&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open searchstore read-only: %w", err)
	}
	conn.SetMaxOpenConns(8)
	store := &Store{sql: conn}
	var version int
	if err := conn.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read searchstore schema version: %w", err)
	}
	if version != CurrentSchemaVersion {
		_ = conn.Close()
		return nil, fmt.Errorf("searchstore schema version %d does not match current %d: %w", version, CurrentSchemaVersion, ErrSchemaMismatch)
	}
	return store, nil
}

func (s *Store) Close() error { return s.sql.Close() }

// migrate applies embedded migrations one step at a time, each in its own
// transaction, gated by PRAGMA user_version — the same pattern as
// internal/storage/sqlite.
func (s *Store) migrate(ctx context.Context) error {
	entries, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	sort.Strings(entries)
	var current int
	if err := s.sql.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&current); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	for _, name := range entries {
		base := filepath.Base(name)
		prefix, _, ok := strings.Cut(base, "_")
		if !ok {
			return fmt.Errorf("migration %q has no numeric prefix", base)
		}
		version, err := strconv.Atoi(prefix)
		if err != nil {
			return fmt.Errorf("migration %q: %w", base, err)
		}
		if version <= current {
			continue
		}
		if version != current+1 {
			return fmt.Errorf("migration gap: have %d, next is %d", current, version)
		}
		payload, err := migrations.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read migration %q: %w", base, err)
		}
		tx, err := s.sql.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %q: %w", base, err)
		}
		if _, err := tx.ExecContext(ctx, string(payload)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %q: %w", base, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", version)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %q: %w", base, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %q: %w", base, err)
		}
		current = version
	}
	if current != CurrentSchemaVersion {
		return fmt.Errorf("schema version %d does not match current %d", current, CurrentSchemaVersion)
	}
	return nil
}

func (s *Store) withTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// UpsertRepo writes the repo row and refreshes its FTS entry. Upserting a
// repo marks it live: any previous tombstone is cleared (the repo evidently
// exists upstream again). The caller's TombstonedAt field is ignored.
func (s *Store) UpsertRepo(ctx context.Context, repo Repo) error {
	if strings.TrimSpace(repo.FullName) == "" {
		return errors.New("searchstore: repo full_name is required")
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO repos (full_name, description, html_url, default_branch, pushed_at, readme_sha, readme_text, tombstoned_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, '')
			ON CONFLICT(full_name) DO UPDATE SET
				description = excluded.description,
				html_url = excluded.html_url,
				default_branch = excluded.default_branch,
				pushed_at = excluded.pushed_at,
				readme_sha = excluded.readme_sha,
				readme_text = excluded.readme_text,
				tombstoned_at = ''`,
			repo.FullName, repo.Description, repo.HTMLURL, repo.DefaultBranch,
			repo.PushedAt, repo.ReadmeSHA, repo.ReadmeText); err != nil {
			return fmt.Errorf("upsert repo %q: %w", repo.FullName, err)
		}
		// repos_fts is a regular FTS5 table (see 001_initial.sql), so a
		// refresh is a plain delete + insert keyed by full_name.
		if _, err := tx.ExecContext(ctx, `DELETE FROM repos_fts WHERE full_name = ?`, repo.FullName); err != nil {
			return fmt.Errorf("clear fts row %q: %w", repo.FullName, err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO repos_fts (full_name, description, readme_text) VALUES (?, ?, ?)`,
			repo.FullName, repo.Description, repo.ReadmeText); err != nil {
			return fmt.Errorf("index fts row %q: %w", repo.FullName, err)
		}
		return nil
	})
}

const repoColumns = `full_name, description, html_url, default_branch, pushed_at, readme_sha, readme_text, tombstoned_at`

func scanRepo(row interface{ Scan(...any) error }) (Repo, error) {
	var repo Repo
	err := row.Scan(&repo.FullName, &repo.Description, &repo.HTMLURL, &repo.DefaultBranch,
		&repo.PushedAt, &repo.ReadmeSHA, &repo.ReadmeText, &repo.TombstonedAt)
	return repo, err
}

// GetRepo returns the repo row (tombstoned or not) and whether it exists.
func (s *Store) GetRepo(ctx context.Context, fullName string) (Repo, bool, error) {
	repo, err := scanRepo(s.sql.QueryRowContext(ctx,
		`SELECT `+repoColumns+` FROM repos WHERE full_name = ?`, fullName))
	if errors.Is(err, sql.ErrNoRows) {
		return Repo{}, false, nil
	}
	if err != nil {
		return Repo{}, false, fmt.Errorf("get repo %q: %w", fullName, err)
	}
	return repo, true, nil
}

// ListRepos returns repos ordered by full_name. With includeTombstoned false
// only live rows are returned.
func (s *Store) ListRepos(ctx context.Context, includeTombstoned bool) ([]Repo, error) {
	query := `SELECT ` + repoColumns + ` FROM repos`
	if !includeTombstoned {
		query += ` WHERE tombstoned_at = ''`
	}
	query += ` ORDER BY full_name`
	rows, err := s.sql.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list repos: %w", err)
	}
	defer rows.Close()
	var repos []Repo
	for rows.Next() {
		repo, err := scanRepo(rows)
		if err != nil {
			return nil, fmt.Errorf("scan repo: %w", err)
		}
		repos = append(repos, repo)
	}
	return repos, rows.Err()
}

// TombstoneMissing marks every live repo NOT present in currentFullNames as
// tombstoned at now, and returns how many rows it marked. An empty list
// tombstones every live repo.
func (s *Store) TombstoneMissing(ctx context.Context, currentFullNames []string, now time.Time) (int64, error) {
	query := `UPDATE repos SET tombstoned_at = ? WHERE tombstoned_at = ''`
	args := []any{now.UTC().Format(timeFormat)}
	if len(currentFullNames) > 0 {
		query += ` AND full_name NOT IN (?` + strings.Repeat(",?", len(currentFullNames)-1) + `)`
		for _, name := range currentFullNames {
			args = append(args, name)
		}
	}
	result, err := s.sql.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("tombstone missing repos: %w", err)
	}
	return result.RowsAffected()
}

// PurgeTombstonedBefore permanently deletes repos tombstoned strictly before
// cutoff, along with their FTS rows, pulls, and node vectors. It returns the
// number of repos removed.
func (s *Store) PurgeTombstonedBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	var purged int64
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT full_name FROM repos WHERE tombstoned_at != '' AND tombstoned_at < ?`,
			cutoff.UTC().Format(timeFormat))
		if err != nil {
			return fmt.Errorf("find purgeable repos: %w", err)
		}
		var names []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return err
			}
			names = append(names, name)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, name := range names {
			for _, del := range []string{
				`DELETE FROM repos_fts WHERE full_name = ?`,
				`DELETE FROM repo_pulls WHERE full_name = ?`,
				`DELETE FROM node_vectors WHERE full_name = ?`,
				`DELETE FROM repos WHERE full_name = ?`,
			} {
				if _, err := tx.ExecContext(ctx, del, name); err != nil {
					return fmt.Errorf("purge %q: %w", name, err)
				}
			}
		}
		purged = int64(len(names))
		return nil
	})
	return purged, err
}

// ReplacePulls replaces the full set of open pulls recorded for fullName.
func (s *Store) ReplacePulls(ctx context.Context, fullName string, pulls []Pull) error {
	if strings.TrimSpace(fullName) == "" {
		return errors.New("searchstore: pulls full_name is required")
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM repo_pulls WHERE full_name = ?`, fullName); err != nil {
			return fmt.Errorf("clear pulls %q: %w", fullName, err)
		}
		for _, pull := range pulls {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO repo_pulls (full_name, number, title, author, html_url, head_ref)
				VALUES (?, ?, ?, ?, ?, ?)`,
				fullName, pull.Number, pull.Title, pull.Author, pull.HTMLURL, pull.HeadRef); err != nil {
				return fmt.Errorf("insert pull %q#%d: %w", fullName, pull.Number, err)
			}
		}
		return nil
	})
}

func (s *Store) listPulls(ctx context.Context, query string, args ...any) ([]Pull, error) {
	rows, err := s.sql.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list pulls: %w", err)
	}
	defer rows.Close()
	var pulls []Pull
	for rows.Next() {
		var pull Pull
		if err := rows.Scan(&pull.FullName, &pull.Number, &pull.Title, &pull.Author, &pull.HTMLURL, &pull.HeadRef); err != nil {
			return nil, fmt.Errorf("scan pull: %w", err)
		}
		pulls = append(pulls, pull)
	}
	return pulls, rows.Err()
}

// ListPulls returns the pulls recorded for fullName ordered by number.
func (s *Store) ListPulls(ctx context.Context, fullName string) ([]Pull, error) {
	return s.listPulls(ctx, `
		SELECT full_name, number, title, author, html_url, head_ref
		FROM repo_pulls WHERE full_name = ? ORDER BY number`, fullName)
}

// ListAllPulls returns every recorded pull ordered by (full_name, number).
func (s *Store) ListAllPulls(ctx context.Context) ([]Pull, error) {
	return s.listPulls(ctx, `
		SELECT full_name, number, title, author, html_url, head_ref
		FROM repo_pulls ORDER BY full_name, number`)
}

// FTSSearch runs a full-text query built ONLY from the caller-provided
// tokens: each token has embedded double quotes stripped, is wrapped in
// double quotes (making it an FTS5 phrase string, immune to query-syntax
// injection such as `OR`, `NEAR(`, `col:` or `*`), and the phrases are
// joined with OR. Tombstoned repos are excluded. Results are ordered by
// FTS5 rank (best first) and truncated to limit.
func (s *Store) FTSSearch(ctx context.Context, tokens []string, limit int) ([]Repo, error) {
	var phrases []string
	for _, token := range tokens {
		clean := strings.TrimSpace(strings.ReplaceAll(token, `"`, ""))
		if clean == "" {
			continue
		}
		phrases = append(phrases, `"`+clean+`"`)
	}
	if len(phrases) == 0 || limit <= 0 {
		return nil, nil
	}
	match := strings.Join(phrases, " OR ")
	rows, err := s.sql.QueryContext(ctx, `
		SELECT r.full_name, r.description, r.html_url, r.default_branch, r.pushed_at, r.readme_sha, r.readme_text, r.tombstoned_at
		FROM repos_fts
		JOIN repos r ON r.full_name = repos_fts.full_name
		WHERE repos_fts MATCH ? AND r.tombstoned_at = ''
		ORDER BY repos_fts.rank
		LIMIT ?`, match, limit)
	if err != nil {
		return nil, fmt.Errorf("fts search: %w", err)
	}
	defer rows.Close()
	var repos []Repo
	for rows.Next() {
		repo, err := scanRepo(rows)
		if err != nil {
			return nil, fmt.Errorf("scan fts hit: %w", err)
		}
		repos = append(repos, repo)
	}
	return repos, rows.Err()
}

// ReplaceVectors replaces the entire node-vector corpus in one transaction.
func (s *Store) ReplaceVectors(ctx context.Context, vectors map[string][]byte) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM node_vectors`); err != nil {
			return fmt.Errorf("clear node vectors: %w", err)
		}
		for fullName, vector := range vectors {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO node_vectors (full_name, vector) VALUES (?, ?)`, fullName, vector); err != nil {
				return fmt.Errorf("insert node vector %q: %w", fullName, err)
			}
		}
		return nil
	})
}

// IterateVectors calls fn for every stored node vector. Returning an error
// from fn stops the iteration and propagates the error.
func (s *Store) IterateVectors(ctx context.Context, fn func(fullName string, vector []byte) error) error {
	rows, err := s.sql.QueryContext(ctx, `SELECT full_name, vector FROM node_vectors ORDER BY full_name`)
	if err != nil {
		return fmt.Errorf("iterate node vectors: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var fullName string
		var vector []byte
		if err := rows.Scan(&fullName, &vector); err != nil {
			return fmt.Errorf("scan node vector: %w", err)
		}
		if err := fn(fullName, vector); err != nil {
			return err
		}
	}
	return rows.Err()
}

// ReplaceTokenVectors replaces the entire token-vector table in one
// transaction.
func (s *Store) ReplaceTokenVectors(ctx context.Context, vectors map[string]TokenVector) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM token_vectors`); err != nil {
			return fmt.Errorf("clear token vectors: %w", err)
		}
		for token, vector := range vectors {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO token_vectors (token, vector, idf) VALUES (?, ?, ?)`,
				token, vector.Vector, vector.IDF); err != nil {
				return fmt.Errorf("insert token vector %q: %w", token, err)
			}
		}
		return nil
	})
}

// GetTokenVector returns the vector for token and whether it exists.
func (s *Store) GetTokenVector(ctx context.Context, token string) (TokenVector, bool, error) {
	var vector TokenVector
	err := s.sql.QueryRowContext(ctx,
		`SELECT vector, idf FROM token_vectors WHERE token = ?`, token).Scan(&vector.Vector, &vector.IDF)
	if errors.Is(err, sql.ErrNoRows) {
		return TokenVector{}, false, nil
	}
	if err != nil {
		return TokenVector{}, false, fmt.Errorf("get token vector %q: %w", token, err)
	}
	return vector, true, nil
}

// SetMeta upserts a sync_meta key (e.g. last_sync timestamp, corpus
// generation).
func (s *Store) SetMeta(ctx context.Context, key, value string) error {
	_, err := s.sql.ExecContext(ctx, `
		INSERT INTO sync_meta (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	if err != nil {
		return fmt.Errorf("set meta %q: %w", key, err)
	}
	return nil
}

// GetMeta returns the value for key and whether it exists.
func (s *Store) GetMeta(ctx context.Context, key string) (string, bool, error) {
	var value string
	err := s.sql.QueryRowContext(ctx, `SELECT value FROM sync_meta WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("get meta %q: %w", key, err)
	}
	return value, true, nil
}
