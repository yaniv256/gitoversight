package sqlite

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
	"sync"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/storage"
	_ "modernc.org/sqlite"
)

const CurrentSchemaVersion = 24

// PRAGMA integrity_check scans the whole database file, which takes multiple
// seconds on a large production database — far over the readiness endpoint's
// per-check budget (production flap, 2026-07-22: 283MB database, 2s check
// timeout, cold page cache → "context deadline exceeded"). Integrity is
// therefore proven synchronously at Open, refreshed in the background, and
// Readiness reports the cached result bounded by maxIntegrityAge.
const (
	integrityRefreshInterval = 10 * time.Minute
	integrityCheckTimeout    = 3 * time.Minute
	maxIntegrityAge          = time.Hour
)

var MinimumSQLiteVersion = mustVersion("3.51.3")

//go:embed migrations/*.sql
var migrations embed.FS

type Config struct {
	Path string
}

type DB struct {
	sql *sql.DB

	integrityMu sync.RWMutex
	integrityOK bool
	integrityAt time.Time

	refreshStop chan struct{}
	refreshDone chan struct{}
}

type Readiness struct {
	SQLiteVersion Version
	SchemaVersion int
	JournalMode   string
	Synchronous   string
	ForeignKeys   bool
	IntegrityOK   bool
}

func Open(ctx context.Context, config Config) (*DB, error) {
	if strings.TrimSpace(config.Path) == "" {
		return nil, errors.New("sqlite path is required")
	}
	if err := os.MkdirAll(filepath.Dir(config.Path), 0o700); err != nil {
		return nil, fmt.Errorf("create sqlite directory: %w", err)
	}
	// _txlock=immediate makes every transaction BEGIN IMMEDIATE rather than
	// BEGIN DEFERRED. A deferred transaction starts as a reader and upgrades to
	// a writer on its first write; SQLite refuses that upgrade with SQLITE_BUSY
	// *immediately* rather than honouring busy_timeout, because waiting on an
	// upgrade can deadlock. Taking the write lock up front means busy_timeout
	// actually applies and concurrent writers queue instead of failing.
	//
	// This matters most on the execution-grant path: two workers racing for one
	// grant must produce exactly one winner and one clean rejection. Under
	// DEFERRED the winner could execute its GitHub mutation and then lose the
	// finalize to SQLITE_BUSY — leaving the operation indeterminate and needing
	// manual reconciliation, with the caller told it failed.
	dsn := "file:" + config.Path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=busy_timeout(5000)&_txlock=immediate"
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	conn.SetMaxOpenConns(8)
	db := &DB{sql: conn, refreshStop: make(chan struct{}), refreshDone: make(chan struct{})}
	if err := db.initialize(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	go db.refreshIntegrity()
	return db, nil
}

// runIntegrityCheck executes the full-file integrity scan under its own
// generous timeout and records the result in the cache.
func (db *DB) runIntegrityCheck(ctx context.Context) error {
	checkCtx, cancel := context.WithTimeout(ctx, integrityCheckTimeout)
	defer cancel()
	var integrity string
	if err := db.sql.QueryRowContext(checkCtx, `PRAGMA integrity_check`).Scan(&integrity); err != nil {
		return fmt.Errorf("sqlite integrity check: %w", err)
	}
	db.integrityMu.Lock()
	db.integrityOK = integrity == "ok"
	db.integrityAt = time.Now()
	db.integrityMu.Unlock()
	if integrity != "ok" {
		return fmt.Errorf("sqlite integrity check failed: %s", integrity)
	}
	return nil
}

func (db *DB) refreshIntegrity() {
	defer close(db.refreshDone)
	ticker := time.NewTicker(integrityRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-db.refreshStop:
			return
		case <-ticker.C:
			// A failed refresh keeps the previous cached result; Readiness
			// fails on its own once the cache exceeds maxIntegrityAge.
			_ = db.runIntegrityCheck(context.Background())
		}
	}
}

func (db *DB) initialize(ctx context.Context) error {
	var rawVersion string
	if err := db.sql.QueryRowContext(ctx, `SELECT sqlite_version()`).Scan(&rawVersion); err != nil {
		return fmt.Errorf("read sqlite version: %w", err)
	}
	version, err := ParseVersion(rawVersion)
	if err != nil {
		return err
	}
	if version.LessThan(MinimumSQLiteVersion) {
		return fmt.Errorf("sqlite runtime %s is older than required %s", version, MinimumSQLiteVersion)
	}
	if err := db.migrate(ctx); err != nil {
		return err
	}
	// Prove integrity synchronously before the database is handed out —
	// startup can afford the full scan that the readiness poll cannot.
	if err := db.runIntegrityCheck(ctx); err != nil {
		return err
	}
	_, err = db.Readiness(ctx)
	return err
}

func (db *DB) migrate(ctx context.Context) error {
	entries, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	sort.Strings(entries)
	var current int
	if err := db.sql.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&current); err != nil {
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
		tx, err := db.sql.BeginTx(ctx, nil)
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

func (db *DB) WithTx(ctx context.Context, fn func(*Tx) error) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	wrapper := &Tx{tx: tx}
	if err := fn(wrapper); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (db *DB) Readiness(ctx context.Context) (Readiness, error) {
	var rawVersion, journalMode string
	var schemaVersion, synchronous, foreignKeys int
	queries := []struct {
		query string
		dest  any
	}{
		{`SELECT sqlite_version()`, &rawVersion},
		{`PRAGMA user_version`, &schemaVersion},
		{`PRAGMA journal_mode`, &journalMode},
		{`PRAGMA synchronous`, &synchronous},
		{`PRAGMA foreign_keys`, &foreignKeys},
	}
	// All reads run on ONE dedicated connection: pragma values (foreign_keys,
	// synchronous) are per-connection, and sampling a different pooled
	// connection per query produced intermittent false negatives in production
	// (readyz sqlite flaps, 2026-07-22) — a long-lived pool can hold a
	// connection whose reads disagree with every other connection while fresh
	// pools read clean.
	conn, err := db.sql.Conn(ctx)
	if err != nil {
		return Readiness{}, err
	}
	defer conn.Close()
	for _, query := range queries {
		if err := conn.QueryRowContext(ctx, query.query).Scan(query.dest); err != nil {
			return Readiness{}, err
		}
	}
	version, err := ParseVersion(rawVersion)
	if err != nil {
		return Readiness{}, err
	}
	// Integrity is the cached background-check result: the full-file scan is
	// far over this call's budget on a large database (see the constants
	// above). Staleness beyond maxIntegrityAge fails readiness so a wedged
	// refresher cannot silently turn the proof into a fiction.
	db.integrityMu.RLock()
	integrityOK, integrityAt := db.integrityOK, db.integrityAt
	db.integrityMu.RUnlock()
	integrityFresh := time.Since(integrityAt) <= maxIntegrityAge
	status := Readiness{
		SQLiteVersion: version, SchemaVersion: schemaVersion, JournalMode: strings.ToLower(journalMode),
		Synchronous: synchronousName(synchronous), ForeignKeys: foreignKeys == 1, IntegrityOK: integrityOK && integrityFresh,
	}
	if status.SchemaVersion != CurrentSchemaVersion || status.JournalMode != "wal" || status.Synchronous != "full" || !status.ForeignKeys || !status.IntegrityOK {
		return status, fmt.Errorf("sqlite readiness failed: %+v (integrity checked %s ago)", status, time.Since(integrityAt).Round(time.Second))
	}
	return status, nil
}

func (db *DB) Backup(ctx context.Context, destination string) error {
	if strings.TrimSpace(destination) == "" {
		return errors.New("backup destination is required")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(destination); err == nil {
		return errors.New("backup destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := db.sql.ExecContext(ctx, `VACUUM INTO ?`, destination); err != nil {
		return fmt.Errorf("sqlite backup: %w", err)
	}
	return os.Chmod(destination, 0o600)
}

func (db *DB) Close() error {
	select {
	case <-db.refreshStop:
	default:
		close(db.refreshStop)
	}
	return db.sql.Close()
}

var _ storage.Store = (*storeAdapter)(nil)

type storeAdapter struct{ *DB }

func (s *storeAdapter) WithTx(ctx context.Context, fn func(storage.Transaction) error) error {
	return s.DB.WithTx(ctx, func(tx *Tx) error { return fn(tx) })
}

func (s *storeAdapter) Readiness(ctx context.Context) (storage.Readiness, error) {
	status, err := s.DB.Readiness(ctx)
	return storage.Readiness{
		SQLiteVersion: status.SQLiteVersion.String(), SchemaVersion: status.SchemaVersion,
		JournalMode: status.JournalMode, Synchronous: status.Synchronous,
		ForeignKeys: status.ForeignKeys, IntegrityOK: status.IntegrityOK,
	}, err
}

func (db *DB) Store() storage.Store { return &storeAdapter{DB: db} }

func synchronousName(value int) string {
	switch value {
	case 0:
		return "off"
	case 1:
		return "normal"
	case 2:
		return "full"
	case 3:
		return "extra"
	default:
		return strconv.Itoa(value)
	}
}
