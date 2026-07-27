CREATE TABLE repos (
    full_name      TEXT PRIMARY KEY,
    description    TEXT NOT NULL DEFAULT '',
    html_url       TEXT NOT NULL DEFAULT '',
    default_branch TEXT NOT NULL DEFAULT '',
    pushed_at      TEXT NOT NULL DEFAULT '',
    readme_sha     TEXT NOT NULL DEFAULT '',
    readme_text    TEXT NOT NULL DEFAULT '',
    tombstoned_at  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE repo_pulls (
    full_name TEXT NOT NULL,
    number    INTEGER NOT NULL,
    title     TEXT NOT NULL DEFAULT '',
    author    TEXT NOT NULL DEFAULT '',
    html_url  TEXT NOT NULL DEFAULT '',
    head_ref  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (full_name, number)
);

-- Full-text index over repos. This is a REGULAR (intrinsic-content) FTS5
-- table rather than a contentless (content='') one: contentless FTS5 cannot
-- be updated in place and requires the special 'delete' command with the
-- exact original column values, which we may no longer have on upsert.
-- Storing the text twice is an acceptable cost for a rebuildable cache and
-- lets the store refresh a repo's row with a plain DELETE + INSERT, which is
-- unambiguously correct on modernc.org/sqlite. Correctness over cleverness.
CREATE VIRTUAL TABLE repos_fts USING fts5(
    full_name,
    description,
    readme_text,
    tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TABLE node_vectors (
    full_name TEXT PRIMARY KEY,
    vector    BLOB NOT NULL
);

CREATE TABLE token_vectors (
    token  TEXT PRIMARY KEY,
    vector BLOB NOT NULL,
    idf    REAL NOT NULL
);

CREATE TABLE sync_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
