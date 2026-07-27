-- Comments on a reviewable subject.
--
-- Keyed on (subject_kind, subject_id) rather than a bare sync id. This
-- migration is the last cheap moment to make that choice: a pre-comment — a
-- reply to a reviewer on an ALREADY-OPEN public pull request — has no sync to
-- hang on, because the sync is done or was never ours. Keying on a sync id
-- today would force either a second comment table or a data migration to reach
-- it later.
--
-- U7 implements and accepts exactly one value, 'sync'. The column is a seam,
-- not speculative generality, and its test asserts an unknown subject_kind is
-- REFUSED so the column is exercised rather than decorative.
--
-- author_kind distinguishes a human approver from an agent, because the whole
-- point of R8 is agents reviewing each other's work: a comment attributed to
-- the wrong party would let an agent's text carry a human's authority.
CREATE TABLE sync_comments (
    tenant_id    TEXT    NOT NULL,
    id           TEXT    NOT NULL,
    subject_kind TEXT    NOT NULL,
    subject_id   TEXT    NOT NULL,
    author_kind  TEXT    NOT NULL,
    author_id    TEXT    NOT NULL,
    body         TEXT    NOT NULL,
    created_at   INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, id)
);

-- The thread read is always "every comment on this subject, oldest first".
CREATE INDEX sync_comments_subject_idx
    ON sync_comments (tenant_id, subject_kind, subject_id, created_at);
