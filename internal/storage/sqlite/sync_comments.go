package sqlite

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// MaxCommentBytes caps one comment. Comments are the only unbounded-growth
	// surface this feature adds, and AGENTS are high-throughput writers.
	MaxCommentBytes = 16 << 10
	// MaxCommentsPerSubject caps the thread. Without it a misbehaving agent
	// could grow the database and make the review page unusable — denying the
	// human the very surface the comments exist to serve.
	MaxCommentsPerSubject = 500
)

// SyncCommentSubjectSync is the only subject kind U7 implements. The column
// exists so a pre-comment on an already-open public pull request has somewhere
// to go later without a second table; accepting an unknown kind now would let
// rows accumulate that nothing can render.
const SyncCommentSubjectSync = "sync"

// Author kinds. A comment attributed to the wrong party would let an agent's
// text carry a human's authority, which is precisely the confusion a review
// surface must not create.
const (
	CommentAuthorHuman = "human"
	CommentAuthorAgent = "agent"
)

type SyncComment struct {
	ID          string
	SubjectKind string
	SubjectID   string
	AuthorKind  string
	AuthorID    string
	Body        string
	CreatedAt   time.Time
}

// AppendSyncComment stores one comment on a reviewable subject.
//
// The author is passed by the CALLER from its authenticated principal and is
// never read from a request body — the same rule the propose path already
// applies when it discards an agent's self-declared file list: anything the
// human's judgment rests on is computed by the party doing the judging.
func (db *DB) AppendSyncComment(ctx context.Context, tenantID string, comment SyncComment, now time.Time) error {
	if tenantID == "" || comment.ID == "" || comment.SubjectID == "" || comment.AuthorID == "" {
		return errors.New("sync comment is incomplete")
	}
	if comment.SubjectKind != SyncCommentSubjectSync {
		// Refusing an unknown kind is what makes subject_kind a real seam
		// rather than a decorative column.
		return fmt.Errorf("unsupported comment subject kind %q", comment.SubjectKind)
	}
	if comment.AuthorKind != CommentAuthorHuman && comment.AuthorKind != CommentAuthorAgent {
		return fmt.Errorf("unsupported comment author kind %q", comment.AuthorKind)
	}
	body := strings.TrimSpace(comment.Body)
	if body == "" {
		return errors.New("comment body is empty")
	}
	if len(body) > MaxCommentBytes {
		// Rejected, never truncated: silently publishing half of what someone
		// wrote is worse than refusing the whole thing, because they cannot
		// tell it happened.
		return fmt.Errorf("comment body is %d bytes, over the %d limit", len(body), MaxCommentBytes)
	}
	return db.WithTx(ctx, func(tx *Tx) error {
		var count int
		if err := tx.tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM sync_comments WHERE tenant_id = ? AND subject_kind = ? AND subject_id = ?`,
			tenantID, comment.SubjectKind, comment.SubjectID).Scan(&count); err != nil {
			return err
		}
		if count >= MaxCommentsPerSubject {
			return fmt.Errorf("comment thread is at its %d-comment limit", MaxCommentsPerSubject)
		}
		_, err := tx.tx.ExecContext(ctx, `INSERT INTO sync_comments
			(tenant_id, id, subject_kind, subject_id, author_kind, author_id, body, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			tenantID, comment.ID, comment.SubjectKind, comment.SubjectID,
			comment.AuthorKind, comment.AuthorID, body, unix(now))
		return err
	})
}

// SyncCommentsFor returns a subject's thread, oldest first.
func (db *DB) SyncCommentsFor(ctx context.Context, tenantID, subjectKind, subjectID string) ([]SyncComment, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT id, subject_kind, subject_id, author_kind, author_id, body, created_at
		FROM sync_comments WHERE tenant_id = ? AND subject_kind = ? AND subject_id = ?
		ORDER BY created_at, id`, tenantID, subjectKind, subjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var comments []SyncComment
	for rows.Next() {
		var comment SyncComment
		var createdAt int64
		if err := rows.Scan(&comment.ID, &comment.SubjectKind, &comment.SubjectID,
			&comment.AuthorKind, &comment.AuthorID, &comment.Body, &createdAt); err != nil {
			return nil, err
		}
		comment.CreatedAt = fromUnix(createdAt)
		comments = append(comments, comment)
	}
	return comments, rows.Err()
}
