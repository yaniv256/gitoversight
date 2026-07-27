package sqlite_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

func commentFixture(id, authorKind, authorID, body string) sqlite.SyncComment {
	return sqlite.SyncComment{
		ID: id, SubjectKind: sqlite.SyncCommentSubjectSync, SubjectID: "s-thread",
		AuthorKind: authorKind, AuthorID: authorID, Body: body,
	}
}

// The point of R8: agents review EACH OTHER's pre-PRs, so a comment must carry
// who wrote it and which kind of party they are. Attribution that blurred the
// two would let an agent's text carry a human's authority.
func TestSyncCommentsRecordAuthorKindAndOrder(t *testing.T) {
	t.Parallel()
	db := openSyncTestDB(t)
	now := time.Unix(1_800_000_000, 0)
	if err := db.AppendSyncComment(context.Background(), "default",
		commentFixture("c1", sqlite.CommentAuthorAgent, "elena", "The vendored binary is still here."), now); err != nil {
		t.Fatal(err)
	}
	if err := db.AppendSyncComment(context.Background(), "default",
		commentFixture("c2", sqlite.CommentAuthorHuman, "yaniv", "Agreed — drop it."), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	thread, err := db.SyncCommentsFor(context.Background(), "default", sqlite.SyncCommentSubjectSync, "s-thread")
	if err != nil {
		t.Fatal(err)
	}
	if len(thread) != 2 {
		t.Fatalf("thread length = %d, want 2", len(thread))
	}
	if thread[0].AuthorKind != sqlite.CommentAuthorAgent || thread[0].AuthorID != "elena" {
		t.Fatalf("first comment misattributed: %+v", thread[0])
	}
	if thread[1].AuthorKind != sqlite.CommentAuthorHuman || thread[1].AuthorID != "yaniv" {
		t.Fatalf("second comment misattributed: %+v", thread[1])
	}
	// Oldest first: a thread that reordered would misrepresent who answered whom.
	if !strings.HasPrefix(thread[0].Body, "The vendored binary") {
		t.Fatalf("thread out of order: %+v", thread)
	}
}

// subject_kind is a seam for pre-comments on already-open public PRs, not
// decoration. Refusing an unknown kind is what makes it real — otherwise rows
// accumulate that nothing can render.
func TestSyncCommentsRefuseAnUnknownSubjectKind(t *testing.T) {
	t.Parallel()
	db := openSyncTestDB(t)
	comment := commentFixture("c-bad", sqlite.CommentAuthorHuman, "yaniv", "hello")
	comment.SubjectKind = "pull_request"
	if err := db.AppendSyncComment(context.Background(), "default", comment, time.Unix(1_800_000_000, 0)); err == nil {
		t.Fatal("stored a comment under an unimplemented subject kind")
	}
}

// Comments are the only unbounded-growth surface this feature adds, and agents
// are high-throughput writers. An oversized body is REFUSED, never truncated:
// silently publishing half of what someone wrote is worse than refusing it,
// because they cannot tell it happened.
func TestSyncCommentsEnforceBodyAndThreadLimits(t *testing.T) {
	t.Parallel()
	db := openSyncTestDB(t)
	now := time.Unix(1_800_000_000, 0)

	if err := db.AppendSyncComment(context.Background(), "default",
		commentFixture("c-empty", sqlite.CommentAuthorHuman, "yaniv", "   "), now); err == nil {
		t.Fatal("stored a whitespace-only comment")
	}
	oversize := strings.Repeat("x", sqlite.MaxCommentBytes+1)
	if err := db.AppendSyncComment(context.Background(), "default",
		commentFixture("c-big", sqlite.CommentAuthorAgent, "zara", oversize), now); err == nil {
		t.Fatal("stored a comment over the byte cap")
	}
	thread, err := db.SyncCommentsFor(context.Background(), "default", sqlite.SyncCommentSubjectSync, "s-thread")
	if err != nil {
		t.Fatal(err)
	}
	if len(thread) != 0 {
		t.Fatalf("a refused comment was stored anyway: %+v", thread)
	}
}

// Tenant isolation, asserted directly rather than assumed from the schema.
func TestSyncCommentsAreTenantScoped(t *testing.T) {
	t.Parallel()
	db := openSyncTestDB(t)
	if err := db.AppendSyncComment(context.Background(), "default",
		commentFixture("c-t", sqlite.CommentAuthorHuman, "yaniv", "mine"), time.Unix(1_800_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	other, err := db.SyncCommentsFor(context.Background(), "other-tenant", sqlite.SyncCommentSubjectSync, "s-thread")
	if err != nil {
		t.Fatal(err)
	}
	if len(other) != 0 {
		t.Fatalf("a foreign tenant read this thread: %+v", other)
	}
}
