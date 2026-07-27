package audit_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/audit"
)

func TestJournalAppendsAndVerifiesChain(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	j, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	for _, state := range []string{"requested", "authorized", "executed", "verified"} {
		if _, err := j.Append(audit.Event{RequestID: "request-1", State: state, Code: "ok", At: now}); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
	}
	if err := j.Verify(); err != nil {
		t.Fatal(err)
	}
	events, err := j.ReadFor("request-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 || events[3].PreviousHash != events[2].Hash {
		t.Fatalf("unexpected events: %#v", events)
	}
}

func TestJournalDetectsTamper(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	j, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Append(audit.Event{RequestID: "request-1", State: "requested", Code: "ok", At: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := audit.TamperForTest(path, []byte("{\"broken\":true}\n")); err != nil {
		t.Fatal(err)
	}
	if err := j.Verify(); err == nil {
		t.Fatal("expected tamper detection")
	}
}

func TestJournalRefusesToOpenTamperedChain(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	j, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Append(audit.Event{RequestID: "request-1", State: "requested", Code: "ok", At: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := audit.TamperForTest(path, []byte("{\"broken\":true}\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Open(path); err == nil {
		t.Fatal("expected open to reject tampered chain")
	}
}

func TestJournalRedactsSecrets(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	j, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	event, err := j.Append(audit.Event{RequestID: "request-1", State: "denied", Code: "bad", Detail: "Authorization: Bearer github_pat_secret", At: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if event.Detail != "[REDACTED]" {
		t.Fatalf("detail = %q", event.Detail)
	}
}
