package audit_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/audit"
	"github.com/yaniv256/gitoversight.dev/internal/checkpoint"
)

func TestAnchoredJournalExtendsCheckpointForEveryDurableEvent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	client, stop := startAuditCheckpointService(t, dir)
	defer stop()
	j, err := audit.OpenAnchored(filepath.Join(dir, "audit.jsonl"), client, 7)
	if err != nil {
		t.Fatal(err)
	}
	event, err := j.Append(audit.Event{RequestID: "request-1", State: "requested", Code: "ok", At: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	state, err := client.State()
	if err != nil {
		t.Fatal(err)
	}
	if state.Sequence != 1 || state.Tail != event.Hash || state.PolicyGeneration != 7 {
		t.Fatalf("checkpoint = %#v", state)
	}
	if err := j.Verify(); err != nil {
		t.Fatalf("verify anchored journal: %v", err)
	}
}

func TestAnchoredJournalFailsClosedWhenSignerIsUnavailable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	client, stop := startAuditCheckpointService(t, dir)
	j, err := audit.OpenAnchored(filepath.Join(dir, "audit.jsonl"), client, 1)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if _, err := j.Append(audit.Event{RequestID: "request-1", State: "authorized", Code: "ok", At: time.Now().UTC()}); err == nil || !strings.Contains(err.Error(), "checkpoint") {
		t.Fatalf("append error = %v", err)
	}
	if _, err := j.Append(audit.Event{RequestID: "request-2", State: "authorized", Code: "ok", At: time.Now().UTC()}); err == nil || !strings.Contains(err.Error(), "unanchored") {
		t.Fatalf("second append error = %v", err)
	}
	events, err := j.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("durable events = %d, want 1", len(events))
	}
}

func TestAnchoredJournalRecoversOneDurableUnanchoredTailAfterRestart(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	journalPath := filepath.Join(dir, "audit.jsonl")
	client, stop := startAuditCheckpointService(t, dir)
	j, err := audit.OpenAnchored(journalPath, client, 2)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if _, err := j.Append(audit.Event{RequestID: "request-1", State: "requested", Code: "ok", At: time.Now().UTC()}); err == nil {
		t.Fatal("expected unavailable signer")
	}
	client, stop = startAuditCheckpointService(t, dir)
	defer stop()
	reopened, err := audit.OpenAnchored(journalPath, client, 2)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if err := reopened.Verify(); err != nil {
		t.Fatal(err)
	}
	state, err := client.State()
	if err != nil {
		t.Fatal(err)
	}
	events, err := reopened.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || state.Tail != events[0].Hash || state.Sequence != 1 {
		t.Fatalf("state = %#v events = %#v", state, events)
	}
}

func TestAnchoredJournalRejectsJournalAndPolicyRollback(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	journalPath := filepath.Join(dir, "audit.jsonl")
	client, stop := startAuditCheckpointService(t, dir)
	defer stop()
	j, err := audit.OpenAnchored(journalPath, client, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Append(audit.Event{RequestID: "request-1", State: "requested", Code: "ok", At: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := audit.TamperForTest(journalPath, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := audit.OpenAnchored(journalPath, client, 3); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("journal rollback error = %v", err)
	}
	if _, err := audit.OpenAnchored(filepath.Join(dir, "other.jsonl"), client, 2); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("policy rollback error = %v", err)
	}
}

func startAuditCheckpointService(t *testing.T, dir string) (*checkpoint.Client, func()) {
	t.Helper()
	signer, err := checkpoint.Open(filepath.Join(dir, "checkpoint.json"), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	server := checkpoint.NewServer(filepath.Join(dir, "checkpoint.sock"), signer, uint32(os.Getuid()))
	listener, err := server.Listen()
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	client, err := checkpoint.NewClient(server.SocketPath(), time.Second)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	return client, func() { _ = listener.Close() }
}
