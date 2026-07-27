package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/checkpoint"
)

var secretPattern = regexp.MustCompile(`(?i)(authorization\s*:|bearer\s+|github_pat_|gh[pousr]_|-----BEGIN [A-Z ]+PRIVATE KEY-----)`)

type Event struct {
	RequestID    string    `json:"request_id"`
	Caller       string    `json:"caller,omitempty"`
	State        string    `json:"state"`
	Code         string    `json:"code"`
	Detail       string    `json:"detail,omitempty"`
	At           time.Time `json:"at"`
	PreviousHash string    `json:"previous_hash"`
	Hash         string    `json:"hash"`
}

type Journal struct {
	mu               sync.Mutex
	path             string
	tail             string
	checkpointer     Checkpointer
	policyGeneration uint64
	unanchored       bool
}

type Checkpointer interface {
	Extend(checkpoint.Extension) (checkpoint.State, error)
	State() (checkpoint.State, error)
	Verify(checkpoint.State) error
}

func Open(path string) (*Journal, error) {
	return open(path, nil, 0)
}

func OpenAnchored(path string, checkpointer Checkpointer, policyGeneration uint64) (*Journal, error) {
	if checkpointer == nil || policyGeneration == 0 {
		return nil, errors.New("anchored audit configuration is incomplete")
	}
	return open(path, checkpointer, policyGeneration)
}

func open(path string, checkpointer Checkpointer, policyGeneration uint64) (*Journal, error) {
	j := &Journal{path: path, checkpointer: checkpointer, policyGeneration: policyGeneration}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		file, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if createErr != nil {
			return nil, createErr
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	events, err := readAll(path)
	if err != nil {
		return nil, err
	}
	if err := verifyEvents(events); err != nil {
		return nil, err
	}
	if len(events) > 0 {
		j.tail = events[len(events)-1].Hash
	}
	if checkpointer != nil {
		if err := j.reconcileCheckpoint(events); err != nil {
			return nil, err
		}
	}
	return j, nil
}

func (j *Journal) Append(event Event) (Event, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.unanchored {
		return Event{}, errors.New("audit journal has an unanchored checkpoint tail")
	}
	if event.RequestID == "" || event.State == "" || event.Code == "" || event.At.IsZero() {
		return Event{}, errors.New("audit event is incomplete")
	}
	if secretPattern.MatchString(event.Detail) {
		event.Detail = "[REDACTED]"
	}
	event.At = event.At.UTC()
	previousTail := j.tail
	event.PreviousHash = previousTail
	event.Hash = hash(event)
	payload, err := json.Marshal(event)
	if err != nil {
		return Event{}, err
	}
	file, err := os.OpenFile(j.path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return Event{}, err
	}
	if _, err = file.Write(append(payload, '\n')); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return Event{}, err
	}
	if closeErr != nil {
		return Event{}, closeErr
	}
	j.tail = event.Hash
	if j.checkpointer != nil {
		state, err := j.checkpointer.Extend(checkpoint.Extension{PreviousTail: previousTail, NewTail: event.Hash, PolicyGeneration: j.policyGeneration})
		if err != nil {
			j.unanchored = true
			return event, fmt.Errorf("checkpoint extension failed: %w", err)
		}
		if state.Tail != event.Hash || state.PolicyGeneration != j.policyGeneration {
			j.unanchored = true
			return event, errors.New("checkpoint extension returned mismatched state")
		}
		if err := j.checkpointer.Verify(state); err != nil {
			j.unanchored = true
			return event, fmt.Errorf("checkpoint verification failed: %w", err)
		}
	}
	return event, nil
}

func (j *Journal) Verify() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	events, err := readAll(j.path)
	if err != nil {
		return err
	}
	if err := verifyEvents(events); err != nil {
		return err
	}
	if j.checkpointer == nil {
		return nil
	}
	state, err := j.checkpointer.State()
	if err != nil {
		return fmt.Errorf("checkpoint state unavailable: %w", err)
	}
	if err := j.checkpointer.Verify(state); err != nil {
		return fmt.Errorf("checkpoint state invalid: %w", err)
	}
	tail := ""
	if len(events) > 0 {
		tail = events[len(events)-1].Hash
	}
	if state.Tail != tail {
		return errors.New("audit journal rollback or fork detected")
	}
	if state.PolicyGeneration > j.policyGeneration {
		return errors.New("policy generation rollback detected")
	}
	return nil
}

func (j *Journal) ReadFor(requestID string) ([]Event, error) {
	events, err := readAll(j.path)
	if err != nil {
		return nil, err
	}
	filtered := make([]Event, 0)
	for _, event := range events {
		if event.RequestID == requestID {
			filtered = append(filtered, event)
		}
	}
	return filtered, nil
}

func (j *Journal) Events() ([]Event, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return readAll(j.path)
}

func TamperForTest(path string, payload []byte) error {
	return os.WriteFile(path, payload, 0o600)
}

func hash(event Event) string {
	event.Hash = ""
	payload, _ := json.Marshal(event)
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func readAll(path string) ([]Event, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	events := make([]Event, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, scanner.Err()
}

func verifyEvents(events []Event) error {
	previous := ""
	for _, event := range events {
		if event.PreviousHash != previous || event.Hash != hash(event) {
			return errors.New("audit chain verification failed")
		}
		previous = event.Hash
	}
	return nil
}

func (j *Journal) reconcileCheckpoint(events []Event) error {
	state, err := j.checkpointer.State()
	if err != nil {
		return fmt.Errorf("checkpoint state unavailable: %w", err)
	}
	if err := j.checkpointer.Verify(state); err != nil {
		return fmt.Errorf("checkpoint state invalid: %w", err)
	}
	if state.PolicyGeneration > j.policyGeneration {
		return errors.New("policy generation rollback detected")
	}
	if state.Tail == j.tail {
		return nil
	}
	if len(events) == 0 {
		return errors.New("audit journal rollback or fork detected")
	}
	last := events[len(events)-1]
	if state.Tail != last.PreviousHash {
		return errors.New("audit journal rollback or fork detected")
	}
	next, err := j.checkpointer.Extend(checkpoint.Extension{PreviousTail: state.Tail, NewTail: last.Hash, PolicyGeneration: j.policyGeneration})
	if err != nil {
		return fmt.Errorf("checkpoint recovery failed: %w", err)
	}
	if next.Tail != last.Hash || next.PolicyGeneration != j.policyGeneration {
		return errors.New("checkpoint recovery returned mismatched state")
	}
	if err := j.checkpointer.Verify(next); err != nil {
		return fmt.Errorf("checkpoint recovery verification failed: %w", err)
	}
	return nil
}
