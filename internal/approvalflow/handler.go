package approvalflow

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/approval"
	"github.com/yaniv256/gitoversight.dev/internal/durable"
	"github.com/yaniv256/gitoversight.dev/internal/ingress"
)

type Sink interface {
	Put(approval.Packet) error
}

type expectation struct {
	Packet approval.Packet `json:"packet"`
	Head   string          `json:"head"`
}

type Coordinator struct {
	mu          sync.Mutex
	verifier    *ingress.WebhookVerifier
	maxBody     int64
	concurrency chan struct{}
	expected    map[string]expectation
	path        string
}

func New(secret []byte, maxBody, maxConcurrent int) *Coordinator {
	if maxBody <= 0 {
		maxBody = 1 << 20
	}
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}
	return &Coordinator{
		verifier:    ingress.NewWebhookVerifier(secret, maxBody),
		maxBody:     int64(maxBody),
		concurrency: make(chan struct{}, maxConcurrent),
		expected:    make(map[string]expectation),
	}
}

func Open(secret []byte, maxBody, maxConcurrent int, path string) (*Coordinator, error) {
	coordinator := New(secret, maxBody, maxConcurrent)
	coordinator.path = path
	payload, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		coordinator.mu.Lock()
		err = coordinator.persistLocked()
		coordinator.mu.Unlock()
		return coordinator, err
	}
	if err != nil {
		return nil, err
	}
	var stored []expectation
	if err := json.Unmarshal(payload, &stored); err != nil {
		return nil, err
	}
	for _, value := range stored {
		if err := coordinator.expect(value.Packet, value.Head, false); err != nil {
			return nil, err
		}
	}
	return coordinator, nil
}

func (c *Coordinator) Expect(packet approval.Packet, head string) error {
	return c.expect(packet, head, true)
}

func (c *Coordinator) expect(packet approval.Packet, head string, persist bool) error {
	if packet.ID == "" || packet.ManifestHash == "" || packet.Repository == "" || len(packet.Operations) == 0 || packet.Approver == "" || packet.Nonce == "" || packet.ExpiresAt.IsZero() || packet.PolicyGeneration == 0 || head == "" {
		return errors.New("approval expectation is incomplete")
	}
	tuple := ingress.ApprovalTuple{Nonce: packet.Nonce, Repository: packet.Repository, Head: head, Manifest: packet.ManifestHash, Approver: packet.Approver}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.expected[packet.Nonce]; exists {
		return errors.New("approval expectation already exists")
	}
	for _, existing := range c.expected {
		if existing.Packet.Repository == packet.Repository && existing.Head == head && existing.Packet.Approver == packet.Approver {
			return errors.New("approval expectation tuple is ambiguous")
		}
	}
	if err := c.verifier.Expect(tuple, packet.ExpiresAt); err != nil {
		return err
	}
	c.expected[packet.Nonce] = expectation{Packet: packet, Head: head}
	if persist {
		if err := c.persistLocked(); err != nil {
			delete(c.expected, packet.Nonce)
			c.verifier.Cancel(tuple)
			return err
		}
	}
	return nil
}

func (c *Coordinator) Handler(sink Sink) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/webhooks/github" {
			http.NotFound(response, request)
			return
		}
		select {
		case c.concurrency <- struct{}{}:
			defer func() { <-c.concurrency }()
		default:
			http.Error(response, "overloaded", http.StatusServiceUnavailable)
			return
		}
		limited := http.MaxBytesReader(response, request.Body, c.maxBody)
		body, err := io.ReadAll(limited)
		if err != nil {
			http.Error(response, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		now := time.Now().UTC()
		tuple, err := c.verifier.ResolveTuple(request.Header.Get("X-Hub-Signature-256"), body, now)
		if err != nil {
			status := http.StatusForbidden
			if errors.Is(err, ingress.ErrReplay) {
				status = http.StatusConflict
			}
			http.Error(response, "webhook rejected", status)
			return
		}
		c.mu.Lock()
		expected, ok := c.expected[tuple.Nonce]
		c.mu.Unlock()
		if !ok || expected.Head != tuple.Head || expected.Packet.ManifestHash != tuple.Manifest {
			http.Error(response, "webhook rejected", http.StatusForbidden)
			return
		}
		if err := sink.Put(expected.Packet); err != nil {
			http.Error(response, "approval sink unavailable", http.StatusServiceUnavailable)
			return
		}
		c.mu.Lock()
		delete(c.expected, tuple.Nonce)
		if err := c.persistLocked(); err != nil {
			c.expected[tuple.Nonce] = expected
			c.mu.Unlock()
			http.Error(response, "approval state unavailable", http.StatusServiceUnavailable)
			return
		}
		c.mu.Unlock()
		if err := c.verifier.ConsumeExpected(tuple, now); err != nil {
			http.Error(response, "approval replay", http.StatusConflict)
			return
		}
		response.WriteHeader(http.StatusAccepted)
	})
}

func (c *Coordinator) persistLocked() error {
	if c.path == "" {
		return nil
	}
	keys := make([]string, 0, len(c.expected))
	for nonce := range c.expected {
		keys = append(keys, nonce)
	}
	sort.Strings(keys)
	values := make([]expectation, 0, len(keys))
	for _, nonce := range keys {
		values = append(values, c.expected[nonce])
	}
	payload, err := json.Marshal(values)
	if err != nil {
		return err
	}
	return durable.Replace(c.path, payload, 0o600)
}
