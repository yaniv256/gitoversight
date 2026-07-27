package checkpoint

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/durable"
)

type Extension struct {
	PreviousTail     string
	NewTail          string
	PolicyGeneration uint64
}

type State struct {
	Sequence         uint64    `json:"sequence"`
	Tail             string    `json:"tail"`
	PolicyGeneration uint64    `json:"policy_generation"`
	SignedAt         time.Time `json:"signed_at"`
	Signature        string    `json:"signature"`
}

type Signer struct {
	mu    sync.Mutex
	path  string
	key   []byte
	state State
}

func Open(path string, key []byte) (*Signer, error) {
	if len(key) < 32 {
		return nil, errors.New("checkpoint key must be at least 32 bytes")
	}
	signer := &Signer{path: path, key: append([]byte(nil), key...)}
	payload, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return signer, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(payload, &signer.state); err != nil {
		return nil, err
	}
	if !signer.valid(signer.state) {
		return nil, errors.New("checkpoint signature invalid")
	}
	return signer, nil
}

func (s *Signer) Extend(extension Extension) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if extension.NewTail == "" {
		return State{}, errors.New("checkpoint reset is forbidden")
	}
	if extension.NewTail == s.state.Tail {
		return State{}, errors.New("checkpoint no-op extension is forbidden")
	}
	if extension.PreviousTail != s.state.Tail {
		return State{}, errors.New("checkpoint fork detected")
	}
	if extension.PolicyGeneration < s.state.PolicyGeneration {
		return State{}, errors.New("policy generation rollback detected")
	}
	next := State{Sequence: s.state.Sequence + 1, Tail: extension.NewTail, PolicyGeneration: extension.PolicyGeneration, SignedAt: time.Now().UTC()}
	next.Signature = s.sign(next)
	payload, err := json.Marshal(next)
	if err != nil {
		return State{}, err
	}
	if err := durable.Replace(s.path, payload, 0o600); err != nil {
		return State{}, err
	}
	s.state = next
	return next, nil
}

func (s *Signer) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func (s *Signer) Verify(state State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if state == (State{}) {
		return nil
	}
	if !s.valid(state) {
		return errors.New("checkpoint signature invalid")
	}
	return nil
}

func (s *Signer) sign(state State) string {
	state.Signature = ""
	payload, _ := json.Marshal(state)
	mac := hmac.New(sha256.New, s.key)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Signer) valid(state State) bool {
	expected, err := hex.DecodeString(s.sign(state))
	if err != nil {
		return false
	}
	actual, err := hex.DecodeString(state.Signature)
	if err != nil {
		return false
	}
	return hmac.Equal(actual, expected)
}
