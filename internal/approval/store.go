package approval

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/durable"
)

var (
	ErrNotFound        = errors.New("approval not found")
	ErrConsumed        = errors.New("approval already consumed")
	ErrRevoked         = errors.New("approval revoked")
	ErrExpired         = errors.New("approval expired")
	ErrBindingMismatch = errors.New("approval binding mismatch")
	ErrDuplicateNonce  = errors.New("approval nonce already registered")
	ErrReserved        = errors.New("approval reserved by another request")
	ErrReservation     = errors.New("approval reservation mismatch")
)

type Packet struct {
	ID               string
	ManifestHash     string
	Repository       string
	Operations       []string
	Approver         string
	Nonce            string
	ExpiresAt        time.Time
	PolicyGeneration uint64
	Consumed         bool
	Revoked          bool
	ReservedBy       string
}

type Store struct {
	mu      sync.Mutex
	packets map[string]Packet
	nonces  map[string]string
	path    string
}

func NewStore() *Store {
	return &Store{packets: make(map[string]Packet), nonces: make(map[string]string)}
}

func OpenStore(path string) (*Store, error) {
	store := NewStore()
	store.path = path
	payload, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if err := store.persistLocked(); err != nil {
			return nil, err
		}
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	var packets []Packet
	if err := json.Unmarshal(payload, &packets); err != nil {
		return nil, err
	}
	for _, packet := range packets {
		if packet.ID == "" || packet.Nonce == "" {
			return nil, errors.New("persisted approval packet is invalid")
		}
		if _, exists := store.packets[packet.ID]; exists {
			return nil, errors.New("duplicate persisted approval id")
		}
		if _, exists := store.nonces[packet.Nonce]; exists {
			return nil, ErrDuplicateNonce
		}
		store.packets[packet.ID] = packet
		store.nonces[packet.Nonce] = packet.ID
	}
	return store, nil
}

func (s *Store) Put(packet Packet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if packet.ID == "" || packet.ManifestHash == "" || packet.Repository == "" || len(packet.Operations) == 0 || packet.Approver == "" || packet.Nonce == "" || packet.ExpiresAt.IsZero() {
		return errors.New("approval packet is incomplete")
	}
	if existing, exists := s.packets[packet.ID]; exists {
		if reflect.DeepEqual(existing, packet) {
			return nil
		}
		return errors.New("approval id already registered")
	}
	if _, exists := s.nonces[packet.Nonce]; exists {
		return ErrDuplicateNonce
	}
	packets := clonePackets(s.packets)
	nonces := cloneStrings(s.nonces)
	packets[packet.ID] = packet
	nonces[packet.Nonce] = packet.ID
	if err := s.persistLocked(packets); err != nil {
		return err
	}
	s.packets = packets
	s.nonces = nonces
	return nil
}

func (s *Store) Reserve(id, requestID, manifestHash, repository, operation string, policyGeneration uint64, allowedApprovers []string, now time.Time) error {
	_, err := s.ReservePacket(id, requestID, manifestHash, repository, operation, policyGeneration, allowedApprovers, now)
	return err
}

func (s *Store) ReservePacket(id, requestID, manifestHash, repository, operation string, policyGeneration uint64, allowedApprovers []string, now time.Time) (Packet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	packet, ok := s.packets[id]
	if !ok {
		return Packet{}, ErrNotFound
	}
	if packet.Consumed {
		return Packet{}, ErrConsumed
	}
	if packet.Revoked {
		return Packet{}, ErrRevoked
	}
	if packet.ReservedBy != "" && packet.ReservedBy != requestID {
		return Packet{}, ErrReserved
	}
	if !now.Before(packet.ExpiresAt) {
		return Packet{}, ErrExpired
	}
	if packet.ManifestHash != manifestHash || packet.Repository != repository || !contains(packet.Operations, operation) {
		return Packet{}, ErrBindingMismatch
	}
	if packet.PolicyGeneration != policyGeneration || !contains(allowedApprovers, packet.Approver) {
		return Packet{}, ErrBindingMismatch
	}
	packet.ReservedBy = requestID
	if err := s.replacePacketLocked(id, packet); err != nil {
		return Packet{}, err
	}
	return packet, nil
}

func (s *Store) Commit(id, requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	packet, ok := s.packets[id]
	if !ok {
		return ErrNotFound
	}
	if packet.Consumed {
		return ErrConsumed
	}
	if packet.ReservedBy != requestID {
		return ErrReservation
	}
	packet.Consumed = true
	packet.ReservedBy = ""
	return s.replacePacketLocked(id, packet)
}

func (s *Store) Release(id, requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	packet, ok := s.packets[id]
	if !ok {
		return ErrNotFound
	}
	if packet.Consumed {
		return ErrConsumed
	}
	if packet.ReservedBy != requestID {
		return ErrReservation
	}
	packet.ReservedBy = ""
	return s.replacePacketLocked(id, packet)
}

func (s *Store) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	packet, ok := s.packets[id]
	if !ok {
		return ErrNotFound
	}
	if packet.Consumed {
		return ErrConsumed
	}
	packet.Revoked = true
	return s.replacePacketLocked(id, packet)
}

func (s *Store) replacePacketLocked(id string, packet Packet) error {
	packets := clonePackets(s.packets)
	packets[id] = packet
	if err := s.persistLocked(packets); err != nil {
		return err
	}
	s.packets = packets
	return nil
}

func (s *Store) persistLocked(packetsByID ...map[string]Packet) error {
	if s.path == "" {
		return nil
	}
	source := s.packets
	if len(packetsByID) > 0 {
		source = packetsByID[0]
	}
	ids := make([]string, 0, len(source))
	for id := range source {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	packets := make([]Packet, 0, len(source))
	for _, id := range ids {
		packets = append(packets, source[id])
	}
	payload, err := json.Marshal(packets)
	if err != nil {
		return err
	}
	return durable.Replace(s.path, payload, 0o600)
}

func clonePackets(source map[string]Packet) map[string]Packet {
	cloned := make(map[string]Packet, len(source))
	for id, packet := range source {
		cloned[id] = packet
	}
	return cloned
}

func cloneStrings(source map[string]string) map[string]string {
	cloned := make(map[string]string, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
