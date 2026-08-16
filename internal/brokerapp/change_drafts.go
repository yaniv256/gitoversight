package brokerapp

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/changedraft"
)

var (
	ErrChangeDraftInvalid    = errors.New("change draft request is invalid")
	ErrChangeDraftNotFound   = errors.New("change draft not found")
	ErrChangeDraftStaleBase  = errors.New("change draft base is stale")
	ErrChangeDraftBinding    = errors.New("change draft binding does not match")
	ErrChangeDraftExpired    = errors.New("change draft expired")
	ErrChangeDraftTampered   = errors.New("change draft content does not match preview")
	ErrChangeDraftRepository = errors.New("change draft repository unavailable")
)

const (
	defaultChangeDraftTTL = 15 * time.Minute
	maxChangeDraftTTL     = time.Hour
)

// ChangeDraftRepository is a read-only broker-side repository projection.
// Callers submit only bounded path operations; they never upload a complete
// base snapshot or caller-chosen Git object graph.
type ChangeDraftRepository interface {
	CurrentBase(context.Context, Identity, string) (changedraft.BaseRef, error)
	Snapshot(context.Context, Identity, string, changedraft.ObjectID) (changedraft.Snapshot, error)
}

type ChangeDraftStore interface {
	PutChangeDraft(context.Context, changedraft.StoredDraft) error
	ChangeDraft(context.Context, string, string, string) (changedraft.StoredDraft, error)
}

type ChangeDraftConfig struct {
	TTL    time.Duration
	Limits changedraft.Limits
	Now    func() time.Time
	NewID  func() (string, error)
}

type CreateChangeDraftRequest struct {
	Repository string
	BaseCommit changedraft.ObjectID
	Changes    []changedraft.Change
}

type ChangeDraftReceipt struct {
	ID        string
	Preview   changedraft.Preview
	ExpiresAt time.Time
}

// ChangeDraftBinding is the complete authority-neutral reference a later
// governed publication must present. A draft ID alone is never sufficient.
type ChangeDraftBinding struct {
	ID          string
	Repository  string
	BaseCommit  changedraft.ObjectID
	PreviewHash string
}

type ChangeDraftService struct {
	repository ChangeDraftRepository
	store      ChangeDraftStore
	ttl        time.Duration
	limits     changedraft.Limits
	now        func() time.Time
	newID      func() (string, error)
}

func NewChangeDraftService(repository ChangeDraftRepository, store ChangeDraftStore, config ChangeDraftConfig) *ChangeDraftService {
	ttl := config.TTL
	if ttl <= 0 {
		ttl = defaultChangeDraftTTL
	}
	if ttl > maxChangeDraftTTL {
		ttl = maxChangeDraftTTL
	}
	limits := config.Limits
	if limits == (changedraft.Limits{}) {
		limits = changedraft.DefaultLimits()
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	newID := config.NewID
	if newID == nil {
		newID = randomChangeDraftID
	}
	return &ChangeDraftService{repository: repository, store: store, ttl: ttl, limits: limits, now: now, newID: newID}
}

func (s *ChangeDraftService) Create(ctx context.Context, identity Identity, request CreateChangeDraftRequest) (ChangeDraftReceipt, error) {
	if err := validateDraftContext(identity, request.Repository, request.BaseCommit); err != nil {
		return ChangeDraftReceipt{}, err
	}
	if s.repository == nil || s.store == nil {
		return ChangeDraftReceipt{}, ErrChangeDraftRepository
	}
	current, err := s.repository.CurrentBase(ctx, identity, request.Repository)
	if err != nil {
		return ChangeDraftReceipt{}, fmt.Errorf("%w: %w", ErrChangeDraftRepository, err)
	}
	if current.Commit != request.BaseCommit {
		return ChangeDraftReceipt{}, ErrChangeDraftStaleBase
	}
	base, err := s.repository.Snapshot(ctx, identity, request.Repository, request.BaseCommit)
	if err != nil {
		return ChangeDraftReceipt{}, fmt.Errorf("%w: %w", ErrChangeDraftRepository, err)
	}
	if base.Repository != request.Repository || base.Commit != request.BaseCommit || base.Tree != current.Tree {
		return ChangeDraftReceipt{}, ErrChangeDraftStaleBase
	}
	preview, err := changedraft.BuildPreview(base, request.Changes, s.limits)
	if err != nil {
		return ChangeDraftReceipt{}, fmt.Errorf("%w: %w", ErrChangeDraftInvalid, err)
	}
	id, err := s.newID()
	if err != nil {
		return ChangeDraftReceipt{}, fmt.Errorf("create change draft id: %w", err)
	}
	if id == "" {
		return ChangeDraftReceipt{}, fmt.Errorf("%w: generated draft id is empty", ErrChangeDraftInvalid)
	}
	now := s.now().UTC()
	draft := changedraft.StoredDraft{
		ID: id, TenantID: identity.TenantID, AgentID: identity.AgentID,
		Preview: preview, Changes: cloneChanges(request.Changes),
		CreatedAt: now, ExpiresAt: now.Add(s.ttl),
	}
	if err := s.store.PutChangeDraft(ctx, draft); err != nil {
		return ChangeDraftReceipt{}, err
	}
	return ChangeDraftReceipt{ID: id, Preview: preview, ExpiresAt: draft.ExpiresAt}, nil
}

// Resolve returns changed-file bytes for the eventual governed publication
// only after checking every persisted binding, current base freshness, and a
// fresh deterministic rebuild. It performs no GitHub write.
func (s *ChangeDraftService) Resolve(ctx context.Context, identity Identity, binding ChangeDraftBinding) (changedraft.StoredDraft, error) {
	if err := validateDraftContext(identity, binding.Repository, binding.BaseCommit); err != nil || binding.ID == "" || binding.PreviewHash == "" {
		return changedraft.StoredDraft{}, ErrChangeDraftInvalid
	}
	if s.repository == nil || s.store == nil {
		return changedraft.StoredDraft{}, ErrChangeDraftRepository
	}
	now := s.now().UTC()
	draft, err := s.store.ChangeDraft(ctx, identity.TenantID, identity.AgentID, binding.ID)
	if errors.Is(err, changedraft.ErrStoredDraftNotFound) || errors.Is(err, ErrChangeDraftNotFound) {
		return changedraft.StoredDraft{}, ErrChangeDraftNotFound
	}
	if err != nil {
		return changedraft.StoredDraft{}, err
	}
	if !now.Before(draft.ExpiresAt) {
		return changedraft.StoredDraft{}, ErrChangeDraftExpired
	}
	if draft.TenantID != identity.TenantID || draft.AgentID != identity.AgentID || draft.ID != binding.ID ||
		draft.Preview.Repository != binding.Repository || draft.Preview.BaseCommit != binding.BaseCommit ||
		!secureStringEqual(draft.Preview.Hash, binding.PreviewHash) {
		return changedraft.StoredDraft{}, ErrChangeDraftBinding
	}
	current, err := s.repository.CurrentBase(ctx, identity, binding.Repository)
	if err != nil {
		return changedraft.StoredDraft{}, fmt.Errorf("%w: %w", ErrChangeDraftRepository, err)
	}
	if current.Commit != draft.Preview.BaseCommit || current.Tree != draft.Preview.BaseTree {
		return changedraft.StoredDraft{}, ErrChangeDraftStaleBase
	}
	base, err := s.repository.Snapshot(ctx, identity, binding.Repository, binding.BaseCommit)
	if err != nil {
		return changedraft.StoredDraft{}, fmt.Errorf("%w: %w", ErrChangeDraftRepository, err)
	}
	if base.Repository != binding.Repository || base.Commit != binding.BaseCommit || base.Tree != current.Tree {
		return changedraft.StoredDraft{}, ErrChangeDraftStaleBase
	}
	rebuilt, err := changedraft.BuildPreview(base, draft.Changes, s.limits)
	if err != nil || !secureStringEqual(rebuilt.Hash, draft.Preview.Hash) || !reflect.DeepEqual(rebuilt, draft.Preview) {
		return changedraft.StoredDraft{}, ErrChangeDraftTampered
	}
	return draft, nil
}

func validateDraftContext(identity Identity, repository string, base changedraft.ObjectID) error {
	if identity.TenantID == "" || identity.AgentID == "" || repository == "" || base == "" {
		return ErrChangeDraftInvalid
	}
	return nil
}

func secureStringEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func cloneChanges(changes []changedraft.Change) []changedraft.Change {
	result := make([]changedraft.Change, len(changes))
	copy(result, changes)
	for index := range result {
		result[index].Content = append([]byte(nil), result[index].Content...)
	}
	return result
}

func randomChangeDraftID() (string, error) {
	value := make([]byte, 18)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "draft_" + base64.RawURLEncoding.EncodeToString(value), nil
}
