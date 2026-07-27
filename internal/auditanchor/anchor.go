package auditanchor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/checkpoint"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

type Checkpointer interface {
	Extend(checkpoint.Extension) (checkpoint.State, error)
	State() (checkpoint.State, error)
	Verify(checkpoint.State) error
}

type Anchor struct {
	mu           sync.Mutex
	db           *sqlite.DB
	tenant       string
	signer       Checkpointer
	timeout      time.Duration
	verifiedTail string
	initialized  bool
}

func New(db *sqlite.DB, tenant string, signer Checkpointer, timeout time.Duration) (*Anchor, error) {
	if db == nil || tenant == "" || signer == nil || timeout <= 0 {
		return nil, errors.New("audit anchor configuration is incomplete")
	}
	return &Anchor{db: db, tenant: tenant, signer: signer, timeout: timeout}, nil
}

func (anchor *Anchor) Verify() error {
	ctx, cancel := context.WithTimeout(context.Background(), anchor.timeout)
	defer cancel()
	return anchor.synchronize(ctx, anchor.tenant)
}

func (anchor *Anchor) Commit(ctx context.Context, tenant string) error {
	if tenant != anchor.tenant {
		return errors.New("audit anchor tenant mismatch")
	}
	return anchor.synchronize(ctx, tenant)
}

func (anchor *Anchor) synchronize(ctx context.Context, tenant string) error {
	anchor.mu.Lock()
	defer anchor.mu.Unlock()
	wantTail, err := anchor.verifyDurableAudit(ctx, tenant)
	if err != nil {
		return err
	}
	policy, err := anchor.db.LatestPolicyGeneration(ctx, tenant)
	if errors.Is(err, sqlite.ErrNotFound) {
		state, stateErr := anchor.signer.State()
		if stateErr != nil {
			return fmt.Errorf("read pre-policy signed checkpoint: %w", stateErr)
		}
		if wantTail != "GENESIS" || state != (checkpoint.State{}) {
			return errors.New("pre-policy authority state is not empty")
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read active policy: %w", err)
	}
	state, err := anchor.signer.State()
	if err != nil {
		return fmt.Errorf("read signed checkpoint: %w", err)
	}
	if state != (checkpoint.State{}) {
		if err := anchor.signer.Verify(state); err != nil {
			return fmt.Errorf("verify signed checkpoint: %w", err)
		}
		if state.PolicyGeneration > policy.Generation {
			return errors.New("signed checkpoint policy generation is ahead of durable policy")
		}
		exists, existsErr := anchor.db.AuthorityAuditHashExists(ctx, tenant, state.Tail)
		if existsErr != nil {
			return fmt.Errorf("locate signed checkpoint tail: %w", existsErr)
		}
		if !exists {
			return errors.New("signed checkpoint tail is absent from durable audit history")
		}
		if state.Tail == wantTail && state.PolicyGeneration == policy.Generation {
			return nil
		}
		if state.Tail == wantTail {
			return errors.New("policy generation advanced without an audit transition")
		}
	}
	next, err := anchor.signer.Extend(checkpoint.Extension{
		PreviousTail: state.Tail, NewTail: wantTail, PolicyGeneration: policy.Generation,
	})
	if err != nil {
		return fmt.Errorf("extend signed checkpoint: %w", err)
	}
	if next.Tail != wantTail || next.PolicyGeneration != policy.Generation {
		return errors.New("signed checkpoint extension did not bind durable authority state")
	}
	if err := anchor.signer.Verify(next); err != nil {
		return fmt.Errorf("verify extended checkpoint: %w", err)
	}
	return nil
}

func (anchor *Anchor) verifyDurableAudit(ctx context.Context, tenant string) (string, error) {
	if !anchor.initialized {
		if err := anchor.db.VerifyAuthorityAuditChain(ctx, tenant); err != nil {
			return "", fmt.Errorf("verify authority audit chain: %w", err)
		}
		tail, err := anchor.db.AuthorityAuditTail(ctx, tenant)
		if err != nil {
			return "", fmt.Errorf("read authority audit tail: %w", err)
		}
		anchor.verifiedTail, anchor.initialized = tail, true
		return tail, nil
	}
	tail, err := anchor.db.VerifyAuthorityAuditSuffix(ctx, tenant, anchor.verifiedTail)
	if err != nil {
		return "", fmt.Errorf("verify authority audit suffix: %w", err)
	}
	anchor.verifiedTail = tail
	return tail, nil
}
