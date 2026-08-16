package changedraft

import (
	"errors"
	"time"
)

var (
	ErrStoredDraftNotFound       = errors.New("stored change draft not found")
	ErrStoredPublicationNotFound = errors.New("stored change draft publication not found")
)

// StoredDraft is the broker-local durable form of an ephemeral change draft.
// Changes contains only the bounded path operations submitted by the caller;
// it is deliberately not a repository snapshot. Preview contains the
// broker-derived resulting tree and content-addressed review contract.
type StoredDraft struct {
	ID        string
	TenantID  string
	AgentID   string
	Preview   Preview
	Changes   []Change
	CreatedAt time.Time
	ExpiresAt time.Time
}

// PublicationBinding survives draft expiry and binds one operation ID to the
// exact reviewed draft request and broker-built commit identity.
type PublicationBinding struct {
	TenantID, AgentID, OperationID string
	RequestHash, HeadSHA           string
	CreatedAt                      time.Time
}
