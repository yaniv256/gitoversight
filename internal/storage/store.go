package storage

import (
	"context"
	"errors"
	"time"
)

var (
	ErrDuplicateNonce      = errors.New("request nonce already consumed")
	ErrDuplicateWebhook    = errors.New("webhook delivery already consumed")
	ErrStagedAssetNotFound = errors.New("staged asset not found")
	ErrStagedAssetState    = errors.New("staged asset state transition rejected")
)

type Store interface {
	WithTx(context.Context, func(Transaction) error) error
	Readiness(context.Context) (Readiness, error)
	Backup(context.Context, string) error
	Close() error
}

type Transaction interface {
	EnsureTenant(context.Context, string, time.Time) error
	PutAgentCredential(context.Context, AgentCredential) error
	PutOperation(context.Context, Operation) error
	ConsumeNonce(context.Context, string, string, string, time.Time) error
	AppendAudit(context.Context, AuditEvent) error
	AppendOutbox(context.Context, OutboxEvent) error
	PutStagedAsset(context.Context, StagedAsset) error
	BeginStagedAssetUpload(context.Context, string, string, string, time.Time) error
	MarkStagedAssetReady(context.Context, string, string, string, time.Time) error
	PinStagedAsset(context.Context, StagedAsset, string, time.Time) error
	AbandonStagedAsset(context.Context, string, string, time.Time) error
	ExpireStagedAsset(context.Context, string, string, time.Time) error
}

type Readiness struct {
	SQLiteVersion string
	SchemaVersion int
	JournalMode   string
	Synchronous   string
	ForeignKeys   bool
	IntegrityOK   bool
}
