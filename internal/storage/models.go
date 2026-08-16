package storage

import "time"

type AgentCredential struct {
	TenantID               string
	AgentID                string
	ID                     string
	PublicKey              []byte
	CreatedAt              time.Time
	RevokedAt              *time.Time
	ApprovedAt             time.Time
	ApprovedBy             string
	SupersedesCredentialID string
}

type AgentEnrollment struct {
	TenantID               string
	ID                     string
	AgentID                string
	CredentialID           string
	PublicKey              []byte
	ProofMessage           []byte
	SupersedesCredentialID string
	CreatedAt              time.Time
	ExpiresAt              time.Time
	ProofVerifiedAt        *time.Time
	ApprovedAt             *time.Time
	ApprovedBy             string
}

type Operation struct {
	TenantID          string
	ID                string
	AgentID           string
	Repository        string
	Kind              string
	PacketHash        string
	State             string
	PolicyGeneration  uint64
	CreatedAt         time.Time
	ExpiresAt         time.Time
	Branch            string
	Title             string
	Body              string
	HeadSHA           string
	ManifestHash      string
	ApprovalID        string
	ApprovalNonce     string
	ApprovalExpiresAt time.Time
	Approver          string
	DecisionCode      string
	Reason            string
	ActorMode         string
	ActorSubject      string
	MutationHash      string
	PayloadJSON       []byte
	ResourceID        string
	UpdatedAt         time.Time
}

type PolicyGeneration struct {
	TenantID     string
	Generation   uint64
	PolicyHash   string
	SnapshotJSON []byte
	ActivatedAt  time.Time
}

type Approval struct {
	TenantID         string
	ID               string
	OperationID      string
	ApproverID       string
	PacketHash       string
	ManifestHash     string
	Repository       string
	Operation        string
	HeadSHA          string
	Nonce            string
	PolicyGeneration uint64
	CreatedAt        time.Time
	ExpiresAt        time.Time
	ConsumedAt       *time.Time
	RevokedAt        *time.Time
}

type HumanSession struct {
	TenantID        string
	IDHash          string
	HumanID         string
	CSRFHash        string
	CreatedAt       time.Time
	AuthenticatedAt *time.Time
	ExpiresAt       time.Time
	RevokedAt       *time.Time
}

type ExecutionGrant struct {
	TenantID     string
	ID           string
	OperationID  string
	PacketHash   string
	MutationHash string
	WorkerID     string
	Repository   string
	Operation    string
	ActorMode    string
	ActorSubject string
	ApprovalID   string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	ConsumedAt   *time.Time
	RevokedAt    *time.Time
	Outcome      string
	FinalizedAt  *time.Time
}

type AuditEvent struct {
	TenantID     string
	ID           string
	Kind         string
	SubjectID    string
	PayloadJSON  []byte
	PreviousHash string
	Hash         string
	CreatedAt    time.Time
}

type OutboxEvent struct {
	TenantID        string
	ID              string
	Kind            string
	AudienceAgentID string
	PayloadJSON     []byte
	State           string
	CreatedAt       time.Time
}

type NotificationSubscription struct {
	TenantID        string
	ID              string
	AgentID         string
	Adapter         string
	EventTypes      []string
	DestinationJSON []byte
	CreatedAt       time.Time
	RevokedAt       *time.Time
}

type NotificationDelivery struct {
	TenantID        string
	ID              string
	OutboxID        string
	SubscriptionID  string
	AgentID         string
	Adapter         string
	DestinationJSON []byte
	Event           OutboxEvent
	State           string
	AttemptCount    int
	AvailableAt     time.Time
	LeaseToken      string
	LeaseUntil      time.Time
	DuplicateRisk   bool
	LastError       string
	CreatedAt       time.Time
	DeliveredAt     *time.Time
}

type WebhookReceipt struct {
	TenantID   string
	Provider   string
	DeliveryID string
	EventType  string
	BodyHash   string
	ReceivedAt time.Time
}

type StagedAssetState string

const (
	StagedAssetCreated    StagedAssetState = "created"
	StagedAssetUploading  StagedAssetState = "uploading"
	StagedAssetReady      StagedAssetState = "ready"
	StagedAssetPinned     StagedAssetState = "pinned"
	StagedAssetAbandoned  StagedAssetState = "abandoned"
	StagedAssetExpired    StagedAssetState = "expired"
	StagedAssetReleasable StagedAssetState = "releasable"
)

// StagedAsset contains metadata only. Release bytes are held by the immutable
// filesystem store and are never serialized into SQLite.
type StagedAsset struct {
	TenantID            string
	ID                  string
	AgentID             string
	CredentialID        string
	Repository          string
	Name                string
	ContentType         string
	ExpectedSHA256      string
	ExpectedSize        int64
	ReservedSize        int64
	State               StagedAssetState
	CapabilityHash      string
	CapabilityExpiresAt time.Time
	CapabilityUsedAt    *time.Time
	TempID              string
	ObjectKey           string
	OperationID         string
	CleanupClaimedAt    *time.Time
	CleanupAttempts     int
	CleanupError        string
	CreatedAt           time.Time
	UpdatedAt           time.Time
	ExpiresAt           time.Time
}

type StagedAssetCleanup struct {
	TenantID       string
	StageID        string
	ObjectKey      string
	ExpectedSize   int64
	ExpectedSHA256 string
	Attempts       int
}

type StagedAssetBackupObject struct {
	Key    string
	Size   int64
	SHA256 string
}
