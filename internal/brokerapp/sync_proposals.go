package brokerapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/commitpacket"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
	"github.com/yaniv256/gitoversight.dev/internal/prpreview"
	"github.com/yaniv256/gitoversight.dev/internal/syncproposal"
	"github.com/yaniv256/gitoversight.dev/internal/workerrpc"
)

var (
	ErrSyncProposalInvalid     = errors.New("sync proposal is invalid")
	ErrSyncProposalDenied      = errors.New("sync proposal is denied")
	ErrSyncProposalRebase      = errors.New("sync proposal rebase failed")
	ErrSyncProposalExists      = errors.New("sync proposal already exists")
	ErrSyncProposalRejected    = errors.New("sync proposal was rejected")
	ErrSyncProposalUnavailable = errors.New("sync proposal service unavailable")
)

type SyncProposalPolicyError struct {
	Code   policy.Code
	Reason string
}

func (err SyncProposalPolicyError) Error() string { return string(err.Code) + ": " + err.Reason }
func (err SyncProposalPolicyError) Unwrap() error { return ErrSyncProposalDenied }

type SyncProposalBaseReader interface {
	ReadBase(workerrpc.BaseReadRequest) (workerrpc.BaseRead, error)
}

type SyncProposalStore interface {
	CreateSyncProposal(context.Context, SyncProposalRecord, string, time.Time) error
}

type SyncProposalPolicySource interface {
	PolicySnapshot(context.Context, string) (policy.Snapshot, error)
}

type SyncProposalRecord struct {
	TenantID, ID, PrivateRepository, PublicRepository string
	ProposalText, CommitPacketJSON, PacketHeadSHA     string
	FileManifest                                      []string
	CreatedBy                                         string
}

type SyncProposalRequest struct {
	ID, Repository, Text, CommitPacketJSON, PacketHeadSHA string
}

type SyncProposalResult struct {
	ID, State, ProposalHash, PublicRepository, PacketHeadSHA string
	Files                                                    []string
}

type SyncProposalConfig struct {
	Policy     policy.Snapshot
	Policies   SyncProposalPolicySource
	Store      SyncProposalStore
	Bases      SyncProposalBaseReader
	BaseBranch string
	Now        func() time.Time
}

type SyncProposalService struct {
	policy     policy.Snapshot
	policies   SyncProposalPolicySource
	store      SyncProposalStore
	bases      SyncProposalBaseReader
	baseBranch string
	now        func() time.Time
}

func NewSyncProposalService(config SyncProposalConfig) *SyncProposalService {
	if config.BaseBranch == "" {
		config.BaseBranch = "main"
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	return &SyncProposalService{policy: config.Policy, policies: config.Policies, store: config.Store, bases: config.Bases, baseBranch: config.BaseBranch, now: config.Now}
}

func (service *SyncProposalService) Propose(ctx context.Context, identity Identity, request SyncProposalRequest) (SyncProposalResult, error) {
	if strings.TrimSpace(identity.TenantID) == "" || strings.TrimSpace(identity.AgentID) == "" ||
		strings.TrimSpace(request.ID) == "" || strings.TrimSpace(request.Repository) == "" ||
		strings.TrimSpace(request.Text) == "" || strings.TrimSpace(request.CommitPacketJSON) == "" || strings.TrimSpace(request.PacketHeadSHA) == "" {
		return SyncProposalResult{}, ErrSyncProposalInvalid
	}
	if service.store == nil || service.bases == nil {
		return SyncProposalResult{}, ErrSyncProposalUnavailable
	}
	snapshot, err := service.currentPolicy(ctx, identity.TenantID)
	if err != nil {
		return SyncProposalResult{}, errors.Join(ErrSyncProposalUnavailable, err)
	}
	repository, exists := snapshot.Repositories[request.Repository]
	if !exists {
		return SyncProposalResult{}, SyncProposalPolicyError{Code: policy.RepositoryUnknown, Reason: "repository is not registered"}
	}
	agent, registered := snapshot.Agents[identity.AgentID]
	if !registered {
		return SyncProposalResult{}, SyncProposalPolicyError{Code: policy.CallerUnknown, Reason: "caller is not registered"}
	}
	remoteScoped := agent.IsRemote() && identity.CredentialID != "" && repository.Visibility == "private" && repository.SyncsTo != ""
	if !remoteScoped {
		decision := policy.Evaluate(snapshot, policy.Request{Caller: identity.AgentID, Repository: request.Repository, Operation: "sync.propose"})
		if decision.Code != policy.Allowed {
			return SyncProposalResult{}, SyncProposalPolicyError{Code: decision.Code, Reason: decision.Reason}
		}
	}
	target := repository.SyncsTo
	if public, ok := snapshot.Repositories[target]; !ok || public.Visibility != "public" {
		return SyncProposalResult{}, SyncProposalPolicyError{Code: policy.SyncMirrorRequired, Reason: "linked public target is not a registered public repository"}
	}
	packetJSON, manifest, err := service.Rebase(target, request.CommitPacketJSON)
	if err != nil {
		return SyncProposalResult{}, errors.Join(ErrSyncProposalRebase, err)
	}
	headSHA := rebasedSyncHeadSHA(packetJSON, request.PacketHeadSHA)
	record := SyncProposalRecord{
		TenantID: identity.TenantID, ID: request.ID,
		PrivateRepository: request.Repository, PublicRepository: target,
		ProposalText: request.Text, FileManifest: manifest,
		CommitPacketJSON: packetJSON, PacketHeadSHA: headSHA, CreatedBy: identity.AgentID,
	}
	if err := service.store.CreateSyncProposal(ctx, record, snapshot.QueueCurator, service.now().UTC()); err != nil {
		return SyncProposalResult{}, err
	}
	hash := syncproposal.Hash(request.Text, manifest, headSHA, packetJSON)
	return SyncProposalResult{
		ID: request.ID, State: "proposed", ProposalHash: hash,
		PublicRepository: target, PacketHeadSHA: headSHA, Files: append([]string(nil), manifest...),
	}, nil
}

func (service *SyncProposalService) currentPolicy(ctx context.Context, tenantID string) (policy.Snapshot, error) {
	if service.policies != nil {
		return service.policies.PolicySnapshot(ctx, tenantID)
	}
	if len(service.policy.Agents) == 0 || len(service.policy.Repositories) == 0 {
		return policy.Snapshot{}, errors.New("policy source is unavailable")
	}
	return service.policy, nil
}

// Rebase derives the exact public manifest and packet from the current public
// base. It is shared by initial proposal and revision paths; callers cannot
// supply their own target, base, or manifest authority.
func (service *SyncProposalService) Rebase(target, packetJSON string) (string, []string, error) {
	if service.bases == nil {
		return "", nil, errors.New("public base resolution is unavailable")
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(packetJSON), &raw); err != nil {
		return "", nil, errors.New("commit packet is not JSON")
	}
	packet, present, err := commitpacket.Decode(raw)
	if err != nil || !present {
		return "", nil, errors.New("commit packet is invalid")
	}
	base, err := service.bases.ReadBase(workerrpc.BaseReadRequest{Repository: target, Branch: service.baseBranch})
	if err != nil {
		return "", nil, err
	}
	rebased, err := prpreview.Rebase(base.Entries, base.TreeSHA, base.CommitSHA, packet.Tree.Entries, packet.Blobs)
	if err != nil {
		return "", nil, err
	}
	packet.Tree.Entries, packet.Tree.BaseTree, packet.Blobs = rebased.Entries, rebased.BaseTreeSHA, rebased.Blobs
	if rebased.BaseCommitSHA != "" {
		packet.Reparent(rebased.BaseCommitSHA)
	} else {
		packet.Reparent()
	}
	if err := packet.Validate(); err != nil {
		return "", nil, fmt.Errorf("rebased packet is invalid: %w", err)
	}
	raw["object_package"], raw["sha"] = packet, packet.Commit.SHA
	rebasedJSON, err := json.Marshal(raw)
	if err != nil {
		return "", nil, err
	}
	return string(rebasedJSON), rebased.Manifest, nil
}

func rebasedSyncHeadSHA(packetJSON, submitted string) string {
	var raw map[string]any
	if err := json.Unmarshal([]byte(packetJSON), &raw); err != nil {
		return submitted
	}
	packet, present, err := commitpacket.Decode(raw)
	if err != nil || !present || packet.Commit.SHA == "" {
		return submitted
	}
	return packet.Commit.SHA
}
