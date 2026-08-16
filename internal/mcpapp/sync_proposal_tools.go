package mcpapp

import (
	"context"
	"errors"
	"strings"

	"github.com/yaniv256/gitoversight.dev/internal/brokerapp"
)

const (
	maxMCPSyncIDBytes     = 128
	maxMCPSyncTextBytes   = 64 << 10
	maxMCPSyncPacketBytes = 1 << 20
)

type SyncProposals interface {
	Propose(context.Context, brokerapp.Identity, brokerapp.SyncProposalRequest) (brokerapp.SyncProposalResult, error)
}

type syncProposalArguments struct {
	ID               string `json:"id"`
	Repository       string `json:"repository"`
	Text             string `json:"text"`
	CommitPacketJSON string `json:"commit_packet_json"`
	PacketHeadSHA    string `json:"packet_head_sha"`
}

func (arguments syncProposalArguments) request() (brokerapp.SyncProposalRequest, error) {
	if arguments.ID == "" || len(arguments.ID) > maxMCPSyncIDBytes || strings.ContainsAny(arguments.ID, "/\x00\r\n\t") ||
		!validMCPRepository(arguments.Repository) || strings.TrimSpace(arguments.Text) == "" || len(arguments.Text) > maxMCPSyncTextBytes ||
		arguments.CommitPacketJSON == "" || len(arguments.CommitPacketJSON) > maxMCPSyncPacketBytes || !validMCPObjectID(arguments.PacketHeadSHA) {
		return brokerapp.SyncProposalRequest{}, errInvalidArguments
	}
	return brokerapp.SyncProposalRequest{
		ID: arguments.ID, Repository: arguments.Repository, Text: arguments.Text,
		CommitPacketJSON: arguments.CommitPacketJSON, PacketHeadSHA: arguments.PacketHeadSHA,
	}, nil
}

type syncProposalEnvelope struct {
	ID               string   `json:"id"`
	State            string   `json:"state"`
	ProposalHash     string   `json:"proposal_hash"`
	PublicRepository string   `json:"public_repository"`
	PacketHeadSHA    string   `json:"packet_head_sha"`
	Files            []string `json:"files"`
}

func syncEnvelope(result brokerapp.SyncProposalResult) syncProposalEnvelope {
	return syncProposalEnvelope{
		ID: result.ID, State: result.State, ProposalHash: result.ProposalHash,
		PublicRepository: result.PublicRepository, PacketHeadSHA: result.PacketHeadSHA,
		Files: append([]string(nil), result.Files...),
	}
}

func syncProposalToolErrorCode(err error) string {
	switch {
	case errors.Is(err, brokerapp.ErrSyncProposalInvalid):
		return "sync_proposal_invalid"
	case errors.Is(err, brokerapp.ErrSyncProposalDenied):
		return "sync_proposal_denied"
	case errors.Is(err, brokerapp.ErrSyncProposalRebase):
		return "sync_proposal_rebase_failed"
	case errors.Is(err, brokerapp.ErrSyncProposalExists):
		return "sync_proposal_exists"
	case errors.Is(err, brokerapp.ErrSyncProposalRejected):
		return "sync_proposal_rejected"
	case errors.Is(err, brokerapp.ErrSyncProposalUnavailable):
		return "sync_proposal_unavailable"
	default:
		return "sync_proposal_failed"
	}
}

func appendSyncProposalTool(tools []map[string]any) []map[string]any {
	return append(tools, map[string]any{
		"name": "sync.propose", "title": "Prepare public sync for human review",
		"description": "Create a review-only pre-PR from an authorized private mirror. GitOversight derives the public target, base, manifest, and proposal hash. This does not approve, publish, create a GitHub PR, or merge.",
		"inputSchema": map[string]any{
			"type": "object", "additionalProperties": false,
			"properties": map[string]any{
				"id":                 map[string]any{"type": "string", "minLength": 1, "maxLength": maxMCPSyncIDBytes, "description": "Unique pre-PR proposal ID"},
				"repository":         map[string]any{"type": "string", "minLength": 3, "maxLength": maxMCPRepositoryNameBytes, "description": "Authorized private mirror owner/name; policy derives its public sync target"},
				"text":               map[string]any{"type": "string", "minLength": 1, "maxLength": maxMCPSyncTextBytes, "description": "Exact public PR text the human will review"},
				"commit_packet_json": map[string]any{"type": "string", "minLength": 2, "maxLength": maxMCPSyncPacketBytes, "description": "Exact private export commit packet; server rebases and validates it"},
				"packet_head_sha":    map[string]any{"type": "string", "pattern": "^[0-9a-f]{40}([0-9a-f]{24})?$", "description": "Submitted packet head SHA"},
			},
			"required": []string{"id", "repository", "text", "commit_packet_json", "packet_head_sha"},
		},
		"annotations": map[string]bool{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": true},
	})
}
