package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
)

const (
	OutcomeVerifiedCreated = "verified_created"
	OutcomeAlreadyPresent  = "already_present"
)

type RepositorySpec struct {
	Name       string `json:"name"`
	Visibility string `json:"visibility"`
	Purpose    string `json:"purpose"`
}

type RepositoryPacket struct {
	SchemaVersion int              `json:"schema_version"`
	Owner         string           `json:"owner"`
	Repositories  []RepositorySpec `json:"repositories"`
}

type RepositoryState struct {
	NameWithOwner string
	Visibility    string
}

type RepositoryReceipt struct {
	Repository string
	Outcome    string
}

type RepositoryRemote interface {
	ReadRepository(context.Context, string) (RepositoryState, bool, error)
	CreateRepository(context.Context, string, RepositorySpec) error
}

var approvedRepositoryPacket = RepositoryPacket{
	SchemaVersion: 1,
	Owner:         "yaniv256",
	Repositories: []RepositorySpec{
		{Name: "gitoversight.dev", Visibility: "private", Purpose: "private development and review twin for the Git Oversight broker"},
		{Name: "gitoversight.authorization", Visibility: "private", Purpose: "human-approved protected governance policy"},
		{Name: "gitoversight.authorization.dev", Visibility: "private", Purpose: "agent-writable development twin for protected governance policy"},
		{Name: "gitoversight.test-public", Visibility: "public", Purpose: "public mutation acceptance fixture"},
		{Name: "gitoversight.test-public.dev", Visibility: "private", Purpose: "private review twin for the public acceptance fixture"},
		{Name: "gitoversight.test-private", Visibility: "private", Purpose: "private mutation acceptance fixture"},
	},
}

func ApprovedRepositoryPacket() RepositoryPacket {
	packet := approvedRepositoryPacket
	packet.Repositories = append([]RepositorySpec(nil), approvedRepositoryPacket.Repositories...)
	return packet
}

func ValidateRepositoryPacket(packet RepositoryPacket) error {
	if !reflect.DeepEqual(packet, approvedRepositoryPacket) {
		return fmt.Errorf("repository bootstrap packet differs from the approved immutable packet")
	}
	return nil
}

func RepositoryPacketDigest(packet RepositoryPacket) (string, error) {
	if err := ValidateRepositoryPacket(packet); err != nil {
		return "", err
	}
	payload, err := json.Marshal(packet)
	if err != nil {
		return "", fmt.Errorf("marshal repository packet: %w", err)
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func ApplyRepositories(ctx context.Context, remote RepositoryRemote, packet RepositoryPacket) ([]RepositoryReceipt, error) {
	if err := ValidateRepositoryPacket(packet); err != nil {
		return nil, err
	}

	receipts := make([]RepositoryReceipt, 0, len(packet.Repositories))
	for _, spec := range packet.Repositories {
		fullName := packet.Owner + "/" + spec.Name
		state, exists, err := remote.ReadRepository(ctx, fullName)
		if err != nil {
			return receipts, fmt.Errorf("read repository %s before mutation: %w", fullName, err)
		}
		if exists {
			if err := validateRepositoryState(fullName, spec, state); err != nil {
				return receipts, err
			}
			receipts = append(receipts, RepositoryReceipt{Repository: fullName, Outcome: OutcomeAlreadyPresent})
			continue
		}

		createErr := remote.CreateRepository(ctx, packet.Owner, spec)
		state, exists, readErr := remote.ReadRepository(ctx, fullName)
		if readErr != nil {
			return receipts, fmt.Errorf("repository %s mutation outcome indeterminate after independent read: create error=%v; read error=%w", fullName, createErr, readErr)
		}
		if !exists {
			return receipts, fmt.Errorf("repository %s was not independently observed after create: %w", fullName, createErr)
		}
		if err := validateRepositoryState(fullName, spec, state); err != nil {
			return receipts, err
		}
		receipts = append(receipts, RepositoryReceipt{Repository: fullName, Outcome: OutcomeVerifiedCreated})
	}
	return receipts, nil
}

func validateRepositoryState(fullName string, spec RepositorySpec, state RepositoryState) error {
	if state.NameWithOwner != fullName {
		return fmt.Errorf("repository identity mismatch: got %q, want %q", state.NameWithOwner, fullName)
	}
	if state.Visibility != spec.Visibility {
		return fmt.Errorf("repository %s visibility mismatch: got %q, want %q", fullName, state.Visibility, spec.Visibility)
	}
	return nil
}
