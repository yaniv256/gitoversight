package releaseasset

import (
	"testing"
	"time"
)

func TestValidateStageRequiresCompleteIntegrityReservationAndCapabilityBinding(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_720_000_000, 0).UTC()
	stage := Stage{
		TenantID: "tenant-a", ID: "stage-a", AgentID: "zara", CredentialID: "zara-1",
		Repository: "yaniv256/private", Name: "bridge.zip", ContentType: "application/zip",
		ExpectedSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ExpectedSize:   100, ReservedSize: 100, State: StateCreated,
		CapabilityHash: "capability-hash", CapabilityExpiresAt: now.Add(time.Minute),
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := ValidateStage(stage); err != nil {
		t.Fatalf("valid stage rejected: %v", err)
	}
	stage.ReservedSize = 99
	if err := ValidateStage(stage); err == nil {
		t.Fatal("mismatched reservation accepted")
	}
	stage.ExpectedSize = 0
	stage.ReservedSize = 0
	if err := ValidateStage(stage); err != nil {
		t.Fatalf("zero-byte stage rejected: %v", err)
	}
}
