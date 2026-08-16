package releaseasset

import (
	"encoding/base64"
	"testing"
)

func TestMaxBytesLeavesRoomInAPIOperationEnvelope(t *testing.T) {
	const (
		apiMaxBodyBytes     = 42 << 20
		jsonEnvelopeReserve = 64 << 10
	)
	encoded := base64.StdEncoding.EncodedLen(MaxBytes)
	if encoded+jsonEnvelopeReserve > apiMaxBodyBytes {
		t.Fatalf("encoded maximum plus envelope = %d, exceeds API limit %d", encoded+jsonEnvelopeReserve, apiMaxBodyBytes)
	}
}
