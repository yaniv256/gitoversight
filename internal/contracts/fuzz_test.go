package contracts_test

import (
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/contracts"
)

func FuzzRequestValidationNeverPanicsOrAcceptsUnknownOperations(f *testing.F) {
	f.Add([]byte(`{"schema_version":1,"request_id":"request-1","repository":"yaniv256/private","operation":"pull_request.create"}`))
	f.Add([]byte(`{"schema_version":1,"request_id":"request-2","repository":"yaniv256/private","operation":"made.up"}`))
	f.Add([]byte(`not-json`))
	f.Fuzz(func(t *testing.T, payload []byte) {
		_ = contracts.Validate(contracts.Request, payload)
	})
}

func FuzzApprovalCanonicalHashNeverPanics(f *testing.F) {
	f.Add([]byte(`{"schema_version":1,"approval_id":"approval-1","source_repository":"yaniv256/source","destination_repository":"yaniv256/destination","source_commit":"abcdef1","export_tree":"1234567","paths":["README.md"],"metadata":{"title":"Review","body":"Body"},"operations":["pull_request.create"],"approver":"yaniv","expires_at":"2026-07-19T00:00:00Z","nonce":"0123456789abcdef"}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = contracts.CanonicalHash(contracts.Approval, payload)
	})
}
