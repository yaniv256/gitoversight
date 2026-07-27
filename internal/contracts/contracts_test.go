package contracts_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/contracts"
)

func TestContractFixtures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		kind    contracts.Kind
		fixture string
		wantErr bool
	}{
		{name: "approved policy", kind: contracts.Policy, fixture: "policy.valid.json"},
		{name: "policy rejects wildcard repository", kind: contracts.Policy, fixture: "policy.wildcard-repository.json", wantErr: true},
		{name: "policy rejects missing owner", kind: contracts.Policy, fixture: "policy.missing-owner.json", wantErr: true},
		{name: "exact request", kind: contracts.Request, fixture: "request.valid.json"},
		{name: "request rejects unknown operation", kind: contracts.Request, fixture: "request.unknown-operation.json", wantErr: true},
		{name: "exact approval", kind: contracts.Approval, fixture: "approval.valid.json"},
		{name: "approval rejects incomplete packet", kind: contracts.Approval, fixture: "approval.incomplete.json", wantErr: true},
		{name: "receipt", kind: contracts.Receipt, fixture: "receipt.valid.json"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join("..", "..", "tests", "fixtures", test.fixture)
			payload, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			err = contracts.Validate(test.kind, payload)
			if test.wantErr && err == nil {
				t.Fatal("expected validation error")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestCanonicalApprovalHashIsStable(t *testing.T) {
	t.Parallel()

	payload, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "approval.valid.json"))
	if err != nil {
		t.Fatal(err)
	}

	first, err := contracts.CanonicalHash(contracts.Approval, payload)
	if err != nil {
		t.Fatal(err)
	}
	second, err := contracts.CanonicalHash(contracts.Approval, payload)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("hash changed: %q != %q", first, second)
	}
}

func TestContractRejectsTrailingJSON(t *testing.T) {
	t.Parallel()

	payload, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "request.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, []byte(`{"second":true}`)...)
	if err := contracts.Validate(contracts.Request, payload); err == nil {
		t.Fatal("expected trailing JSON to be rejected")
	}
}
