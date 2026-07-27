package contracts_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/yaniv256/gitoversight.dev/internal/contracts"
	"github.com/yaniv256/gitoversight.dev/internal/policy"
)

func TestSchemasAreVersionedJSONDocuments(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"policy", "request", "manifest", "approval", "receipt", "enrollment"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			payload, err := os.ReadFile(filepath.Join("..", "..", "schemas", name+".schema.json"))
			if err != nil {
				t.Fatal(err)
			}
			var schema map[string]any
			if err := json.Unmarshal(payload, &schema); err != nil {
				t.Fatalf("invalid schema JSON: %v", err)
			}
			if schema["$schema"] == "" || schema["$id"] == "" {
				t.Fatal("schema requires $schema and $id")
			}
		})
	}
}

func TestFixturesAgreeWithDraft202012Schemas(t *testing.T) {
	t.Parallel()
	tests := []struct {
		kind, fixture string
		valid         bool
	}{
		{"policy", "policy.valid.json", true},
		{"policy", "policy.wildcard-repository.json", false},
		{"policy", "policy.missing-owner.json", false},
		{"request", "request.valid.json", true},
		{"request", "request.unknown-operation.json", false},
		{"approval", "approval.valid.json", true},
		{"approval", "approval.incomplete.json", false},
		{"receipt", "receipt.valid.json", true},
	}
	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			schemaPayload, err := os.ReadFile(filepath.Join("..", "..", "schemas", test.kind+".schema.json"))
			if err != nil {
				t.Fatal(err)
			}
			var schemaDocument any
			if err := json.Unmarshal(schemaPayload, &schemaDocument); err != nil {
				t.Fatal(err)
			}
			compiler := jsonschema.NewCompiler()
			compiler.AssertFormat()
			location := "https://gitoversight.invalid/" + test.kind
			if err := compiler.AddResource(location, schemaDocument); err != nil {
				t.Fatal(err)
			}
			schema, err := compiler.Compile(location)
			if err != nil {
				t.Fatal(err)
			}
			fixturePayload, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", test.fixture))
			if err != nil {
				t.Fatal(err)
			}
			var instance any
			if err := json.Unmarshal(fixturePayload, &instance); err != nil {
				t.Fatal(err)
			}
			err = schema.Validate(instance)
			if test.valid && err != nil {
				t.Fatalf("schema rejected valid fixture: %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("schema accepted invalid fixture")
			}
		})
	}
}

func TestBootstrapPolicyMatchesContract(t *testing.T) {
	t.Parallel()

	payload, err := os.ReadFile(filepath.Join("..", "..", "policy", "bootstrap.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := contracts.Validate(contracts.Policy, payload); err != nil {
		t.Fatal(err)
	}
}

func TestProductionPolicyV2IsAValidRuntimeSnapshot(t *testing.T) {
	t.Parallel()
	payload, err := os.ReadFile(filepath.Join("..", "..", "policy", "production.v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var snapshot policy.Snapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Generation != 2 {
		t.Fatalf("generation = %d, want 2", snapshot.Generation)
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatal(err)
	}
}
