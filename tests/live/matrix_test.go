package live

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPermanentFixturesAreExactAndMinimal(t *testing.T) {
	t.Parallel()
	want := []Fixture{
		{Repository: "yaniv256/gitoversight.test-public", Visibility: "public"},
		{Repository: "yaniv256/gitoversight.test-public.dev", Visibility: "private"},
		{Repository: "yaniv256/gitoversight.test-private", Visibility: "private"},
	}
	got := PermanentFixtures()
	if len(got) != len(want) {
		t.Fatalf("fixtures = %d, want %d", len(got), len(want))
	}
	for index := range want {
		if got[index].Repository != want[index].Repository || got[index].Visibility != want[index].Visibility {
			t.Fatalf("fixture[%d] = %#v, want %#v", index, got[index], want[index])
		}
	}
}

func TestAcceptanceMatrixCoversEveryApprovedMisuseClass(t *testing.T) {
	t.Parallel()
	matrix := AcceptanceMatrix()
	if err := ValidateMatrix(matrix); err != nil {
		t.Fatal(err)
	}
	covered := map[string]bool{}
	for _, scenario := range matrix {
		for _, requirement := range scenario.Covers {
			covered[requirement] = true
		}
		if scenario.ExpectedDecision == DecisionDeny && scenario.IndependentRead == "" {
			t.Fatalf("denial %q has no independent zero-mutation read", scenario.ID)
		}
		if scenario.Repository == "yaniv256/gitoversight.test-public" && scenario.ExpectedDecision != DecisionDeny && !scenario.RequiresExactHumanApproval {
			t.Fatalf("public scenario %q can proceed without exact human approval", scenario.ID)
		}
	}
	for _, requirement := range RequiredCoverage() {
		if !covered[requirement] {
			t.Errorf("missing acceptance coverage %q", requirement)
		}
	}
	if !covered["approval.exact_allow"] {
		t.Error("missing positive exact-approved public publication proof")
	}
}

func TestRunnerNeverRetriesMutationAndIndependentlyObservesEveryResult(t *testing.T) {
	t.Parallel()
	scenarios := []Scenario{
		{ID: "allow", Repository: "yaniv256/gitoversight.test-private", Operation: "issue.create", ExpectedDecision: DecisionAllow, IndependentRead: "issue.by_marker"},
		{ID: "deny", Repository: "yaniv256/gitoversight.test-public", Operation: "issue.create", ExpectedDecision: DecisionDeny, IndependentRead: "issue.by_marker"},
	}
	executor := &recordingExecutor{results: map[string]ExecutionResult{
		"allow": {Decision: DecisionAllow, State: "verified", Attempts: 1, Receipt: "receipt-allow"},
		"deny":  {Decision: DecisionDeny, State: "denied", Code: "unapproved_public", Attempts: 0, Receipt: "receipt-deny"},
	}}
	observer := &recordingObserver{results: map[string]Observation{
		"allow": {MutationCount: 1, EvidenceSHA256: strings.Repeat("a", 64)},
		"deny":  {MutationCount: 0, EvidenceSHA256: strings.Repeat("b", 64)},
	}}
	report, err := Run(context.Background(), scenarios, executor, observer)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 2 || executor.calls["allow"] != 1 || executor.calls["deny"] != 1 {
		t.Fatalf("report=%#v calls=%#v", report, executor.calls)
	}
	if observer.calls["allow"] != 1 || observer.calls["deny"] != 1 {
		t.Fatalf("independent reads = %#v", observer.calls)
	}
}

func TestRunnerRejectsAttemptCountOrDenialMutationContradictions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		execution ExecutionResult
		observe   Observation
	}{
		{name: "blind retry", execution: ExecutionResult{Decision: DecisionAllow, State: "verified", Attempts: 2, Receipt: "receipt-1"}, observe: Observation{MutationCount: 1, EvidenceSHA256: strings.Repeat("a", 64)}},
		{name: "denial mutated", execution: ExecutionResult{Decision: DecisionDeny, State: "denied", Code: "denied", Attempts: 0, Receipt: "receipt-1"}, observe: Observation{MutationCount: 1, EvidenceSHA256: strings.Repeat("a", 64)}},
		{name: "missing receipt", execution: ExecutionResult{Decision: DecisionAllow, State: "verified", Attempts: 1}, observe: Observation{MutationCount: 1, EvidenceSHA256: strings.Repeat("a", 64)}},
		{name: "missing denial code", execution: ExecutionResult{Decision: DecisionDeny, State: "denied", Attempts: 0, Receipt: "receipt-1"}, observe: Observation{MutationCount: 0, EvidenceSHA256: strings.Repeat("a", 64)}},
		{name: "missing independent evidence digest", execution: ExecutionResult{Decision: DecisionAllow, State: "verified", Attempts: 1, Receipt: "receipt-1"}, observe: Observation{MutationCount: 1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scenario := Scenario{ID: "case", Repository: "yaniv256/gitoversight.test-private", Operation: "issue.create", ExpectedDecision: test.execution.Decision, IndependentRead: "issue.by_marker"}
			_, err := Run(context.Background(), []Scenario{scenario}, &recordingExecutor{results: map[string]ExecutionResult{"case": test.execution}}, &recordingObserver{results: map[string]Observation{"case": test.observe}})
			if err == nil {
				t.Fatal("contradictory evidence was accepted")
			}
		})
	}
}

type recordingExecutor struct {
	results map[string]ExecutionResult
	calls   map[string]int
}

func (executor *recordingExecutor) Execute(_ context.Context, scenario Scenario) (ExecutionResult, error) {
	if executor.calls == nil {
		executor.calls = map[string]int{}
	}
	executor.calls[scenario.ID]++
	result, ok := executor.results[scenario.ID]
	if !ok {
		return ExecutionResult{}, errors.New("missing execution result")
	}
	return result, nil
}

type recordingObserver struct {
	results map[string]Observation
	calls   map[string]int
}

func (observer *recordingObserver) Observe(_ context.Context, scenario Scenario) (Observation, error) {
	if observer.calls == nil {
		observer.calls = map[string]int{}
	}
	observer.calls[scenario.ID]++
	result, ok := observer.results[scenario.ID]
	if !ok {
		return Observation{}, errors.New("missing observation")
	}
	return result, nil
}
