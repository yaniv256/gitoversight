package live

import (
	"context"
	"errors"
	"fmt"
	"regexp"
)

var (
	receiptIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{2,255}$`)
	sha256Pattern    = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type ExecutionResult struct {
	Decision Decision `json:"decision"`
	State    string   `json:"state"`
	Code     string   `json:"code,omitempty"`
	Attempts int      `json:"attempts"`
	Receipt  string   `json:"receipt,omitempty"`
}

type Observation struct {
	MutationCount  int    `json:"mutation_count"`
	ResourceID     string `json:"resource_id,omitempty"`
	EvidenceSHA256 string `json:"evidence_sha256"`
}

type ScenarioResult struct {
	ScenarioID  string          `json:"scenario_id"`
	Execution   ExecutionResult `json:"execution"`
	Observation Observation     `json:"observation"`
}

type Report struct {
	Results []ScenarioResult `json:"results"`
}

type Executor interface {
	Execute(context.Context, Scenario) (ExecutionResult, error)
}

type Observer interface {
	Observe(context.Context, Scenario) (Observation, error)
}

func Run(ctx context.Context, scenarios []Scenario, executor Executor, observer Observer) (Report, error) {
	if len(scenarios) == 0 || executor == nil || observer == nil {
		return Report{}, errors.New("scenarios, executor, and observer are required")
	}
	report := Report{Results: make([]ScenarioResult, 0, len(scenarios))}
	for _, scenario := range scenarios {
		execution, err := executor.Execute(ctx, scenario)
		if err != nil {
			return report, fmt.Errorf("execute %s: %w", scenario.ID, err)
		}
		if execution.Decision != scenario.ExpectedDecision {
			return report, fmt.Errorf("scenario %s decision = %s, want %s", scenario.ID, execution.Decision, scenario.ExpectedDecision)
		}
		if execution.State == "" || !receiptIDPattern.MatchString(execution.Receipt) {
			return report, fmt.Errorf("scenario %s lacks a safe durable receipt", scenario.ID)
		}
		if execution.Decision == DecisionDeny && !receiptIDPattern.MatchString(execution.Code) {
			return report, fmt.Errorf("scenario %s lacks a stable denial code", scenario.ID)
		}
		if execution.Attempts < 0 || execution.Attempts > 1 {
			return report, fmt.Errorf("scenario %s mutation attempts = %d, want at most one", scenario.ID, execution.Attempts)
		}
		if execution.Decision != DecisionAllow && execution.Attempts != 0 {
			return report, fmt.Errorf("scenario %s attempted a mutation after %s", scenario.ID, execution.Decision)
		}
		observation, err := observer.Observe(ctx, scenario)
		if err != nil {
			return report, fmt.Errorf("observe %s: %w", scenario.ID, err)
		}
		if observation.MutationCount < 0 || observation.MutationCount > 1 {
			return report, fmt.Errorf("scenario %s observed %d mutations", scenario.ID, observation.MutationCount)
		}
		if !sha256Pattern.MatchString(observation.EvidenceSHA256) {
			return report, fmt.Errorf("scenario %s lacks an independent evidence digest", scenario.ID)
		}
		if execution.Decision != DecisionAllow && observation.MutationCount != 0 {
			return report, fmt.Errorf("scenario %s denied but independently observed a mutation", scenario.ID)
		}
		if execution.Decision == DecisionAllow && execution.State == "verified" && observation.MutationCount != 1 {
			return report, fmt.Errorf("scenario %s claimed verified without exactly one observed mutation", scenario.ID)
		}
		report.Results = append(report.Results, ScenarioResult{ScenarioID: scenario.ID, Execution: execution, Observation: observation})
	}
	return report, nil
}
