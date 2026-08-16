package server

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/policy"
)

func TestEnrollWorkAgentRegistersRemoteWithoutBroadeningRepositoryPrivileges(t *testing.T) {
	ctx := context.Background()
	broker := newTestDurableBroker(openDurableDB(t))
	if err := broker.InstallPolicy(ctx, "tenant-a", durablePolicy()); err != nil {
		t.Fatal(err)
	}
	before, err := broker.PolicyStatus(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	after, err := broker.EnrollWorkAgent(ctx, "tenant-a", "yaniv", WorkAgentEnrollment{
		AgentID: "chatgpt-work", DisplayName: "ChatGPT Work", RepositoryScope: []string{"yaniv256/private"},
		ExpectedGeneration: before.Generation, ExpectedPolicyHash: before.PolicyHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	if after.Generation != before.Generation+1 || after.PolicyHash == before.PolicyHash {
		t.Fatalf("unexpected enrolled status: before=%+v after=%+v", before, after)
	}
	snapshot, err := broker.policy(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	agent := snapshot.Agents["chatgpt-work"]
	if !agent.IsRemote() || agent.UID != 0 || agent.FirstName != "ChatGPT Work" {
		t.Fatalf("unexpected remote agent: %+v", agent)
	}
	for name, repository := range snapshot.Repositories {
		if len(repository.Writers) != 0 {
			t.Fatalf("enrollment broadened writers on %s: %v", name, repository.Writers)
		}
	}
	privateDecision := policy.Evaluate(snapshot, policy.Request{Caller: "chatgpt-work", Repository: "yaniv256/private", Operation: "branch.push"})
	if privateDecision.Code != policy.AllowedPrivateContributor {
		t.Fatalf("private contribution decision = %+v", privateDecision)
	}
	publicDecision := policy.Evaluate(snapshot, policy.Request{Caller: "chatgpt-work", Repository: "yaniv256/public", Operation: "branch.push"})
	if publicDecision.Code != policy.ApprovalRequired {
		t.Fatalf("public privilege was broadened: %+v", publicDecision)
	}
}

func TestEnrollWorkAgentSupportsExplicitAllPrivateScope(t *testing.T) {
	ctx := context.Background()
	broker := newTestDurableBroker(openDurableDB(t))
	if err := broker.InstallPolicy(ctx, "tenant-a", durablePolicy()); err != nil {
		t.Fatal(err)
	}
	current, _ := broker.PolicyStatus(ctx, "tenant-a")
	_, err := broker.EnrollWorkAgent(ctx, "tenant-a", "yaniv", WorkAgentEnrollment{
		AgentID: "mobile", DisplayName: "Mobile Work", AllPrivate: true,
		ExpectedGeneration: current.Generation, ExpectedPolicyHash: current.PolicyHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := broker.policy(ctx, "tenant-a")
	if err != nil || !snapshot.Agents["mobile"].IsRemote() {
		t.Fatalf("all-private agent was not registered: %+v, %v", snapshot.Agents["mobile"], err)
	}
}

func TestEnrollWorkAgentRejectsInvalidIdentityAndRepositoryScopes(t *testing.T) {
	tests := []struct {
		name       string
		enrollment WorkAgentEnrollment
	}{
		{name: "duplicate identity", enrollment: WorkAgentEnrollment{AgentID: "zara", DisplayName: "Zara Work", AllPrivate: true}},
		{name: "public repository", enrollment: WorkAgentEnrollment{AgentID: "work", DisplayName: "Work", RepositoryScope: []string{"yaniv256/public"}}},
		{name: "unknown repository", enrollment: WorkAgentEnrollment{AgentID: "work", DisplayName: "Work", RepositoryScope: []string{"yaniv256/missing"}}},
		{name: "ambiguous scope", enrollment: WorkAgentEnrollment{AgentID: "work", DisplayName: "Work", AllPrivate: true, RepositoryScope: []string{"yaniv256/private"}}},
		{name: "missing scope", enrollment: WorkAgentEnrollment{AgentID: "work", DisplayName: "Work"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			broker := newTestDurableBroker(openDurableDB(t))
			if err := broker.InstallPolicy(ctx, "tenant-a", durablePolicy()); err != nil {
				t.Fatal(err)
			}
			current, _ := broker.PolicyStatus(ctx, "tenant-a")
			test.enrollment.ExpectedGeneration = current.Generation
			test.enrollment.ExpectedPolicyHash = current.PolicyHash
			if _, err := broker.EnrollWorkAgent(ctx, "tenant-a", "yaniv", test.enrollment); !errors.Is(err, ErrDurableInvalid) {
				t.Fatalf("expected invalid enrollment, got %v", err)
			}
			after, err := broker.PolicyStatus(ctx, "tenant-a")
			if err != nil || after.Generation != current.Generation {
				t.Fatalf("rejected enrollment changed policy: %+v, %v", after, err)
			}
		})
	}
}

func TestEnrollWorkAgentGenerationRaceAllowsOnePromotion(t *testing.T) {
	ctx := context.Background()
	broker := newTestDurableBroker(openDurableDB(t))
	if err := broker.InstallPolicy(ctx, "tenant-a", durablePolicy()); err != nil {
		t.Fatal(err)
	}
	current, _ := broker.PolicyStatus(ctx, "tenant-a")
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, id := range []string{"work-one", "work-two"} {
		id := id
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := broker.EnrollWorkAgent(ctx, "tenant-a", "yaniv", WorkAgentEnrollment{
				AgentID: id, DisplayName: id, AllPrivate: true,
				ExpectedGeneration: current.Generation, ExpectedPolicyHash: current.PolicyHash,
			})
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful concurrent promotions = %d, want 1", successes)
	}
	after, err := broker.PolicyStatus(ctx, "tenant-a")
	if err != nil || after.Generation != current.Generation+1 {
		t.Fatalf("generation after race = %+v, %v", after, err)
	}
	snapshot, err := broker.policy(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	registered := 0
	for _, id := range []string{"work-one", "work-two"} {
		if _, ok := snapshot.Agents[id]; ok {
			registered++
		}
	}
	if registered != 1 {
		t.Fatalf("registered racing agents = %d, want 1", registered)
	}
}
