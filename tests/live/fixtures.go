package live

import (
	"errors"
	"fmt"
	"regexp"
)

type Decision string

const (
	DecisionAllow            Decision = "allow"
	DecisionDeny             Decision = "deny"
	DecisionAwaitingApproval Decision = "awaiting_approval"
)

type Fixture struct {
	Repository string `json:"repository"`
	Visibility string `json:"visibility"`
}

type Scenario struct {
	ID                         string   `json:"id"`
	Repository                 string   `json:"repository"`
	Operation                  string   `json:"operation"`
	ExpectedDecision           Decision `json:"expected_decision"`
	RequiresExactHumanApproval bool     `json:"requires_exact_human_approval,omitempty"`
	IndependentRead            string   `json:"independent_read"`
	Covers                     []string `json:"covers"`
}

var scenarioID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,79}$`)

func PermanentFixtures() []Fixture {
	return []Fixture{
		{Repository: "yaniv256/gitoversight.test-public", Visibility: "public"},
		{Repository: "yaniv256/gitoversight.test-public.dev", Visibility: "private"},
		{Repository: "yaniv256/gitoversight.test-private", Visibility: "private"},
	}
}

func RequiredCoverage() []string {
	return []string{
		"credential.unknown", "credential.revoked", "credential.replayed", "credential.expired", "credential.tenant_mismatch",
		"ownership.owner_allow", "ownership.non_owner_deny", "branch.exact_allow", "branch.novel_object_publication", "branch.substituted_deny", "branch.protected_deny",
		"approval.exact_allow", "approval.stale", "approval.modified", "approval.expired", "approval.replayed", "approval.wrong_human",
		"public.agent_attribution_deny", "destructive.force_push_deny", "destructive.delete_deny", "settings.unapproved_deny",
		"access.unapproved_deny", "release.unapproved_deny", "merge.unapproved_deny", "github.app_suspension",
		"github.token_expiry", "audit.checkpoint_failure", "execution.ambiguous_zero_retry", "notification.outage_non_authoritative",
		"cross_user.signed_identity", "cross_user.novel_commit_publication", "bootstrap.direct_write_fails", "bootstrap.private_broker_allow", "bootstrap.public_broker_deny",
	}
}

func AcceptanceMatrix() []Scenario {
	private := "yaniv256/gitoversight.test-private"
	privateTwin := "yaniv256/gitoversight.test-public.dev"
	public := "yaniv256/gitoversight.test-public"
	return []Scenario{
		{ID: "unknown-credential-deny", Repository: private, Operation: "issue.create", ExpectedDecision: DecisionDeny, IndependentRead: "issue.by_marker", Covers: []string{"credential.unknown"}},
		{ID: "revoked-credential-deny", Repository: private, Operation: "issue.create", ExpectedDecision: DecisionDeny, IndependentRead: "issue.by_marker", Covers: []string{"credential.revoked"}},
		{ID: "replayed-signature-deny", Repository: private, Operation: "issue.create", ExpectedDecision: DecisionDeny, IndependentRead: "issue.by_marker", Covers: []string{"credential.replayed"}},
		{ID: "expired-signature-deny", Repository: private, Operation: "issue.create", ExpectedDecision: DecisionDeny, IndependentRead: "issue.by_marker", Covers: []string{"credential.expired"}},
		{ID: "tenant-mismatch-deny", Repository: private, Operation: "issue.create", ExpectedDecision: DecisionDeny, IndependentRead: "issue.by_marker", Covers: []string{"credential.tenant_mismatch"}},
		{ID: "private-owner-allow", Repository: private, Operation: "issue.create", ExpectedDecision: DecisionAllow, IndependentRead: "issue.by_marker", Covers: []string{"ownership.owner_allow", "bootstrap.private_broker_allow"}},
		{ID: "private-non-owner-deny", Repository: private, Operation: "issue.create", ExpectedDecision: DecisionDeny, IndependentRead: "issue.by_marker", Covers: []string{"ownership.non_owner_deny"}},
		{ID: "exact-contribution-novel-commit-allow", Repository: private, Operation: "branch.push", ExpectedDecision: DecisionAllow, IndependentRead: "git.ref_and_commit", Covers: []string{"branch.exact_allow", "branch.novel_object_publication"}},
		{ID: "substituted-contribution-branch-deny", Repository: private, Operation: "branch.push", ExpectedDecision: DecisionDeny, IndependentRead: "git.ref", Covers: []string{"branch.substituted_deny"}},
		{ID: "protected-branch-deny", Repository: private, Operation: "branch.push", ExpectedDecision: DecisionDeny, IndependentRead: "git.ref", Covers: []string{"branch.protected_deny"}},
		{ID: "stale-public-approval-deny", Repository: public, Operation: "pull_request.create", ExpectedDecision: DecisionDeny, IndependentRead: "pull_request.by_marker", Covers: []string{"approval.stale"}},
		{ID: "modified-public-packet-deny", Repository: public, Operation: "pull_request.create", ExpectedDecision: DecisionDeny, IndependentRead: "pull_request.by_marker", Covers: []string{"approval.modified"}},
		{ID: "expired-public-approval-deny", Repository: public, Operation: "pull_request.create", ExpectedDecision: DecisionDeny, IndependentRead: "pull_request.by_marker", Covers: []string{"approval.expired"}},
		{ID: "replayed-public-approval-deny", Repository: public, Operation: "pull_request.create", ExpectedDecision: DecisionDeny, IndependentRead: "pull_request.by_marker", Covers: []string{"approval.replayed"}},
		{ID: "wrong-human-public-approval-deny", Repository: public, Operation: "pull_request.create", ExpectedDecision: DecisionDeny, IndependentRead: "pull_request.by_marker", Covers: []string{"approval.wrong_human"}},
		{ID: "public-agent-attribution-deny", Repository: public, Operation: "pull_request.create", ExpectedDecision: DecisionDeny, IndependentRead: "pull_request.by_marker", Covers: []string{"public.agent_attribution_deny"}},
		{ID: "force-push-deny", Repository: private, Operation: "branch.force_push", ExpectedDecision: DecisionDeny, IndependentRead: "git.ref", Covers: []string{"destructive.force_push_deny"}},
		{ID: "repository-delete-deny", Repository: private, Operation: "repository.delete", ExpectedDecision: DecisionDeny, IndependentRead: "repository.exists", Covers: []string{"destructive.delete_deny"}},
		{ID: "repository-settings-deny", Repository: private, Operation: "repository.settings.update", ExpectedDecision: DecisionDeny, IndependentRead: "repository.settings", Covers: []string{"settings.unapproved_deny"}},
		{ID: "repository-access-deny", Repository: private, Operation: "repository.access.update", ExpectedDecision: DecisionDeny, IndependentRead: "repository.collaborators", Covers: []string{"access.unapproved_deny"}},
		{ID: "release-publish-deny", Repository: public, Operation: "release.publish", ExpectedDecision: DecisionDeny, IndependentRead: "release.by_tag", Covers: []string{"release.unapproved_deny"}},
		{ID: "merge-without-scope-deny", Repository: public, Operation: "pull_request.merge", ExpectedDecision: DecisionDeny, IndependentRead: "pull_request.merge_state", Covers: []string{"merge.unapproved_deny"}},
		{ID: "app-suspension-fails-closed", Repository: private, Operation: "issue.create", ExpectedDecision: DecisionDeny, IndependentRead: "issue.by_marker", Covers: []string{"github.app_suspension"}},
		{ID: "token-expiry-fails-closed", Repository: private, Operation: "issue.create", ExpectedDecision: DecisionDeny, IndependentRead: "issue.by_marker", Covers: []string{"github.token_expiry"}},
		{ID: "checkpoint-failure-deny", Repository: private, Operation: "issue.create", ExpectedDecision: DecisionDeny, IndependentRead: "issue.by_marker", Covers: []string{"audit.checkpoint_failure"}},
		{ID: "ambiguous-response-one-attempt", Repository: private, Operation: "issue.create", ExpectedDecision: DecisionAllow, IndependentRead: "issue.by_marker", Covers: []string{"execution.ambiguous_zero_retry"}},
		{ID: "notification-outage-private-allow", Repository: private, Operation: "issue.create", ExpectedDecision: DecisionAllow, IndependentRead: "issue.by_marker", Covers: []string{"notification.outage_non_authoritative"}},
		{ID: "cross-unix-user-novel-commit-publication", Repository: private, Operation: "branch.push", ExpectedDecision: DecisionAllow, IndependentRead: "git.ref_and_commit", Covers: []string{"cross_user.signed_identity", "cross_user.novel_commit_publication"}},
		{ID: "direct-github-write-fails", Repository: private, Operation: "direct.github.write", ExpectedDecision: DecisionDeny, IndependentRead: "git.ref", Covers: []string{"bootstrap.direct_write_fails"}},
		{ID: "unapproved-public-broker-deny", Repository: public, Operation: "issue.create", ExpectedDecision: DecisionDeny, IndependentRead: "issue.by_marker", Covers: []string{"bootstrap.public_broker_deny"}},
		{ID: "approved-public-packet-awaits-human", Repository: public, Operation: "pull_request.create", ExpectedDecision: DecisionAwaitingApproval, RequiresExactHumanApproval: true, IndependentRead: "pull_request.by_marker", Covers: []string{"approval.modified"}},
		{ID: "exact-approved-public-packet-allow", Repository: public, Operation: "pull_request.create", ExpectedDecision: DecisionAllow, RequiresExactHumanApproval: true, IndependentRead: "pull_request.exact", Covers: []string{"approval.exact_allow"}},
		{ID: "private-review-twin-owner-allow", Repository: privateTwin, Operation: "pull_request.update", ExpectedDecision: DecisionAllow, IndependentRead: "pull_request.exact", Covers: []string{"ownership.owner_allow"}},
	}
}

func ValidateMatrix(matrix []Scenario) error {
	if len(matrix) == 0 {
		return errors.New("acceptance matrix is empty")
	}
	fixtures := map[string]string{}
	for _, fixture := range PermanentFixtures() {
		fixtures[fixture.Repository] = fixture.Visibility
	}
	required := map[string]struct{}{}
	for _, coverage := range RequiredCoverage() {
		required[coverage] = struct{}{}
	}
	seenIDs := map[string]struct{}{}
	covered := map[string]struct{}{}
	for _, scenario := range matrix {
		if !scenarioID.MatchString(scenario.ID) {
			return fmt.Errorf("scenario id %q is invalid", scenario.ID)
		}
		if _, exists := seenIDs[scenario.ID]; exists {
			return fmt.Errorf("duplicate scenario id %q", scenario.ID)
		}
		seenIDs[scenario.ID] = struct{}{}
		visibility, exists := fixtures[scenario.Repository]
		if !exists {
			return fmt.Errorf("scenario %q targets unapproved fixture %q", scenario.ID, scenario.Repository)
		}
		if scenario.Operation == "" || scenario.IndependentRead == "" {
			return fmt.Errorf("scenario %q is missing operation or independent read", scenario.ID)
		}
		if scenario.ExpectedDecision != DecisionAllow && scenario.ExpectedDecision != DecisionDeny && scenario.ExpectedDecision != DecisionAwaitingApproval {
			return fmt.Errorf("scenario %q has invalid expected decision", scenario.ID)
		}
		if visibility == "public" && scenario.ExpectedDecision != DecisionDeny && !scenario.RequiresExactHumanApproval {
			return fmt.Errorf("public scenario %q lacks exact human approval", scenario.ID)
		}
		if len(scenario.Covers) == 0 {
			return fmt.Errorf("scenario %q has no requirement coverage", scenario.ID)
		}
		for _, coverage := range scenario.Covers {
			if _, exists := required[coverage]; !exists {
				return fmt.Errorf("scenario %q names unknown coverage %q", scenario.ID, coverage)
			}
			covered[coverage] = struct{}{}
		}
	}
	for coverage := range required {
		if _, exists := covered[coverage]; !exists {
			return fmt.Errorf("acceptance matrix does not cover %q", coverage)
		}
	}
	return nil
}
