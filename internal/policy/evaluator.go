package policy

import (
	"errors"
	"fmt"
	"strings"

	"github.com/yaniv256/gitoversight.dev/internal/attribution"
)

type Code string

const (
	Allowed                    Code = "allowed_private_owner"
	AllowedStanding            Code = "allowed_standing_exception"
	AllowedPrivateContributor  Code = "allowed_private_contributor"
	AllowedBranchGrant         Code = "allowed_branch_grant"
	AllowedPrivateReview       Code = "allowed_private_review"
	AllowedRead                Code = "allowed_read"
	ApprovalRequired           Code = "approval_required"
	BranchGrantRequired        Code = "branch_grant_required"
	PrivateAttributionRequired Code = "private_attribution_required"
	PublicIdentityLeak         Code = "public_identity_leak"
	RepositoryUnknown          Code = "repository_unknown"
	CallerUnknown              Code = "caller_unknown"
	OperationUnknown           Code = "operation_unknown"
	ReadDenied                 Code = "read_denied"
	SyncMirrorRequired         Code = "sync_mirror_required"
	QueueCuratorRequired       Code = "queue_curator_required"
)

var operations = map[string]struct{}{
	"branch.push": {}, "branch.delete": {}, "pull_request.create": {}, "pull_request.update": {},
	"pull_request.review": {}, "pull_request.reply": {}, "pull_request.merge": {}, "pull_request.close": {},
	"repository.create": {}, "repository.settings.update": {}, "installation.repository.add": {}, "policy.promote": {},
	"release.publish": {}, "release.asset.upload": {}, "release.assets.upload": {}, "issue.create": {}, "issue.comment": {},
	"repository.read": {},
	"sync.propose":    {}, "sync.update": {}, "sync.comment": {}, "queue.set_order": {},
}

var executableOperations = map[string]struct{}{
	"branch.push": {}, "branch.delete": {}, "pull_request.create": {}, "pull_request.update": {},
	"pull_request.review": {}, "pull_request.reply": {}, "pull_request.merge": {}, "pull_request.close": {},
	"issue.create": {}, "issue.comment": {},
	"policy.promote": {}, "release.publish": {}, "release.asset.upload": {}, "release.assets.upload": {},
	"repository.create": {}, "repository.settings.update": {}, "installation.repository.add": {},
}

// Executable reports whether the privileged worker has a complete write and
// independent-reconciliation adapter for an operation. Policy vocabulary may
// be broader while adapters are developed, but no capability may be issued
// until both halves exist.
func Executable(operation string) bool {
	_, ok := executableOperations[operation]
	return ok
}

type AgentKind string

const (
	AgentKindLocal  AgentKind = "local"
	AgentKindRemote AgentKind = "remote"
)

type Agent struct {
	// Kind is omitted by legacy policies. An empty kind retains the historical
	// local-agent meaning; remote agents have no Unix peer identity and must use
	// an explicit remote kind.
	Kind      AgentKind `json:"kind,omitempty"`
	UID       uint32    `json:"uid"`
	FirstName string    `json:"first_name"`
	Emails    []string  `json:"emails"`
}

func (a Agent) IsRemote() bool { return a.Kind == AgentKindRemote }

func (a Agent) IsLocal() bool { return a.Kind == "" || a.Kind == AgentKindLocal }

// PermissionSet contains non-mutating repository capabilities. It is kept
// separate from ownership and writer grants so a broad read default cannot
// accidentally broaden mutation authority.
type PermissionSet struct {
	Read bool `json:"read"`
}

type Repository struct {
	Visibility      string         `json:"visibility"`
	Owners          []string       `json:"owners"`
	Writers         []string       `json:"writers"`
	Approvers       []string       `json:"approvers"`
	Standing        []string       `json:"standing_exceptions"`
	ProtectedPolicy bool           `json:"protected_policy"`
	Permissions     *PermissionSet `json:"permissions,omitempty"`
	// SyncsTo names the exact public repository this private staging mirror
	// publishes to via the human-authorized sync flow. Only valid on private
	// repositories.
	SyncsTo string `json:"syncs_to,omitempty"`
	// Derived marks private authority created by a verified repository.create.
	// It is never accepted from administrator policy documents.
	Derived      bool   `json:"derived,omitempty"`
	ActorSubject string `json:"-"`
}

type BranchGrant struct {
	Repository string `json:"repository"`
	Agent      string `json:"agent"`
	Branch     string `json:"branch"`
	Active     bool   `json:"active"`
}

type RepositoryDocument struct {
	Name               string         `json:"name"`
	Visibility         string         `json:"visibility"`
	Owners             []string       `json:"owners"`
	AuthorizedWriters  []string       `json:"authorized_writers"`
	HumanApprovers     []string       `json:"human_approvers"`
	StandingExceptions []string       `json:"standing_exceptions"`
	ProtectedPolicy    bool           `json:"protected_policy,omitempty"`
	Permissions        *PermissionSet `json:"permissions,omitempty"`
	SyncsTo            string         `json:"syncs_to,omitempty"`
}

type Document struct {
	SchemaVersion       int           `json:"schema_version"`
	Generation          uint64        `json:"generation"`
	FallbackOwner       string        `json:"fallback_owner,omitempty"`
	FallbackPermissions PermissionSet `json:"fallback_permissions,omitempty"`
	// QueueCurator names the designated assistant agent allowed to order the
	// human's review queue (queue.set_order).
	QueueCurator string               `json:"queue_curator,omitempty"`
	Repositories []RepositoryDocument `json:"repositories"`
	BranchGrants []BranchGrant        `json:"branch_grants,omitempty"`
}

func (d Document) Compile(agents map[string]Agent) (Snapshot, error) {
	if d.SchemaVersion != 1 {
		return Snapshot{}, errors.New("unsupported policy schema version")
	}
	snapshot := Snapshot{Generation: d.Generation, FallbackOwner: d.FallbackOwner, FallbackPermissions: d.FallbackPermissions, QueueCurator: d.QueueCurator, Agents: agents, Repositories: make(map[string]Repository, len(d.Repositories)), BranchGrants: d.BranchGrants}
	for _, item := range d.Repositories {
		if _, exists := snapshot.Repositories[item.Name]; exists {
			return Snapshot{}, fmt.Errorf("duplicate repository %q", item.Name)
		}
		snapshot.Repositories[item.Name] = Repository{Visibility: item.Visibility, Owners: item.Owners, Writers: item.AuthorizedWriters, Approvers: item.HumanApprovers, Standing: item.StandingExceptions, ProtectedPolicy: item.ProtectedPolicy, Permissions: item.Permissions, SyncsTo: item.SyncsTo}
	}
	if err := snapshot.Validate(); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

type Snapshot struct {
	Generation          uint64                `json:"generation"`
	FallbackOwner       string                `json:"fallback_owner,omitempty"`
	FallbackPermissions PermissionSet         `json:"fallback_permissions,omitzero"`
	QueueCurator        string                `json:"queue_curator,omitempty"`
	Agents              map[string]Agent      `json:"agents"`
	Repositories        map[string]Repository `json:"repositories"`
	BranchGrants        []BranchGrant         `json:"branch_grants"`
}

type Request struct {
	Caller     string
	Repository string
	Operation  string
	Branch     string
	Title      string
	Body       string
	Payload    map[string]any
}

type Decision struct {
	Code   Code
	Reason string
}

func (s Snapshot) Validate() error {
	if s.Generation == 0 {
		return errors.New("policy generation must be positive")
	}
	seenUID := make(map[uint32]string, len(s.Agents))
	for name, agent := range s.Agents {
		if name == "" || agent.FirstName == "" {
			return errors.New("agent name and first name are required")
		}
		if !agent.IsLocal() && !agent.IsRemote() {
			return fmt.Errorf("agent %s has invalid kind %q", name, agent.Kind)
		}
		if agent.IsRemote() {
			if agent.UID != 0 {
				return fmt.Errorf("remote agent %s must not declare a unix uid", name)
			}
			continue
		}
		if other, ok := seenUID[agent.UID]; ok {
			return fmt.Errorf("agents %s and %s share uid %d", other, name, agent.UID)
		}
		seenUID[agent.UID] = name
	}
	if s.FallbackOwner != "" {
		if _, ok := s.Agents[s.FallbackOwner]; !ok {
			return fmt.Errorf("fallback owner %q is not a registered agent", s.FallbackOwner)
		}
	}
	if s.QueueCurator != "" {
		if _, ok := s.Agents[s.QueueCurator]; !ok {
			return fmt.Errorf("queue curator %q is not a registered agent", s.QueueCurator)
		}
	}
	for name, repo := range s.Repositories {
		if strings.Count(name, "/") != 1 || strings.ContainsAny(name, "*?[") {
			return fmt.Errorf("repository %q is not exact", name)
		}
		if repo.Visibility != "private" && repo.Visibility != "public" {
			return fmt.Errorf("repository %q has invalid visibility", name)
		}
		if len(repo.Owners) == 0 && s.FallbackOwner == "" {
			return fmt.Errorf("repository %q has no owners", name)
		}
		if repo.SyncsTo != "" {
			if strings.Count(repo.SyncsTo, "/") != 1 || strings.ContainsAny(repo.SyncsTo, "*?[") {
				return fmt.Errorf("repository %q syncs_to %q is not exact", name, repo.SyncsTo)
			}
			if repo.Visibility != "private" {
				return fmt.Errorf("repository %q declares syncs_to but is not private", name)
			}
		}
	}
	return nil
}

func Evaluate(snapshot Snapshot, request Request) Decision {
	if _, ok := snapshot.Agents[request.Caller]; !ok {
		return Decision{Code: CallerUnknown, Reason: "caller is not registered"}
	}
	if _, ok := operations[request.Operation]; !ok {
		return Decision{Code: OperationUnknown, Reason: "operation is not registered"}
	}
	// repository.create is the bootstrap exception: it is the one operation whose
	// target repository legitimately does not exist yet, so it cannot be gated on
	// prior registration (that would make repository creation impossible). The gate
	// keys on public exposure, not on the operation: a PRIVATE create exposes
	// nothing outside the owner's account, so any registered agent may request it
	// (execution still requires the namespace owner's stored human credential,
	// which only enrolled humans have). A PUBLIC create is externally visible and
	// keeps exact human approval of the name+visibility packet. If the repository
	// is already registered, fall through to the normal evaluation below (which
	// will approval-gate or deny it).
	if request.Operation == "repository.create" {
		if _, exists := snapshot.Repositories[request.Repository]; !exists {
			if visibility, ok := request.Payload["visibility"].(string); ok && visibility == "private" {
				return Decision{Code: Allowed, Reason: "private repository creation by a registered agent"}
			}
			return Decision{Code: ApprovalRequired, Reason: "public repository creation requires human approval"}
		}
	}
	// queue.set_order targets the human's review queue, not a repository, so it
	// is evaluated before the repository gate. Only the designated curator may
	// order the queue.
	if request.Operation == "queue.set_order" {
		if snapshot.QueueCurator != "" && request.Caller == snapshot.QueueCurator {
			return Decision{Code: Allowed, Reason: "designated queue curator"}
		}
		return Decision{Code: QueueCuratorRequired, Reason: "queue ordering is reserved for the designated curator"}
	}
	repo, ok := snapshot.Repositories[request.Repository]
	if !ok {
		return Decision{Code: RepositoryUnknown, Reason: "repository is not registered"}
	}
	// Sync proposals live on a private staging mirror that declares its public
	// target via syncs_to. The caller must be eligible on the mirror AND on the
	// linked public repository, so the human-authorized publication cannot fail
	// policy after approval (KTD9).
	if request.Operation == "sync.propose" || request.Operation == "sync.update" {
		if repo.Visibility != "private" || repo.SyncsTo == "" {
			return Decision{Code: SyncMirrorRequired, Reason: "sync operations require a private repository with syncs_to"}
		}
		target, registered := snapshot.Repositories[repo.SyncsTo]
		if !registered {
			return Decision{Code: SyncMirrorRequired, Reason: "linked public target is not registered"}
		}
		mirrorEligible := owner(snapshot, repo, request.Caller) || contains(repo.Writers, request.Caller)
		targetEligible := owner(snapshot, target, request.Caller) || contains(target.Writers, request.Caller)
		if mirrorEligible && targetEligible {
			return Decision{Code: Allowed, Reason: "eligible caller on a linked private mirror"}
		}
		return Decision{Code: BranchGrantRequired, Reason: "caller lacks standing on the mirror or its public target"}
	}
	if request.Operation == "repository.read" {
		if repo.Derived {
			if owner(snapshot, repo, request.Caller) {
				return Decision{Code: AllowedRead, Reason: "derived repository owner may read"}
			}
			return Decision{Code: ReadDenied, Reason: "derived repository read is limited to its owner"}
		}
		permissions := snapshot.FallbackPermissions
		if repo.Permissions != nil {
			permissions = *repo.Permissions
		}
		if permissions.Read {
			return Decision{Code: AllowedRead, Reason: "registered agent has repository read permission"}
		}
		return Decision{Code: ReadDenied, Reason: "repository read permission is denied"}
	}

	if repo.Visibility == "public" && (containsAgentIdentity(snapshot, request.Branch+"\n"+request.Title+"\n"+request.Body) || payloadContainsAgentIdentity(snapshot, request.Payload)) {
		return Decision{Code: PublicIdentityLeak, Reason: "public metadata contains private agent attribution"}
	}

	if repo.Visibility == "private" && !repo.ProtectedPolicy && isDiscussion(request.Operation) {
		agent := snapshot.Agents[request.Caller]
		if !strings.HasSuffix(strings.TrimSpace(request.Body), "— "+agent.FirstName) {
			return Decision{Code: PrivateAttributionRequired, Reason: "private discussion must identify its agent speaker"}
		}
		return Decision{Code: AllowedPrivateReview, Reason: "registered agent may discuss a controlled private pull request"}
	}

	if repo.ProtectedPolicy || repo.Visibility == "public" || destructive(request.Operation) {
		// A standing exception is the owner's deliberate, per-operation grant, so it
		// is honored on a public repository too. Previously it was not, which made
		// the feature unreachable on exactly the repositories it was written for —
		// and the only way to express the intent was to declare a public repository
		// private, disabling every visibility-keyed guard on it. The grant must
		// still be exact (this operation, not a class) and the caller eligible.
		//
		// ProtectedPolicy remains absolute: the repository that holds the rules
		// cannot grant itself an exception to them.
		if contains(repo.Standing, request.Operation) && eligible(snapshot, repo, request.Caller) && !repo.ProtectedPolicy {
			return Decision{Code: AllowedStanding, Reason: "exact standing exception"}
		}
		return Decision{Code: ApprovalRequired, Reason: "public, destructive, or protected-policy mutation"}
	}

	if contains(repo.Standing, request.Operation) && eligible(snapshot, repo, request.Caller) {
		return Decision{Code: AllowedStanding, Reason: "exact standing exception"}
	}
	if owner(snapshot, repo, request.Caller) || contains(repo.Writers, request.Caller) {
		return Decision{Code: Allowed, Reason: "eligible private non-destructive mutation"}
	}
	if grantMatches(snapshot.BranchGrants, request) {
		return Decision{Code: AllowedBranchGrant, Reason: "active exact contributor branch grant"}
	}
	// Any registered agent may open a branch or PR on a PRIVATE, non-protected repo.
	// Reaching here means the repo is private, non-protected, and the operation is
	// non-destructive (public / protected-policy / destructive already returned above),
	// and the caller was confirmed registered at the top of Evaluate. Branch/PR creation
	// on a private repo is ordinary collaboration, not a privileged act — no per-branch
	// grant is required. Public writes, destructive ops, and protected-policy repos keep
	// their approval gate; owners keep allowed_private_owner.
	if isPrivateContributorOperation(request.Operation) {
		return Decision{Code: AllowedPrivateContributor, Reason: "registered agent may open a branch or pull request on a private repository"}
	}
	return Decision{Code: BranchGrantRequired, Reason: "caller is neither owner nor exact branch grantee"}
}

func payloadContainsAgentIdentity(snapshot Snapshot, value any) bool {
	switch typed := value.(type) {
	case string:
		return containsAgentIdentity(snapshot, typed)
	case []any:
		for _, item := range typed {
			if payloadContainsAgentIdentity(snapshot, item) {
				return true
			}
		}
	case map[string]any:
		for key, item := range typed {
			// Commit packets carry changed blob bytes as base64 strings. Those
			// strings are transport, not public attribution metadata, and random
			// encoded bytes can contain an agent name by coincidence. The packet
			// validator separately verifies the encoding and object SHA before
			// execution; keep inspecting the blob descriptor and every other
			// payload field, but do not interpret encoded bytes as prose.
			if key == "content" && encodedBlob(typed) {
				continue
			}
			if containsAgentIdentity(snapshot, key) || payloadContainsAgentIdentity(snapshot, item) {
				return true
			}
		}
	}
	return false
}

func encodedBlob(value map[string]any) bool {
	encoding, encodingOK := value["encoding"].(string)
	_, contentOK := value["content"].(string)
	_, shaOK := value["sha"].(string)
	return encodingOK && encoding == "base64" && contentOK && shaOK
}

// isPrivateContributorOperation reports whether the operation is a branch or
// pull-request write that any registered agent may perform on a private,
// non-protected repository without a per-branch grant. It intentionally covers
// exactly the same operations as grantMatches — the grant simply becomes
// unnecessary for private repos.
func isPrivateContributorOperation(operation string) bool {
	return operation == "branch.push" || operation == "pull_request.create" || operation == "pull_request.update"
}

func grantMatches(grants []BranchGrant, request Request) bool {
	if request.Operation != "branch.push" && request.Operation != "pull_request.create" && request.Operation != "pull_request.update" {
		return false
	}
	for _, grant := range grants {
		if grant.Active && grant.Repository == request.Repository && grant.Agent == request.Caller && grant.Branch == request.Branch {
			return true
		}
	}
	return false
}

func eligible(snapshot Snapshot, repo Repository, caller string) bool {
	return owner(snapshot, repo, caller) || contains(repo.Writers, caller)
}

func owner(snapshot Snapshot, repo Repository, caller string) bool {
	if len(repo.Owners) != 0 {
		return contains(repo.Owners, caller)
	}
	return snapshot.FallbackOwner != "" && caller == snapshot.FallbackOwner
}

// pull_request.merge is deliberately NOT destructive: an owner merges their own
// private PR without approval (see TestEvaluatePolicyMatrix). The
// worker-observability branch proposed adding it, predating that rule.
func destructive(operation string) bool {
	switch operation {
	case "repository.settings.update", "installation.repository.add", "policy.promote":
		return true
	default:
		return false
	}
}

func isDiscussion(operation string) bool {
	return operation == "pull_request.review" || operation == "pull_request.reply" || operation == "issue.comment"
}

func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func containsAgentIdentity(snapshot Snapshot, text string) bool {
	identities := make([]attribution.Identity, 0, len(snapshot.Agents)*3)
	for name, agent := range snapshot.Agents {
		identities = append(identities, attribution.Identity{Name: name}, attribution.Identity{Name: agent.FirstName})
		for _, email := range agent.Emails {
			identities = append(identities, attribution.Identity{Email: email})
		}
	}
	return attribution.Contains(text, identities)
}
