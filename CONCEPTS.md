# Concepts

Shared domain vocabulary for this project — entities, named processes, and status concepts with project-specific meaning. Seeded with core domain vocabulary, then accretes as ce-compound and ce-compound-refresh process learnings; direct edits are fine. Glossary only, not a spec or catch-all.

## Authorization & Identity

### Governance Human Id
The tenant-scoped identifier of a human participant in governance (an approver or namespace owner). It is a name in the governance universe, not a GitHub login — the two can differ arbitrarily, and a GitHub account with the same spelling may belong to an unrelated person.
*Avoid:* using a GitHub login where a governance id is expected, or vice versa.

The enrolled-human map translates governance ids to GitHub logins. Any ownership or credential decision that compares names across the two universes is invalid; ownership is proven by asking GitHub who a credential is.

### Enrolled Human
A human who has completed the GitHub OAuth login against the broker, leaving a stored human credential. Only enrolled humans can act as human-user actors; operations that require a human whose namespace is not owned by any enrolled human fail closed.

### Human Credential
The stored OAuth token pair (access + refresh) belonging to an enrolled human, keyed by governance human id. Access tokens expire and are refreshed transparently; an expired refresh means the human must log in again.

### Actor Mode
Which credential class executes a GitHub operation: the App installation token (automated private-scope work) or an enrolled human's user token (human-attributed actions, and operations GitHub only permits to user tokens, such as creating a user-owned repository).

### Actor Subject
The identity an actor mode is scoped to. Empty for App installation actors; for human-user actors it is the governance human id whose stored credential executes the operation.

### Public-Exposure Gate
The governance principle deciding which operations need human approval: anything whose effect is publicly visible is human-gated; anything private-scope is available to registered agents. The gate keys on exposure, not on how consequential an operation sounds.

### Work Agent
A registered agent identity whose runtime is hosted by ChatGPT Work. Enrollment names and scopes it like any other agent; it never inherits the enrolling human's identity or GitHub credential merely because the human initiated the connection.

### Broker Operation Contract
The canonical remote interface for governed GitHub work. Remote apps and command-line clients consume this same contract; authorization, execution, receipts, and reconciliation remain broker behavior rather than client-specific policy.

## Operations

### Operation Control Plane
The signed, durable governance path that authorizes a GitHub mutation using bounded metadata; it carries an exact asset descriptor but never carries release binary bytes.

### Asset Byte Plane
The authenticated raw-stream path that moves release bytes into immutable staging outside the Operation Control Plane. It accepts only a stream bound to an Upload Capability, while governance and audit records retain the corresponding descriptor.

### Pre-PR
A proposed public pull request held in escrow by the broker, before it exists on GitHub. Opening a PR on a public repository is itself a public change — it creates a branch, a diff, a title and an author that remain visible even if the PR is closed unmerged — so agents do not open public PRs directly. They submit a pre-PR: the commit packet plus the proposed PR text, reviewable and revisable inside GitOversight, which manifests as a real pull request only after a human authorizes it.

A pre-PR carries the same review affordances as a PR — approve, request changes, revise — and is the unit a human actually reviews. *Avoid:* using "packet" (the transport format) or "sync proposal" (the workflow row) where the reviewable artifact is meant.

### Durable Operation
The persisted record of a requested GitHub mutation, moving through a state machine: submission immediately yields denied, authorized, or awaiting approval; execution passes through executing to a terminal verified, absent, or indeterminate (with revoked and expired as administrative terminals). It binds the exact packet — repository, operation, actor mode and subject, payload — so what executes is what was authorized.

### Staged Asset
A tenant-scoped logical reference to immutable release bytes held on the Asset Byte Plane. Its durable record, addressed by an opaque stage id, binds a creating agent, repository, digest, size, filename, content type, lifecycle, and operation pins; the content digest identifies bytes but does not grant access.

### Upload Capability
A short-lived, single-success bearer credential that authorizes one exact raw asset stream. It is minted by a normally signed metadata request and bound to the enrolled agent, tenant, repository, expected digest, size, filename, content type, and expiry. Only its hash is stored; it never appears in an operation packet, audit event, URL, or log.

### Reconciliation
The independent read-back that decides a durable operation's terminal state: after execution, the worker asks GitHub whether the intended end state actually holds. Committed means observed present; absent means observed missing; unknown/indeterminate means the probe could not decide and should be retried later rather than trusted.

An absent read taken immediately after an error-free execution is not terminal evidence — read replicas lag writes, so that contradiction parks the operation as indeterminate for a later re-probe. Absent is terminal only when execution itself failed, and then it carries the execution failure's reason.

### Policy Generation
A versioned snapshot of the governance policy (registered repositories, owners, writers, approvers, grants). A configured policy orchestrator may promote any strictly validated, compare-and-swap-bound next generation. Human review is reserved for exact public-facing artifacts and identity-binding actions, not ceremonial policy confirmation. Agents operate under the currently active generation.

## Flagged ambiguities

- "yaniv" (governance human id) and "yaniv256" (GitHub login) had been conflated in ownership checks — these are names in two distinct universes and must be translated, never compared.
