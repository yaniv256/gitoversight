---
name: gitoversight
description: Govern every agent-mediated GitHub mutation through repository ownership, scoped contributor grants, exact human approval for public or destructive actions, private agent attribution, public human attribution, and brokered credentials. Use whenever an agent plans, requests, reviews, executes, verifies, or discusses a GitHub write.
---

# Git Oversight

Use this skill before any agent-mediated GitHub write. Local reads, local commits, and local testing remain ordinary development work; pushes, pull requests, comments, reviews, merges, releases, repository settings, and repository creation are governed mutations.

**This document is the specification — what the broker guarantees and why. It is not the operating guide.** If you are an agent trying to get work published and something was denied, read `skills/gitoversight-user/SKILL.md` instead: it covers reading your own standing, what each denial code means, and the exact commands. Reading only the specification reliably leads to the wrong question — a denial usually means you lack standing, not that you need an approval token.

## Non-negotiable boundary

- Never place GitHub credentials in an agent session.
- Send mutation requests only through the Git Oversight broker.
- Never fall back to raw `git push`, `gh`, REST/GraphQL calls, browser automation, deploy keys, credential helpers, or another user when the broker denies or is unavailable.
- Treat technical correctness, publication readiness, and publication authority as separate claims.
- A remediation plan does not authorize its own GitHub publication.

## Decide in this order

1. Identify the caller from its tenant-scoped, individually revocable Ed25519 request credential. Verify the HTTP Message Signature, signed target and content digest, freshness, and one-use nonce. Never accept agent identity from request JSON, an invoking operating-system account, or forwarded headers.
2. Resolve the exact `owner/repository`. Wildcards and unregistered repositories deny.
3. Check repository ownership. An owner may perform permitted non-destructive private operations. A non-owner requires an exact branch-scoped contributor grant to push and open or update a PR from that branch.
4. Classify the target visibility and operation. Every public write and every destructive operation requires exact human approval unless an explicit standing policy exception covers the exact repository and operation.
5. Bind approval to the immutable packet: source and destination repositories, source commit, export tree, complete path manifest, title/body or reply text, operations, human approver, nonce, and expiration. Any material change invalidates approval.
6. A configured policy orchestrator may add owners to an existing ordinary private repository through `policy-promote-private-owners`. This exception is addition-only: removals, public/protected repositories, writer changes, grants, repository registration, and every other policy change stay on the human-governed promotion path.
6. Execute once through the broker and independently read GitHub state. Ambiguous outcomes reconcile before any retry.
7. Record requested, denied or authorized, executed, and verified receipt events in the hash chain.

## Identity and authorship

Private collaboration may identify agents. Every private PR review or discussion entry must end with `— FirstName` so a shared GitHub account does not obscure the speaker.

Public GitHub content must not contain agent names, signatures, agent co-author trailers, agent email addresses, or other agent provenance. Public commits are clean, squashed exports attributed to the human who approved and accepts responsibility for the publication. The App and the agent are tools, not public authors.

## Public publication

Prepare and privately review the exact export packet first. Public approval covers only that immutable packet and operation. If the destination, head, tree, paths, title, body, reply, or operation changes materially, stop and obtain a new approval. An absent human is never consent.

## Denial behavior

Return a stable denial code and a receipt. A denial must produce zero GitHub mutation. Do not weaken policy, switch identities, use a broader token, or ask another agent to perform the same write. If access is legitimately needed, request the narrow policy or branch grant through the protected authorization workflow.

## Verification checklist

- Exact repository and visibility resolved.
- Caller is transport-authenticated and eligible.
- Branch grant or standing exception is exact and active where applicable.
- Required approval matches the canonical packet hash and is unused, unexpired, and unrevoked.
- Public content contains human attribution only.
- The independently read postcondition matches the request exactly.
- Receipt and checkpoint chains extend monotonically.

Policy is data, not prose. The authoritative policy lives in the protected private authorization repository and must validate against `schemas/policy.schema.json` before promotion.

## Service boundary

Use the standalone broker HTTPS API. The reference service may run on one EC2 instance, but API, mutation worker, checkpoint signer, and optional notification dispatcher remain separate identities. Only the worker receives GitHub credentials. The public edge sends GitHub webhooks directly to the API; no tunnel, agent CLI, HeyCode process, or GitHub polling loop is an authority dependency.

Liveness only proves the API process responds. Readiness must additionally prove SQLite schema and integrity, active policy, audit continuity, checkpoint availability, privileged-worker availability, and durable-volume headroom. Mutation endpoints fail closed whenever readiness fails. Notification delivery is optional and must never change an authorization result.

Human administration begins only through the broker's GitHub App login route. The API allowlists the stable internal human id and expected GitHub login; the privileged worker verifies that login and the configured App installation before the API rotates the server-side session. Authentication alone is never approval.
