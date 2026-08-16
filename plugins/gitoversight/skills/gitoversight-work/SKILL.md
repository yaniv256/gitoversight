---
name: gitoversight-work
description: Govern private GitHub repository work through the GitOversight remote app, including repository discovery, bounded change previews, operation receipts, reconciliation, and public pre-PR review.
---

# GitOversight Work

Use GitOversight for repository work when GitHub authority must remain in the
broker. Treat the connected Work identity as an agent, never as the human who
enrolled it.

## Install and authenticate

Install the GitOversight plugin and connect its app. Complete authentication in
the GitOversight browser flow, choose a distinct agent name, and review the
repository scope. Never ask the human to paste a GitHub credential, OAuth token,
agent secret, or release payload into chat. Authentication belongs in the app
connection flow.

If the app is already connected, do not reconnect merely because a tool call
failed. Diagnose the stable error first. A revoked connection must be enrolled
again; do not attempt to recover or reuse its token.

## Discover repository scope first

Call `repositories.list` before repository work. Use only a returned
`owner/name` key. An absent repository is not evidence that it does not exist;
it means this agent cannot currently select it. Never probe an unlisted private
repository through another operation.

## Prepare a bounded private contribution

1. Read the exact repository, branch, base commit, and base tree through the
   read tools advertised by the server. Do not infer a base from memory.
2. Express the smallest useful path-level delta: add, replace, delete, or mode
   change. Exclude generated archives, credentials, large binaries, and
   unrelated files.
3. Request a **bounded change preview** before publication. Check its repository,
   exact base, result tree, changed paths, limits, and content-addressed preview
   hash. A stale-base result means read the new base and reconsider the change;
   it is not permission to replay the old preview.
4. Run only validations the current environment actually supports. Never call a
   change "tested" merely because its preview was accepted.
5. Call `change_draft.publish` with the exact draft ID, repository, base commit,
   preview hash, target branch, commit message, and one unique operation ID. The
   broker reconstructs and submits the commit packet from its stored bounded
   bytes. Never reconstruct a large commit packet or binary as prompt text.

Use the exact change-preview tool exposed by `tools/list`; availability is a
server capability. If it is absent, report that bounded contribution is not
available rather than falling back to direct GitHub or an unbounded payload.

## Preserve the operation receipt

`operation.submit` requires one unique request ID. Preserve the complete
**operation receipt**, especially the operation ID, repository, decision,
state, policy generation, reason, and next action. A successful request call is
not proof that GitHub changed.

- Use `operation.status` for observation.
- If and only if the receipt says the outcome is indeterminate and its next
  action is reconciliation, call `operation.reconcile` with the **same operation ID**.
- Never create a replacement request before the original has a terminal
  disposition.
- Report success only after a terminal verified result and the independent read
  required by the operation contract.
- Stop on denied, absent, or terminal failure. Do not turn an error into a new
  request unless the recovery guidance explicitly authorizes one.

## Prepare public exposure as a pre-PR

For a public destination, use the server's governed **public pre-PR** or sync
preparation capability. Include the exact file scope, title, complete public
body, validation, and known residuals. Confirm that private investigations,
development-history documents, agent attribution, absolute private paths, and
secrets are excluded.

Preparation is not publication. Stop at the meaningful GitOversight review
surface so the human can inspect the actual diff and public text. Never create a
public branch, pull request, release, comment, or listing directly.

## Revoke a Work connection

The human revokes the named Work credential from GitOversight connection
management. After **revoke**, stop using that connection. An
`authentication_required` or `invalid_token` result after revocation is
expected; reconnect only through a fresh human enrollment.

## Stable error recovery

- `authentication_required` or `invalid_token`: use the app connection UI; do
  not request a token in chat.
- `repository_denied`: stop. Ask the human to review this agent's repository
  scope; do not probe or retry.
- `repository_scope_unavailable`: wait for scope service recovery, then repeat a
  read-only discovery call before mutation.
- `invalid_arguments`: correct the request locally; do not submit a second
  mutation with guessed fields.
- `result_too_large`: narrow the read or delta. Never pass the raw result through
  the conversation or split one mutation into unordered fragments.
- `operation_forbidden`: stop; policy denied the operation.
- `operation_not_found`: verify the original operation ID. Do not manufacture a
  replacement to obtain a success-shaped response.
- `reconciliation_unavailable`: preserve the receipt and wait; do not retry the
  mutation.
- `operation_failed`: preserve the receipt and follow its explicit safe recovery
  guidance. If mutation may have committed, treat the outcome as indeterminate.
- `session_expired` or `session_not_found`: establish a new MCP session, then
  observe the existing operation ID before doing any new work.
