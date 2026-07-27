# Security Policy

GitOversight sits in the path between coding agents and your GitHub account. A
vulnerability here is a vulnerability in something people trust with their
identity. We take reports seriously and we would rather hear about a problem
early and awkwardly than late and publicly.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting on this repository
(**Security → Report a vulnerability**). It goes straight to the maintainers and
stays private while we work on it.

Useful to include, though a partial report is far better than none:

- What you can do that you shouldn't be able to.
- The steps to reproduce it.
- Which component is involved — the API, the worker, the checkpoint signer, the
  client, the policy evaluator.
- Whether it needs an enrolled agent, an approved human, or neither.

**We will acknowledge your report within 72 hours.** If you don't hear back in
that window, assume the message went astray and ping the maintainers publicly
without describing the issue.

## What counts

We're most interested in anything that lets someone cross a boundary the system
exists to enforce:

- **Publishing without approval.** Any path where a mutation reaches a public
  repository without a human approving that exact content.
- **Credential exposure.** Anything that lets an agent, or any process other
  than the worker, obtain GitHub credentials.
- **Approval forgery or replay.** Reusing, transplanting, or fabricating an
  approval; binding an approval to content it wasn't granted for.
- **Identity confusion.** One agent acting as another, or an agent acting as a
  human approver.
- **Receipt tampering.** Breaking the hash chain, or making the audit record
  disagree with what actually happened.
- **Policy bypass.** Reaching an operation the policy evaluator should have
  denied.

Also welcome, at lower severity: denial of service against the broker, secrets
leaking into logs or receipts, and TOCTOU races in the approval or execution
path.

## What doesn't count

- Findings against a deployment you don't own or have permission to test.
- Missing hardening that doesn't lead to a concrete impact.
- Reports produced by running a scanner and forwarding the output without
  checking whether the finding is real.

## Disclosure

We'll work with you on a fix and a timeline. Once a fix is available we'll
credit you in the release notes unless you'd rather stay anonymous — say so and
we'll leave you out.

If we can't reproduce something or we disagree that it's a vulnerability, we'll
tell you why rather than going quiet.

## Scope

This policy covers the code in this repository. If you find something in a
hosted deployment run by someone else, report it to whoever operates it.
