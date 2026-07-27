# Live acceptance runbook

Execution status: **NOT RUN**. This document defines the reviewed procedure; it is not evidence that EC2 deployment or a GitHub mutation occurred.

## Authority boundary

Run this procedure only after the human approver accepts one immutable deployment packet containing the private review PR, commit and tree, reproducible archive SHA-256, complete non-secret configuration hashes, policy generation, public hostname, fixture repository set, known residuals, and this rollback procedure. A changed byte, hostname, destination, policy generation, or public action invalidates that approval.

Use the B3 Dev SSH boundary for EC2 operator commands. Do not copy GitHub credentials into an agent session, use a tunnel, add a polling loop, or fall back to raw `gh`, GitHub API, Git push, or browser mutation when the broker rejects an action. Every mutation is attempted at most once; an ambiguous result is reconciled through a separate independent read.

## Before deployment

1. Confirm the reviewed tree is clean and reproduce the archive twice with `deploy/ec2/package.sh`; both archives must have the approved SHA-256.
2. Hash the exact runtime `api.json`, `worker.json`, `notify.json`, and `policy.json`. Record the hashes, never the secret bytes, in the acceptance receipt manifest you keep for the deployment.
3. Confirm DNS resolves the approved hostname to the EC2 instance. Confirm the shared Nginx configuration passes `nginx -t` before any change.
4. Confirm the GitHub App registration packet digest, permissions, callback URL, webhook URL, and repository installation scope are exactly the approved values.
5. Confirm the App installation inventory matches the reviewed owner scope. Record every installation id and whether GitHub reports `all` or `selected` repository access. Organization-wide installations must have matching `"owner/*"` worker routing. Keep the permanent fixture repositories below as the mutation acceptance matrix; they no longer define the production installation boundary:
   - public `yaniv256/gitoversight.test-public`
   - private review twin `yaniv256/gitoversight.test-public.dev`
   - private `yaniv256/gitoversight.test-private`
6. Confirm the acceptance runner and cross-user dispatcher client hashes match the approved packet. Install the dispatcher configuration as root-owned `0600`; it contains paths and credential identifiers, not private-key bytes.

## Deploy and prove readiness

1. Transfer the approved archive over the B3 SSH boundary, verify its SHA-256 on EC2, extract it into a new versioned directory, and run its root-only `deploy/ec2/install.sh`.
2. Install the isolated shared-host edge with `gitoversight-install-nginx-edge APPROVED_HOSTNAME APPROVED_ACME_EMAIL`. Re-run `nginx -t` and verify existing virtual hosts are unchanged.
3. Start the checkpoint, worker, API, and optional notification services. `/livez` must return 200. `/readyz` must return 200 only after SQLite integrity/schema, active policy, audit checkpoint, free-disk, and worker checks pass.
4. Verify the GitHub webhook target is `https://APPROVED_HOSTNAME/webhooks/github`. A signed delivery must create one deduplicated evidence receipt and must not create approval authority.
5. Capture service version, deployed commit/tree, archive hash, configuration hashes, policy generation, Nginx site hash, certificate fingerprint, App id, installation ids, and readiness receipt in the manifest.

## Execute the fixture matrix

Use `tests/live.AcceptanceMatrix()` as the canonical scenario list. For every scenario:

1. Generate a unique run id and immutable request packet.
2. Record the expected decision and independent read before execution.
3. Submit the broker request once. Never retry a mutation after transport failure or an indeterminate response.
4. Record the broker decision, stable denial code or receipt id, attempt count, and response SHA-256.
5. Perform the declared independent GitHub read through a separately authorized read path. Record the observed resource id or zero-mutation result.
6. Require exactly one observed mutation for a verified allow and zero for every denial or awaiting-approval state. Stop immediately on contradiction.

Public publication tests remain denied unless the human approves that exact public packet. Public title, body, commit, and comment content must contain no agent identity or agent metadata. Private discussion may identify the participating agent with the approved `- Firstname` signature.

## Cross-user proof

Build and hash the dispatcher from `tests/crossuser`. Copy `tests/crossuser/config.example.json` to the root-owned configuration path and replace only the reviewed hashes, URL, tenant, identifiers, and absolute identity paths. Invoke only embedded scenario ids with a unique run id. The dispatcher uses `/usr/bin/sudo -n -u` directly, exposes no shell or arbitrary command parameter, and returns only bounded structured fields plus a response hash.

Run all five embedded scenarios from the Zara and Tomas Unix identities. Independently verify both allowed mutations and all denied absences in GitHub, then bind the signed-identity results and receipt hashes into the acceptance manifest.

## Human acceptance and bootstrap exit

Present the completed report, receipt manifest, exact deployed revision, configuration/policy hashes, independent reads, residuals, and rollback packet to the human approver. Do not revoke bootstrap access before that exact packet is approved.

After approval, remove direct GitHub credentials from every agent session and revoke the bootstrap exception. Prove, in order:

1. a direct private write fails and the independent read shows zero mutation;
2. one allowed brokered private operation succeeds exactly once and reconciles to one receipt;
3. one unapproved brokered public operation is denied and the independent read shows zero mutation.

Mark the report complete only when all evidence is present, audit verification passes, secret scanning is clean, and the rollback runbook has been exercised against the deployed revision.
