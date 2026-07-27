# Rollback runbook

Exercise status: **NOT RUN** against the EC2 deployment. Rollback is not complete until independent readiness, audit, receipt, and GitHub-state checks pass.

## Preconditions

The rollback packet must name the current and target commit/tree, archive SHA-256, database schema, configuration hashes, policy generation, backup URI/hash, checkpoint tail, Nginx site hash, certificate fingerprint, and reason. Rollback never restores direct agent GitHub credentials and never grants publication authority. If a database downgrade is not explicitly proven compatible, restore the matching validated database/checkpoint pair instead of running older code on newer state.

## Automatic edge rollback

`gitoversight-install-nginx-edge` stages an isolated virtual host, validates the complete Nginx configuration, and restores the prior site if certificate issuance, validation, or reload fails. After any failure, run `nginx -t`, hash the effective site, and independently probe every pre-existing host plus the broker hostname. Record the result in the rollback receipt.

## Service or release rollback

1. Stop public ingress for the broker virtual host. Do not stop unrelated Nginx sites.
2. Read the operation table. Wait for all operations to leave `executing`; on timeout, keep ingress closed and mark unresolved operations `indeterminate` for independent reconciliation. Never retry them blindly.
3. Stop API and notification services, then the worker and checkpoint services. Preserve logs, the active database, checkpoint, configuration, and service hashes before replacement.
4. Verify the target immutable archive SHA-256 and configuration hashes. Install into a new versioned directory; do not mutate the retained rollback source.
5. If state restoration is required, run `gitoversight-restore s3://BUCKET/PREFIX/TIMESTAMP.tar.gz` with the exact expected tenant and policy generation. This command validates into an isolated directory and does not activate it.
6. Compare the validated schema, audit tail, checkpoint HMAC, tenant, and policy generation to the rollback packet. Only after explicit operator authorization, atomically install the validated database and checkpoint together while authority services remain stopped.
7. Start checkpoint, worker, API, and optional notification services. Require local `/livez` and `/readyz` success before reopening the broker virtual host.
8. Validate Nginx, reopen ingress, and independently read GitHub for every operation that was executing or indeterminate at rollback time.

## Credential or App compromise

Suspend the GitHub App installation or revoke the affected agent credential first. Keep readiness failed closed while rotating the App private key, webhook secret, OAuth client secret, agent credential, or checkpoint key. A replacement credential is a new versioned secret; no secret is written to Git, the receipt manifest, logs, or an agent session. Re-run denial, one-attempt, webhook HMAC, checkpoint, and independent reconciliation tests before resuming writes.

## Verification and receipt

The rollback receipt must include timestamps, operator approval reference, current/target immutable hashes, backup validation result, before/after service and edge hashes, readiness result, audit verification, affected operation ids, independent GitHub reads, and residuals. A rollback with missing evidence remains incomplete. Update the acceptance report back to **NOT RUN** if the deployed revision, policy generation, App installation, configuration, or hostname changes.
