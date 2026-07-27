# EC2 reference deployment

This directory is the single-instance reference deployment for the self-hosted broker. GitHub and agents reach exactly one approved TLS edge on public HTTPS: Caddy on a dedicated host or an isolated Nginx virtual host on a shared host. The edge proxies to the API on `127.0.0.1:17445`; the mutation worker and checkpoint signer expose Unix sockets only. The optional notification dispatcher is not an authority dependency.

## Host and network prerequisites

- Ubuntu 24.04 on an encrypted EBS volume.
- Security group ingress: TCP 443 from the internet and TCP 22 only from the operator network. Port 80 is optional for ACME redirect/challenge behavior. No application port is public.
- Cloudflare is the DNS authority for the production origin. The A/AAAA record for `gitoversight.com` must point at the instance before certificate issuance; the exact record values and Cloudflare change receipt belong in the reviewed deployment packet.
- An instance role limited to the immutable release object, the named encrypted SSM parameters, and an encrypted backup prefix. The backup prefix must enforce SSE-KMS with the configured key.
- Secrets provisioned as root-owned `0600` files below `/etc/gitoversight-secrets`; never place secret bytes in cloud-init, Git, environment variables, logs, or unit files.

## Install

1. Before App credentials exist, prepare an owner-only manifest bundle with `gitoversight-app-bootstrap --prepare --redirect-url https://gitoversight.com/bootstrap/github-app/callback --bundle-dir REVIEW_BUNDLE`. Record the printed packet digest without exposing the bundle's random state. From the same reviewed commit, run `deploy/ec2/package-app-bootstrap.sh BOOTSTRAP.tar.gz`; the bootstrap artifact contains no reviewed packet or generated secret.
2. Transfer the exact bootstrap archive and reviewed bundle through the operator boundary. Make the bundle root-owned mode `0700` with exactly two root-owned mode `0600` files. Run `install-app-bootstrap.sh REVIEW_BUNDLE PACKET_DIGEST`, then configure exactly one TLS edge. On a dedicated host, cloud-init selects Caddy with `GITOVERSIGHT_EDGE=caddy`. On the approved shared Ubuntu host where Nginx already owns ports 80/443, omit `/etc/gitoversight/install.env` while installing the core package (or set `GITOVERSIGHT_EDGE=nginx` in the invoking environment), deploy through the B3 Dev SSH tool, and run `sudo gitoversight-install-nginx-edge gitoversight.com ACME_EMAIL`; it obtains the certificate, installs one isolated virtual host, validates the complete Nginx configuration, and reloads without replacing the existing edge.
3. Start `gitoversight-app-bootstrap.service`, open `https://gitoversight.com/bootstrap/github-app/register`, and review GitHub's exact private-App permissions before creating it. The root-confined service accepts only the exact registration and callback paths, consumes one callback, stores credentials directly as root-owned files, emits only a redacted receipt, and exits. Do not restart it after any indeterminate conversion; prepare a new manifest packet instead.
4. Install the App only on the reviewed fixture repositories and record the App id, client id, exact installation ids, packet digest, and repository selection without recording secret bytes. Use those generated non-secret values to prepare exact `api.json`, `worker.json`, `notify.json`, and approved `policy.json` files in a private runtime-config directory.
5. From the same immutable reviewed commit, run `deploy/ec2/package.sh OUTPUT.tar.gz RUNTIME_CONFIG_DIRECTORY`. Set `TARGET_ARCH=arm64` for Graviton; the default is `amd64`. The script builds all six runtime binaries, produces a reproducible archive, and prints its SHA-256. Place that archive in a private immutable object.
6. Store the five required secrets in encrypted SSM parameters or keep the root-owned credential files created by the bootstrap on the existing encrypted host. For a new-instance deployment, preserve the reviewed `gitoversight.com` domain and replace only the artifact, email, and parameter-name placeholders in `cloud-init.yaml`. A notification token is optional.
7. Install `sysusers.conf` and `tmpfiles.conf`, then run `systemd-sysusers` and `systemd-tmpfiles --create` before starting services.

The API starts only on loopback. `/livez` proves the process can answer; `/readyz` is `200` only when SQLite schema/integrity, active policy, audit chain, free disk threshold, checkpoint signer, and privileged worker are all healthy. Mutation routes also pass through this readiness gate.

The approved production target was verified to contain no legacy broker units, state, configuration, edge site, or listener, so this rollout is greenfield. The renamed protocol domains, cookies, execution markers, encrypted-vault associated data, service identities, and filesystem paths cut over atomically. Do not point this release at a legacy broker state directory or reuse an in-flight legacy operation; a host with legacy state requires a separately reviewed migration and matching rollback pair.

## Configuration and credentials

`api.json` points `webhook_secret_file` at `/run/credentials/gitoversight-api.service/webhook-secret` and maps each stable internal human id to its expected GitHub login in `human_approvers`. `worker.json` maps that GitHub login to its exact App installation in `human_installations` and points its three secrets at `/run/credentials/gitoversight-worker.service/*`. The `.service` suffix is required because systemd names each credential directory after the full unit name. A listed human authenticates at `https://gitoversight.com/login/github?human_id=INTERNAL_ID`; the callback rotates the session and sets secure session and CSRF cookies. Authentication alone grants no approval.

`worker.json` may map an organization-wide GitHub App installation as `"owner/*": installation_id`. An exact `"owner/repository"` entry takes precedence. The wildcard covers current and future repositories for installation-token minting while each minted token remains scoped to the single requested repository and operation. Repository visibility remains an explicit per-repository setting, so an unclassified repository can be cloned through the read proxy but cannot be mutated until its public/private classification is configured.

`notify.json` may omit an adapter entirely; if Hive-compatible delivery is enabled, its bearer credential comes from `/run/credentials/gitoversight-notify.service/notification-token`. The API never receives GitHub mutation or notification credentials.

The reference deployment is single-tenant, but durable records and credentials remain tenant-keyed. Notifications are optional and adapter-based. The authority path works with the notification service disabled and has no HeyCode dependency.

## Backup and recovery

Run `backup.sh s3://BUCKET/PREFIX` from a root-owned timer with `GITOVERSIGHT_BACKUP_KMS_KEY` set to the allowed KMS key ARN. Use `GITOVERSIGHT_EDGE_MODE=caddy` on a dedicated host or `GITOVERSIGHT_EDGE_MODE=nginx` on the approved shared host. The Caddy path stops the dedicated edge; the Nginx path creates `/run/gitoversight-maintenance`, which makes only the Git Oversight virtual host return `503` and leaves every unrelated site online. The script waits for all in-flight mutations to leave `executing` and refuses the backup if the bounded drain times out. It then briefly quiesces the API (the only checkpoint writer), captures SQLite and the signed checkpoint as one coherent snapshot, verifies integrity, records hashes/schema, restores ingress and services even on failure, and uploads with SSE-KMS. On process startup, any mutation left `executing` by a host crash is durably changed to `indeterminate`; only independent reconciliation may resolve it.

`restore.sh s3://BUCKET/PREFIX/TIMESTAMP.tar.gz` downloads into an isolated `restore-validation` directory and verifies the archive hash, database hash, integrity, exact schema, every audit-event hash, the checkpoint HMAC, and the checkpoint binding to the restored audit tail and policy generation. It deliberately does not replace the active database. An operator may then stop API and notification services and atomically install the validated database and checkpoint together.

## Failure checks

- Stop the checkpoint or worker: `/livez` remains healthy and `/readyz` becomes `503`; mutations are rejected.
- Fill the EBS volume below `minimum_free_bytes`: readiness becomes `503` before authority writes.
- Corrupt a restore or use the wrong schema: `restore.sh` exits nonzero without touching live state.
- Disable the notification service: authority and GitHub webhook processing continue.
- Expire the selected edge certificate or block renewal: external TLS monitoring must alert; the application cannot claim TLS health from behind the proxy.

There is no tunnel daemon and no GitHub polling loop. Direct GitHub webhooks target `https://gitoversight.com/webhooks/github`.

Before live operation, follow `docs/operations/acceptance-runbook.md`. Keep your acceptance report and receipt manifest in `NOT RUN` state until evidence actually exists — an artifact that claims a passing run before one happened is worse than no artifact. Use `docs/operations/rollback-runbook.md` for release, state, edge, or credential rollback.
