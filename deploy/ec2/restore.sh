#!/usr/bin/env bash
set -euo pipefail
umask 077

source_uri=${1:?usage: restore.sh s3://bucket/prefix/timestamp.tar.gz}
validation_parent=${GITOVERSIGHT_RESTORE_PARENT:-/var/lib/gitoversight-api/restore-validation}
expected_schema=${GITOVERSIGHT_SCHEMA_VERSION:-11}
checkpoint_key=${GITOVERSIGHT_CHECKPOINT_KEY:-/etc/gitoversight-secrets/checkpoint.key}
restore_verifier=${GITOVERSIGHT_RESTORE_VERIFIER:-/usr/local/libexec/gitoversight-restore-verify}
expected_tenant=${GITOVERSIGHT_EXPECTED_TENANT:?GITOVERSIGHT_EXPECTED_TENANT is required}
expected_policy_generation=${GITOVERSIGHT_EXPECTED_POLICY_GENERATION:?GITOVERSIGHT_EXPECTED_POLICY_GENERATION is required}
[[ "$expected_tenant" =~ ^[A-Za-z0-9._-]+$ ]]
[[ "$expected_policy_generation" =~ ^[1-9][0-9]*$ ]]
install -d -m 0700 "$validation_parent"
validation_root=$(mktemp -d "$validation_parent/restore.XXXXXX")

archive="$validation_root/gitoversight-backup.tar.gz"
aws s3 cp "$source_uri" "$archive" --only-show-errors
aws s3 cp "$source_uri.sha256" "$archive.sha256" --only-show-errors
(
  cd "$validation_root"
  sha256sum -c gitoversight-backup.tar.gz.sha256
  tar -xzf gitoversight-backup.tar.gz
  sha256sum -c gitoversight.db.sha256
  sha256sum -c checkpoint.json.sha256
)
test "$(sqlite3 "$validation_root/gitoversight.db" 'PRAGMA integrity_check;')" = "ok"
test "$(sqlite3 "$validation_root/gitoversight.db" 'PRAGMA user_version;')" = "$expected_schema"
test "$(cat "$validation_root/schema-version")" = "$expected_schema"
test "$(sqlite3 "$validation_root/gitoversight.db" "SELECT COUNT(*) FROM tenants WHERE id = '$expected_tenant';")" = "1"
test "$(sqlite3 "$validation_root/gitoversight.db" "SELECT COALESCE(MAX(generation),0) FROM policy_generations WHERE tenant_id = '$expected_tenant';")" = "$expected_policy_generation"
audit_tail=$(sqlite3 "$validation_root/gitoversight.db" "SELECT COALESCE((SELECT event_hash FROM audit_events WHERE tenant_id = '$expected_tenant' ORDER BY sequence DESC LIMIT 1),'GENESIS');")
audit_link_errors=$(sqlite3 "$validation_root/gitoversight.db" "WITH ordered AS (SELECT previous_hash, LAG(event_hash,1,'GENESIS') OVER (ORDER BY sequence) AS expected_previous FROM audit_events WHERE tenant_id = '$expected_tenant') SELECT COUNT(*) FROM ordered WHERE previous_hash <> expected_previous;")
test "$audit_link_errors" = "0"
test "$(jq -r .tail "$validation_root/checkpoint.json")" = "$audit_tail"
test "$(jq -r .policy_generation "$validation_root/checkpoint.json")" = "$expected_policy_generation"
"$restore_verifier" \
  -database "$validation_root/gitoversight.db" \
  -checkpoint-state "$validation_root/checkpoint.json" \
  -checkpoint-key "$checkpoint_key" \
  -tenant "$expected_tenant"
printf 'validated restore at %s\n' "$validation_root/gitoversight.db"
