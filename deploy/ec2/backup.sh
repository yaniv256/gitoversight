#!/usr/bin/env bash
set -euo pipefail
umask 077

database=${GITOVERSIGHT_DATABASE:-/var/lib/gitoversight-api/gitoversight.db}
checkpoint_state=${GITOVERSIGHT_CHECKPOINT_STATE:-/var/lib/gitoversight-checkpoint/state.json}
backup_parent=${GITOVERSIGHT_BACKUP_PARENT:-/var/lib/gitoversight-api}
destination=${1:?usage: backup.sh s3://bucket/prefix}
kms_key=${GITOVERSIGHT_BACKUP_KMS_KEY:?GITOVERSIGHT_BACKUP_KMS_KEY is required}
if [[ ! -d "$backup_parent" ]]; then
  install -d -m 0700 "$backup_parent"
fi
workdir=$(mktemp -d "$backup_parent/backup.XXXXXX")
api_stopped=0
edge_mode=${GITOVERSIGHT_EDGE_MODE:-caddy}
maintenance_marker=${GITOVERSIGHT_MAINTENANCE_MARKER:-/run/gitoversight-maintenance}
drain_timeout=${GITOVERSIGHT_BACKUP_DRAIN_TIMEOUT_SECONDS:-60}
[[ "$drain_timeout" =~ ^[1-9][0-9]*$ ]]
ingress_closed=0

close_ingress() {
  case "$edge_mode" in
    caddy)
      systemctl stop caddy.service
      ;;
    nginx)
      if [ -e "$maintenance_marker" ]; then
        echo "Git Oversight maintenance marker already exists" >&2
        return 1
      fi
      install -m 0644 /dev/null "$maintenance_marker"
      ;;
    *)
      echo "GITOVERSIGHT_EDGE_MODE must be caddy or nginx" >&2
      return 2
      ;;
  esac
  ingress_closed=1
}

open_ingress() {
  case "$edge_mode" in
    caddy)
      systemctl start caddy.service
      ;;
    nginx)
      rm -f "$maintenance_marker"
      ;;
  esac
  ingress_closed=0
}

cleanup() {
  rm -rf "$workdir"
  if [[ $api_stopped = 1 ]]; then
    systemctl start gitoversight-api.service
  fi
  if [[ $ingress_closed = 1 ]]; then
    open_ingress
  fi
}
trap cleanup EXIT

backup="$workdir/gitoversight.db"
# Stop public ingress first, then let already-authorized mutations finish while
# the authority RPC remains available. A snapshot is forbidden while any
# operation is executing because a restored worker must never retry it blindly.
close_ingress
deadline=$((SECONDS + drain_timeout))
while [[ "$(sqlite3 "$database" "SELECT COUNT(*) FROM operation_packets WHERE state = 'executing';")" != "0" ]]; do
  if (( SECONDS >= deadline )); then
    echo "backup refused: execution drain timed out" >&2
    exit 1
  fi
  sleep 1
done
# The API is the only identity allowed to extend authority state. Quiescing it
# after the drain makes SQLite and the signed checkpoint one coherent snapshot.
systemctl stop gitoversight-api.service
api_stopped=1
sqlite3 "$database" ".timeout 5000" ".backup '$backup'"
test "$(sqlite3 "$backup" 'PRAGMA integrity_check;')" = "ok"
sqlite3 "$backup" 'PRAGMA user_version;' > "$workdir/schema-version"
install -m 0600 "$checkpoint_state" "$workdir/checkpoint.json"
systemctl start gitoversight-api.service
api_stopped=0
open_ingress
(
  cd "$workdir"
  sha256sum gitoversight.db > gitoversight.db.sha256
  sha256sum checkpoint.json > checkpoint.json.sha256
  tar -czf gitoversight-backup.tar.gz gitoversight.db gitoversight.db.sha256 checkpoint.json checkpoint.json.sha256 schema-version
  sha256sum gitoversight-backup.tar.gz > gitoversight-backup.tar.gz.sha256
)

stamp=$(date -u +%Y%m%dT%H%M%SZ)
aws s3 cp "$workdir/gitoversight-backup.tar.gz" "$destination/$stamp.tar.gz" --sse aws:kms --sse-kms-key-id "$kms_key" --only-show-errors
aws s3 cp "$workdir/gitoversight-backup.tar.gz.sha256" "$destination/$stamp.tar.gz.sha256" --sse aws:kms --sse-kms-key-id "$kms_key" --only-show-errors
printf '%s\n' "$destination/$stamp.tar.gz"
