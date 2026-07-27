#!/usr/bin/env bash
set -euo pipefail
umask 077

output=${1:?usage: package.sh OUTPUT_TAR_GZ RUNTIME_CONFIG_DIRECTORY}
runtime_config=${2:?usage: package.sh OUTPUT_TAR_GZ RUNTIME_CONFIG_DIRECTORY}
target_arch=${TARGET_ARCH:-amd64}
case "$target_arch" in
  amd64|arm64) ;;
  *) echo "TARGET_ARCH must be amd64 or arm64" >&2; exit 1 ;;
esac
for name in api.json worker.json notify.json policy.json; do
  test -f "$runtime_config/$name"
  jq -e . "$runtime_config/$name" >/dev/null
done

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
install -d -m 0755 "$stage/bin" "$stage/config/runtime" "$stage/deploy/ec2"

for command in gitoversight-api gitoversight-worker gitoversight-checkpoint gitoversight-notify gitoversight-restore-verify gitoversightctl; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$target_arch" go build -trimpath -ldflags='-buildid=' -o "$stage/bin/$command" "$repo/cmd/$command"
done
for name in api.json worker.json notify.json policy.json; do
  install -m 0644 "$runtime_config/$name" "$stage/config/runtime/$name"
done
install -m 0644 \
  "$repo/deploy/ec2/gitoversight-api.service" \
  "$repo/deploy/ec2/gitoversight-worker.service" \
  "$repo/deploy/ec2/gitoversight-checkpoint.service" \
  "$repo/deploy/ec2/gitoversight-notify.service" \
  "$repo/deploy/ec2/Caddyfile" \
  "$repo/deploy/ec2/nginx.conf.template" \
  "$repo/deploy/ec2/cloud-init.yaml" \
  "$repo/deploy/ec2/sysusers.conf" \
  "$repo/deploy/ec2/tmpfiles.conf" \
  "$repo/deploy/ec2/README.md" \
  "$stage/deploy/ec2/"
install -m 0755 "$repo/deploy/ec2/install.sh" "$repo/deploy/ec2/install-nginx-edge.sh" "$repo/deploy/ec2/backup.sh" "$repo/deploy/ec2/restore.sh" "$stage/deploy/ec2/"

source_date_epoch=${SOURCE_DATE_EPOCH:-$(git -C "$repo" show -s --format=%ct HEAD)}
tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner -C "$stage" -czf "$output" .
sha256sum "$output"
