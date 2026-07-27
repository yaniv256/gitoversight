#!/usr/bin/env bash
set -euo pipefail
umask 077

output=${1:?usage: package-app-bootstrap.sh OUTPUT_TAR_GZ}
target_arch=${TARGET_ARCH:-amd64}
case "$target_arch" in
  amd64|arm64) ;;
  *) echo "TARGET_ARCH must be amd64 or arm64" >&2; exit 1 ;;
esac

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
install -d -m 0755 "$stage/bin" "$stage/deploy/ec2"

CGO_ENABLED=0 GOOS=linux GOARCH="$target_arch" go build -trimpath -ldflags='-buildid=' -o "$stage/bin/gitoversight-app-bootstrap" "$repo/cmd/gitoversight-app-bootstrap"
install -m 0644 \
  "$repo/deploy/ec2/gitoversight-app-bootstrap.service" \
  "$repo/deploy/ec2/Caddyfile" \
  "$repo/deploy/ec2/nginx.conf.template" \
  "$repo/deploy/ec2/README.md" \
  "$stage/deploy/ec2/"
install -m 0755 \
  "$repo/deploy/ec2/install-app-bootstrap.sh" \
  "$repo/deploy/ec2/serve-app-bootstrap.sh" \
  "$repo/deploy/ec2/install-nginx-edge.sh" \
  "$stage/deploy/ec2/"

source_date_epoch=${SOURCE_DATE_EPOCH:-$(git -C "$repo" show -s --format=%ct HEAD)}
tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner -C "$stage" -czf "$output" .
sha256sum "$output"
