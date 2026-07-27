#!/usr/bin/env bash
set -euo pipefail
umask 077

if [ "$(id -u)" -ne 0 ]; then
  echo "gitoversight-serve-app-bootstrap must run as root" >&2
  exit 1
fi

digest_file=/etc/gitoversight/app-bootstrap.digest
if [ "$(stat -c %F "$digest_file")" != "regular file" ] || [ "$(stat -c %a "$digest_file")" != "600" ] || [ "$(stat -c %u "$digest_file")" != "0" ]; then
  echo "App bootstrap digest file is not root-owned mode 0600" >&2
  exit 1
fi
packet_digest=$(tr -d '\n' < "$digest_file")
case "$packet_digest" in
  *[!0-9a-f]*|'') echo "App bootstrap digest is invalid" >&2; exit 1 ;;
esac
if [ "${#packet_digest}" -ne 64 ]; then
  echo "App bootstrap digest is invalid" >&2
  exit 1
fi

exec /usr/local/libexec/gitoversight-app-bootstrap \
  --serve \
  --bundle-dir /etc/gitoversight/app-bootstrap \
  --packet-digest "$packet_digest" \
  --secret-dir /etc/gitoversight-secrets/github-app \
  --listen 127.0.0.1:17446
