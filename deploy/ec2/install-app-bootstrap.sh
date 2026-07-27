#!/usr/bin/env bash
set -euo pipefail
umask 077

if [ "$#" -ne 2 ]; then
  echo "usage: install-app-bootstrap.sh REVIEW_BUNDLE PACKET_DIGEST" >&2
  exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "install-app-bootstrap.sh must run as root" >&2
  exit 1
fi

review_bundle=$1
packet_digest=$2
case "$review_bundle" in
  /*) ;;
  *) echo "review bundle must be an absolute path" >&2; exit 2 ;;
esac
digest_re='^[0-9a-f]{64}$'
if [[ ! "$packet_digest" =~ $digest_re ]]; then
  echo "packet digest must match ^[0-9a-f]{64}$" >&2
  exit 2
fi

if [ "$(stat -c %F "$review_bundle")" != "directory" ] || [ "$(stat -c %a "$review_bundle")" != "700" ] || [ "$(stat -c %u "$review_bundle")" != "0" ]; then
  echo "review bundle must be a root-owned mode-0700 directory" >&2
  exit 1
fi
for name in manifest-packet.json register-github-app.html; do
  path="$review_bundle/$name"
  if [ "$(stat -c %F "$path")" != "regular file" ] || [ "$(stat -c %a "$path")" != "600" ] || [ "$(stat -c %u "$path")" != "0" ]; then
    echo "review file $name must be a root-owned mode-0600 regular file" >&2
    exit 1
  fi
done
if [ "$(find "$review_bundle" -mindepth 1 -maxdepth 1 | wc -l)" -ne 2 ]; then
	echo "review bundle must contain exactly the reviewed packet and registration page" >&2
	exit 1
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
"$root/bin/gitoversight-app-bootstrap" --verify --bundle-dir "$review_bundle" --packet-digest "$packet_digest" >/dev/null

target=/etc/gitoversight/app-bootstrap
if [ -e "$target" ] || [ -e /etc/gitoversight/app-bootstrap.digest ] || [ -e /etc/gitoversight-secrets/github-app ]; then
	echo "App bootstrap state or credentials already exist; refusing overwrite" >&2
	exit 1
fi
install -D -m 0755 "$root/bin/gitoversight-app-bootstrap" /usr/local/libexec/gitoversight-app-bootstrap
install -d -m 0755 /etc/gitoversight
install -d -m 0700 /etc/gitoversight-secrets "$target"
install -m 0600 "$review_bundle/manifest-packet.json" "$target/manifest-packet.json"
install -m 0600 "$review_bundle/register-github-app.html" "$target/register-github-app.html"
install -m 0600 /dev/null /etc/gitoversight/app-bootstrap.digest
printf '%s\n' "$packet_digest" > /etc/gitoversight/app-bootstrap.digest
/usr/local/libexec/gitoversight-app-bootstrap --verify --bundle-dir "$target" --packet-digest "$packet_digest" >/dev/null

install -D -m 0755 "$root/deploy/ec2/serve-app-bootstrap.sh" /usr/local/sbin/gitoversight-serve-app-bootstrap
install -D -m 0755 "$root/deploy/ec2/install-nginx-edge.sh" /usr/local/sbin/gitoversight-install-nginx-edge
install -D -m 0644 "$root/deploy/ec2/nginx.conf.template" /usr/share/gitoversight/nginx.conf.template
install -D -m 0644 "$root/deploy/ec2/Caddyfile" /usr/share/gitoversight/Caddyfile
install -D -m 0644 "$root/deploy/ec2/gitoversight-app-bootstrap.service" /etc/systemd/system/gitoversight-app-bootstrap.service
systemctl daemon-reload
