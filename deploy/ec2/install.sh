#!/usr/bin/env bash
set -euo pipefail
umask 077

if [ "$(id -u)" -ne 0 ]; then
  echo "install.sh must run as root" >&2
  exit 1
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
for binary in gitoversight-api gitoversight-worker gitoversight-checkpoint gitoversight-notify gitoversight-restore-verify gitoversightctl; do
  test -x "$root/bin/$binary"
done
for runtime_config in api.json worker.json notify.json policy.json; do
  test -f "$root/config/runtime/$runtime_config"
done

install -D -m 0644 "$root/deploy/ec2/sysusers.conf" /usr/lib/sysusers.d/gitoversight.conf
install -D -m 0644 "$root/deploy/ec2/tmpfiles.conf" /usr/lib/tmpfiles.d/gitoversight.conf
systemd-sysusers /usr/lib/sysusers.d/gitoversight.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/gitoversight.conf

for binary in gitoversight-api gitoversight-worker gitoversight-checkpoint gitoversight-notify gitoversight-restore-verify; do
  install -D -m 0755 "$root/bin/$binary" "/usr/local/libexec/$binary"
done
install -D -m 0755 "$root/bin/gitoversightctl" /usr/local/bin/gitoversightctl
for unit in gitoversight-api.service gitoversight-worker.service gitoversight-checkpoint.service gitoversight-notify.service; do
	install -D -m 0644 "$root/deploy/ec2/$unit" "/etc/systemd/system/$unit"
done
for runtime_config in notify.json policy.json; do
  install -D -m 0644 "$root/config/runtime/$runtime_config" "/etc/gitoversight/$runtime_config"
done
api_uid=$(id -u gitoversight-api)
worker_uid=$(id -u gitoversight-worker)
notification_uid=$(id -u gitoversight-notify)
authority_gid=$(getent group gitoversight-authority | cut -d: -f3)
notification_gid=$(getent group gitoversight-notifications | cut -d: -f3)
jq --argjson uid "$api_uid" '.broker_uid = $uid' "$root/config/runtime/worker.json" > /etc/gitoversight/worker.json
jq --argjson worker_uid "$worker_uid" --argjson authority_gid "$authority_gid" --argjson notification_uid "$notification_uid" --argjson notification_gid "$notification_gid" '.worker_uid = $worker_uid | .authority_socket_gid = $authority_gid | .notification_uid = $notification_uid | .notification_socket_gid = $notification_gid' "$root/config/runtime/api.json" > /etc/gitoversight/api.json
chmod 0644 /etc/gitoversight/worker.json
chmod 0644 /etc/gitoversight/api.json
install -D -m 0644 "$root/deploy/ec2/Caddyfile" /usr/share/gitoversight/Caddyfile
install -D -m 0644 "$root/deploy/ec2/nginx.conf.template" /usr/share/gitoversight/nginx.conf.template
install -D -m 0755 "$root/deploy/ec2/install-nginx-edge.sh" /usr/local/sbin/gitoversight-install-nginx-edge
install -D -m 0755 "$root/deploy/ec2/backup.sh" /usr/local/sbin/gitoversight-backup
install -D -m 0755 "$root/deploy/ec2/restore.sh" /usr/local/sbin/gitoversight-restore

edge=${GITOVERSIGHT_EDGE:-}
if [ -f /etc/gitoversight/install.env ]; then
  # cloud-init writes this root-owned file for a dedicated-host install.
  # Existing shared hosts intentionally omit it and configure Nginx separately.
  source /etc/gitoversight/install.env
  edge=${GITOVERSIGHT_EDGE:-caddy}
fi
case "$edge" in
  ""|nginx)
    ;;
  caddy)
    : "${GITOVERSIGHT_DOMAIN:?GITOVERSIGHT_DOMAIN is required for the Caddy edge}"
    : "${ACME_EMAIL:?ACME_EMAIL is required for the Caddy edge}"
    install -D -m 0644 /usr/share/gitoversight/Caddyfile /etc/caddy/Caddyfile
    install -D -m 0644 /dev/null /etc/gitoversight/caddy.env
    printf 'GITOVERSIGHT_DOMAIN=%s\nACME_EMAIL=%s\n' "$GITOVERSIGHT_DOMAIN" "$ACME_EMAIL" > /etc/gitoversight/caddy.env
    install -d -m 0755 /etc/systemd/system/caddy.service.d
    printf '[Service]\nEnvironmentFile=/etc/gitoversight/caddy.env\n' > /etc/systemd/system/caddy.service.d/gitoversight.conf
    ;;
  *)
    echo "GITOVERSIGHT_EDGE must be caddy or nginx" >&2
    exit 2
    ;;
esac

systemctl daemon-reload
