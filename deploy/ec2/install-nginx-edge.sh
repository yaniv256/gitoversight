#!/usr/bin/env bash
set -euo pipefail
umask 077

if [ "$#" -ne 2 ]; then
  echo "usage: install-nginx-edge.sh DOMAIN EMAIL" >&2
  exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "install-nginx-edge.sh must run as root" >&2
  exit 1
fi

domain=$1
email=$2
domain_re='^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$'
email_re='^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
if [[ ! "$domain" =~ $domain_re ]]; then
  echo "invalid public DNS name" >&2
  exit 2
fi
if [[ ! "$email" =~ $email_re ]]; then
  echo "invalid ACME email" >&2
  exit 2
fi

for command in nginx certbot install mktemp sed systemctl; do
  command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 1; }
done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
template=${GITOVERSIGHT_NGINX_TEMPLATE:-/usr/share/gitoversight/nginx.conf.template}
if [ ! -f "$template" ]; then
  template="$script_dir/nginx.conf.template"
fi
test -f "$template"

site_available=/etc/nginx/sites-available/gitoversight
site_enabled=/etc/nginx/sites-enabled/gitoversight
workdir=$(mktemp -d /run/gitoversight-nginx.XXXXXX)
final_config="$workdir/final.conf"
bootstrap_config="$workdir/bootstrap.conf"
backup_config="$workdir/previous.conf"
had_previous=false
committed=false

if [ -e "$site_available" ]; then
  install -m 0600 "$site_available" "$backup_config"
  had_previous=true
fi

restore_previous() {
  if [ "$committed" = false ]; then
    if [ "$had_previous" = true ]; then
      install -m 0644 "$backup_config" "$site_available"
    else
      rm -f "$site_available" "$site_enabled"
    fi
    nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
  fi
  rm -rf "$workdir"
}
trap restore_previous EXIT

sed "s/__GITOVERSIGHT_DOMAIN__/$domain/g" "$template" > "$final_config"
if grep -q '__GITOVERSIGHT_DOMAIN__' "$final_config"; then
  echo "unrendered Nginx domain placeholder" >&2
  exit 1
fi

if [ ! -s "/etc/letsencrypt/live/$domain/fullchain.pem" ] || [ ! -s "/etc/letsencrypt/live/$domain/privkey.pem" ]; then
  install -d -m 0755 /var/lib/letsencrypt
  cat > "$bootstrap_config" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $domain;
    location ^~ /.well-known/acme-challenge/ { root /var/lib/letsencrypt; }
    location / { return 404; }
}
EOF
  install -m 0644 "$bootstrap_config" "$site_available.new"
  mv "$site_available.new" "$site_available"
  ln -sfn "$site_available" "$site_enabled"
  nginx -t
  systemctl reload nginx
  certbot certonly --nginx --non-interactive --agree-tos --email "$email" -d "$domain"
fi

install -m 0644 "$final_config" "$site_available.new"
mv "$site_available.new" "$site_available"
ln -sfn "$site_available" "$site_enabled"
nginx -t
systemctl reload nginx
committed=true
echo "https://$domain"
