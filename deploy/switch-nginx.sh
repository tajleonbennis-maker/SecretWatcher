#!/usr/bin/env bash
set -euo pipefail

enabled_dir="/etc/nginx/sites-enabled"
available_dir="/etc/nginx/sites-available"
disabled_dir="/etc/nginx/sites-disabled"
old_link="$enabled_dir/cyberstroll-dashboard"
new_link="$enabled_dir/secretwatcher"
stamp="$(date +%Y%m%d%H%M%S)"

install -d "$disabled_dir"
if [[ -f "$available_dir/cyberstroll-dashboard" ]]; then
  cp -a "$available_dir/cyberstroll-dashboard" "$available_dir/cyberstroll-dashboard.secretwatcher-backup-$stamp"
fi
install -m 644 /opt/secretwatcher/current/deploy/secretwatcher.nginx "$available_dir/secretwatcher"
ln -sfn "$available_dir/secretwatcher" "$new_link"

old_was_enabled=false
if [[ -L "$old_link" || -f "$old_link" ]]; then
  mv "$old_link" "$disabled_dir/cyberstroll-dashboard.$stamp"
  old_was_enabled=true
fi

if ! nginx -t; then
  rm -f "$new_link"
  if [[ "$old_was_enabled" == true ]]; then
    mv "$disabled_dir/cyberstroll-dashboard.$stamp" "$old_link"
  fi
  nginx -t
  exit 1
fi

systemctl reload nginx
curl -fsS -H 'Host: www.cyberstroll.top' http://127.0.0.1/health

