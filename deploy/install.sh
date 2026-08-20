#!/usr/bin/env bash
set -euo pipefail

release_dir="/opt/secretwatcher/releases/20260820-mvp1"
current_link="/opt/secretwatcher/current"
venv_dir="/opt/secretwatcher/venv"
data_dir="/var/lib/secretwatcher"

if ! id secretwatcher >/dev/null 2>&1; then
  useradd --system --home /opt/secretwatcher --shell /usr/sbin/nologin secretwatcher
fi

install -d -o secretwatcher -g secretwatcher /opt/secretwatcher/releases "$data_dir"
if [[ -e "$release_dir" ]]; then
  mv "$release_dir" "${release_dir}.previous-$(date +%s)"
fi
install -d -o secretwatcher -g secretwatcher "$release_dir"
tar -xzf /tmp/secretwatcher-release.tar.gz -C "$release_dir"
chown -R secretwatcher:secretwatcher "$release_dir"
ln -sfn "$release_dir" "$current_link"

if [[ ! -x "$venv_dir/bin/python" ]]; then
  python3 -m venv "$venv_dir"
fi
"$venv_dir/bin/pip" install --quiet "$current_link"

if [[ ! -f "$data_dir/secretwatcher.db" ]]; then
  install -o secretwatcher -g secretwatcher -m 600 /tmp/secretwatcher.db "$data_dir/secretwatcher.db"
fi
chown -R secretwatcher:secretwatcher /opt/secretwatcher "$data_dir"

install -m 644 "$current_link/deploy/secretwatcher.service" /etc/systemd/system/secretwatcher.service
systemctl daemon-reload
systemctl enable --now secretwatcher.service
sleep 2
curl -fsS http://127.0.0.1:8092/health
systemctl is-active secretwatcher.service

