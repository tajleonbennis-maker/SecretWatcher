#!/usr/bin/env bash
set -euo pipefail

install -m 644 /tmp/secretwatcher-health.service /etc/systemd/system/secretwatcher-health.service
install -m 644 /tmp/secretwatcher-health.timer /etc/systemd/system/secretwatcher-health.timer
install -m 755 /tmp/secretwatcher-health-recover /usr/local/sbin/secretwatcher-health-recover

install -d /etc/systemd/system/secretwatcher-health.service.d
install -m 644 /tmp/secretwatcher-health-override.conf /etc/systemd/system/secretwatcher-health.service.d/recover.conf

systemctl daemon-reload
systemctl enable --now secretwatcher-health.timer
systemctl start secretwatcher-health.service
systemctl is-active secretwatcher.service
systemctl is-active secretwatcher-health.timer

