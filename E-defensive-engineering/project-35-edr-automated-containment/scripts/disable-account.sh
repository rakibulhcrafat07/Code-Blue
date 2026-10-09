#!/bin/bash
# disable-account.sh — Wazuh active-response: disable a newly-created off-hours account
# (REVERSIBLE: re-enable with `usermod -U` / enable in AD). Also revokes active sessions.
set -euo pipefail
read -r INPUT || true
USER="$(echo "$INPUT" | sed -n 's/.*"dstuser":"\([^"]*\)".*/\1/p' | head -1)"
[ -z "${USER:-}" ] && { logger -t wz-disable "no user in alert"; exit 0; }
usermod -L "$USER" 2>/dev/null || true          # lock password
usermod -s /sbin/nologin "$USER" 2>/dev/null || true
pkill -KILL -u "$USER" 2>/dev/null || true      # kill active sessions
logger -t wz-disable "DISABLED account $USER (reversible: usermod -U $USER)"
