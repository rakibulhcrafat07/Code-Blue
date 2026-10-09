#!/bin/bash
# kill-process.sh — Wazuh active-response: kill a verified-malicious process and
# quarantine its binary (reversible). Expects the offending path/pid via the alert.
set -euo pipefail
QDIR="/var/ossec/quarantine"; mkdir -p "$QDIR"
# Wazuh AR passes the alert JSON on stdin; pull the process path and pid.
read -r INPUT || true
PID="$(echo "$INPUT"  | sed -n 's/.*"pid":"\?\([0-9]\+\).*/\1/p' | head -1)"
EXE="$(echo "$INPUT"  | sed -n 's/.*"image":"\([^"]*\)".*/\1/p'    | head -1)"

if [ -n "${PID:-}" ] && kill -0 "$PID" 2>/dev/null; then
  kill -9 "$PID" && logger -t wz-kill "killed PID $PID"
fi
if [ -n "${EXE:-}" ] && [ -f "$EXE" ]; then
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  sha="$(sha256sum "$EXE" | awk '{print $1}')"
  mv "$EXE" "$QDIR/${ts}_${sha}.bin"          # quarantine (restore = move back)
  logger -t wz-kill "quarantined $EXE ($sha)"
fi
