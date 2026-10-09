#!/bin/bash
# isolate-host.sh — Wazuh active-response: network-isolate a Linux host but keep
# the Wazuh manager reachable (so we can un-isolate remotely) and SSH from the admin subnet.
# SAFE ROLLBACK: running with "delete" restores connectivity. A dead-man timer auto-rolls back.
#
# Wazuh passes the action (add/delete) on stdin as JSON (AR v2) or as $1 (v1).
set -euo pipefail

ACTION="${1:-add}"
WAZUH_MGR="10.0.0.10"          # keep management channel up
ADMIN_SUBNET="10.0.0.0/24"     # keep break-glass SSH
ROLLBACK_AFTER="900"           # dead-man: auto un-isolate after 15 min if not confirmed
MARK="/var/run/wz-isolated"

apply() {
  # default-deny, allow loopback + established + manager + admin subnet
  nft add table inet wzcontain 2>/dev/null || true
  nft -f - <<NFT
table inet wzcontain {
  chain input  { type filter hook input  priority -200; policy drop;
    ct state established,related accept
    iif lo accept
    ip saddr ${ADMIN_SUBNET} accept
    ip saddr ${WAZUH_MGR} accept }
  chain output { type filter hook output priority -200; policy drop;
    ct state established,related accept
    oif lo accept
    ip daddr ${ADMIN_SUBNET} accept
    ip daddr ${WAZUH_MGR} accept }
}
NFT
  touch "$MARK"
  logger -t wz-isolate "HOST ISOLATED (manager+admin reachable). Dead-man ${ROLLBACK_AFTER}s."
  # dead-man rollback so a bad isolation can't strand the host forever
  ( sleep "$ROLLBACK_AFTER"; [ -f "$MARK.confirmed" ] || nft delete table inet wzcontain 2>/dev/null; \
    logger -t wz-isolate "dead-man rollback fired" ) &
}

rollback() {
  nft delete table inet wzcontain 2>/dev/null || true
  rm -f "$MARK" "$MARK.confirmed"
  logger -t wz-isolate "HOST UN-ISOLATED"
}

case "$ACTION" in
  add)     apply ;;
  delete)  rollback ;;
  confirm) touch "$MARK.confirmed" ;;   # analyst confirms -> cancel dead-man, keep isolated
  *) echo "usage: $0 {add|delete|confirm}"; exit 2 ;;
esac
