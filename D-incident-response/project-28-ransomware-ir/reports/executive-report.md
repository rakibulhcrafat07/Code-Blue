# Ransomware Incident — Executive Report

**Case:** CB-28-0001 · **Severity:** SEV-1 · **Status:** Resolved — recovered from backup · **Date:** 2026-02-10 (UTC)

## What happened (plain language)
A staff member's login was stolen through a phishing email. The attacker used it to move across the network and ran ransomware that encrypted files on one file server and three computers, and tried to delete our backups so we couldn't recover. Our monitoring caught it within **~2 minutes** of the encryption starting.

## Business impact
| Item | Impact |
|---|---|
| Systems affected | 1 file server + 3 workstations (of ~5 in scope) |
| Data affected | the Finance file share (encrypted, **recovered from backup**) |
| Data stolen | no confirmed exfiltration in this simulation |
| Downtime | Finance share unavailable ~3 hours during restore |
| Ransom | **not paid** — restored from our own offline backups |

## Key decisions
- Declared a major incident (SEV-1) immediately and isolated affected machines.
- **Did not pay** the ransom — our offline backups made recovery possible (decision made with legal).
- No customer data confirmed affected; notification duties reviewed with legal.

## Why it was contained, not catastrophic
1. We detected the **backup-deletion step** almost immediately and isolated hosts before the spread completed.
2. We had a **tested, offline backup** to restore from.
3. A documented IR plan meant clear roles and no wasted time.

## What we're fixing
| Gap | Action | Owner | Due |
|---|---|---|---|
| Phished credential (entry point) | Phishing-resistant MFA for all; quarterly phishing drills | IT Security | 30 days |
| External RDP was reachable | Close RDP at perimeter; VPN + MFA only | Infra | 14 days |
| Backup restore confidence | Monthly restore test (was not routine) | IT | Ongoing |

## Bottom line
The incident was **detected fast, contained, and fully recovered with no ransom paid**. The investment that paid off was **offline backups + monitoring + a rehearsed plan**. The remaining risk is the human entry point, addressed by the actions above.
