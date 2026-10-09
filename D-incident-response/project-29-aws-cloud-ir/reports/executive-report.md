# AWS Account Compromise — Executive Report

**Case:** CB-29-0001 · **Severity:** SEV-1 · **Status:** Contained & remediated · **Account:** (my lab AWS account)

## What happened (plain language)
One of our AWS access keys was leaked and used by an attacker from an unfamiliar location. They looked around the account, gave themselves higher permissions, and copied data out of a storage bucket. Our cloud threat-detection (GuardDuty) flagged the unusual activity, and we traced every action the key took using AWS's audit log.

## Business impact
| Item | Impact |
|---|---|
| Entry point | a leaked long-lived access key |
| Attacker actions | reconnaissance → gave self admin via a new role → copied an S3 bucket |
| Data affected | one storage bucket's contents accessed (scope confirmed from logs) |
| Infrastructure damage | none — no resources destroyed |
| Cost impact | reviewed billing for egress/compute abuse |

## Key decisions
- Disabled the leaked key **immediately** (kept it for investigation, not deleted).
- Removed the attacker's created role/user; locked the bucket from public access.
- Moved the account from long-lived keys toward **short-lived role credentials + MFA**.

## Why it was contained
1. **CloudTrail was already on** — we could reconstruct exactly what the key did.
2. **GuardDuty** caught the anomaly quickly.
3. A clear containment order (disable identity first) stopped further access fast.

## What we're fixing
| Gap | Action | Owner | Due |
|---|---|---|---|
| Long-lived access keys | Move to IAM roles / short-lived creds; rotate all keys | Cloud admin | 14 days |
| Over-broad permissions (`*FullAccess`) | Apply least privilege | Cloud admin | 30 days |
| EC2 role-credential theft risk | Enforce IMDSv2 | Cloud admin | 14 days |
| Limited S3 visibility | Enable S3 data events + access logs | Cloud admin | 7 days |

## Bottom line
A leaked key led to privilege escalation and data access, but logging + detection meant we **saw everything, contained it fast, and lost no infrastructure**. The fix is to end long-lived keys and tighten permissions.
