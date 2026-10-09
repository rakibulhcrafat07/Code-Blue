# Ransomware Incident — Technical Report

**Case:** CB-28-0001 · **Severity:** SEV-1 · **Analyst:** Rakibul H. Chowdhury

## 1. Summary
A safe ransomware simulator executed a full kill chain on the `lab.local` network after initial access via a phished credential (`lab\jdoe`). Encryption (T1486) was preceded by shadow-copy deletion (T1490) and preceded lateral movement (T1021). Detected in SIEM within ~2 minutes; contained via host isolation; recovered from offline backup.

## 2. Attack chain (see images/01-attack-chain.png)
| Stage | Technique | Evidence |
|---|---|---|
| Initial access | T1078 Valid Accounts (phished) | 4624 interactive logon from 203.0.113.55 on WS-03, 02:14 UTC |
| Discovery | T1083 / T1087 | `net view`, `net group "Domain Admins"` (Sysmon EID 1) |
| Lateral movement | T1021 Remote Services | 7045 service install on FILESRV-01; 4648 WS-03→WS-01/02 |
| Inhibit recovery | T1490 | `vssadmin delete shadows /all /quiet` 02:41:50 |
| Impact | T1486 | >200 files modified/40s 02:42:10; ransom note 02:42:55 |

## 3. Patient zero & scope
- **Patient zero:** WS-03 (earliest simulator process-create; phished logon).
- **Spread:** WS-03 → FILESRV-01 (`\Shares\Finance`) → WS-01, WS-02.
- **Not spread:** DC-01 creds harvested but no encryption; rest of fleet clean (confirmed by hunt).

## 4. Detections that fired
- `vssadmin-delete-shadows.yml` (T1490) — earliest, bought response time
- `mass-file-rename.yml` (T1486) — >200 files/1 proc/40s
- `ransom-note-dropped.yml` (T1486) — note filename pattern across dirs

## 5. Containment (see data/containment-log.csv)
Host isolation (Velociraptor Quarantine) of all 4 affected hosts within ~6 min of declaration; compromised account disabled; entry IP blocked; external RDP closed; fleet hunt confirmed no further hosts.

## 6. Eradication & recovery
Rotated all credentials (domain-wide theft assumed), reset `krbtgt` ×2, re-imaged patient zero, restored Finance share from offline backup, verified by hash, patched entry vector (MFA + RDP).

## 7. IOCs
| Type | Value |
|---|---|
| Account | lab\jdoe (phished) |
| IPv4 | 203.0.113.55 (initial access) |
| Behaviour | vssadmin delete shadows /all /quiet |
| File | *_RECOVER_FILES.txt |

## 8. Recommendations
Phishing-resistant MFA; close RDP exposure; tiered admin to limit lateral movement; monthly backup-restore tests; keep the three detections above in production.
