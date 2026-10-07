# Project 33 — Active Directory Security

**Status:** ⚪ Planned  
**Track:** Defensive Engineering & Hardening

## Objective
Assess, harden and monitor Active Directory against the attacks used in real intrusions.

## Scenario
The lab domain was built quickly and has typical misconfigurations. Find them, fix them and detect abuse.

## Environment
| Item | Value |
|---|---|
| Case ID | `CB-33-____` |
| Host OS | |
| VMs used | |
| Tool versions | |
| Evidence source | |
| Time zone used | UTC |

## Tools
- PingCastle
- Purple Knight
- BloodHound (defensive use)
- Wazuh / Elastic
- Windows event logs

## Evidence Inventory
| Item | Size | MD5 | SHA-256 | Source | Acquired (UTC) |
|---|---|---|---|---|---|
| | | | | | |

## Investigation / Build Steps

### Step 1 — Seed common misconfigurations (SPN on privileged user, weak delegation, excessive admins)
_Commands, screenshots and observations._

### Step 2 — Audit with PingCastle and Purple Knight; record scores
_Commands, screenshots and observations._

### Step 3 — Map attack paths with BloodHound and break the shortest ones
_Commands, screenshots and observations._

### Step 4 — Simulate Kerberoasting, AS-REP roasting, DCSync and password spraying
_Commands, screenshots and observations._

### Step 5 — Build detections (4769 RC4, 4662 replication, 4771/4625 spray patterns)
_Commands, screenshots and observations._

### Step 6 — Implement tiered admin model and Protected Users; re-audit
_Commands, screenshots and observations._

## Problems Encountered
| Problem | What happened | Root cause | Fix | Lesson |
|---|---|---|---|---|
| | | | | |

## Findings
| # | Observation | Evidence location | Interpretation | Confidence |
|---|---|---|---|---|
| 1 | | | | |

## ATT&CK Mapping
- T1558.003 Kerberoasting
- T1558.004 AS-REP Roasting
- T1003.006 DCSync
- T1110.003 Password Spraying

## IOCs
| Type | Value | Context |
|---|---|---|
| | | |

## Deliverables
- [ ] Investigation notes
- [ ] Screenshots in `images/`
- [ ] AD audit scores (before/after)
- [ ] Attack path findings
- [ ] AD detection rules
- [ ] Final report in `report/`

## Key Learnings
1. 
2. 
3. 
