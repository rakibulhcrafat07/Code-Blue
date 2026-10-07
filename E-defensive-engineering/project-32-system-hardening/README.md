# Project 32 — System Hardening (CIS Benchmarks)

**Status:** ⚪ Planned  
**Track:** Defensive Engineering & Hardening

## Objective
Harden Windows and Linux to a measurable baseline and prove the improvement.

## Scenario
New servers are deployed with default settings. Bring them to CIS Level 1 without breaking services.

## Environment
| Item | Value |
|---|---|
| Case ID | `CB-32-____` |
| Host OS | |
| VMs used | |
| Tool versions | |
| Evidence source | |
| Time zone used | UTC |

## Tools
- CIS Benchmarks
- CIS-CAT Lite
- Lynis
- Wazuh SCA
- Windows LAPS
- GPO

## Evidence Inventory
| Item | Size | MD5 | SHA-256 | Source | Acquired (UTC) |
|---|---|---|---|---|---|
| | | | | | |

## Investigation / Build Steps

### Step 1 — Baseline score with CIS-CAT Lite (Windows) and Lynis (Linux)
_Commands, screenshots and observations._

### Step 2 — Apply CIS Level 1 via GPO and Linux configuration
_Commands, screenshots and observations._

### Step 3 — Deploy Windows LAPS for local admin passwords
_Commands, screenshots and observations._

### Step 4 — Disable legacy protocols (SMBv1, LLMNR, NBT-NS, NTLMv1)
_Commands, screenshots and observations._

### Step 5 — Re-score and record every exception with reason
_Commands, screenshots and observations._

### Step 6 — Monitor drift with Wazuh SCA
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
- T1557.001 LLMNR/NBT-NS Poisoning
- T1078.003 Local Accounts

## IOCs
| Type | Value | Context |
|---|---|---|
| | | |

## Deliverables
- [ ] Investigation notes
- [ ] Screenshots in `images/`
- [ ] Before/after compliance scores
- [ ] Hardening GPO export
- [ ] Exception register
- [ ] Final report in `report/`

## Key Learnings
1. 
2. 
3. 
