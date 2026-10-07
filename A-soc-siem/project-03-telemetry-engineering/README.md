# Project 03 — Telemetry Engineering

**Status:** ⚪ Planned  
**Track:** SOC & SIEM

## Objective
Raise log quality so detections are possible, and measure coverage gaps.

## Scenario
Default Windows logging misses most attacker activity. Fix it and prove the difference.

## Environment
| Item | Value |
|---|---|
| Case ID | `CB-03-____` |
| Host OS | |
| VMs used | |
| Tool versions | |
| Evidence source | |
| Time zone used | UTC |

## Tools
- Sysmon (community config)
- Windows Advanced Audit Policy via GPO
- PowerShell Script Block & Module logging
- auditd

## Evidence Inventory
| Item | Size | MD5 | SHA-256 | Source | Acquired (UTC) |
|---|---|---|---|---|---|
| | | | | | |

## Investigation / Build Steps

### Step 1 — Baseline: run a few Atomic tests with default logging and record what is missing
_Commands, screenshots and observations._

### Step 2 — Deploy Sysmon with a community config via GPO
_Commands, screenshots and observations._

### Step 3 — Enable advanced audit policy, command-line process auditing, PowerShell logging
_Commands, screenshots and observations._

### Step 4 — Configure auditd rules on Linux
_Commands, screenshots and observations._

### Step 5 — Re-run the same tests and compare visibility
_Commands, screenshots and observations._

### Step 6 — Map the new visibility to ATT&CK data sources
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
- T1059.001 PowerShell
- T1053 Scheduled Task/Job

## IOCs
| Type | Value | Context |
|---|---|---|
| | | |

## Deliverables
- [ ] Investigation notes
- [ ] Screenshots in `images/`
- [ ] Before/after visibility table
- [ ] GPO and Sysmon config files
- [ ] ATT&CK data-source coverage map
- [ ] Final report in `report/`

## Key Learnings
1. 
2. 
3. 
