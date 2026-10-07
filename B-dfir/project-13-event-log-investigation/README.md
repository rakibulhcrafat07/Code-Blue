# Project 13 — Windows Event Log Investigation

**Status:** ⚪ Planned  
**Track:** DFIR

## Objective
Trace an intrusion end to end using only Windows event logs.

## Scenario
Brute force on RDP, successful logon, new admin account, scheduled task persistence, lateral movement.

## Environment
| Item | Value |
|---|---|
| Case ID | `CB-13-____` |
| Host OS | |
| VMs used | |
| Tool versions | |
| Evidence source | |
| Time zone used | UTC |

## Tools
- Hayabusa
- Chainsaw
- EvtxECmd
- Timeline Explorer

## Evidence Inventory
| Item | Size | MD5 | SHA-256 | Source | Acquired (UTC) |
|---|---|---|---|---|---|
| | | | | | |

## Investigation / Build Steps

### Step 1 — Simulate the attack chain in the lab; export EVTX
_Commands, screenshots and observations._

### Step 2 — Run Hayabusa and Chainsaw; review hits
_Commands, screenshots and observations._

### Step 3 — Manually verify key Event IDs (4625, 4624, 4720, 4732, 4698, 7045, 4688)
_Commands, screenshots and observations._

### Step 4 — Build the attack timeline
_Commands, screenshots and observations._

### Step 5 — Map each step to ATT&CK
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
- T1110
- T1078 Valid Accounts
- T1136
- T1053.005 Scheduled Task
- T1021.001 RDP

## IOCs
| Type | Value | Context |
|---|---|---|
| | | |

## Deliverables
- [ ] Investigation notes
- [ ] Screenshots in `images/`
- [ ] Event ID reference table
- [ ] Attack timeline
- [ ] Detection recommendations
- [ ] Final report in `report/`

## Key Learnings
1. 
2. 
3. 
