# Project 37 — Deception & Honeypots

**Status:** ⚪ Planned  
**Track:** Defensive Engineering & Hardening

## Objective
Catch attackers early with decoys that legitimate users never touch.

## Scenario
The SOC wants high-fidelity alerts with near-zero false positives.

## Environment
| Item | Value |
|---|---|
| Case ID | `CB-37-____` |
| Host OS | |
| VMs used | |
| Tool versions | |
| Evidence source | |
| Time zone used | UTC |

## Tools
- T-Pot
- Canarytokens
- Decoy AD accounts and files
- Wazuh

## Evidence Inventory
| Item | Size | MD5 | SHA-256 | Source | Acquired (UTC) |
|---|---|---|---|---|---|
| | | | | | |

## Investigation / Build Steps

### Step 1 — Deploy T-Pot in an isolated segment; collect attack data
_Commands, screenshots and observations._

### Step 2 — Place canary tokens (documents, AWS keys, URLs) in realistic locations
_Commands, screenshots and observations._

### Step 3 — Create a decoy privileged AD account and decoy file share
_Commands, screenshots and observations._

### Step 4 — Route all decoy triggers to the SIEM as high-severity alerts
_Commands, screenshots and observations._

### Step 5 — Trigger each decoy from the attacker VM; measure alert latency
_Commands, screenshots and observations._

### Step 6 — Summarize attacker behaviour observed in T-Pot
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
- T1083 File and Directory Discovery
- T1087 Account Discovery
- T1552 Unsecured Credentials

## IOCs
| Type | Value | Context |
|---|---|---|
| | | |

## Deliverables
- [ ] Investigation notes
- [ ] Screenshots in `images/`
- [ ] Decoy inventory and placement map
- [ ] Alert latency table
- [ ] Honeypot attack summary
- [ ] Final report in `report/`

## Key Learnings
1. 
2. 
3. 
