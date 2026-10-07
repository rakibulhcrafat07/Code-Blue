# Project 34 — Network Defense: IDS/IPS & Firewall

**Status:** ⚪ Planned  
**Track:** Defensive Engineering & Hardening

## Objective
Prevent and detect network attacks at the perimeter and between segments.

## Scenario
The lab network allows everything everywhere. Segment it, filter egress and block attacks inline.

## Environment
| Item | Value |
|---|---|
| Case ID | `CB-34-____` |
| Host OS | |
| VMs used | |
| Tool versions | |
| Evidence source | |
| Time zone used | UTC |

## Tools
- pfSense
- Suricata (inline IPS)
- Emerging Threats rules
- Zeek

## Evidence Inventory
| Item | Size | MD5 | SHA-256 | Source | Acquired (UTC) |
|---|---|---|---|---|---|
| | | | | | |

## Investigation / Build Steps

### Step 1 — Document current allowed flows; design segmentation and least-privilege rules
_Commands, screenshots and observations._

### Step 2 — Implement firewall rules and egress filtering (DNS, HTTP only via proxy)
_Commands, screenshots and observations._

### Step 3 — Deploy Suricata in IPS mode with ET Open rules
_Commands, screenshots and observations._

### Step 4 — Run scans, exploits and C2 simulation from the attacker VM
_Commands, screenshots and observations._

### Step 5 — Tune rules: suppress false positives, record changes
_Commands, screenshots and observations._

### Step 6 — Verify segmentation with a reachability test matrix
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
- T1046 Network Service Discovery
- T1071 Application Layer Protocol
- T1048

## IOCs
| Type | Value | Context |
|---|---|---|
| | | |

## Deliverables
- [ ] Investigation notes
- [ ] Screenshots in `images/`
- [ ] Firewall rule set with justification
- [ ] Reachability matrix (before/after)
- [ ] Suricata tuning log
- [ ] Final report in `report/`

## Key Learnings
1. 
2. 
3. 
