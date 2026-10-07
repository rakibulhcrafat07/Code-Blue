# Project 14 — Linux Intrusion Investigation

**Status:** ⚪ Planned  
**Track:** DFIR

## Objective
Investigate a compromised Linux web server.

## Scenario
A web shell was uploaded through a vulnerable app, followed by privilege escalation and persistence.

## Environment
| Item | Value |
|---|---|
| Case ID | `CB-14-____` |
| Host OS | |
| VMs used | |
| Tool versions | |
| Evidence source | |
| Time zone used | UTC |

## Tools
- UAC (Unix-like Artifacts Collector)
- auditd / ausearch
- journalctl
- grep/awk

## Evidence Inventory
| Item | Size | MD5 | SHA-256 | Source | Acquired (UTC) |
|---|---|---|---|---|---|
| | | | | | |

## Investigation / Build Steps

### Step 1 — Compromise the lab web server (vulnerable app -> web shell)
_Commands, screenshots and observations._

### Step 2 — Collect triage with UAC; hash the collection
_Commands, screenshots and observations._

### Step 3 — Analyze web access logs for the exploit and shell use
_Commands, screenshots and observations._

### Step 4 — Check auth.log, bash history, new users, sudoers, SSH keys
_Commands, screenshots and observations._

### Step 5 — Check cron, systemd services and rc scripts for persistence
_Commands, screenshots and observations._

### Step 6 — Build timeline and IOC list
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
- T1190 Exploit Public-Facing App
- T1505.003 Web Shell
- T1053.003 Cron
- T1098.004 SSH Authorized Keys

## IOCs
| Type | Value | Context |
|---|---|---|
| | | |

## Deliverables
- [ ] Investigation notes
- [ ] Screenshots in `images/`
- [ ] Log excerpts (sanitized)
- [ ] Persistence findings
- [ ] Timeline
- [ ] Final report in `report/`

## Key Learnings
1. 
2. 
3. 
