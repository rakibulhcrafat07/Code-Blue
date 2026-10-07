# Project 38 — Web Application Firewall

**Status:** ⚪ Planned  
**Track:** Defensive Engineering & Hardening

## Objective
Protect a vulnerable web app with a WAF and investigate blocked attacks.

## Scenario
The lab web server hosts a deliberately vulnerable app that cannot be patched quickly.

## Environment
| Item | Value |
|---|---|
| Case ID | `CB-38-____` |
| Host OS | |
| VMs used | |
| Tool versions | |
| Evidence source | |
| Time zone used | UTC |

## Tools
- ModSecurity
- OWASP Core Rule Set
- Nginx / Apache
- DVWA / bWAPP

## Evidence Inventory
| Item | Size | MD5 | SHA-256 | Source | Acquired (UTC) |
|---|---|---|---|---|---|
| | | | | | |

## Investigation / Build Steps

### Step 1 — Deploy the vulnerable app behind Nginx/Apache
_Commands, screenshots and observations._

### Step 2 — Enable ModSecurity with OWASP CRS in detection-only mode
_Commands, screenshots and observations._

### Step 3 — Run SQLi, XSS, command injection and path traversal tests
_Commands, screenshots and observations._

### Step 4 — Tune paranoia level and exclusions; switch to blocking
_Commands, screenshots and observations._

### Step 5 — Forward WAF logs to the SIEM and build alerts
_Commands, screenshots and observations._

### Step 6 — Show which attacks were blocked, which bypassed, and why
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

## IOCs
| Type | Value | Context |
|---|---|---|
| | | |

## Deliverables
- [ ] Investigation notes
- [ ] Screenshots in `images/`
- [ ] WAF tuning log
- [ ] Blocked vs bypassed attack table
- [ ] SIEM WAF dashboard
- [ ] Final report in `report/`

## Key Learnings
1. 
2. 
3. 
