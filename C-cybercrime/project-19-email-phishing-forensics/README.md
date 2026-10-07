# Project 19 — Email Forensics & Phishing Investigation

**Status:** ⚪ Planned  
**Track:** Cybercrime Investigation

## Objective
Determine whether an email is spoofed or malicious and trace its true origin.

## Scenario
Staff receive an invoice email that appears to come from the CEO.

## Environment
| Item | Value |
|---|---|
| Case ID | `CB-19-____` |
| Host OS | |
| VMs used | |
| Tool versions | |
| Evidence source | |
| Time zone used | UTC |

## Tools
- Raw .eml headers
- MXToolbox
- SPF/DKIM/DMARC checkers
- oletools
- Thunderbird

## Evidence Inventory
| Item | Size | MD5 | SHA-256 | Source | Acquired (UTC) |
|---|---|---|---|---|---|
| | | | | | |

## Investigation / Build Steps

### Step 1 — Collect the original .eml; hash it
_Commands, screenshots and observations._

### Step 2 — Parse Received headers bottom-up to trace the path
_Commands, screenshots and observations._

### Step 3 — Validate SPF, DKIM and DMARC results
_Commands, screenshots and observations._

### Step 4 — Compare From, Return-Path, Reply-To and Message-ID
_Commands, screenshots and observations._

### Step 5 — Analyze links and attachments safely
_Commands, screenshots and observations._

### Step 6 — Write report and recommend mail-server controls
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
- T1566.001 Spearphishing Attachment
- T1566.002 Spearphishing Link

## IOCs
| Type | Value | Context |
|---|---|---|
| | | |

## Deliverables
- [ ] Investigation notes
- [ ] Screenshots in `images/`
- [ ] Header analysis table
- [ ] Authentication results
- [ ] Mail-server hardening recommendations
- [ ] Final report in `report/`

## Key Learnings
1. 
2. 
3. 
