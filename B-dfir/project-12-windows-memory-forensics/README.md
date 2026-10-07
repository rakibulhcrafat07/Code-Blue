# Project 12 — Windows Memory Forensics

**Status:** ⚪ Planned  
**Track:** DFIR

## Objective
Detect malicious activity that only exists in RAM.

## Scenario
An endpoint beacons to an unknown IP but disk scans find nothing.

## Environment
| Item | Value |
|---|---|
| Case ID | `CB-12-____` |
| Host OS | |
| VMs used | |
| Tool versions | |
| Evidence source | |
| Time zone used | UTC |

## Tools
- Volatility 3
- WinPmem / DumpIt
- strings
- YARA

## Evidence Inventory
| Item | Size | MD5 | SHA-256 | Source | Acquired (UTC) |
|---|---|---|---|---|---|
| | | | | | |

## Investigation / Build Steps

### Step 1 — Capture memory; hash the dump
_Commands, screenshots and observations._

### Step 2 — Profile the image (windows.info)
_Commands, screenshots and observations._

### Step 3 — Process analysis: pslist, pstree, psscan, cmdline
_Commands, screenshots and observations._

### Step 4 — Network: netscan; injected code: malfind
_Commands, screenshots and observations._

### Step 5 — Dump suspicious process; scan with YARA
_Commands, screenshots and observations._

### Step 6 — Correlate with disk and SIEM evidence
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
- T1055 Process Injection
- T1071 Application Layer Protocol

## IOCs
| Type | Value | Context |
|---|---|---|
| | | |

## Deliverables
- [ ] Investigation notes
- [ ] Screenshots in `images/`
- [ ] Volatility command log
- [ ] Suspicious process report
- [ ] IOC list
- [ ] Final report in `report/`

## Key Learnings
1. 
2. 
3. 
