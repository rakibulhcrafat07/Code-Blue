# Project 01 — Evidence Acquisition & Integrity

**Status:** ⚪ Planned  
**Track:** Lab Foundation

## Objective
Acquire evidence in a forensically sound way and prove its integrity with hashes and chain of custody.

## Scenario
A suspect USB/virtual disk is handed over. Image it, verify it, and demonstrate what happens to evidence integrity when it is mounted read-only versus read-write.

## Environment
| Item | Value |
|---|---|
| Case ID | `CB-01-____` |
| Host OS | |
| VMs used | |
| Tool versions | |
| Evidence source | |
| Time zone used | UTC |

## Tools
- FTK Imager
- dc3dd
- ewfacquire / ewfverify
- sha256sum / md5sum
- HxD
- Autopsy

## Evidence Inventory
| Item | Size | MD5 | SHA-256 | Source | Acquired (UTC) |
|---|---|---|---|---|---|
| | | | | | |

## Investigation / Build Steps

### Step 1 — Create the case folder structure and open the chain-of-custody log
_Commands, screenshots and observations._

### Step 2 — Create controlled evidence (small VHD with files, some deleted) and record ground truth
_Commands, screenshots and observations._

### Step 3 — Enable write-blocking (read-only attach or blockdev --setro)
_Commands, screenshots and observations._

### Step 4 — Hash the source (MD5 + SHA-256)
_Commands, screenshots and observations._

### Step 5 — Acquire E01 with FTK Imager and raw with dc3dd; keep acquisition logs
_Commands, screenshots and observations._

### Step 6 — Verify image hashes against source
_Commands, screenshots and observations._

### Step 7 — Integrity lab: mount original read-only (hash unchanged); mount a working copy read-write and add a file (hash changes)
_Commands, screenshots and observations._

### Step 8 — Mount E01 read-only and do a first pass in Autopsy; compare with ground truth
_Commands, screenshots and observations._

### Step 9 — Write a 2-3 page acquisition report
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
- Add techniques as they are discovered

## IOCs
| Type | Value | Context |
|---|---|---|
| | | |

## Deliverables
- [ ] Investigation notes
- [ ] Screenshots in `images/`
- [ ] Hash table (source -> image -> verify -> post-analysis)
- [ ] Chain-of-custody record
- [ ] FTK Imager / dc3dd logs
- [ ] Integrity verification table (read-only vs read-write)
- [ ] Final report in `report/`

## Key Learnings
1. 
2. 
3. 
