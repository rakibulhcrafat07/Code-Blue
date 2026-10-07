# Project 00 — Home Lab Build

**Status:** ⚪ Planned  
**Track:** Lab Foundation

## Objective
Build a segmented, reproducible lab that every later project depends on.

## Scenario
A small company network: one AD domain, two Windows endpoints, a Linux web/mail server, an attacker VM and a monitoring segment.

## Environment
| Item | Value |
|---|---|
| Case ID | `CB-00-____` |
| Host OS | |
| VMs used | |
| Tool versions | |
| Evidence source | |
| Time zone used | UTC |

## Tools
- VirtualBox / VMware / Proxmox
- Windows Server (AD DS)
- Windows 10/11
- Ubuntu Server
- Kali Linux
- pfSense

## Evidence Inventory
| Item | Size | MD5 | SHA-256 | Source | Acquired (UTC) |
|---|---|---|---|---|---|
| | | | | | |

## Investigation / Build Steps

### Step 1 — Draw the network diagram (IP plan, networks, roles)
_Commands, screenshots and observations._

### Step 2 — Install hypervisor and pfSense; create LAN, SERVER, MGMT and ATTACKER networks
_Commands, screenshots and observations._

### Step 3 — Build Windows Server, promote to domain controller, create OUs, users, groups
_Commands, screenshots and observations._

### Step 4 — Join Windows endpoints to the domain; create realistic user accounts
_Commands, screenshots and observations._

### Step 5 — Build Ubuntu server with a web app and SSH
_Commands, screenshots and observations._

### Step 6 — Build Kali attacker VM on its own segment
_Commands, screenshots and observations._

### Step 7 — Take clean snapshots of every VM and record them
_Commands, screenshots and observations._

### Step 8 — Document resource usage and what you had to scale down
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
- [ ] Network diagram (draw.io / PNG)
- [ ] IP plan (lab-only, no real passwords)
- [ ] Snapshot inventory
- [ ] Final report in `report/`

## Key Learnings
1. 
2. 
3. 
