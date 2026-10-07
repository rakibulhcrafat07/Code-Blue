# Project 11 — Windows Disk Forensics

**Status:** 🟡 In progress (registry, LNK and system analysis done; execution artifacts and timeline pending)
**Track:** DFIR

## Objective
Reconstruct user and attacker activity on a Windows server from a disk image: what ran, what was opened, when, and by whom.

## Scenario
A domain controller belonging to a small organisation is suspected of being involved in the theft of confidential files. A forensic copy (E01) of the server disk was provided. The task is to identify the system, its accounts, the sensitive files that were accessed, any connected devices and remote access activity, and to build a timeline an investigating officer can rely on.

> Evidence source: public training image (DFIR Madness, "The Stolen Szechuan Sauce" case, DC01). Analysis below is my own.

## Environment
| Item | Value |
|---|---|
| Case ID | `CB-11-0001` |
| Analyst workstation | Windows 10/11 (fill in) |
| Tools | Autopsy (version: ___), FTK Imager (___), Registry Viewer (___), WinHex (___), EZ Tools (___), KAPE (___) |
| Evidence | `DC01` disk image, E01 format |
| Time zone used in this report | **UTC** (Autopsy displayed UTC+06:00; all times below converted) |

## Evidence Inventory
| Item | Size | MD5 | SHA-256 | Source | Verified |
|---|---|---|---|---|---|
| DC01 E01 | ___ | ___ | ___ | DFIR Madness | ☐ FTK Imager "Verify Drive/Image" |

---

## Completed Analysis

### Step 1 — System identification (SYSTEM / SOFTWARE hives)
| Property | Value | Source |
|---|---|---|
| Operating system | Windows Server 2012 R2 Standard Evaluation | SOFTWARE\Microsoft\Windows NT\CurrentVersion |
| Architecture | AMD64 | SYSTEM\...\Session Manager\Environment |
| Install path | C:\Windows | SOFTWARE\Microsoft\Windows NT\CurrentVersion |
| Platform | VMware Virtual Platform (VMware, Inc.) | SYSTEM\HardwareConfig |
| BIOS | Phoenix Technologies 6.00, 07/22/2020 | SYSTEM\HardwareConfig |
| Boot device | multi(0)disk(0)rdisk(0)partition(2) | SYSTEM\Setup |
| VMware drivers present | vsock, vmxnet3, vmhgfs | SOFTWARE / SYSTEM services |

**Interpretation:** the evidence is a virtualised Windows Server. Because it is a server OS, **Prefetch is disabled by default**, so program-execution evidence must come from Amcache, Shimcache and event logs instead.

### Step 2 — Accounts and user profiles
| Profile | Type | Notes |
|---|---|---|
| Administrator | Interactive account | NTUSER.DAT extracted; active profile with Recent items and MRU entries |
| Default | **Profile template, not a logon account** | Used to build new profiles; it has no logon history |

> Correction from first attempt: the Default profile cannot have a "last logon". Account logon data comes from the SAM hive (`SAM\Domains\Account\Users`) and Security event log 4624, not from NTUSER.DAT. Since this is a domain controller, domain accounts live in `ntds.dit`, not SAM. **To do:** list accounts from SAM and ntds.dit and record last logon times from verified keys.

### Step 3 — Registry hive findings
| Hive | Finding | Significance |
|---|---|---|
| SYSTEM | Virtual hardware, boot partition, service shutdown order | System profiling |
| SOFTWARE | OS build, installed components, VMware tools | System profiling |
| SECURITY | `NL$1`–`NL$10` and `NL$Control` present | **Cached domain logon credentials (MSCache v2).** An attacker with SYSTEM access can extract and crack these. Check whether any slots are populated. |
| SAM | Local account records (`Users`, `Names`) | Local accounts, RIDs, last logon, password-last-set. `ServerDomainUpdates` is internal SAM data, not AD sync. |
| DEFAULT | Default UI settings (FontSmoothing, DragFullWindows), TEMP paths | No investigative value |
| NTUSER.DAT (Administrator) | MMC MRU: `dsa.msc` (AD Users & Computers), `gpmc.msc` (Group Policy) | Administrator used AD and GPO consoles |

### Step 4 — Connected USB devices (SYSTEM\CurrentControlSet\Enum\USB, USBSTOR)
| Device | Make | Device ID | First seen (UTC) |
|---|---|---|---|
| ROOT_HUB | — | 5&3bb57b&0 | 2020-09-19 01:22:38 |
| ROOT_HUB20 | — | 5&6106580&0 | 2020-09-19 01:22:38 |
| ROOT_HUB30 | — | 5&d01e486&0&0 | 2020-09-19 01:22:38 |
| Virtual Mouse (×3) | VMware, Inc. | 6&a693ed3&0&5 (and two others) | 2020-09-19 01:22:39 |

**Finding:** all entries are virtual controller hubs and VMware input devices created at boot. **No external USB storage device was found** (USBSTOR empty — confirm with screenshot). Data theft via USB is therefore unlikely; exfiltration must be looked for over the network or remote sessions.

### Step 5 — Recent files (LNK files in `Administrator\AppData\Roaming\Microsoft\Windows\Recent`)
| LNK file | Target | Time (UTC) |
|---|---|---|
| Secret.lnk | C:\FileShare\Secret (folder) | 2020-09-18 22:29:54 |
| NoJerry.lnk | C:\FileShare\Secret\NoJerry.txt | 2020-09-18 22:29:54 |
| PortalGunPlans.lnk | C:\FileShare\Secret\PortalGunPlans.txt | 2020-09-18 22:34:02 |
| Szechuan Sauce.lnk | C:\FileShare\Secret\Szechuan Sauce.txt | 2020-09-18 22:35:59 |
| SECRET_beth.lnk | C:\FileShare\Secret\SECRET_beth.txt | 2020-09-18 22:39:22 |
| Beth_Secret.lnk | C:\FileShare\Secret\Beth_Secret.txt | 2020-09-19 03:35:07 |
| mstsc.exe.lnk | C:\Windows\System32\mstsc.exe | ___ |

> Times converted from Autopsy display (UTC+06:00). **To do:** confirm with LECmd which timestamp each value is (LNK created/modified vs. target created/modified/accessed) and fill the full table below.

**Findings:**
- The Administrator account opened the `C:\FileShare\Secret` folder and four sensitive files within ~10 minutes (22:29–22:39 UTC on 18 Sep).
- `Beth_Secret.txt` was accessed about 5 hours later, separately from the others — worth correlating with logon events.
- `mstsc.exe` (Remote Desktop client) was used from this server, i.e. **outbound RDP from the domain controller**, which is unusual and needs explaining.

---

## Remaining Work (runbook)

### Step 6 — Verify the image
```
FTK Imager → File → Verify Drive/Image → record MD5 and SHA-1, compare with acquisition values
```
Or in PowerShell: `Get-FileHash .\DC01.E01 -Algorithm SHA256`

### Step 7 — Triage collection and parsing with KAPE
Mount the E01 read-only (FTK Imager → Image Mounting → Read Only, e.g. as `F:`), then:
```powershell
.\kape.exe --tsource F: --tdest C:\Cases\CB-11\tout --target KapeTriage `
           --mdest C:\Cases\CB-11\mout --module !EZParser --mef csv
```
Screenshot the KAPE console and the output folders.

If running tools individually against the KAPE target output (`tout\F\...`):
```powershell
MFTECmd.exe -f "tout\F\$MFT" --csv mout --csvf mft.csv
MFTECmd.exe -f "tout\F\$Extend\$J" -m "tout\F\$MFT" --csv mout --csvf usnjrnl.csv
AmcacheParser.exe -f "tout\F\Windows\appcompat\Programs\Amcache.hve" -i --csv mout
AppCompatCacheParser.exe -f "tout\F\Windows\System32\config\SYSTEM" --csv mout
PECmd.exe -d "tout\F\Windows\Prefetch" --csv mout          # expect empty on Server
LECmd.exe -d "tout\F\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent" --csv mout
JLECmd.exe -d "tout\F\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv mout
SBECmd.exe -d "tout\F\Users\Administrator" --csv mout
RECmd.exe -d "tout\F" --bn BatchExamples\Kroll_Batch.reb --csv mout
EvtxECmd.exe -d "tout\F\Windows\System32\winevt\Logs" --csv mout
```

### Step 8 — Fill the artifact tables
**Program execution (Amcache / Shimcache)**
| Executable | Path | SHA-1 (Amcache) | First/last seen (UTC) | Source | Suspicious? |
|---|---|---|---|---|---|
| | | | | | |

**File system ($MFT / $UsnJrnl) for `C:\FileShare\Secret` and any new executables**
| File | Created | Modified | MFT changed | USN reason (create/rename/delete) |
|---|---|---|---|---|
| | | | | |

**Jump Lists (mstsc)** — which hosts were connected to via RDP, and when
| AppID | Target host / file | First / last used (UTC) |
|---|---|---|
| | | |

**ShellBags** — folders browsed by Administrator
| Folder | First interacted | Last interacted |
|---|---|---|
| | | |

**Logons (EvtxECmd — Security 4624/4625, RDP 1149, TerminalServices 21/24/25)**
| Time (UTC) | Event ID | Account | Logon type | Source IP |
|---|---|---|---|---|
| | | | | |

### Step 9 — Keyword search: "Antonio"
Re-run in Autopsy: Keyword Search → `antonio` (substring, case-insensitive), plus a filename search. Record every hit with full path and $MFT timestamps.

> The first attempt listed `letter_to_antonio.txt` and `antonio_expenses.xlsx` with times in "AST". These could not be matched to the other evidence (wrong time zone, no screenshots) and must be **re-verified from the image** before being reported.

| Hit | Path | Type | Created / Modified (UTC) | Content summary |
|---|---|---|---|---|
| | | | | |

### Step 10 — Super timeline
Load all CSVs into Timeline Explorer, filter to 2020-09-18 00:00 → 2020-09-19 23:59 UTC and build the narrative below.

| Time (UTC) | Source | Event | Significance |
|---|---|---|---|
| | | | |

---

## Problems Encountered
| Problem | What happened | Root cause | Fix | Lesson |
|---|---|---|---|---|
| Time zone confusion | Mixed BDT and "AST" times in first report | Autopsy shows analyst's local time by default | Set Autopsy display to UTC (Tools → Options → View) | Always normalise to UTC |
| USB over-reporting | Reported 6 "USB devices" | Counted root hubs and VMware virtual mouse | Checked USBSTOR for mass storage only | Separate controllers from storage devices |
| Misread SECURITY hive | Treated NL$ entries as network settings | Unfamiliar key | Researched: NL$ = cached domain credentials | Verify every key's meaning before interpreting |
| Web history over-inferred | Concluded file-sharing browsing from local folder paths | No URLs were found | Report only what the browser artifacts show | Absence of evidence is a valid finding |
| | | | | |

## Findings
| # | Observation | Evidence location | Interpretation | Confidence |
|---|---|---|---|---|
| 1 | Server is a VMware-hosted Windows Server 2012 R2 Eval | SYSTEM, SOFTWARE hives | Lab/virtual domain controller | High |
| 2 | Administrator opened 4 files in `C:\FileShare\Secret` within 10 minutes | LNK files in Recent | Deliberate review of sensitive files | Medium (confirm with LECmd/ShellBags) |
| 3 | `Beth_Secret.txt` accessed ~5 h after the other files | LNK file | Separate session; correlate with logons | Medium |
| 4 | Outbound RDP client used on the DC | mstsc.exe.lnk | Lateral movement or admin activity; needs Jump List + logon correlation | Low (pending) |
| 5 | No external USB storage connected | SYSTEM\Enum\USBSTOR | Exfiltration via USB unlikely | Medium |
| 6 | MSCache slots exist in SECURITY hive | SECURITY\Cache | Credential theft risk if populated | Low (pending) |

## ATT&CK Mapping (to confirm after Steps 7–10)
- T1021.001 Remote Services: RDP (mstsc usage)
- T1005 Data from Local System (access to `C:\FileShare\Secret`)
- T1003.005 Cached Domain Credentials (if MSCache populated and accessed)

## IOCs
| Type | Value | Context |
|---|---|---|
| | | |

## Deliverables
- [x] Registry hive analysis (SYSTEM, SOFTWARE, SECURITY, SAM, DEFAULT, NTUSER.DAT)
- [x] USB device review
- [x] LNK / Recent files review
- [ ] Image hash verification
- [ ] KAPE triage + EZ Tools parsing
- [ ] Amcache / Shimcache execution table
- [ ] $MFT / $UsnJrnl review
- [ ] Jump Lists and ShellBags
- [ ] "Antonio" keyword search re-verified
- [ ] Super timeline
- [ ] Screenshots in `images/`
- [ ] Final report in `report/`

## Key Learnings
1. Server editions have Prefetch disabled by default, so execution evidence comes from Amcache, Shimcache and event logs.
2. Normalise all timestamps to UTC before correlating artifacts.
3. 
