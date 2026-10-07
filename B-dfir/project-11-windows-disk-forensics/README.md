# Project 11 — Windows Disk Forensics

**Status:** 🟡 In progress — Autopsy analysis done (system, accounts, registry, USB, LNK, web history, keyword search). Execution artifacts and super timeline pending.
**Track:** DFIR

## Objective
Reconstruct user and attacker activity on a Windows server from a disk image: what ran, what was opened, when, and by whom.

## Scenario
A domain controller belonging to a small organisation is suspected of being involved in the theft of confidential files. A forensic copy of the server's C: drive (E01) was provided. The task is to identify the system and its accounts, the sensitive files that were accessed, connected devices, network/browser activity and any evidence linked to a named suspect, and to build a timeline an investigating officer can rely on.

> Evidence source: public training image from DFIR Madness, "The Stolen Szechuan Sauce" case (DC01). All analysis below is my own.

## Environment
| Item | Value |
|---|---|
| Case ID | `CB-11-0001` |
| Analyst workstation | Windows (fill in version) |
| Tools | Autopsy 4.21.0, Registry Viewer, FTK Imager, WinHex; EZ Tools + KAPE (pending) |
| Evidence | `20200918_0347_CDrive.E01` |
| Time zone used in this report | **UTC**. Autopsy displayed UTC+06:00 (BDT); all times below are converted by subtracting 6 hours. |

## Evidence Inventory
| Item | Size | MD5 | SHA-256 | Source | Verified |
|---|---|---|---|---|---|
| 20200918_0347_CDrive.E01 | ___ | ___ | ___ | DFIR Madness | ☐ FTK Imager "Verify Drive/Image" |

---

## Step 1 — Case creation and data source
The E01 was added to a new Autopsy case with default ingest modules.

![New case host](images/01-autopsy-new-case-host.png)
![Selecting the E01](images/02-autopsy-select-e01.png)

## Step 2 — Disk layout
| Volume | File system | Start sector | Length (sectors) | Size | Role |
|---|---|---|---|---|---|
| vol1 | Unallocated | 0 | 2,048 | 1 MB | MBR + alignment gap |
| vol2 | NTFS (0x07) | 2,048 | 716,800 | 350 MB | System Reserved (boot) |
| vol3 | NTFS (0x07) | 718,848 | 22,872,064 | ~10.9 GB | Windows (C:) |
| vol4 | Unallocated | 23,590,912 | 2,048 | 1 MB | Trailing gap |

![Partition layout](images/03-partition-layout.png)

The root of vol3 contains a non-standard folder **`C:\FileShare`** (created 2020-09-18 04:48:11 UTC, last modified 2020-09-19 03:34:18 UTC), which becomes central to the case.

![vol3 root](images/04-vol3-root-directory.png)

## Step 3 — System identification
| Property | Value | Source |
|---|---|---|
| Computer name | **CITADEL-DC01** | SYSTEM / SOFTWARE hives |
| Domain | **C137.local** | SYSTEM / SOFTWARE hives |
| Operating system | Windows Server 2012 R2 Standard Evaluation | SOFTWARE\Microsoft\Windows NT\CurrentVersion |
| Product ID | 00252-10000-00000-AA228 | SOFTWARE |
| Architecture | AMD64 | SYSTEM\...\Session Manager\Environment |
| Platform | VMware Virtual Platform (VMware, Inc.) | SYSTEM\HardwareConfig |
| BIOS | Phoenix Technologies 6.00, 07/22/2020 | SYSTEM\HardwareConfig |
| Boot device | multi(0)disk(0)rdisk(0)partition(2) | SYSTEM\ControlSet001\Control |

![Registry hives in config](images/05-config-registry-hives.png)
![HardwareConfig](images/06-system-hive-hardwareconfig.png)
![OS information](images/07-os-information.png)
![SYSTEM Control key](images/08-system-hive-control.png)
![SOFTWARE CurrentVersion](images/09-software-hive-currentversion.png)

**Interpretation:** the evidence is a virtualised **domain controller** (`netlogon.dns` present, `ntds` folder exists). Because it is a server OS, **Prefetch is disabled by default**, so program-execution evidence must come from Amcache, Shimcache and event logs.

## Step 4 — User profiles
`C:\Users` contains: **Administrator**, Default, Default User, Public, All Users.

![Users folder](images/10-users-folder.png)

| Profile | Type | Notes |
|---|---|---|
| Administrator | Interactive account | The only real user profile. NTUSER.DAT last written 2020-09-19 03:57:40 UTC. |
| Default / Default User | Profile template, not a logon account | Used to build new profiles; contains only default settings (TEMP/TMP paths, WindowsLogon sound). No logon history exists for it. |
| Public / All Users | Shared folders / legacy junction | Not accounts |

![Administrator NTUSER.DAT](images/11-administrator-ntuser.png)
![Default profile NTUSER.DAT](images/12-default-profile-ntuser.png)
![Default profile Environment](images/13-default-profile-environment.png)

> Domain accounts on a DC are stored in `C:\Windows\NTDS\ntds.dit`, not SAM. **To do:** extract account list and last-logon times from ntds.dit / Security event log 4624.

## Step 5 — Registry hive findings
| Hive | Finding | Significance |
|---|---|---|
| SYSTEM | Computer name, virtual hardware, boot partition, service shutdown order | System profiling |
| SOFTWARE | OS build, program paths, VMware components | System profiling |
| SECURITY | `Policy\Secrets` contains **`$MACHINE.ACC`, `DefaultPassword`, `DPAPI_SYSTEM`, `NL$KM`**. `DefaultPassword\CurrVal` holds encrypted data. | `DefaultPassword` is the **AutoLogon password stored as an LSA secret**; anyone with the SYSTEM and SECURITY hives can decrypt it offline. `NL$KM` is the key protecting cached domain credentials. High-value credential material on a DC. |
| SAM | `Domains\Account` (`C` value, `ServerDomainUpdates`), `LastSkuUpgrade`, `RXACT` | Local account database. On a DC, local SAM is only used for DSRM; domain accounts are in ntds.dit. |
| DEFAULT | Default UI settings and TEMP/TMP paths | No investigative value |
| NTUSER.DAT (Administrator) | MMC MRU: `dsa.msc` (AD Users & Computers), `gpmc.msc` (Group Policy Management) | Administrator used AD and GPO consoles |

![SECURITY hive LSA secrets](images/14-security-hive-lsa-secrets.png)
![SAM hive](images/15-sam-hive.png)
![DEFAULT hive](images/16-default-hive-environment.png)

## Step 6 — USB devices (SYSTEM\Enum\USB, USBSTOR)
| Device | Make | Device ID | First seen (UTC) |
|---|---|---|---|
| ROOT_HUB | — | 5&3bb57b&0 | 2020-09-19 01:22:38 |
| ROOT_HUB20 | — | 5&6106580&0 | 2020-09-19 01:22:38 |
| ROOT_HUB30 | — | 5&d01e486&0&0 | 2020-09-19 01:22:38 |
| Virtual Mouse | VMware, Inc. | 6&a693ed3&0&5 | 2020-09-19 01:22:39 |
| Virtual Mouse | VMware, Inc. | 7&d3efc8d8&0&0000 | 2020-09-19 01:22:39 |
| Virtual Mouse | VMware, Inc. | 7&d3efc8d8&0&0001 | 2020-09-19 01:22:39 |

![USB devices](images/17-usb-devices-list.png)
![USB device detail](images/18-usb-device-detail.png)

**Finding:** all six entries are virtual USB controller hubs and VMware input devices, registered within the same second at boot. **No external USB storage device was found.** Exfiltration via USB is unlikely; network/remote channels must be examined.

## Step 7 — Recent files (LNK files, Administrator profile)
| LNK file | Target | Path ID (MFT ref) | Time (UTC) |
|---|---|---|---|
| Secret.lnk | C:\FileShare\Secret (folder) | 3284 | 2020-09-18 22:29:54 |
| NoJerry.lnk | C:\FileShare\Secret\NoJerry.txt | 3288 | 2020-09-18 22:29:54 |
| PortalGunPlans.lnk | C:\FileShare\Secret\PortalGunPlans.txt | 3289 | 2020-09-18 22:34:02 |
| Szechuan Sauce.lnk | C:\FileShare\Secret\Szechuan Sauce.txt | 3290 | 2020-09-18 22:35:59 |
| SECRET_beth.lnk | C:\FileShare\Secret\SECRET_beth.txt | **225337** | 2020-09-18 22:39:22 |
| Beth_Secret.lnk | C:\FileShare\Secret\Beth_Secret.txt | 3287 | 2020-09-19 03:35:07 |
| mstsc.exe.lnk | C:\Windows\System32\mstsc.exe | — | no time recorded |
| No preferred path found.lnk | (Jump List entry, AutomaticDestinations) | -1 | — |

NTUSER.DAT MRU also lists `C:\Windows\system32\dsa.msc` and `gpmc.msc`.

![Recent documents overview](images/19-recent-documents-overview.png)
![Beth_Secret.lnk](images/20-lnk-beth-secret.png)
![NoJerry.lnk](images/21-lnk-nojerry.png)
![PortalGunPlans.lnk](images/22-lnk-portalgunplans.png)
![Secret folder LNK](images/23-lnk-secret-folder.png)
![SECRET_beth.lnk](images/24-lnk-secret-beth.png)
![Szechuan Sauce.lnk](images/25-lnk-szechuan-sauce.png)
![Jump List entry](images/26-jumplist-no-preferred-path.png)

**Findings:**
- The Administrator account opened the `Secret` folder and four sensitive files within ~10 minutes (22:29–22:39 UTC, 18 Sep).
- `SECRET_beth.txt` has MFT reference **225337**, while the other files are 3284–3290. The low, consecutive references suggest the original files were created together; `SECRET_beth.txt` was **created separately, later** — possibly a planted or renamed file. Confirm with $MFT timestamps.
- `Beth_Secret.txt` was accessed again ~5 hours later (03:35 UTC, 19 Sep), in a separate session.
- `mstsc.exe` (Remote Desktop client) was used **from** the DC: outbound RDP from a domain controller is unusual.

> **To do:** confirm with LECmd which timestamp Autopsy shows (LNK vs. target times).

## Step 8 — Web artifacts
![Data artifacts overview](images/27-data-artifacts-overview.png)

| Artifact | Finding | Time (UTC) |
|---|---|---|
| Bookmark | `Bing.url` (default IE favourite, microsoft.com) | 2020-09-17 16:46:25 (profile creation) |
| Cookie | `Y8KFNFMU.txt`, microsoft.com SRCHD — default Bing cookie | 2020-09-19 03:24:06 |
| Web history (WebCacheV01.dat, 8 entries) | see below | — |

![Bookmark](images/28-web-bookmark.png)
![Cookie](images/29-web-cookie.png)
![Web history](images/30-web-history-webcache.png)

**Web history entries (Administrator, Internet Explorer):**
| URL | Meaning |
|---|---|
| `http://194.61.24.102/` and `/favicon.ico` | **Browser on the DC connected to an external IP over plain HTTP** |
| `file:///C:/FileShare/Secret/PortalGunPlans.txt` | Secret file opened in the browser |
| `file:///C:/FileShare/Secret/Szechuan%20Sauce.txt` | Secret file opened in the browser |
| `file:///C:/FileShare/Secret/SECRET_beth.txt` | Secret file opened in the browser |
| `file:///C:/FileShare/Secret/Beth_Secret.txt` | Secret file opened in the browser |
| `res://iesetup.dll/HardAdmin.htm` | IE Enhanced Security Configuration page (normal on servers) |
| `res://C:\Windows\system32\mmcndmgr.dll/views.htm` | MMC console view (normal admin activity) |

**Finding:** Browsing from a domain controller to a bare external IP address (`194.61.24.102`) is highly suspicious and is a typical pattern for downloading attacker tools. This IP is the strongest lead in the case. **To do:** get visit timestamps from WebCacheV01.dat (ESEDatabaseView / Hindsight), check the Downloads folder, $MFT and Amcache for files created around that time, and correlate with RDP logons.

## Step 9 — Keyword search: "Antonio"
Exact-match keyword search for `Antonio` across the image returned **2 hits**:

| Hit | Path | Type | MD5 |
|---|---|---|---|
| IMJPNW.DIC | `C:\Windows\IME\IMEJP\DICTS\IMJPNW.DIC` | Microsoft Japanese IME dictionary (PE file, MZ header), 12,097,024 bytes | 82c01f26328775fd556faf377f526200 |
| IMJPNW.DIC | `C:\Windows\WinSxS\amd64_microsoft-windows-d..e-newworddictionary_...\IMJPNW.DIC` | Same file (WinSxS component store copy) | 82c01f26328775fd556faf377f526200 |

![Keyword search](images/31-keyword-search-antonio.png)
![Antonio hits](images/32-antonio-hits.png)
![Extracted text](images/33-antonio-hit-extracted-text.png)
![File metadata](images/34-antonio-hit-file-metadata.png)
![Hex view, MZ header](images/35-antonio-hit-hex-mz-header.png)
![WinSxS copy](images/36-antonio-hit-winsxs-copy.png)

**Finding:** both hits are the same Microsoft system dictionary (identical MD5, dated 2013 from the OS install, owned by NT SERVICE). "Antonio" appears as a dictionary word inside binary data. **These are false positives: no user-created file, document or communication related to "Antonio" exists on this system.** The suspect is not linked to this machine by name; evidence against him must come from other sources (accounts, logons, network).

---

## Remaining Work (runbook)

### Step 10 — Verify the image
```
FTK Imager → File → Verify Drive/Image → record MD5 / SHA-1 and compare with acquisition values
```
Or: `Get-FileHash .\20200918_0347_CDrive.E01 -Algorithm SHA256`

### Step 11 — KAPE triage + EZ Tools
Mount the E01 read-only (FTK Imager → Image Mounting → Read Only, e.g. as `F:`):
```powershell
.\kape.exe --tsource F: --tdest C:\Cases\CB-11\tout --target KapeTriage `
           --mdest C:\Cases\CB-11\mout --module !EZParser --mef csv
```
Individual tools against the KAPE output (`tout\F\...`):
```powershell
MFTECmd.exe -f "tout\F\$MFT" --csv mout --csvf mft.csv
MFTECmd.exe -f "tout\F\$Extend\$J" -m "tout\F\$MFT" --csv mout --csvf usnjrnl.csv
AmcacheParser.exe -f "tout\F\Windows\appcompat\Programs\Amcache.hve" -i --csv mout
AppCompatCacheParser.exe -f "tout\F\Windows\System32\config\SYSTEM" --csv mout
LECmd.exe -d "tout\F\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent" --csv mout
JLECmd.exe -d "tout\F\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv mout
SBECmd.exe -d "tout\F\Users\Administrator" --csv mout
RECmd.exe -d "tout\F" --bn BatchExamples\Kroll_Batch.reb --csv mout
EvtxECmd.exe -d "tout\F\Windows\System32\winevt\Logs" --csv mout
```

### Step 12 — Fill the tables
**Program execution (Amcache / Shimcache)** — look especially for anything created after the visit to 194.61.24.102
| Executable | Path | SHA-1 | First/last seen (UTC) | Source | Suspicious? |
|---|---|---|---|---|---|
| | | | | | |

**$MFT / $UsnJrnl** — `C:\FileShare\Secret\*`, `C:\Windows\*`, `Downloads`
| File | Created | Modified | MFT changed | USN reason |
|---|---|---|---|---|
| | | | | |

**Logons (Security 4624/4625, RDP 1149, TerminalServices 21/24/25)**
| Time (UTC) | Event ID | Account | Logon type | Source IP |
|---|---|---|---|---|
| | | | | |

**Jump Lists (mstsc) and ShellBags (25 entries in Autopsy)**
| Artifact | Value | Time (UTC) |
|---|---|---|
| | | |

**Other Autopsy leads to review:** Extension Mismatch Detected (6), Encryption Suspected (2), User Content Suspected (3), Recycle Bin (1), Installed Programs (29).

### Step 13 — Super timeline
Load all CSVs into Timeline Explorer, filter 2020-09-17 → 2020-09-19 UTC.

| Time (UTC) | Source | Event | Significance |
|---|---|---|---|
| 2020-09-17 16:46:25 | Bookmark | Administrator profile created | Baseline |
| 2020-09-18 04:48:11 | $MFT (Autopsy) | `C:\FileShare` created | Share set up |
| 2020-09-18 22:29:54 | LNK | `Secret` folder and NoJerry.txt opened | Start of file access |
| 2020-09-18 22:34–22:39 | LNK | PortalGunPlans, Szechuan Sauce, SECRET_beth opened | Sensitive file review |
| 2020-09-19 01:22:38 | SYSTEM\Enum\USB | Virtual USB hubs enumerated | System boot |
| 2020-09-19 03:24:06 | Cookie | IE used (Bing cookie written) | Browser activity |
| 2020-09-19 03:34:18 | $MFT (Autopsy) | `C:\FileShare` last modified | Change in share |
| 2020-09-19 03:35:07 | LNK | Beth_Secret.txt opened | Second session |
| ___ | WebCache | Visit to http://194.61.24.102/ | **Possible tool download** |
| | | | |

---

## Problems Encountered
| Problem | What happened | Root cause | Fix | Lesson |
|---|---|---|---|---|
| Time zone confusion | First draft mixed BDT and "AST" times | Autopsy shows analyst's local time by default | Converted all times to UTC; set Autopsy to UTC (Tools → Options → View) | Normalise to UTC before correlating |
| USB over-reporting | First draft reported 6 "USB devices" | Counted root hubs and VMware virtual mice | Checked USBSTOR for mass storage only | Separate controllers from storage devices |
| Misread SECURITY hive | First draft described NL$ entries as network settings | Unfamiliar keys | Researched LSA secrets: NL$KM, DefaultPassword, DPAPI_SYSTEM | Verify a key's meaning before interpreting |
| Web history under-read | First draft said no URLs existed | Did not open the Web History artifact | Reviewed all 8 WebCache entries; found external IP | Look at every artifact before concluding "nothing found" |
| Unsupported statements | First draft described "Antonio" files and a 2023 logon not present in the evidence | Wrote answers before checking the screenshots | Rewrote every finding from the screenshots; the Antonio hits are false positives in a system dictionary | Every claim needs a screenshot or artifact behind it |

## Findings
| # | Observation | Evidence location | Interpretation | Confidence |
|---|---|---|---|---|
| 1 | CITADEL-DC01, domain C137.local, Windows Server 2012 R2 on VMware | SYSTEM / SOFTWARE hives | Virtual domain controller | High |
| 2 | Administrator opened 4 files in `C:\FileShare\Secret` within 10 minutes | LNK files | Deliberate review of sensitive files | Medium (confirm with LECmd) |
| 3 | `SECRET_beth.txt` has a far higher MFT reference than its siblings | LNK Path ID | Created separately/later than the other secret files | Low (confirm with $MFT) |
| 4 | IE on the DC visited `http://194.61.24.102/` | WebCacheV01.dat | External connection from a DC; likely tool download | Medium |
| 5 | Secret files opened through the browser (`file:///`) | WebCacheV01.dat | Files viewed in IE as well as via Explorer | High |
| 6 | Outbound RDP client used on the DC | mstsc.exe LNK | Lateral movement or admin activity | Low (pending Jump Lists + logons) |
| 7 | AutoLogon password stored as LSA secret | SECURITY\Policy\Secrets\DefaultPassword | Plain-text-recoverable admin credential on a DC | Medium |
| 8 | No external USB storage connected | SYSTEM\Enum\USB, USBSTOR | Exfiltration via USB unlikely | Medium |
| 9 | "Antonio" only appears inside a Microsoft IME dictionary | Keyword search, IMJPNW.DIC | False positive; no user data links the suspect to this system | High |

## ATT&CK Mapping (to confirm after Steps 10–13)
- T1105 Ingress Tool Transfer — browser connection to 194.61.24.102
- T1021.001 Remote Services: RDP — mstsc usage
- T1005 Data from Local System — access to `C:\FileShare\Secret`
- T1552.002 / T1003.004 Credentials in Registry / LSA Secrets — DefaultPassword stored

## IOCs
| Type | Value | Context |
|---|---|---|
| IPv4 | 194.61.24.102 | Visited over HTTP from the DC's browser |
| Path | C:\FileShare\Secret\ | Folder containing the targeted files |

## Deliverables
- [x] Case creation and disk layout
- [x] System identification
- [x] User profiles
- [x] Registry hive analysis (SYSTEM, SOFTWARE, SECURITY, SAM, DEFAULT, NTUSER.DAT)
- [x] USB device review
- [x] LNK / Recent files review
- [x] Web artifacts review
- [x] Keyword search ("Antonio")
- [ ] Image hash verification
- [ ] KAPE triage + EZ Tools parsing
- [ ] Amcache / Shimcache execution table
- [ ] $MFT / $UsnJrnl review
- [ ] Event log logon analysis
- [ ] Jump Lists and ShellBags
- [ ] Super timeline
- [ ] Final report in `report/`

## Key Learnings
1. Server editions have Prefetch disabled by default, so execution evidence comes from Amcache, Shimcache and event logs.
2. Normalise all timestamps to UTC before correlating artifacts.
3. A keyword hit is not evidence until you check what file it is in; binary system files produce false positives.
4. 
