# Project 12 — Windows Memory Forensics

**Status:** 🟡 In progress — process, network, handle and code-injection triage complete; user-activity extraction (command line, browser, files) pending.
**Track:** DFIR

## Objective
Analyse a RAM capture to establish what was running, what was connected, and whether there is evidence of malicious code or of the suspect's activity at the moment of acquisition.

## Scenario
An employee is accused of cyberstalking and sending threats of violence from a work PC. A previous administrator tried to recover deleted files with forensic software before investigators arrived. A memory capture (`MemorySample.raw`) was taken with DumpIt and handed over for analysis.

**Investigative questions**
1. What was the system and who was logged in?
2. What was the user doing at the time of capture (browsers, command line, archiving)?
3. Is there any malware, code injection or suspicious network activity?
4. What evidence relevant to the stalking allegation can be recovered from memory?

## Environment
| Item | Value |
|---|---|
| Case ID | `CB-12-0001` |
| Analyst workstation | Kali Linux |
| Tool | Volatility Framework 2.6.1 |
| Evidence | `MemorySample.raw` |
| Time zone used | **UTC** (Volatility default). The suspect system's local time zone was **UTC+05:30**. |

## Evidence Inventory
| Item | Size | MD5 | SHA-256 | Acquired with | Verified |
|---|---|---|---|---|---|
| MemorySample.raw | ___ | ___ | ___ | DumpIt | ☐ `md5sum` / `sha256sum` before analysis |

## Evidence Handling Notes
- The administrator's earlier recovery attempt on the live system is itself an evidence-handling problem: installing or running tools writes to disk (possibly overwriting deleted data), changes timestamps and must be documented in the chain of custody. It does not invalidate the memory capture, but it must be disclosed in the report.
- Memory was captured with DumpIt **from the live system**, so `DumpIt.exe` and its `conhost.exe` appear in the process list by design.
- Disk imaging and hashing are covered in [Project 01](../../00-lab-foundation/project-01-evidence-acquisition-integrity/).

---

## Step 1 — Profile identification (`imageinfo`)
```bash
volatility -f MemorySample.raw imageinfo
```
| Property | Value |
|---|---|
| Suggested profile (used) | **Win7SP1x64** |
| Kernel AS | WindowsAMD64PagedMemory |
| Processors | 1 |
| Service pack | 1 |
| Capture time (UTC) | **2019-08-19 14:41:58** |
| Capture time (local) | 2019-08-19 20:11:58 **+0530** |

![imageinfo](images/01-imageinfo.png)

**Interpretation:** the machine is **Windows 7 SP1 x64**, not Windows 10 as the case brief stated; the brief should be corrected. The local offset of +05:30 tells us the system clock was set to India Standard Time, which matters when correlating with any external records (ISP logs, social media timestamps).

## Step 2 — Process analysis (`pslist`, `pstree`, `psscan`)
```bash
volatility -f MemorySample.raw --profile=Win7SP1x64 pslist
volatility -f MemorySample.raw --profile=Win7SP1x64 pstree
volatility -f MemorySample.raw --profile=Win7SP1x64 psscan
```
![pslist](images/02-pslist.png)
![pslist continued](images/03-pslist-continued.png)
![pstree](images/04-pstree.png)
![pstree continued](images/05-pstree-continued.png)
![psscan](images/06-psscan.png)
![psscan continued](images/07-psscan-continued.png)

**User-launched processes (children of `explorer.exe`, PID 1944):**
| Time (UTC) | Process | PID | PPID | Meaning |
|---|---|---|---|---|
| 14:40:19 | explorer.exe | 1944 | 1844 | User logon / desktop started |
| 14:40:20 | VBoxTray.exe | 1108 | 1944 | VirtualBox guest tools |
| 14:40:26 | **cmd.exe** | 880 | 1944 | **Command prompt opened by the user** |
| 14:40:46 | chrome.exe | 2124 | 1944 | Chrome (+6 child processes) |
| 14:41:08 | firefox.exe | 2080 | 3060 | Firefox (+4 children); parent 3060 no longer exists |
| 14:41:43 | **WinRAR.exe** | 3716 | 1944 | **Archive tool opened by the user** |
| 14:41:55 | DumpIt.exe | 4084 | 1944 | Memory acquisition tool (investigator) |

**System processes:** System (4), smss, csrss ×2, wininit, winlogon, services, lsass, lsm, multiple svchost, spoolsv, taskhost, taskeng, dwm, audiodg, SearchIndexer, WmiPrvSE ×2, WmiApSrv, sppsvc. Parent-child relationships and counts are normal for Windows 7 (one lsass, one services, svchost children of services.exe 480).

**Background updaters:** GoogleUpdate.exe (2256) and GoogleCrashHandler ×4 are Chrome's standard update/crash-reporting components, not evidence of crashes or compromise.

**pslist vs psscan:** both return the same set of processes; **no hidden (unlinked) processes** were found.

**Findings**
- The user was actively working: a **command prompt**, **two browsers** and **WinRAR** were all opened within ~80 seconds before acquisition. These are the priority targets for user-activity extraction (Step 6).
- `DumpIt.exe` and `VBoxService.exe`/`VBoxTray.exe` are **not suspicious**: one is the acquisition tool, the others show the machine is a VirtualBox VM.
- Processes with start times after 14:41:58 (sppsvc, GoogleUpdate, GoogleCrashHandler at 14:42:39–41) were created **while DumpIt was still writing**: memory capture is not instantaneous, which is normal "smear".

## Step 3 — Network connections (`netscan`)
```bash
volatility -f MemorySample.raw --profile=Win7SP1x64 netscan
```
![netscan](images/08-netscan.png)
![netscan continued](images/09-netscan-continued.png)

| Owner | Connections | Assessment |
|---|---|---|
| firefox.exe (2080, 2968, 3016) | ~35 TCP to ports 80/443: 172.217.x.x and 216.58.x.x (Google), plus 54.149.112.164, 52.24.89.101, 35.167.81.14, 117.18.237.29:80, 23.195.74.70:80, 13.224.25.60:443 | Normal web browsing. Non-Google IPs are cloud/CDN ranges; **to do:** WHOIS each and match with browser history to see which sites the user visited |
| firefox.exe | 127.0.0.1 ↔ 127.0.0.1 pairs | Normal Firefox inter-process communication |
| chrome.exe (2124) | UDP 5353 (mDNS) | Normal |
| svchost / System | UDP 137/138, 1900, 3702, 5355; TCP 135/445 listening | Standard Windows services (NetBIOS, SSDP, WS-Discovery, LLMNR, RPC, SMB) |
| firefox.exe | TCPv6 entry in state CLOSED with garbage remote address | Stale, partially overwritten socket structure. Not an active connection |
| VBoxService.exe (668) | UDP only, no external TCP | **No suspicious network activity** |

**Finding:** all external traffic belongs to Firefox and points to mainstream web/CDN infrastructure. **No C2, beaconing or unusual listening port was found.** Because the allegation is about online harassment, the *content* of the browsing (Step 6) matters more than the IPs.

## Step 4 — Handles of VBoxService.exe (`handles -p 668`)
```bash
volatility -f MemorySample.raw --profile=Win7SP1x64 handles -p 668
```
![handles](images/10-handles-vboxservice.png)
![handles continued](images/11-handles-vboxservice-continued.png)

| Handle | Meaning |
|---|---|
| Key `...\Image File Execution Options` | Opened by the Windows loader for **every** process at start-up; presence of a handle is normal and does not mean the key was modified |
| Key `...\NetworkProvider\HwOrder`, `NLS\*`, `Winsock2\Parameters\*` | Standard keys read by any networked service |
| File `\Device\VBoxGuest` | VirtualBox guest driver: expected for VBoxService |
| File `\Device\Nsi` | Network Store Interface driver: used by every process that queries network state |
| Events, semaphores, mutants, ALPC ports, threads (TIDs 700–716) | Ordinary synchronisation and IPC objects |

**Finding:** the handle table of VBoxService is **consistent with a normal VirtualBox guest service**. No evidence of persistence or tampering. To prove IFEO abuse, the key's *values* must be checked (`printkey -K "Microsoft\Windows NT\CurrentVersion\Image File Execution Options"`) for a `Debugger` value on any executable.

## Step 5 — Code injection triage (`malfind`)
```bash
volatility -f MemorySample.raw --profile=Win7SP1x64 malfind
```
![malfind explorer 0x3ce0000](images/12-malfind-explorer-0x3ce0000.png)
![malfind explorer 0x4320000](images/13-malfind-explorer-0x4320000.png)
![malfind WmiPrvSE](images/14-malfind-wmiprvse-0x1bd0000.png)

| Process | Address | Protection | Content | Assessment |
|---|---|---|---|---|
| explorer.exe (1944) | 0x3ce0000 | PAGE_EXECUTE_READWRITE | Almost entirely zeros, no MZ header | Empty RWX allocation: common benign artefact |
| explorer.exe (1944) | 0x4320000 | PAGE_EXECUTE_READWRITE | Repeating `mov edx, N; mov eax, …; jmp [eax]` stubs | Thunk/trampoline table typical of shell extensions and hooks used by legitimate software |
| WmiPrvSE.exe (2292) | 0x1bd0000 | PAGE_EXECUTE_READWRITE | Small data structure, no MZ header | Typical WMI/.NET allocation |

**Finding:** malfind flags memory that is private and executable; it does not prove injection. **None of the hits contain a PE header or recognisable shellcode, so code injection is not confirmed.** To close this out: dump the regions with `malfind -D out/`, scan with YARA and an AV engine, and compare against a clean Windows 7 baseline.

---

## Step 6 — User activity extraction (next steps)
These are the steps that answer the stalking allegation directly.
```bash
# What did the user type and run?
volatility -f MemorySample.raw --profile=Win7SP1x64 cmdline
volatility -f MemorySample.raw --profile=Win7SP1x64 consoles        # cmd.exe 880 history
volatility -f MemorySample.raw --profile=Win7SP1x64 cmdscan

# Which archive did WinRAR open?
volatility -f MemorySample.raw --profile=Win7SP1x64 cmdline -p 3716
volatility -f MemorySample.raw --profile=Win7SP1x64 filescan | grep -iE "\.rar|\.zip|\.7z|Users\\\\Jaffa"
volatility -f MemorySample.raw --profile=Win7SP1x64 dumpfiles -Q <offset> -D out/

# Browser activity (Chrome and Firefox)
volatility -f MemorySample.raw --profile=Win7SP1x64 filescan | grep -iE "History|places.sqlite|Cookies|sessionstore"
volatility -f MemorySample.raw --profile=Win7SP1x64 dumpfiles -Q <offset> -D out/
volatility -f MemorySample.raw --profile=Win7SP1x64 memdump -p 2080 -D out/   # then strings | grep -i for URLs, usernames, messages
volatility -f MemorySample.raw --profile=Win7SP1x64 yarascan -Y "/(facebook|twitter|instagram|gmail|mail\.)/i" -p 2080,2124

# User account and registry context
volatility -f MemorySample.raw --profile=Win7SP1x64 hivelist
volatility -f MemorySample.raw --profile=Win7SP1x64 printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
volatility -f MemorySample.raw --profile=Win7SP1x64 userassist
volatility -f MemorySample.raw --profile=Win7SP1x64 clipboard
volatility -f MemorySample.raw --profile=Win7SP1x64 screenshot -D out/
```

| Question | Plugin | Result |
|---|---|---|
| What commands were typed in cmd.exe? | consoles / cmdscan | |
| Which file did WinRAR open or create? | cmdline -p 3716, filescan | |
| Which sites / accounts were used in Firefox and Chrome? | filescan + dumpfiles, memdump + strings | |
| Any threatening text in memory (messages, drafts)? | yarascan / strings on browser memory | |
| What was on the clipboard / screen? | clipboard, screenshot | |

---

## Hives present in memory (`hivelist`)
| Hive | Path |
|---|---|
| NTUSER.DAT (user **Jaffa**) | C:\Users\Jaffa\ntuser.dat |
| UsrClass.dat (Jaffa) | C:\Users\Jaffa\AppData\Local\Microsoft\Windows\UsrClass.dat |
| SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT, HARDWARE, BCD | Standard locations |
| NTUSER.DAT (LocalService, NetworkService) | C:\Windows\ServiceProfiles\... |

**Finding:** the only interactive user profile loaded is **Jaffa**, so the activity in Step 2 is attributable to that account.

## Problems Encountered
| Problem | What happened | Root cause | Fix | Lesson |
|---|---|---|---|---|
| OS mismatch | First draft said Windows 10 | Copied from case brief | Used imageinfo / profile: Windows 7 SP1 x64 | Trust the evidence over the brief |
| Tool flagged as threat | DumpIt listed as suspicious | Did not account for acquisition footprint | Documented as investigator tool | Know your own tool's footprint |
| VM treated as evasion | VBoxService linked to "malicious activity" | VirtualBox guest tools misread | Confirmed via handles: only VBoxGuest driver, no external connections | Virtualisation alone is not evidence |
| malfind over-claimed | First draft said injection "confirmed" | malfind output taken as a verdict | Reviewed each hit: no PE, no shellcode | malfind is a lead, not a conclusion |
| Normal keys read as persistence | IFEO / HwOrder handles described as backdoor | Handle presence confused with modification | Check key values with printkey | A handle shows access, not tampering |
| Noise in strings | ACPI `_OSI("Windows 2009")` style strings reported as findings | Unfiltered strings output | Removed; focus strings on process memory of interest | Targeted strings beat whole-image strings |
| Case question not answered | No stalking evidence was looked for | Focused on malware instead of the allegation | Added Step 6 | Start from the investigative questions |

## Findings
| # | Observation | Evidence location | Interpretation | Confidence |
|---|---|---|---|---|
| 1 | Windows 7 SP1 x64 VM, local time UTC+05:30, captured 2019-08-19 14:41:58 UTC | imageinfo | System context | High |
| 2 | User **Jaffa** was logged on | hivelist (NTUSER.DAT) | Activity is attributable to Jaffa | High |
| 3 | cmd.exe, Chrome, Firefox and WinRAR were opened by the user in the 90 s before capture | pslist / pstree | Active user session; priority targets for content extraction | High |
| 4 | No hidden processes | pslist vs psscan | No rootkit-style hiding | High |
| 5 | External traffic is only Firefox to web/CDN hosts | netscan | Normal browsing; no C2 | High |
| 6 | malfind hits have no PE header or shellcode | malfind | Code injection not confirmed | Medium |
| 7 | VBoxService handles are standard | handles -p 668 | No persistence or tampering shown | Medium |

**Conclusion so far:** there is **no evidence of malware** on this system. The machine shows a live user session (Jaffa) with a command prompt, two browsers and WinRAR open. Evidence for or against the stalking allegation is most likely in the browser memory, the WinRAR target and the console history (Step 6).

## ATT&CK Mapping
No adversary technique confirmed. Candidate to test: T1560.001 Archive via Utility (WinRAR), pending Step 6.

## IOCs
None identified.

## Deliverables
- [x] Profile identification
- [x] Process analysis (pslist / pstree / psscan)
- [x] Network analysis (netscan)
- [x] Handle review
- [x] malfind triage
- [ ] Memory image hash
- [ ] malfind dumps scanned with YARA
- [ ] Console / command-line history
- [ ] WinRAR target file
- [ ] Browser history and content from memory
- [ ] Final report in `report/`

## Key Learnings
1. Start from the investigative question; malware hunting is only one part of memory forensics.
2. Know the acquisition tool's footprint (DumpIt, conhost) and the platform's (VirtualBox) so they are not reported as findings.
3. malfind, handles and strings produce leads, not conclusions; every claim needs a second artifact.
