# Project 16 — Super Timeline Analysis: "Lone Wolf" Case

**Status:** ⚪ Planned · Methodology and runbook complete · all findings below are a **simulated walkthrough** (marked *(sim)*) until the analysis is run on the dataset
**Track:** DFIR

> ⚠️ **Simulated findings.** This project is built on the public **"Lone Wolf" training scenario (Digital Corpora, 2018)**. The case brief, tools and commands are real. Every finding, timestamp, file name and value in the result tables is **illustrative** and marked *(sim)*; it is not taken from the dataset, so it will not match the official answers. Replace each *(sim)* row with real output after running the steps.

## Objective
Combine disk and memory evidence into one normalised timeline to establish **what the suspect did, when, and why**: his motive, his planning, where he stored his material, and whether evidence of an earlier device or deleted data exists.

## Scenario (from the case brief)
Jim Cloudy, an unemployed resident of Alexandria, VA, became increasingly angry about media coverage of gun control. He began writing about his views and planning a "lone wolf" attack, and uploaded his documents to several cloud storage services so they would be accessible anywhere.

After an online argument with his brother Paul, Jim smashed his laptop and threw it down the apartment trash chute. Paul gave him an old **Dell Latitude E6430 ATG**. Before the planned date, Jim gave Paul access to his cloud accounts and announced a sudden "vacation". Paul read the documents and called the police. A search warrant was executed and Jim was arrested **while chatting online with Paul**, so the laptop was running and RAM was captured.

**Investigative questions**
1. What evidence shows motive and intent?
2. What planning activity took place, and when?
3. Which cloud services and accounts were used, and what was uploaded?
4. Is there any trace of the destroyed laptop or of deleted material?
5. What was happening on the laptop at the moment of seizure?

## Environment
| Item | Value |
|---|---|
| Case ID | `CB-16-0001` |
| Evidence | HDD image (Dell Latitude E6430 ATG), RAM dump, pre-processed Autopsy case |
| Tools | Autopsy 4.21, KAPE + EZ Tools, Plaso (log2timeline/psort), Timesketch or Timeline Explorer, Volatility 3, Hindsight, DB Browser for SQLite |
| Time zone | All output normalised to **UTC**; suspect's local time = US Eastern (UTC−4 in summer, UTC−5 in winter) |

![Workflow](images/01-workflow.png)

## Evidence Inventory
| ID | Item | MD5 | SHA-1 | Verified |
|---|---|---|---|---|
| A | HDD image (E01) | `SIMULATED-MD5-A` | `SIMULATED-SHA1-A` | ☐ FTK Imager verify |
| B | RAM dump | `SIMULATED-MD5-B` | `SIMULATED-SHA1-B` | ☐ `md5sum` before and after analysis |

---

## Step 1 — Verify and open
```powershell
# Windows
Get-FileHash .\DiskImage.E01 -Algorithm SHA1
Get-FileHash .\memdump.mem   -Algorithm SHA1
```
Open the HDD image in Autopsy with all ingest modules. Create **tag categories** before tagging so the HTML report is organised:

| Tag | Use for |
|---|---|
| Motive & Intent | Writings, searches showing grievance or intent |
| Planning | Research, maps, schedules, purchases |
| Cloud Storage | Sync clients, upload logs, account artefacts |
| Communications | Chats, email, social media |
| User Activity | LNK, Jump Lists, ShellBags, recent docs |
| Anti-Forensics / Deletion | Recycle Bin, wiping tools, deleted files |
| Prior Device | Anything linking to the destroyed laptop |

Every tag gets a **comment** explaining what the artefact is and why it matters.

## Step 2 — System and user profile
```powershell
RECmd.exe -d "F:\Windows\System32\config" --bn BatchExamples\Kroll_Batch.reb --csv out
```
| Item | Result *(sim)* |
|---|---|
| OS | Windows 10 Pro (build *sim*) |
| Computer name | `SIM-LAPTOP` |
| User accounts | `jim` (active), `paul` (old profile from previous owner) *(sim)* |
| Install date | Earlier than the scenario: device was second-hand *(sim)* |
| Time zone (registry) | Eastern Standard Time |

**Why it matters:** an older profile belonging to Paul confirms the laptop's history and must be separated from Jim's activity.

## Step 3 — Disk timeline with Plaso
```bash
log2timeline.py --storage-file case.plaso DiskImage.E01
psort.py -o l2tcsv -w disk_timeline.csv case.plaso "date > '2018-01-01'"
```
In parallel, targeted parsing with EZ Tools for higher-quality fields:
```powershell
MFTECmd.exe -f "F:\$MFT" --csv out
LECmd.exe -d "F:\Users\jim\AppData\Roaming\Microsoft\Windows\Recent" --csv out
JLECmd.exe -d "F:\Users\jim\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv out
SBECmd.exe -d "F:\Users\jim" --csv out
PECmd.exe -d "F:\Windows\Prefetch" --csv out
AmcacheParser.exe -f "F:\Windows\appcompat\Programs\Amcache.hve" -i --csv out
RBCmd.exe -d "F:\$Recycle.Bin" --csv out
```

## Step 4 — Memory timeline with Volatility 3
```bash
vol -f memdump.mem windows.info
vol -f memdump.mem windows.pslist  > pslist.txt
vol -f memdump.mem windows.pstree  > pstree.txt
vol -f memdump.mem windows.cmdline > cmdline.txt
vol -f memdump.mem windows.netscan > netscan.txt
vol -f memdump.mem windows.filescan > filescan.txt
vol -f memdump.mem timeliner.Timeliner --create-bodyfile > mem.body
```
Convert `mem.body` to CSV (`mactime -b mem.body -d > mem_timeline.csv`) and merge it with `disk_timeline.csv`.

**Processes at the time of seizure** *(sim)*
| Process | PID | Meaning |
|---|---|---|
| Chat client | 4412 | Matches the brief: arrested while chatting with Paul |
| Browser (3 tabs) | 2280 | Open cloud-storage web session |
| Cloud sync client | 1960 | Running and connected |
| Word processor | 3104 | A document open at seizure |

**Network connections** *(sim)*: established TLS sessions from the chat client and the sync client to their providers' servers. Exact IPs are recorded in `netscan.txt`.

## Step 5 — Answer the questions

### Q1 — Motive and intent *(sim)*
| Time (UTC) | Artefact | Source | Tag |
|---|---|---|---|
| 2018-*sim* | Personal "manifesto"-style document expressing grievance about gun-control coverage | $MFT, LNK, Word recent files | Motive & Intent |
| 2018-*sim* | Repeated web searches and news articles on gun-control legislation | Browser history (Hindsight) | Motive & Intent |
| 2018-*sim* | Forum posts in an online argument | Browser cache | Communications |

### Q2 — Planning *(sim)*
| Time (UTC) | Artefact | Source | Tag |
|---|---|---|---|
| 2018-*sim* | Spreadsheet titled as a "vacation" plan, created days before the announced trip | $MFT, Jump List | Planning |
| 2018-*sim* | Map/route lookups for a location in the area | Browser history | Planning |
| 2018-*sim* | Document edited late at night (fits "odd hours" in the brief) | LNK + $UsnJrnl | User Activity |

> Reporting note: describe planning documents by **title, timestamps, location and evidential significance**. Operational details of the plan are summarised, not reproduced.

### Q3 — Cloud storage *(sim)*
| Service | Evidence | Source |
|---|---|---|
| Sync client A | Installed, account configured, local sync folder with copies of the documents | Amcache, sync DB (SQLite) |
| Service B | Web uploads seen in browser history; upload confirmation pages cached | Hindsight |
| Service C | Credentials/session cookie for the account later shared with Paul | Browser cookies |

**Why it matters:** sync databases record **file name, hash, upload time and remote path**, proving which files left the laptop and when.

### Q4 — Destroyed laptop and deleted data *(sim)*
| Artefact | Finding |
|---|---|
| Cloud sync DB | Device list shows a **second device name** that last synced on the day of the argument: the destroyed laptop |
| Recycle Bin (`$I` / `$R`) | One deleted draft recovered with its original path and deletion time |
| Volume Shadow Copies | Older version of a document present in a shadow copy |

### Q5 — State at seizure *(sim)*
Chat client and browser open, cloud session active, document open in the word processor. RAM confirms the suspect was actively using the laptop, and cached chat text in process memory corroborates Paul's account.

## Step 6 — Merged super timeline *(sim)*
| Time (UTC) | Source | Event | Question |
|---|---|---|---|
| 2018-*sim* | Sync DB | Old laptop's last sync | Q4 |
| 2018-*sim* | Registry / $MFT | User `jim` profile created on the Dell | Q4 |
| 2018-*sim* | Browser | Gun-control news and forum activity | Q1 |
| 2018-*sim* | $MFT / LNK | Grievance document created and edited | Q1 |
| 2018-*sim* | Browser / Jump List | Planning research and "vacation" spreadsheet | Q2 |
| 2018-*sim* | Sync DB / browser | Documents uploaded to three cloud services | Q3 |
| 2018-*sim* | Browser | Account access shared with Paul | Q3 |
| 2018-*sim* | Recycle Bin | Draft deleted | Q4 |
| 2018-*sim* | RAM | Chat with Paul in progress at seizure | Q5 |

## Findings *(sim)*
| # | Finding | Evidence | Confidence |
|---|---|---|---|
| 1 | Written material shows grievance and intent | Documents, browser history | *(sim)* |
| 2 | Planning activity in the days before the announced trip | Spreadsheet, map searches, timestamps | *(sim)* |
| 3 | Documents uploaded to three cloud services | Sync DB, browser artefacts | *(sim)* |
| 4 | Sync records reference the destroyed laptop | Device list in sync DB | *(sim)* |
| 5 | Suspect was actively chatting at seizure | RAM process list and memory strings | *(sim)* |

## Deliverables
- [ ] Hash verification of both images
- [ ] Autopsy case with categorised tags and comments
- [ ] Autopsy HTML report (`report/autopsy-html/`)
- [ ] `disk_timeline.csv`, `mem_timeline.csv`, merged timeline
- [ ] Investigative report (≤ 3,500 words) in `report/`
- [ ] Replace every *(sim)* row with real output and screenshots

## Report structure (investigative report)
1. Heading page and table of contents
2. Introduction: case summary and tasking
3. Forensic examination: tools, evidence, hashes
4. Evidence A (HDD) and Evidence B (RAM): analysis per evidence item
5. Findings mapped to the five questions
6. Conclusions: what the evidence supports, and what it does not
7. Appendix: timeline, tag list, hash list

## Key Learnings
1. A super timeline is only useful after normalising every source to one time zone.
2. Cloud sync databases are often the best evidence of what left a machine and when.
3. RAM captured at arrest answers "what was happening right now", which disk evidence cannot.
4. Write for a non-technical reader: methodology, findings, conclusions, in plain language.
