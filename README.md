# Code-Blue
### Hands-On Blue Team Lab: SOC, SIEM, Digital Forensics, Incident Response & Cybercrime Investigation

A project-based blue team portfolio covering the full defender lifecycle: **build the lab → harden → collect telemetry → detect → triage → investigate → respond → report.**

Every project is a self-contained investigation or build with its own scenario, evidence, findings, troubleshooting log and report. No copied commands, no empty templates: a project is marked complete only when it contains real screenshots, hashes, queries and findings produced in this lab.

**Progress:** 28 of 37 projects complete. Track A (SOC & SIEM) is in progress; all other tracks are done.

---

## Lab Architecture

| Component | Role | Tooling |
|---|---|---|
| Hypervisor | Hosts all VMs | VirtualBox / VMware Workstation / Proxmox |
| Domain | Realistic victim environment | Windows Server (AD DS), 2× Windows 10/11 endpoints |
| Linux servers | Web & mail targets | Ubuntu Server (Apache/Nginx), mail server |
| Attacker | Adversary simulation | Kali Linux, Atomic Red Team, Caldera |
| SIEM | Central detection | Wazuh, Elastic Stack (ELK), Splunk Free |
| Network sensor | Traffic visibility | Security Onion / Zeek + Suricata |
| Case management & SOAR | Alert handling | TheHive, Cortex, Shuffle |
| Threat intel | IOC enrichment | MISP |
| DFIR workstation | Forensics | Windows (FLARE VM, KAPE, EZ Tools, FTK Imager, Autopsy), Linux (SIFT / REMnux) |
| Live response | Endpoint collection at scale | Velociraptor |
| Vulnerability & compliance | Scanning and hardening baselines | Nessus Essentials, OpenVAS, CIS-CAT Lite, Lynis |
| Perimeter & deception | Prevention and early warning | pfSense + Suricata IPS, ModSecurity WAF, T-Pot, Canarytokens |

Minimum host: 16 GB RAM (run tracks one at a time). Recommended: 32 GB+.

---

## Project Catalog

**Legend:** ✅ Complete · 🟡 In progress · ⚪ Planned

### Track 0 — Lab Foundation & Evidence Handling

| # | Project | Scenario / Goal | Key Tools | Status |
|---|---|---|---|---|
| 01 | [Evidence Acquisition & Integrity](./00-lab-foundation/project-01-evidence-acquisition-integrity/) | Image a disk, verify hashes, prove read-only vs read-write mount effects, maintain chain of custody | FTK Imager, dc3dd, ewfacquire, sha256sum | ✅ |

### Track A — SOC & SIEM Operations

| # | Project | Scenario / Goal | Key Tools | Status |
|---|---|---|---|---|
| 02 | [Wazuh SIEM Deployment](./A-soc-siem/project-02-wazuh-deployment/) | Deploy Wazuh, onboard Windows & Linux agents, tune default rules | Wazuh | ⚪ |
| 03 | [Telemetry Engineering](./A-soc-siem/project-03-telemetry-engineering/) | Sysmon, Windows advanced audit policy, PowerShell logging, auditd; measure coverage gaps | Sysmon, auditd, GPO | ⚪ |
| 04 | [Elastic Stack SOC](./A-soc-siem/project-04-elastic-soc/) | Build a second SIEM, compare detections and query languages | Elasticsearch, Kibana, Fleet | ⚪ |
| 05 | [Detection Engineering with Sigma](./A-soc-siem/project-05-detection-engineering-sigma/) | Write, test and convert Sigma rules for 15+ ATT&CK techniques; detection-as-code in Git | Sigma, pySigma, Atomic Red Team | ⚪ |
| 06 | [Alert Triage & Case Management](./A-soc-siem/project-06-alert-triage-thehive/) | Tier-1/Tier-2 triage workflow, severity matrix, escalation, case notes | TheHive, Cortex | ⚪ |
| 07 | [SOAR Automation](./A-soc-siem/project-07-soar-shuffle/) | Auto-enrich alerts, auto-open cases, notify analysts | Shuffle, VirusTotal API, AbuseIPDB | ⚪ |
| 08 | [Threat Intelligence Platform](./A-soc-siem/project-08-threat-intel-misp/) | Ingest feeds, correlate IOCs with SIEM events | MISP, OpenCTI (optional) | ⚪ |
| 09 | [Hypothesis-Driven Threat Hunting](./A-soc-siem/project-09-threat-hunting/) | Hunt for persistence, LOLBins and lateral movement after simulated attacks | Wazuh/Elastic, Velociraptor, ATT&CK | ⚪ |
| 10 | [Purple Team Validation](./A-soc-siem/project-10-purple-team/) | Run Caldera campaign, score detection coverage, close gaps | Caldera, ATT&CK Navigator | ⚪ |

### Track B — Digital Forensics & Incident Response

| # | Project | Scenario / Goal | Key Tools | Status |
|---|---|---|---|---|
| 11 | [Windows Disk Forensics](./B-dfir/project-11-windows-disk-forensics/) | Reconstruct user activity: MFT, registry, LNK, Jump Lists, Prefetch, ShellBags | KAPE, EZ Tools, Autopsy | ✅ |
| 12 | [Windows Memory Forensics](./B-dfir/project-12-windows-memory-forensics/) | Find injected code, malicious processes and network connections in RAM | Volatility 3, WinPmem | ✅ |
| 13 | [Windows Event Log Investigation](./B-dfir/project-13-event-log-investigation/) | Trace brute force → logon → persistence → lateral movement | Hayabusa, Chainsaw, EvtxECmd | ✅ |
| 14 | [Linux Intrusion Investigation](./B-dfir/project-14-linux-intrusion/) | Compromised web server: web logs, auth logs, cron, SSH keys, web shells | auditd, journalctl, UAC | ✅ |
| 15 | [Network Forensics](./B-dfir/project-15-network-forensics/) | Reconstruct C2, exfiltration and file transfers from PCAP | Wireshark, Zeek, Suricata, NetworkMiner | ✅ |
| 16 | [Super Timeline Analysis](./B-dfir/project-16-super-timeline/) | Merge disk, log and memory artifacts into one timeline | Plaso, Timesketch | ✅ |
| 17 | [Live Response at Scale](./B-dfir/project-17-velociraptor-live-response/) | Hunt and collect across all endpoints without imaging | Velociraptor | ✅ |
| 18 | [Malware Triage](./B-dfir/project-18-malware-triage/) | Static and dynamic analysis of a known sample; extract IOCs; write YARA | FLARE VM, REMnux, YARA, Ghidra (intro) | ✅ |

### Track C — Cybercrime Investigation

| # | Project | Scenario / Goal | Key Tools | Status |
|---|---|---|---|---|
| 19 | [Email Forensics & Phishing](./C-cybercrime/project-19-email-phishing-forensics/) | Header analysis, SPF/DKIM/DMARC validation, spoofing detection, attachment triage | MXToolbox, eml parsers, Thunderbird | ✅ |
| 20 | [Business Email Compromise](./C-cybercrime/project-20-business-email-compromise/) | Mailbox takeover: forwarding rules, suspicious logins, fraudulent invoice trail | Mail server logs, SIEM | ✅ |
| 21 | [Browser & Messaging Artifacts](./C-cybercrime/project-21-browser-messaging-artifacts/) | History, downloads, cookies, cached sessions as evidence of user intent | Hindsight, BrowsingHistoryView, DB Browser for SQLite | ✅ |
| 22 | [Mobile Forensics](./C-cybercrime/project-22-mobile-forensics/) | Acquire an Android test device over ADB; map artifact locations; app, media and lock-config analysis | Genymotion, ADB, ALEAPP, Autopsy | ✅ |
| 23 | [Image & Document Forensics](./C-cybercrime/project-23-image-document-forensics/) | Metadata, edits, tampering and authenticity of photos and documents | ExifTool, FotoForensics, oletools, pdfid | ✅ |
| 24 | [OSINT Investigation](./C-cybercrime/project-24-osint-investigation/) | Attribute an online entity using only open sources (infrastructure, pivots, archives); documented legally and ethically | WhatsMyName, whois, Wayback Machine, Maltego CE | ✅ |
| 25 | [Cryptocurrency Fraud Tracing](./C-cybercrime/project-25-crypto-fraud-tracing/) | Follow funds from a publicly reported scam wallet through the blockchain | Block explorers, Breadcrumbs | ✅ |
| 26 | [Insider Data Theft / USB Forensics](./C-cybercrime/project-26-insider-data-theft/) | USB/removable-media evidence analysis and device-to-user attribution (USBSTOR, LNK, ShellBags) | USB registry artifacts, EZ Tools, Autopsy | ✅ |

### Track D — Incident Response Operations

| # | Project | Scenario / Goal | Key Tools | Status |
|---|---|---|---|---|
| 27 | [IR Plan & Playbooks](./D-incident-response/project-27-ir-playbooks/) | NIST 800-61 aligned IR plan plus playbooks for phishing, ransomware, BEC, insider, compromised account | Markdown, draw.io | ✅ |
| 28 | [Ransomware Incident Response](./D-incident-response/project-28-ransomware-ir/) | Detect, contain, scope and recover from a simulated ransomware outbreak | SIEM, Velociraptor, EDR telemetry | ✅ |
| 29 | [Cloud Incident Response (AWS)](./D-incident-response/project-29-aws-cloud-ir/) | Leaked access key → privilege escalation → S3 exfiltration | CloudTrail, GuardDuty, Athena | ✅ |
| 30 | [DFIR Automation with Python](./D-incident-response/project-30-dfir-python-automation/) | Build triage, hashing, log-parsing and IOC-enrichment scripts used in earlier projects | Python | ✅ |

### Track E — Defensive Engineering & Hardening

| # | Project | Scenario / Goal | Key Tools | Status |
|---|---|---|---|---|
| 31 | [Vulnerability Management](./E-defensive-engineering/project-31-vulnerability-management/) | Discover, prioritize (CVSS + EPSS + KEV), remediate and verify; SLAs and risk acceptance | Nessus Essentials, OpenVAS, Wazuh | ✅ |
| 32 | [System Hardening (CIS)](./E-defensive-engineering/project-32-system-hardening/) | Bring Windows and Linux to CIS Level 1, prove improvement with before/after scores, monitor drift | CIS-CAT Lite, Lynis, Wazuh SCA, LAPS | ✅ |
| 33 | [Active Directory Security](./E-defensive-engineering/project-33-active-directory-security/) | Audit AD, break attack paths, detect Kerberoasting, AS-REP roasting, DCSync and spraying | PingCastle, Purple Knight, BloodHound | ✅ |
| 34 | [Network Defense: IDS/IPS & Firewall](./E-defensive-engineering/project-34-network-defense-ids-ips/) | Segmentation, egress filtering and inline IPS with tuned rules | pfSense, Suricata, ET Open | ✅ |
| 35 | [EDR & Automated Containment](./E-defensive-engineering/project-35-edr-automated-containment/) | Auto-block, kill process, disable account and isolate host with safe rollback | Wazuh Active Response, Velociraptor | ✅ |
| 36 | [Splunk SOC](./E-defensive-engineering/project-36-splunk-soc/) | Onboard logs, CIM normalization, SPL detections, correlation searches and dashboards | Splunk Enterprise, Universal Forwarder | ✅ |
| 37 | [Deception & Honeypots](./E-defensive-engineering/project-37-deception-honeypots/) | High-fidelity early warning with decoy accounts, files, tokens and honeypots | T-Pot, Canarytokens | ✅ |
| 38 | [Web Application Firewall](./E-defensive-engineering/project-38-waf-modsecurity/) | Protect a vulnerable app, tune CRS, analyze blocked vs bypassed attacks | ModSecurity, OWASP CRS | ✅ |

---

## Standard Project Structure

```
project-XX-name/
├── README.md        # Scenario, environment, steps, findings, ATT&CK, lessons
├── evidence/        # Hashes, logs, sanitized exports (no raw images)
├── queries/         # KQL / Lucene / SPL / Sigma / YARA
├── scripts/         # Automation used in the project
├── images/          # Numbered screenshots: 01-..., 02-...
└── report/          # Final investigation report (PDF/MD)
```

Every project README covers: **Objective · Scenario · Environment & tool versions · Evidence & hashes · Investigation steps · Problems encountered & fixes · Findings (observation, location, interpretation, confidence) · ATT&CK mapping · IOCs · Key learnings.**

---

## Skills Matrix

| Skill area | Projects |
|---|---|
| SIEM engineering & log onboarding (Wazuh, Elastic, Splunk) | 02, 03, 04, 36 |
| Detection engineering | 05, 09, 10, 33, 36 |
| SOC triage & case handling | 06, 07, 08 |
| Vulnerability management | 31 |
| Hardening & compliance | 32, 33 |
| Active Directory security | 33, 13 |
| Network defense (firewall, IDS/IPS, WAF) | 34, 38 |
| Endpoint response (EDR) | 17, 35 |
| Deception | 37 |
| Windows forensics | 11, 12, 13, 16 |
| Linux forensics | 14 |
| Network forensics | 15 |
| Malware analysis | 18 |
| Cybercrime & fraud investigation | 19–26 |
| Incident response | 27, 28, 29 |
| Automation | 07, 30, 35 |
| Report writing | Every project |

---

## Evidence & Ethics Rules

- Only lab-generated evidence, public forensic datasets or sanitized material.
- Never commit raw disk/memory images, real credentials, customer data, private IPs or personal data. `*.E01`, `*.dd`, `*.raw`, `*.mem`, `*.vmem` are git-ignored.
- OSINT and cybercrime projects use fictional subjects, public figures with only public data, or publicly reported cases only.
- Malware samples are referenced by hash and source, never committed.

---

## Public Datasets Used

- NIST CFReDS
- Digital Corpora
- DFIR Madness / The Stolen Szechuan Sauce
- Malware Traffic Analysis (PCAPs)
- Josh Hickman's mobile reference images

---

## Author

**Rakibul Hoque Chowdhury** — SC-200 · SC-100 · AWS SAA-C03
[GitHub](https://github.com/rakibulhcrafat07)
