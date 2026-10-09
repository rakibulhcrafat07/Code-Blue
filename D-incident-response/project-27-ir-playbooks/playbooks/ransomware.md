# Playbook 2 — Ransomware

**Trigger:** files encrypted, ransom note found, mass file-rename alerts, or EDR ransomware detection.
**Default severity:** SEV-1 (anything spreading).

![Ransomware flowchart](../images/03-pb-ransomware.png)

## Steps
1. **Isolate, don't power off** — pull affected hosts off the network (disable switch port / EDR network-contain). **Powering off loses memory** (keys, running process) and may trigger damage. Preserve RAM if you can.
2. **Declare SEV-1** — IC + exec sponsor + legal engaged immediately.
3. **Identify** — strain (ransom note / extension / ID Ransomware), and the **entry vector** (phished cred, exposed RDP, exploited app, prior web shell).
4. **Scope the spread** — hunt the whole fleet for the strain's IOCs and the entry vector (see [P17 Velociraptor](../../project-17-velociraptor-live-response/)). Find every affected and every *at-risk* host.
5. **Decision — backups** — are backups **clean, complete and offline**? That answer decides recovery vs. the much harder alternatives.
   - **Ransom is an executive + legal decision**, never the SOC's — and paying is discouraged (no guarantee, sanctions risk).
6. **Eradicate & recover** — rebuild/restore from known-good backups, rotate **all** credentials (assume domain-wide theft), patch the entry vector, re-image anything uncertain.
7. **Post-incident** — report, notification duties (legal), lessons learned.

## Runs for real in
[Project 28 — Ransomware Incident Response](../../project-28-ransomware-ir/)
