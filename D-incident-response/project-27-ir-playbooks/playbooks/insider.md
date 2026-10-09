# Playbook 4 — Insider Data Theft

**Trigger:** HR flag (resignation/termination), DLP alert, or USB/cloud-upload anomaly.
**Default severity:** SEV-2.

![Insider flowchart](../images/05-pb-insider.png)

## Steps
1. **Involve HR + Legal FIRST** — before any investigation. Insider cases are employment + legal matters; acting alone can breach policy/law and taint the case.
2. **Preserve quietly** — do not tip off the subject. Snapshot/image the endpoint, mailbox and relevant cloud logs. Hash everything.
3. **Collect host artefacts** — **USBSTOR / MountedDevices / setupapi** (devices connected), **LNK / Jump Lists / ShellBags** (files opened), browser/cloud-upload history, `$Recycle.Bin`.
4. **Decide — exfil confirmed?** — tie a device serial to the user and to the files/time (see chain in [P26](../../project-26-insider-data-theft/)).
5. **Scope** — exactly **what data** left, **by what channel** (USB, personal email, cloud), and **when**.
6. **Contain & hand off** — disable access, preserve a clean **chain of custody** package for HR/legal; let them drive consequences.

## Runs for real in
[Project 26 — USB & Insider Data Theft](../../project-26-insider-data-theft/)
