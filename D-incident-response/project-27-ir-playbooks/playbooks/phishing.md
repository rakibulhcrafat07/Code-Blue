# Playbook 1 — Phishing

**Trigger:** a user reports a suspicious email, or the mail gateway/SIEM flags one.
**Default severity:** SEV-3 (SEV-2 if credentials were entered or malware ran).

![Phishing flowchart](../images/02-pb-phishing.png)

## Steps
1. **Preserve** — get the original `.eml` with **full headers** (not a forwarded copy). Hash it.
2. **Analyse the message**
   - Headers: `From` vs `Reply-To` vs `Return-Path`; `Received` chain; `Authentication-Results`.
   - **SPF/DKIM/DMARC `pass` proves domain control, not honesty** — a look-alike domain can still pass.
   - URLs: expand redirects in a sandbox; check the real landing domain. Attachments: detonate, don't open.
3. **Decide** — malicious / spam / legitimate. If malicious, declare the incident.
4. **Scope** — search the mail platform: who else received it, who **clicked**, who **entered credentials**.
5. **Contain**
   - Block sender domain/IP and the URL at the gateway/proxy.
   - **Purge** the message from all mailboxes.
   - For anyone who entered credentials → treat as **Compromised Account** (Playbook 5): reset + revoke sessions.
   - For anyone who ran an attachment → isolate the host, triage (Velociraptor/EDR).
6. **Recover & close** — confirm removal, document IOCs, add a detection rule, user-awareness note.

## Runs for real in
[Project 19 — Email Phishing Forensics](../../project-19-email-phishing-forensics/)
