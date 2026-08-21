# Phase 3 — OS Internals & Logging

A SOC analyst spends their day inside logs. Knowing what Windows and Linux record — and why — makes the SIEM phase click instead of feeling like memorization.

**Suggested pace:** Month 2
**Difficulty:** Intermediate

## Topics

- [ ] Windows Event Log categories: Security, System, Application
- [ ] Key Event IDs to know cold: 4624/4625 (logon), 4688 (process creation), 4720 (user created)
- [ ] Windows Registry and common persistence locations (Run keys, Scheduled Tasks)
- [ ] Linux logging: `/var/log`, syslog, `auditd` rules
- [ ] Installing Sysmon with the SwiftOnSecurity config
- [ ] Enabling PowerShell Script Block Logging and Module Logging
- [ ] Running a harmless simulated technique (Atomic Red Team) and finding it in the logs

## Projects in this phase

| # | Project | Status |
|---|---|---|
| 1 | [Attack-to-Log Mapping](./project-01-attack-to-log-mapping) | ⬜ To Do |
| 2 | [Windows Event ID Cheat-Sheet](./project-02-windows-event-id-cheatsheet) | ⬜ To Do |
| 3 | [Sysmon Config Tuning](./project-03-sysmon-config-tuning) | ⬜ To Do |
| 4 | [Linux auditd Rules](./project-04-linux-auditd-rules) | ⬜ To Do |

## Resources

- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [Microsoft Security Auditing Docs](https://learn.microsoft.com/windows/security/threat-protection/auditing/)
