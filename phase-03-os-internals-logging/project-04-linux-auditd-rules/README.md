# Project 4 — Linux auditd Rules

**Phase:** [3 — OS Internals & Logging](../)
**Status:** ⬜ To Do

## Objective

Get the Linux-side equivalent of Sysmon visibility working: know what `auditd` can tell you and how to configure it.

## Tasks

- [ ] Install and enable `auditd` on the Linux lab VM
- [ ] Write a rule to watch a sensitive file (e.g., `/etc/passwd` or `/etc/shadow`) for reads/writes
- [ ] Write a rule to log execution of a specific binary (e.g., `sudo` or `su`)
- [ ] Trigger each rule deliberately and confirm the resulting log entry with `ausearch`
- [ ] Note the syscall(s) each rule is actually watching

## Tools

`auditd`, `ausearch`, `auditctl`

## Deliverable

Your `audit.rules` additions plus the corresponding log entries you triggered and captured.

## Notes / Write-up

_(Fill in as you go.)_
