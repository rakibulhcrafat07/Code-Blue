# Project 1 — Attack-to-Log Mapping

**Phase:** [3 — OS Internals & Logging](../)
**Status:** ⬜ To Do

## Objective

Build the mental model of "technique in → log entry out" that every later detection depends on.

## Tasks

- [ ] Install Sysmon on the Windows lab VM using the SwiftOnSecurity config
- [ ] Pick 2–3 Atomic Red Team tests (e.g., a credential-access or discovery technique)
- [ ] Execute each test on the lab VM (isolated network only)
- [ ] Open Event Viewer and locate the resulting log entries for each test
- [ ] Record the Event ID, log source, and what field in the event actually reveals the technique
- [ ] Reset the VM to its clean snapshot when done

## Tools

Sysmon, Atomic Red Team, Windows Event Viewer

## Deliverable

A table mapping each technique tested → Event ID(s) generated → the specific field/value that would trigger a detection.

## Notes / Write-up

_(Fill in as you go.)_
