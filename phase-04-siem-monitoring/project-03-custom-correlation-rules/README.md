# Project 3 — Custom Correlation Rules

**Phase:** [4 — SIEM & Monitoring](../)
**Status:** ⬜ To Do

## Objective

Move past single-event alerts and write a rule that correlates multiple events into one meaningful alert.

## Tasks

- [ ] In Wazuh or ELK, identify two related events that are only suspicious *together* (e.g., a failed-then-successful login burst, or a new user immediately added to an admin group)
- [ ] Write a correlation rule that fires only when both conditions occur within a time window
- [ ] Test it against both the "should fire" case and a "should NOT fire" case
- [ ] Document the time window you chose and why

## Tools

Wazuh or ELK (whichever you set up in Project 1)

## Deliverable

The correlation rule definition, plus test results showing it firing correctly and staying quiet on benign activity.

## Notes / Write-up

_(Fill in as you go.)_
