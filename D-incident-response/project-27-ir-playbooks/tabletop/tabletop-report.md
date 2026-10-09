# Tabletop Exercise — Report

**Exercise ID:** CB-27-TTX-01
**Type:** Discussion-based tabletop (no live systems)
**Duration:** 90 minutes
**Scenario:** Ransomware outbreak originating from a phished credential
**Participants (roles):** Incident Commander, Tier-1, DFIR analyst, Comms lead, Legal, HR, Exec sponsor, IT/System owner

> A tabletop tests the **plan and the people**, not the tools. Everyone reasons aloud through a scenario; a facilitator injects new facts; we record decisions and gaps.

## Scenario narrative
A finance employee receives a convincing invoice email, clicks the link, and enters their credentials on a fake Microsoft login. Two days later, EDR alerts fire on mass file encryption across a file server and three workstations. A ransom note demands payment in cryptocurrency.

## Injects & decisions
| T+ | Inject (facilitator) | Expected action | What the team did |
|---|---|---|---|
| 00:00 | EDR: mass file rename on FILESRV-01 | Declare **SEV-1**; assign IC | ✅ IC assigned in 3 min |
| 00:05 | Two more hosts encrypting | **Isolate** affected hosts (network, not power) | ⚠️ one responder suggested powering off — corrected: isolate to preserve memory |
| 00:15 | Ransom note identifies strain | Identify strain + entry vector | ✅ used note + ID Ransomware |
| 00:25 | Help-desk ticket: finance user "weird login email 2 days ago" | Link entry vector = **phished credential** (Playbook 1 → 5) | ✅ connected phishing → account compromise |
| 00:35 | Exec asks "should we just pay?" | Ransom = **exec + legal** decision; SOC advises, doesn't decide | ✅ escalated correctly; legal noted sanctions risk |
| 00:45 | Are backups usable? | Verify **clean + offline** backups | ⚠️ **gap found** — last offline backup test was 5 months ago |
| 01:00 | Press enquiry received | Only **Comms lead** responds | ✅ others deferred |
| 01:10 | Scope question: how many hosts at risk? | **Fleet hunt** for IOCs + entry vector | ✅ referenced P17 Velociraptor hunt |

## Lessons learned → fed back into the plan
| # | Gap / observation | Action | Owner |
|---|---|---|---|
| 1 | Instinct to **power off** a ransomwared host | Add an explicit "ISOLATE, don't power off — preserve memory" line to the ransomware playbook (done) | IR manager |
| 2 | **Offline backup restore not tested** in 5 months | Institute a **monthly** restore test; add to Preparation checklist | IT |
| 3 | No pre-drafted **holding statement** for press/customers | Comms lead to prepare templated holding statements per severity | Comms |
| 4 | Out-of-band comms channel not pre-agreed | Stand up a Signal/phone tree before it's needed | IC |
| 5 | Legal's **breach-notification clock** awareness was fuzzy | Legal to document notification deadlines per jurisdiction | Legal |

## Outcome
The team ran the lifecycle correctly and escalated well. The two material gaps — **untested offline backups** and the **power-off instinct** — are exactly what a tabletop exists to surface **before** a real SEV-1. Plan updated; re-test in 90 days.

## Key takeaways
1. The response was only as good as its **weakest untested assumption** (backups).
2. Muscle-memory errors (power-off) are cheap to fix in a tabletop, expensive in reality.
3. Running the exercise across **one connected scenario** (phish → account → ransomware) proved the playbooks chain together, which is how real incidents actually unfold.
