# Project 29 — Cloud Incident Response (AWS)

**Status:** ⚪ Planned  
**Track:** Incident Response

## Objective
Investigate a cloud account compromise.

## Scenario
A leaked access key is used to escalate privileges and exfiltrate an S3 bucket.

## Environment
| Item | Value |
|---|---|
| Case ID | `CB-29-____` |
| Host OS | |
| VMs used | |
| Tool versions | |
| Evidence source | |
| Time zone used | UTC |

## Tools
- CloudTrail
- GuardDuty
- Athena
- IAM

## Evidence Inventory
| Item | Size | MD5 | SHA-256 | Source | Acquired (UTC) |
|---|---|---|---|---|---|
| | | | | | |

## Investigation / Build Steps

### Step 1 — Build a lab AWS account with CloudTrail and GuardDuty (watch costs)
_Commands, screenshots and observations._

### Step 2 — Simulate the attack with a deliberately leaked test key
_Commands, screenshots and observations._

### Step 3 — Query CloudTrail with Athena
_Commands, screenshots and observations._

### Step 4 — Identify actions, source IPs and affected resources
_Commands, screenshots and observations._

### Step 5 — Contain: disable key, revoke sessions, lock bucket
_Commands, screenshots and observations._

### Step 6 — Document lessons and preventive controls; tear down resources
_Commands, screenshots and observations._

## Problems Encountered
| Problem | What happened | Root cause | Fix | Lesson |
|---|---|---|---|---|
| | | | | |

## Findings
| # | Observation | Evidence location | Interpretation | Confidence |
|---|---|---|---|---|
| 1 | | | | |

## ATT&CK Mapping
- T1078.004 Cloud Accounts
- T1530 Data from Cloud Storage

## IOCs
| Type | Value | Context |
|---|---|---|
| | | |

## Deliverables
- [ ] Investigation notes
- [ ] Screenshots in `images/`
- [ ] Athena queries
- [ ] Cloud IR timeline
- [ ] Final report in `report/`

## Key Learnings
1. 
2. 
3. 
