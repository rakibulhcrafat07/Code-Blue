# AWS Account Compromise — Technical Report

**Case:** CB-29-0001 · **Analyst:** Rakibul H. Chowdhury · **Region:** ap-southeast-1

## 1. Environment (real)
- IAM: console-managed users/groups; notable managed policy in use: `AWSLambda_FullAccess`.
- VPC `b15-Rakibul-vpc` (`vpc-0c273daf5367b1baf`, 192.168.0.0/24), 2 public + 2 private subnets, **S3 Gateway endpoint**, DNS on.
- EC2 `rakibul-t1` (`i-02cb28bd0a5e92ed4`), Amazon Linux 2023, key pair `b1-zz-key`.

## 2. Detection
GuardDuty: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`, `Discovery:S3/AnomalousBehavior` on key `AKIA...EXAMPLE`.

## 3. Kill chain (from CloudTrail) — *(sim timings)*
| Time (UTC) | eventName | sourceIP | ATT&CK |
|---|---|---|---|
| 03:02 | GetCallerIdentity | 203.0.113.70 | stolen-key tell |
| 03:03 | ListBuckets / ListAttachedUserPolicies | 203.0.113.70 | T1526/T1087 discovery |
| 03:08 | CreateRole + AttachRolePolicy (Admin) | 203.0.113.70 | T1098 privilege escalation |
| 03:10 | PassRole | 203.0.113.70 | escalation (Lambda path) |
| 03:12 | GetObject ×N on ...-finance (via VPC endpoint) | — | T1530 exfiltration |

## 4. Escalation path
`AWSLambda_FullAccess` + `iam:CreateRole`/`iam:PassRole` is a known AWS privesc route: the principal creates a role with an admin policy and passes it, obtaining elevated execution. Confirmed from the CreateRole/AttachRolePolicy/PassRole events.

## 5. Exfiltration
Object reads against the finance bucket routed through the **S3 VPC endpoint** (no IGW traversal). Object-level detail requires S3 data events (recommend enabling). Scope = objects listed in query #4.

## 6. Containment
Disabled `AKIA...EXAMPLE` (Inactive, not deleted); attached QuarantineDenyAll to the principal; removed attacker role/user; applied S3 public-access-block; snapshotted + isolated the EC2 instance.

## 7. IOCs
| Type | Value |
|---|---|
| AccessKeyId | AKIA...EXAMPLE |
| IPv4 | 203.0.113.70 |
| Rogue role | attacker-created admin role |

## 8. Recommendations
End long-lived keys (roles + STS), MFA everywhere, least privilege (drop `*FullAccess`), IMDSv2, S3 data events, GuardDuty/Config/Access Analyzer in all regions.
