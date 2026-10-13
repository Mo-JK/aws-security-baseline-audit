# AWS Security Baseline Audit (CIS v1.4 + NIST 800-53)

I audited an AWS account against the **CIS AWS Foundations Benchmark v1.4 (Level 1)** using **AWS Config conformance packs**, fixed what it found, and mapped each finding to **NIST SP 800-53 Rev. 5**.

**Result:** noncompliant rules went from **10 → 3**, and the 3 that remain are documented exceptions. Compliant rules went from 34/44 to 41/44.

📄 **Full report:** [report/audit-report.md](report/audit-report.md)

## What I did

- Set up logging before changing anything: a multi-region CloudTrail trail and the AWS Config recorder, with IAM resource recording turned on.
- Planted two realistic misconfigurations:
  - SSH open to the internet
  - An IAM user with AdministratorAccess attached directly
- Ran the CIS v1.4 Level 1 conformance pack (44 rules) and recorded the baseline.
# AWS Security Baseline Audit (CIS v1.4 + NIST 800-53)

I audited an AWS account against the **CIS AWS Foundations Benchmark v1.4 (Level 1)** using **AWS Config conformance packs**, fixed what it found, and mapped each finding to **NIST SP 800-53 Rev. 5**.

**Result:** noncompliant rules went from **10 → 3**, and the 3 that remain are documented exceptions. Compliant rules went from 34/44 to 41/44.

📄 **Full report:** [report/audit-report.md](report/audit-report.md)

## What I did

- Set up logging before changing anything: a multi-region CloudTrail trail and the AWS Config recorder, with IAM resource recording turned on.
- Planted two realistic misconfigurations:
  - SSH open to the internet
  - An IAM user with AdministratorAccess attached directly
- Ran the CIS v1.4 Level 1 conformance pack (44 rules) and recorded the baseline.
- Fixed each finding and re-ran the matching Config rule to prove the fix worked.
- Wrote up three exceptions caused by the account type, with the risk and compensating controls for each.

## Findings at a glance

| Finding | Fix | Status |
|---|---|---|
| SSH (22) open to 0.0.0.0/0 | Removed the inbound rule | ✅ |
| Admin policy attached directly to an IAM user | Detached it and deleted the unused user | ✅ |
| IAM user not in a group | Removed the user | ✅ |
| S3 account-level Block Public Access off | Turned on all 4 settings | ✅ |
| EBS encryption by default off | Turned it on (aws/ebs key) | ✅ |
| S3 versioning off (3 buckets) | Turned on versioning | ⚠️ MFA Delete needs the root user (exception) |
| S3 server access logging off (3 buckets) | Logs now go to a dedicated access-log bucket | ✅ (the log bucket itself is an exception) |
| CloudTrail not sent to CloudWatch Logs | Connected the trail to a log group | ✅ |
| No AWS Support role (CIS 1.17) | Created a role with AWSSupportAccess | ✅ |
| No IAM password policy | Not possible in this account type | ⚠️ exception |

## Tools

AWS Config (conformance packs), AWS CloudTrail, Amazon CloudWatch Logs, Amazon S3, Amazon EC2 / EBS, AWS IAM

## Evidence

Every step has a screenshot in this repo (the numbered `00`–`58` PNG files), in order:

| Screenshots | What they show |
|---|---|
| `00–14` | Setup |
| `15–17` | Before |
| `18–42` | Each fix |
| `43–51` | Re-evaluation and the final state |
| `52–58` | Cleanup (lab resources removed) |

Account IDs and other identifiers are blacked out.

## What I learned

- **Log before you change anything.** With CloudTrail and Config running first, every fix in this audit has its own record.
- **A failing rule doesn't always mean a misconfiguration.** The versioning rule kept failing after versioning was turned on, because the pack also checks for MFA Delete, and only the root user can turn that on. Reading the rule's parameters showed the real cause.
- **Compliance scores lag.** I verified each fix by re-evaluating the specific rule, not by waiting for the score to update.
- **Some exceptions are reasonable and should be written down.** Turning on logging for the log destination bucket would send its logs into itself.

## Next steps

- Block public access for EBS snapshots.
- Turn on CloudTrail log file validation.
- Add CloudWatch alarms for the CIS section 4 events.
- Repeat the audit with CIS v3.0 and Security Hub in a standard AWS account.
