# AWS Security Baseline Audit — Findings and Remediation Report

**Author:** Mohammed Jadkarim
**Date:** October 12, 2026
**Scope:** One AWS account (lab environment), Region us-east-2 (Ohio)
**Standard:** CIS AWS Foundations Benchmark v1.4, Level 1, deployed as an AWS Config conformance pack (44 rules)
**Mapping:** NIST SP 800-53 Rev. 5

---

## 1. Summary

I built a small AWS environment, put in a few common misconfigurations on purpose, and audited it against the CIS AWS Foundations Benchmark using AWS Config. The first scan found **10 noncompliant rules**. I fixed 7 of them and re-evaluated each rule to confirm the fix.

The 3 rules still failing can't be fixed in this kind of account. Each one is written up as a documented exception in Section 5.

| | Before | After |
|---|---|---|
| Noncompliant rules | 10 | 3 (all documented exceptions) |
| Compliant rules | 34 / 44 (77%) | 41 / 44 (93%) |
| Conformance pack score shown in console | 67% | refresh pending |

The console's score tile weights resources, not rules. It was still showing the old value ("updated 6 hours ago") when I took the final screenshots. The rule-level result is in `screenshots/51-after-noncompliant-3-exceptions.png`.

## 2. Method

1. **Logging first.** I created a multi-region CloudTrail trail (`audit-trail`) so every change I made during the audit was recorded.
2. **Recording.** I turned on the AWS Config recorder for all resource types, including IAM. IAM types were excluded by default, so I removed those overrides.
3. **Planted issues.** I added two misconfigurations an auditor should catch:
   - A security group (`lab-open-ssh`) that allowed SSH (port 22) from 0.0.0.0/0.
   - An IAM user (`lab-user`) with `AdministratorAccess` attached directly.
4. **Baseline scan.** I deployed the CIS v1.4 Level 1 conformance pack and recorded the starting results (screenshots 13–17).
5. **Remediate and verify.** I fixed each finding and re-evaluated the matching Config rule one at a time, because re-evaluation is rate-limited (screenshots 18–51).

## 3. Findings and remediation

The **Source** column says how the NIST mapping was obtained:

- **AWS**: from the AWS Config "Operational Best Practices for NIST 800-53 rev 5" page.
- **Analyst**: my own mapping, based on what the control is meant to do.

| # | Config rule | Finding (before) | Risk | Fix | Result | NIST 800-53 r5 | Source | Evidence |
|---|---|---|---|---|---|---|---|---|
| 1 | restricted-ssh | `lab-open-ssh` allowed TCP 22 from 0.0.0.0/0 | Anyone on the internet can attempt SSH logins | Deleted the inbound rule | Compliant | SC-7, AC-4, CM-7 | Analyst | 03, 18, 19 |
| 2 | iam-user-no-policies-check | `AdministratorAccess` attached directly to `lab-user` | Full admin rights outside group or role controls | Detached the policy, then deleted the unused user | Compliant | AC-2, AC-6 | Analyst | 04, 21, 23 |
| 3 | iam-user-group-membership-check | `lab-user` was in no group | Permissions not managed centrally | Deleted the user (this account type has no IAM user groups) | Compliant | AC-2, AC-3, AC-3(15), AC-6(3) | AWS | 20, 22, 23 |
| 4 | s3-account-level-public-access-blocks-periodic | Account-level S3 Block Public Access was off | A future bucket or policy could be made public by mistake | Turned on all 4 Block Public Access settings for the account | Compliant | AC-3, AC-21 | AWS | 25, 26, 45 |
| 5 | ec2-ebs-encryption-by-default | New EBS volumes were not encrypted by default | Data at rest on new volumes left unencrypted | Turned on default EBS encryption (aws/ebs key) in us-east-2 | Compliant | SC-28, SC-28(1) | Analyst | 27, 28, 49 |
| 6 | s3-bucket-versioning-enabled | Versioning off on 3 buckets | Deleted or overwritten objects, including logs, can't be recovered | Turned on versioning on all 3 buckets | Versioning on; rule still fails on MFA Delete (see 5.1) | AU-9(2) | AWS | 29–31, 47 |
| 7 | s3-bucket-logging-enabled | No server access logging on 3 buckets | No record of who accessed bucket data | Created `mo-audit-access-logs-4821` and sent access logs from all 3 buckets to it | 3/3 source buckets compliant; log bucket is an exception (see 5.3) | AC-2(4), AC-4(26), AC-6(9), AU-2 | AWS | 32–37, 46 |
| 8 | cloud-trail-cloud-watch-logs-enabled | Trail was not sent to CloudWatch Logs | No real-time alerting on API activity | Connected `audit-trail` to a CloudWatch Logs group with the role `CloudTrailToCloudWatchRole` | Compliant | AC-2(4), AC-4(26), AC-6(9), AU-2 | AWS | 38, 39 |
| 9 | iam-policy-in-use | `AWSSupportAccess` was not attached to anything | No role exists to manage AWS Support incidents (CIS 1.17) | Created `aws-support-role` with `AWSSupportAccess` | Compliant | IR-7, AC-6 | Analyst | 40–42, 50 |
| 10 | iam-password-policy | No account password policy | Weak passwords allowed for console users | Not possible in this account type (see 5.2) | Exception | AC-3(15) | AWS | 17, 20 |

Evidence numbers refer to files in `screenshots/` (for example `03` is `03-security-group-ssh-inbound-rule.png`).

## 4. Controls already passing at baseline

These rules were compliant from the start, so the planted issues were the only obvious gaps:

- `multi-region-cloudtrail-enabled`
- `s3-bucket-level-public-access-prohibited`
- `s3-bucket-public-read-prohibited`
- `iam-no-inline-policy-check`

## 5. Accepted exceptions

This lab used an AWS account created through the new "Sign up for AWS" Projects flow. That kind of account has no root user, no IAM user groups and no IAM **Account settings** page. Human sign-in goes through the project team page instead of IAM users. Three rules can't be satisfied because of those limits.

### 5.1 s3-bucket-versioning-enabled: MFA Delete

- **Why it still fails:** Versioning is on for every bucket. The pack runs this rule with `isMfaDeleteEnabled = TRUE`, and AWS only lets the **root user** turn on MFA Delete, using the CLI or API. This account has no root user.
- **Compensating controls:**
  - Versioning keeps every previous object version.
  - CloudTrail records every delete call.
  - Account-level Block Public Access is on.
- **In a production account:** the root user would enable MFA Delete on the log buckets, or S3 Object Lock would be used on the CloudTrail bucket.

### 5.2 iam-password-policy

- **Why it still fails:** The account doesn't expose IAM Account settings, so no password policy can be set. There are also no console IAM users. The only IAM user was deleted in fix 2.
- **Risk:** Low. No IAM user can sign in with a password.
- **In a production account:** set a policy with at least 14 characters, password reuse prevention, and expiry that follows the organization's standard.

### 5.3 s3-bucket-logging-enabled: the log destination bucket

- **Why it still fails:** `mo-audit-access-logs-4821` is the bucket that receives access logs. Turning on logging for it would send its logs into itself, which loops, or would need yet another bucket. Not logging the log bucket itself is a normal, accepted design.
- **Compensating controls:**
  - Block Public Access is on.
  - CloudTrail records management events for the bucket.

## 6. Recommended next steps

1. **Block public access for EBS snapshots.** It is currently "Not blocked". This is outside the pack, but it is a one-click improvement.
2. **Turn on CloudTrail log file validation.** It is currently disabled, and validation lets you prove log files weren't tampered with (AU-9).
3. **Add CloudWatch metric filters and alarms on the trail's log group,** for example:
   - Root activity
   - Unauthorized API calls
   - Security group changes
   - IAM policy changes

   These cover CIS section 4.
4. **Move to CIS v3.0 or the NIST 800-53 conformance pack** for broader coverage.
5. **Use Security Hub and GuardDuty in a standard AWS account.** Neither is available in Projects accounts.

## 7. Cleanup

After evidence was collected, I took the lab down so nothing keeps billing (screenshots 52–58):

| Resource | Action | Evidence |
|---|---|---|
| Conformance pack `cis-level1` | Deleted | 52 |
| AWS Config recorder | Recording turned off | 53 |
| CloudTrail trail `audit-trail` | Deleted | 54 |
| CloudWatch log group for the trail | Deleted | 55 |
| S3 buckets (lab, CloudTrail, Config, access logs) | Emptied and deleted | 56 |
| Security group `lab-open-ssh` | Deleted | 57 |
| IAM roles `aws-support-role` and `CloudTrailToCloudWatchRole` | Deleted | 58 |

The budget alert was kept as a safeguard.
