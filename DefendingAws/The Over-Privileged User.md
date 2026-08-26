# The Over-Privileged User

## Room Overview
A developer, Carl, joins the team and needs AWS access. An admin under time pressure grants full Administrator rights outright, intending to scope it down later. Weeks pass with no follow-up. The developer retains unrestricted access to every service and resource. Task: audit user permissions, identify and remediate the misconfiguration, and design a secure IAM deployment strategy.

## Category
- AWS IAM Misconfiguration

## Incident Summary
Code Spaces provided subversion and git hosting for development teams on AWS. On June 17, 2014, the company was hit by a DDoS attack that served as cover for the real intrusion already underway. While staff focused on mitigating traffic, the attacker had already gained access to the Code Spaces AWS management console via the EC2 control panel, leaving ransom demands inside the console itself.

When staff detected the intrusion and rotated console passwords, the attacker's pre-created backdoor IAM logins gave them a path back in. On detecting recovery attempts, the attacker escalated to destruction. Within 12 hours, the production environment, backups, machine configurations, and off-site backups were partially or completely deleted. Code Spaces shut down permanently.

## Core Failure
The compromised identity held unrestricted administrative access to the entire AWS account. No permission boundaries, no explicit deny policies against destructive actions, no MFA requirement on sensitive operations, no monitoring on IAM changes. A single compromised credential carried the same blast radius as full account ownership.

## Identification Process
Listed IAM users, revealing two additional accounts beyond the expected baseline, including `carl-the-dev`:
```bash
aws iam list-users
```
Checked attached policies for `carl-the-dev`:
```bash
aws iam list-attached-user-policies --user-name carl-the-dev
```
Found a policy named `AWS201-DevCarlAdmin`. Inspecting the policy document confirmed unrestricted access:
```json
"Action": "*",
"Resource": "*"
```
Carl holds full administrative rights over every service and resource in the account, identical in scope to the credential compromised in the Code Spaces incident.

## Remediation
Detached and removed `AWS201-DevCarlAdmin`, leaving Carl with no permissions. Created a scoped least-privilege policy for developer-level access to the required S3 bucket, EC2 describe actions, and CloudWatch log access:

![AppAccess policy creation](path-to-image/cloudshellpolicycreate.png)

Created a `Developers` group, attached the new policy to the group rather than the individual user, and added Carl to it. Group-based assignment turns onboarding into "add to group" and offboarding into "remove from group," with no per-user policy edits required.

Validated the new policy's effective permissions with AWS Policy Simulator before considering the fix complete:

![Policy simulator validation](path-to-image/awspolicysimulator.png)

## Secure Build
**Group-based permission model.** Department-specific groups (Developers, Accounting, etc.) with least-privilege policies attached at the group level:

![AccountingPolicy creation and group attachment](path-to-image/policy.png)

**Permission boundaries.** An IAM policy that sets the maximum permissions an identity can ever hold, regardless of what other policies are attached or added later. Applied as a hard ceiling on Carl's account, an additional safeguard beyond group membership:

![Permission boundary applied to Carl](path-to-image/PermissionBoundary.png)

## Tools & Environment
- AWS CloudShell
- AWS Policy Simulator

## Key Takeaways
- `"Action": "*", "Resource": "*"` on a standing IAM identity carries the same blast radius as the credential that ended Code Spaces. Scope by default, not by promise.
- Group-based permission models turn onboarding and offboarding into a single membership change instead of per-user policy edits.
- Permission boundaries cap what an identity can ever do, even if a future policy attachment is overly permissive.
- AWS Policy Simulator validates real-world effective permissions before deployment, catching unintended allows or denies.
