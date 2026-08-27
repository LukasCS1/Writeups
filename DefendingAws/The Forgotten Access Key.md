# The Forgotten Access Key

## Room Overview
An engineer creates an AWS access key to run a deployment script. The script works, the project ships, and the key is forgotten: still active, never rotated, sitting in a config file somewhere. If the key leaks, an attacker gains persistent, long-lived access to the environment.

## Category
- Credential Hygiene Misconfiguration

## Incident Summary
Uber runs on AWS and stores sensitive data in S3 buckets. Engineering teams use GitHub for source control and AWS access keys to authenticate programmatically to AWS services.

The breach unfolded as a chain of credential failures:
- **Credential stuffing into GitHub:** Attackers tested stolen email/password combinations against GitHub accounts. A valid login gave them access to Uber's private repositories. No MFA enforcement blocked the attempt.
- **Access key leak:** Inside a private repository, the attackers found AWS access keys hardcoded in source code.
- **S3 data exfiltration:** Using the leaked keys, the attackers authenticated to the AWS account and downloaded 16 unencrypted database backup files from S3.
- **Ransom and cover-up:** The attackers demanded payment. Uber's Chief Security Officer paid the ransom and classified the incident as a vulnerability disclosure rather than a breach.

## Core Failure
- **Long-lived access keys with no rotation:** persistent access with no expiration
- **Hardcoded keys in source code:** stored in application code instead of a secrets manager or replaced with temporary role-based credentials
- **No MFA:** GitHub and AWS access for privileged users required no second factor
- **Over-privileged access:** the leaked keys granted broad access to S3 data stores
- **No monitoring or alerting:** no detection for unusual API activity, such as bulk S3 downloads

## Identification Process
Generated a credential report to audit account-wide key and MFA status:
```bash
aws iam generate-credential-report
aws iam get-credential-report \
    --query 'Content' \
    --output text | base64 --decode > credential-report.csv
```
Report showed no MFA active on the account and two active access keys. Listed the keys for the flagged user:
```bash
aws iam list-access-keys \
    --user-name dev-keyleaks
```
Checked last-used activity for both keys. `KEY1_ID` returned `N/A`, never used. `KEY2_ID` showed recent S3 activity:

![Access key last-used check](path-to-image/lastusedkey.png)

Checked inline policies on the user (none) and group membership. `dev-keyleaks` belongs to `AppDataReaders`, which carries `AppDataReadersPolicy`:

![Group policy permissions](path-to-image/grouppolicyperm.png)

Policy scopes access to a specific S3 bucket only. Blast radius from this credential is limited to that bucket, not account-wide.

## Remediation
Deactivated the unused key (`KEY1_ID`) first rather than deleting it outright, to confirm no dependent process breaks:
```bash
aws iam update-access-key \
    --user-name dev-keyleaks \
    --access-key-id $KEY1_ID \
    --status Inactive
```
After a 24 to 72 hour observation window with no reported failures, deleted the stale key:
```bash
aws iam delete-access-key \
    --user-name dev-keyleaks \
    --access-key-id $KEY1_ID
```

![Key deactivation and deletion](path-to-image/deletekey.png)

Rotated the remaining active key: created a new key for the user, validated it against `sts get-caller-identity` and an S3 list call, then deactivated and deleted the old one:

![New key creation and validation](path-to-image/newkey.png)

Enabled MFA on the account. End state: stale key removed, active key rotated, MFA enforced.

## Secure Build
The entire exposure was avoidable with temporary credentials from day one instead of static keys.

Created a trust policy requiring MFA to assume the role:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${ACCOUNT_ID}:user/dev-keyleaks"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        }
      }
    }
  ]
}
```
Created the role with this trust policy and a permissions boundary attached at creation, capping maximum privilege regardless of any policy attached later:
```bash
aws iam create-role \
  --role-name DevS3ReadRole \
  --assume-role-policy-document file:///tmp/trust-policy.json \
  --permissions-boundary "arn:aws:iam::${ACCOUNT_ID}:policy/Room22-DevS3ReadBoundary" \
  --description "Developer role for S3 read access, requires MFA"
```

![Role creation with MFA condition and permissions boundary](path-to-image/temporary.png)

Attached a scoped inline policy limiting the role to read-only access on the specific bucket:
```bash
aws iam put-role-policy \
  --role-name DevS3ReadRole \
  --policy-name S3ReadAccess \
  --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Sid\": \"S3ReadSpecificBucket\",
      \"Effect\": \"Allow\",
      \"Action\": [\"s3:GetObject\", \"s3:ListBucket\"],
      \"Resource\": [
        \"arn:aws:s3:::${BUCKET_NAME}\",
        \"arn:aws:s3:::${BUCKET_NAME}/*\"
      ]
    }]
  }"
```
This role stacks two controls the original setup had neither of: credentials expire automatically, and MFA gates the assume-role call itself.

## Tools & Environment
- AWS CloudShell

## Key Takeaways
- Static access keys have no expiration by default. Treat any long-lived key as a liability the moment it's created, not just after it leaks.
- `get-access-key-last-used` is the fastest way to separate dead keys from active ones before deciding what to rotate or delete.
- A scoped group policy limits blast radius even when a key leaks. Uber's incident had no such scoping, which is why the exposure was catastrophic instead of contained.
- Deactivate before deleting. A short observation window catches dependent processes before the key is gone for good.
- Role assumption with an MFA condition closes the exact gap that let stolen GitHub credentials cascade into AWS access at Uber: even a valid login can't assume the role without a second factor.
- Permissions boundaries on roles, not just policies on users, cap privilege at the account level regardless of what gets attached later.
