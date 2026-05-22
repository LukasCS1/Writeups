# Snapped Phish-ing Line

## Room Overview
Multiple SwiftSpend Financial employees report a suspicious email. Several have already submitted credentials and lost account access.
Objective: identify attacker infrastructure, recover the phishing kit, and determine scope of compromise.

**Category:** Phishing Investigation / CTI

## Objective
- Extract key artifacts from provided email samples
- Map the phishing redirection chain
- Retrieve and analyze the phishing kit
- Gather adversary intelligence via CTI tools

## Tools & Environment
- TryHackMe AttackBox
- VirusTotal
- CyberChef
- CLI — `sha256sum`, `unzip`, `find`

## Investigation Process
Reviewed 5 emails in phish-emails folder. Extracted recipient name and adversary sender address from headers in *Quote for Services Rendered*.
Zoe Duncan's email contained an attachment redirecting to a Microsoft login impersonation page on `kennaroads[.]buzz`.
Navigated to `/data/` on the attacker's server — open directory exposing `update365.zip`. Downloaded and hashed:
```bash
sha256sum update365.zip
ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686
```
VirusTotal confirmed phishing classification plus an additional threat category, with file count visible on the Details tab.

`/data/Update365/log.txt` contained submitted credentials — manually identified a repeat submission without tooling.

Located `submit.php` for exfiltration email:
```bash
find -type f -name submit.php 2>/dev/null
```
Flag found at `/data/Update365/office365/flag.txt` — Base64 encoded, decoded in reverse via CyberChef.

## Findings
- **Attack chain:** Phishing email → malicious attachment → redirect → credential harvesting page → exfiltration via submit.php
- **Phishing domain:** `kennaroads[.]buzz`
- **Phishing kit hash:** `ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686`
- **Credential log:** `/data/Update365/log.txt`

## Analysis & Response
- **MITRE ATT&CK:** T1566 (Phishing), T1078 (Valid Accounts)
- Reset credentials for all affected accounts, prioritize repeat submission identified in log.txt
- Block `kennaroads[.]buzz` at perimeter
- Notify all recipients regardless of submission status
- Enforce MFA, conduct phishing awareness training

## Key Takeaways
- Open `/data/` directories are a common attacker OPSEC failure — directory enumeration is an early high-value step
- Environment isolation determines what interaction with live URLs is safe
- CyberChef handles encoding/decoding quickly during triage
