
# Invite Only

## Room Overview
As an SOC analyst at TrySecureMe, supporting an L3 analyst during IR activities. Two suspicious indicators flagged by L1 and escalated for further investigation and threat intelligence gathering.

**Category:** Incident Response / Threat Intelligence

## Objective
- Analyse flagged IP and SHA256 hash
- Pivot through CTI platforms to build threat intelligence
- Identify malware family, attack chain, and tooling
- Attribute findings to a known threat report

## Tools & Environment
- TryHackMe AttackBox
- VirusTotal
- AlienVault OTX
- Talos Intelligence
- ipinfo.io
- Google

## Investigation Process
Searched flagged SHA256 hash (`5d0509f68a9b7c415a726be75a078180e3f02e59866f193b0a99eee8e39c874f`) in VirusTotal — identified filename and file type from the Details tab. Relations tab surfaced execution parents and dropped file for `syshelpers.exe`.

Pivoted to the hash of `installer.exe` (execution parent) — Relations tab revealed 4 additional dropped files: `searchhost.exe`, `syshelpers.exe`, `nat.vbs`, `runsys.vbs`.

Searched flagged IP (`101[.]99[.]76[.]120`) and hash (`5d0509f68a9b7c415a726be75a078180e3f02e59866f193b0a99eee8e39c874f`) across platforms:
- VirusTotal — returned results but no malware family
- ipinfo.io — no malware family
- Talos Intelligence — no results on hash or IP
- AlienVault OTX — malware family identified in related tags: **AsyncRAT C2**

Googled the flagged hash directly — surfaced the original threat report. Report confirmed:
- Cookie theft tool: **ChromeKatz**
- Phishing technique: **ClickFix**
- Redirect platform: **Discord**

## Findings
- **Flagged file:** `syshelpers.exe`
- **Flagged hash:** `5d0509f68a9b7c415a726be75a078180e3f02e59866f193b0a99eee8e39c874f`
- **Execution parents:** `361GJX7J`, `installer.exe`
- **Dropped files (syshelpers.exe):** `AClient.exe`
- **Dropped files (installer.exe):** `searchhost.exe`, `syshelpers.exe`, `nat.vbs`, `runsys.vbs`
- **Flagged IP:** `101[.]99[.]76[.]120`
- **Malware family:** AsyncRAT C2
- **Threat report:** `https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/`

## Analysis & Response
- **MITRE ATT&CK:** T1566 (Phishing), T1027 (Obfuscated Files), T1071 (Application Layer Protocol), T1573 (Encrypted Channel), T1539 (Steal Web Session Cookie), T1059.005 (VBScript)
- Isolate affected endpoint via EDR
- Block flagged IP `101[.]99[.]76[.]120` at perimeter
- Revoke and rotate any compromised browser session cookies
- Notify affected user and escalate to L3 with compiled threat intelligence

## Key Takeaways
- No single CTI platform is sufficient — VT, OTX, Talos, and ipinfo can serve their own purposes during a pivot
- AlienVault OTX surfaces malware family context when VirusTotal doesn't
- Googling a hash directly can surface threat reports faster than platform-only pivoting
- VBS dropped files (`nat.vbs`, `runsys.vbs`) signal scripted persistence or execution chaining


