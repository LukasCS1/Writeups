# Invite Only

## Room Overview
As an SOC analyst at TrySecureMe, supporting an L3 analyst during IR activities. Two suspicious indicators flagged by L1 and escalated for further investigation and threat intelligence gathering.

## Category
- Incident Response / Threat Intelligence

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
Searched the flagged SHA256 hash (`5d0509f68a9b7c415a726be75a078180e3f02e59866f193b0a99eee8e39c874f`) in VirusTotal. Identified filename and file type from the Details tab. Relations tab surfaced execution parents and the dropped file for `syshelpers.exe`.

Pivoted to the hash of `installer.exe` (execution parent). Relations tab revealed 4 additional dropped files: `searchhost.exe`, `syshelpers.exe`, `nat.vbs`, `runsys.vbs`.

Searched the flagged IP (`101[.]99[.]76[.]120`) and hash across platforms:
- VirusTotal: results returned, no malware family
- ipinfo.io: no malware family
- Talos Intelligence: no results on hash or IP
- AlienVault OTX: malware family identified in related tags, **AsyncRAT C2**

Googled the flagged hash. Surfaced the original threat report. Report confirmed:
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
- **Threat report:** `hxxps[://]research[.]checkpoint[.]com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/`

## Analysis & Response
- Isolate the affected endpoint via EDR
- Block flagged IP `101[.]99[.]76[.]120` at the perimeter
- Revoke and rotate any compromised browser session cookies
- Notify the affected user and escalate to L3 with compiled threat intelligence

## MITRE ATT&CK
- Phishing (T1566): ClickFix phishing used for initial access via Discord
- Obfuscated Files or Information (T1027): obfuscated payloads within dropped files
- Application Layer Protocol (T1071): AsyncRAT C2 communication over standard protocols
- Encrypted Channel (T1573): encrypted C2 communications
- Steal Web Session Cookie (T1539): ChromeKatz used to harvest browser cookies
- Command and Scripting Interpreter: VBScript (T1059.005): `nat.vbs` and `runsys.vbs` used for execution chaining

## Key Takeaways
- No single CTI platform covers everything. VT, OTX, Talos, and ipinfo serve different purposes during a pivot.
- AlienVault OTX surfaces malware family context when VirusTotal doesn't.
- Googling a hash can surface threat reports faster than platform-only pivoting.
- VBS dropped files (`nat.vbs`, `runsys.vbs`) signal scripted persistence or execution chaining.
