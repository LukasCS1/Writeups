# ItsyBitsy

## Room Overview
Analyst John flags an IDS alert indicating potential C2 communication from HR user Browne. A week of HTTP connection logs are ingested into the `connection_logs` index in Kibana for investigation.

## Category
- SIEM

## Objective
- Investigate HTTP connection logs for C2 activity
- Identify the malicious user agent and source IP
- Locate and retrieve C2 content

## Tools & Environment
- Kali Linux (VirtualBox)
- OpenVPN
- Kibana

## Investigation Process
Connected to TryHackMe via OpenVPN on Kali, accessed Kibana at `http://machine-ip`. In the Discover tab, set the timeframe to March 1 through March 31, 2022 to scope the investigation window.

Queried the `user_agent` field:
```kql
user_agent : bitsadmin
```
Returned events for a single suspicious agent. Pivoted to the source IP from those events, confirmed as the adversary machine.

Identified the full C2 URL from connection logs: `pastebin[.]com/yTg0Ah6a`. Navigated to the URL and retrieved the secret file `secret.txt` containing the flag.

## Findings
- **Adversary user agent:** `bitsadmin`
- **Source IP:** `192.166.65.54`
- **C2 URL:** `hxxps[://]pastebin[.]com/yTg0Ah6a`
- **Retrieved file:** `secret.txt`

## Analysis & Response
- Block or monitor `pastebin[.]com` traffic at the perimeter
- Investigate Browne's endpoint for additional compromise indicators
- Isolate the endpoint and escalate

## MITRE ATT&CK
- Masquerading (T1036): bitsadmin abused as a legitimate Windows binary to blend in
- Web Service (T1102): Pastebin used as C2 infrastructure
- Ingress Tool Transfer (T1105): bitsadmin downloading payload from C2
- Application Layer Protocol: Web Protocols (T1071.001): HTTP used for C2 communication

## Key Takeaways
- `user_agent` is a viable pivot when `userName` is unavailable in logs.
- `bitsadmin` is a legitimate Windows binary that can be abused for C2 download.
- Pastebin and similar paste sites are commonly abused as C2 infrastructure.
