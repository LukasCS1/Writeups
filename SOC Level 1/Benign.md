# Benign

## Room Overview
An IDS alert flags suspicious process execution on a host in the HR department. Network information gathering tools and scheduled tasks were executed, confirming compromise. Process execution logs with Event ID 4688 are ingested into Splunk under `win_eventlogs` for investigation.

## Category
- SIEM

## Objective
- Investigate process execution logs in Splunk
- Identify compromised users and imposter account
- Locate C2 infrastructure and downloaded payload

## Tools & Environment
- Kali Linux (VirtualBox)
- OpenVPN
- Splunk

## Investigation Process
Accessed Splunk and searched `index=win_eventlogs` with timeframe set to March 1–31 2022. Clicked the `UserName` field — top 10 users displayed but network information indicated 11 users total. Ran:
```splunk
index=win_eventlogs | top limit=20 UserName
```
Top 20 results revealed an imposter account masquerading as Amelia — `Amel1a`.

To find scheduled task activity, attempted Event ID filtering first:
```splunk
index=win_eventlogs EventCode IN (4698, 4699, 4700, 4701, 4702)
| table _time, host, EventCode, SubjectUserName, TaskName, TaskContent
```
No results — Event IDs not present in the dataset. Pivoted to filtering by HR usernames and checking the `CommandLine` field:
```splunk
index=win_eventlogs UserName IN (Haroon, Chris.fort, Diana)
```
`CommandLine` field identified `Chris.fort` running `schtasks`.

To find the LOLBIN used for payload download, filtered HR users and examined rare values in `CommandLine` — `certutil.exe` surfaced as the first rare value. Searched specifically for certutil activity to retrieve full command details including date and target URL.

Navigated to the C2 URL in the isolated VM — `controlc[.]com/e4d11035` — confirmed malicious file `benign.exe` and retrieved the flag.

![certutil execution](https://github.com/user-attachments/assets/20a410d4-e13a-460f-8737-ac1d34d26af7)
![C2 content](https://github.com/user-attachments/assets/ec6bdb11-1fbe-449a-8ae5-41f5f36f8f62)

## Findings
- **Imposter account:** `Amel1a` (masquerading as `Amelia`)
- **Compromised users:** `Chris.fort`, `Haroon`
- **LOLBIN used:** `certutil.exe`
- **Execution date:** `2022-03-04`
- **C2 URL:** `hxxps[://]controlc[.]com/e4d11035`
- **Downloaded file:** `benign.exe`

## Analysis & Response
- Isolate endpoints of `Chris.fort` and `Haroon`
- Disable and investigate `Amel1a` imposter account
- Block `controlc[.]com` at perimeter
- Hunt for `benign.exe` across all endpoints
- Review scheduled tasks across HR department

## MITRE ATT&CK v19
- Masquerading (T1036) — `Amel1a` impersonating legitimate user `Amelia`; `certutil.exe` abused as legitimate Windows binary
- Scheduled Task/Job (T1053) — `Chris.fort` executing scheduled tasks for persistence
- Valid Accounts (T1078) — adversary operating under compromised HR user accounts
- Ingress Tool Transfer (T1105) — `certutil.exe` used to download payload from C2
- Application Layer Protocol (T1071) — `controlc[.]com` abused as C2 infrastructure

## Key Takeaways
- `top limit=20 UserName` reveals username anomalies that top 10 misses — always check beyond default limits
- Rare values in `CommandLine` field surface LOLBINs that don't appear in top results
- `certutil.exe` is a commonly abused Windows binary for payload download (LOLBIN)
- Network segmentation context (knowing which users belong to which department) significantly narrows investigation scope
````
