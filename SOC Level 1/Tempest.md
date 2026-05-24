# Room Overview 
This room aims to introduce the process of analysing endpoint and network logs from a compromised asset. Given the artefacts, we will aim to uncover the incident from the Tempest machine.
In this scenario, you will be tasked to be one of the Incident Responders that will focus on handling and analysing the captured artefacts of a compromised machine.
In this incident, we will act as an Incident Responder from an alert triaged by one of our Security Operations Center analysts. The analyst has confirmed that the alert has a CRITICAL severity that needs further investigation.

# Category 
IR 


# Objective



# Tools & Environment
Tryhackme attackbox
Kali virtualbox
Event Viewer
SysmonView
EvtxEcmd
Timeline Explorer
Wireshark
Brim


# Investigation Process 
I start the attackbox and there is a folder on the desktop with 3 files inside, a pcap called capture and 2 eventlogs sysmon and windows.
First thing im doing is parsing sysmon logs to csv with evtxecmd 
-f C:\Users\user\Desktop\Incident Files\sysmon.evtx — csv C:\Users\user\Desktop\Incident Files — csvf sysmon.csv
I wonder why its not working and try multiple iterations and finally realize that i need to be in the C:\Tools\EvtxECmd directory.
.\EvtxECmd.exe -f 'C:\Users\user\Desktop\Incident Files\sysmon.evtx' --csv 'C:\Users\user\Desktop\Incident Files' --csvf sysmon.csv
attackbox didnt have a copy paste function for some reason and I progress further into the room slowly losing my mind until i break and switch to my kali vm even if i have to start over,







# Findings — IOCs, attack chain, key artifacts
# Analysis & Response — Containment and remediation actions
# MITRE ATT&CK — Mapped techniques with reasoning

# Key Takeaways 
I dont like the tryhackme attackbox.
EvtxEcmd requires you to be in its directory and needs to be executed in order to parse from evtx to csv, its not a tool you call.
