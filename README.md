Home SOC Lab — Splunk SIEM & Endpoint Detection Environment
Overview
A fully operational Security Operations Center built on a personal Windows machine using Splunk Enterprise and Sysmon. This project simulates a real enterprise SOC environment, monitoring a live endpoint and detecting threats using production-style detection rules and a professional monitoring dashboard.

Environment

OS: Windows 11
SIEM: Splunk Enterprise 10.2
Endpoint Telemetry: Sysmon with SwiftOnSecurity config
Splunk Add-on: Splunk Add-on for Microsoft Windows
Index: wineventlog
Sourcetypes: WinEventLog:Security, XmlWinEventLog


Architecture
[Windows Endpoint]
        │
        ├── Windows Event Logs (Security, System, Application)
        ├── Sysmon (Process, Network, File, Registry telemetry)
        │
        ▼
[Splunk Enterprise]
        │
        ├── inputs.conf (log ingestion)
        ├── props.conf (field parsing)
        ├── XmlWinEventLog sourcetype
        │
        ▼
[Detection Rules → Scheduled Alerts → SOC Dashboard]

Configuration Files
inputs.conf
Located at:
C:\Program Files\Splunk\etc\system\local\inputs.conf
ini[WinEventLog://Application]
index = wineventlog
disabled = false

[WinEventLog://Security]
index = wineventlog
disabled = false

[WinEventLog://System]
index = wineventlog
disabled = false

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = wineventlog
sourcetype = XmlWinEventLog
renderXml = true
disabled = false

Detection Rules
Rule 1 — Brute Force Login Detection
MITRE ATT&CK: T1110 — Brute Force
Description: Detects repeated failed login attempts indicating a possible brute force or password spraying attack.
splindex=wineventlog sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, Logon_Type
| where count > 5

Rule 2 — Successful Login After Failures
MITRE ATT&CK: T1110 — Brute Force
Description: Detects a successful login following multiple failures within the same 5 minute window, indicating possible credential compromise.
splindex=wineventlog sourcetype="WinEventLog:Security" (EventCode=4624 OR EventCode=4625)
| bin _time span=5m
| stats count(eval(EventCode=4625)) as failed count(eval(EventCode=4624)) as success by _time, Account_Name
| where failed > 5 AND success > 0

Rule 3 — Suspicious PowerShell Execution
MITRE ATT&CK: T1059.001 — PowerShell
Description: Detects PowerShell using encoded commands, execution policy bypass, or hidden execution — common techniques in fileless malware and post-exploitation.
splindex=wineventlog Image="*powershell.exe"
| search CommandLine="*-enc*" OR CommandLine="*bypass*" OR CommandLine="*hidden*"
| table _time Image CommandLine ParentImage

Rule 4 — Suspicious Parent-Child Process
MITRE ATT&CK: T1566.001 — Spearphishing Attachment
Description: Detects Word or Excel spawning PowerShell or CMD, the classic malicious macro attack chain from phishing documents.
splindex=wineventlog (ParentImage="*winword.exe" OR ParentImage="*excel.exe")
| search (Image="*powershell.exe" OR Image="*cmd.exe")
| table _time ParentImage Image CommandLine

Rule 5 — New Local User Account Created
MITRE ATT&CK: T1136.001 — Local Account
Description: Detects new user account creation or addition to privileged groups, a common attacker persistence technique.
splindex=wineventlog sourcetype="WinEventLog:Security" (EventCode=4720 OR EventCode=4732)
| table _time Account_Name Security_ID

Rule 6 — Logins Outside Business Hours
MITRE ATT&CK: T1078 — Valid Accounts
Description: Flags successful logins between 10pm and 6am. Compromised accounts are frequently used outside normal working hours.
splindex=wineventlog sourcetype="WinEventLog:Security" EventCode=4624
| eval hour=strftime(_time,"%H")
| where hour < 6 OR hour > 22
| table _time Account_Name Logon_Type hour

Rule 7 — Outbound Connections to External IPs
MITRE ATT&CK: T1071 — Application Layer Protocol
Description: Detects processes making outbound connections outside the local network, potentially indicating command-and-control communication or data exfiltration.
splindex=wineventlog EventCode=3
| search NOT DestinationIp="192.168.*" NOT DestinationIp="10.*" NOT DestinationIp="127.*"
| table _time Image DestinationIp DestinationPort

Rule 8 — Executables Running from Temp Directory
MITRE ATT&CK: T1036 — Masquerading
Description: Detects programs launching from AppData\Temp folders. Legitimate software rarely runs from these locations — malware frequently uses them to evade detection.
splindex=wineventlog Image="*\\AppData\\Local\\Temp\\*"
| table _time Image CommandLine ParentImage

Rule 9 — Windows Defender Tampered
MITRE ATT&CK: T1562.001 — Disable or Modify Tools
Description: Detects Windows Defender being disabled or modified. Attackers commonly kill antivirus before deploying payloads.
splindex=wineventlog sourcetype="WinEventLog:Security" (EventCode=5001 OR EventCode=5010)
| table _time EventCode Account_Name

Rule 10 — Excessive Process Creation
MITRE ATT&CK: T1543 — Create or Modify System Process
Description: Detects abnormal spikes in process creation within a single minute, indicating possible malware loops, worms, or runaway scripts.
splindex=wineventlog EventCode=1
| bin _time span=1m
| stats count by _time Image
| where count > 20
| table _time Image count

Troubleshooting Challenges Solved
Problem                                     Root                                     Cause Solution 
No logs ingesting                   NT SERVICE\Splunkd lacked permissions       Changed Splunk service to run as LocalSystem 
Binary garbage in logs              Splunk reading raw .evtx files              Fixed inputs.conf to use channel-based ingestion
All data being dropped              wineventlog index didn't exist              Created index in Splunk Settings
Missing Image/CommandLine fields    Wrong sourcetype for Sysmon                 Installed Splunk Add-on for Microsoft Windows
Empty CommandLine field             Sysmon config not applied correctly         Reinstalled Sysmon with SwiftOnSecurity config

SOC Dashboard Panels

Total Events (Last 24 Hours)
Failed Login Attempts (Last 24 Hours)
Suspicious PowerShell Executions
Outbound External Connections
Failed Login Attempts Over Time (Column Chart)
Event Activity Over Time (Line Chart)
Top 10 Processes Created
Top User Accounts Seen
Recent Suspicious PowerShell Activity
Recent Failed Logins
Executables Running from Temp Directory
Recent Outbound External Connections


Skills Demonstrated

Splunk Enterprise administration and configuration
SIEM data pipeline troubleshooting
Sysmon deployment and tuning
SPL detection rule development
MITRE ATT&CK framework mapping
Windows Event Log analysis
Endpoint telemetry collection


References
Splunk Add-on for Microsoft Windows
SwiftOnSecurity [Sysmon Config]([url](https://github.com/swiftonsecurity/sysmon-config))
MITRE ATT&CK Framework
Sysmon Microsoft Sysinternals


Built as part of a self-directed cybersecurity career transition project. March 2026.
