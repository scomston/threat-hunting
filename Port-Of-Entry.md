# Threat Hunt Report — Port of Entry

<p align="center">
  <img width="723" height="1083" alt="image" src="https://github.com/user-attachments/assets/6c14bef9-ccfb-4419-88c4-978d03ae6769" />
</p>


## Executive Summary

This investigation uncovered a deliberate, multi-stage intrusion that targeted Azuki Import/Export Trading Co. (梓貿易株式会社). The attacker gained interactive access to an IT administrator workstation, performed local network reconnaissance, downloaded and staged tools in a hidden folder, dumped credentials from memory, compressed targeted data, and exfiltrated that data to an external cloud/communication service. The adversary used living-off-the-land binaries (LOLBins), scheduled tasks for persistence, and event log clearing for anti-forensics.

**Target system:** `AZUKI-SL` (IT admin workstation)  
**Time window:** 2025-11-19 → 2025-11-20  
**Data sources:**  
- `DeviceProcessEvents`  
- `DeviceFileEvents`  
- `DeviceNetworkEvents`  
- `DeviceRegistryEvents`  
- `DeviceLogonEvents`

---

## 🚩 Key Findings (flags) 

Here is the logical chain followed, which informed how each flag was detected:


| Flag | Timestamp (UTC) | Description | Observed Artifact / Activity |
|---|---|---|---|
| **1** | 2025-11-19T18:36:21Z | Remote Access Source | (RDP client IP) `88.97.178.12` |
| **2** | 2025-11-19T18:36:21Z | Compromised User Account | `kenji.sato` |
| **3** | 2025-11-19T19:04:01Z |  Network Reconnaissance | **"ARP.EXE" -a** |
| **4** | 2025-11-19T19:05:33Z | DEFENCE EVASION - Malware Staging Directory | `**C:\ProgramData\WindowsCache**` |
| **5** | 2025-11-19T18:49:27Z | DEFENCE EVASION - File Extension Exclusions | 3 unique extensions excluded (`.bat, .ps1, .exe`)|
| **6** | 2025-11-19T18:49:27Z | Temporary Folder Exclusion | `C:\Users\KENJI~1.SAT\AppData\Local\Temp` |
| **7** | 2025-11-19T19:06:58Z | Download Utility Abuse | `certutil.exe` |
| **8** | 2025-11-19T19:07:46Z | Scheduled Task Name | **Windows Update Check** |
| **9** | 2025-11-19T19:07:46Z | Scheduled Task Target | `C:\ProgramData\WindowsCache\svchost.exe` |
| **10** | 2025-11-19T19:11:04Z | C2 Server Address | Outbound traffic to `78.141.196.6*` |
| **11** | 2025-11-19T19:11:04Z |  C2 Communication Port | Destination Port `443` |
| **12** | 2025-11-19T19:07:22Z |  Credential Theft Tool | **mm.exe** |
| **13** | 2025-11-19T19:08:26Z | Memory Extraction Module | `sekurlsa::logonpasswords` |
| **14** | 2025-11-19T19:08:58Z |  Data Staging Archive | `export-data.zip` |
| **15** | 2025-11-19T19:09:21Z | Exfiltration Channel | `discord.com` |
| **16** | 2025-11-19T19:11:39Z |  Log Tampering | Security |
| **17** | 2025-11-19T19:09:53Z |  Persistence Account | support |
| **18** | 2025-11-19T18:49:48Z | Malicious Script | `wupdate.ps1` |
| **19** | 2025-11-19T19:10:37Z |  Secondary Target |  `10.1.0.188` |
| **20** | 2025-11-19T19:10:41Z | Remote Access Tool | `mstsc.exe` |
---

## Flag 1 - Remote Access Source

**Objective:**
Remote Desktop Protocol connections leave network traces that identify the source of unauthorised access. Determining the origin helps with threat actor attribution and blocking ongoing attacks.

- **Observation:** An RDP logon originated from the external IP `88.97.178.12`.
- **Logical Flow:** An unexpected remote interactive session is the earliest indication of compromise. Who connected — and from where?  
- **Interpretation:** The connection originated from outside the corporate network, confirming external unauthorized access as the entry point.

**KQL Query Used:**

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-11-25))
| extend ActionVal = tostring(column_ifexists("ActionType", column_ifexists("Action", column_ifexists("ResultType",""))))
| project TimeGenerated, AccountName, LogonType = tostring(column_ifexists("LogonType","")), ActionVal, RemoteIP = tostring(coalesce(
    column_ifexists("RemoteIpAddress",""),
    column_ifexists("RemoteIP",""),
    column_ifexists("RemoteIp",""),
    column_ifexists("RemoteAddress",""),
    column_ifexists("IpAddress","")
  ))
| order by TimeGenerated asc
| take 10
```

<img width="956" height="313" alt="image" src="https://github.com/user-attachments/assets/b478e7a3-7c1d-43b3-b1e0-0b18c19d5182" />

**Flag 1 Answer:** The source IP address of the Remote Desktop Protocol connection: `88.97.178.12`

---

## Flag 2 - Compromised User Account

**Objective:**
Identifying which credentials were compromised determines the scope of unauthorised access and guides remediation efforts including password resets and privilege reviews.

- **Observation:** The user `kenji.sato` authenticated during the suspicious RDP session.
- **Logical Flow:** If the source is malicious, the next question is: whose credentials were stolen?
- **Interpretation:** This account was compromised and used by the attacker to gain full workstation access.

**KQL Query Used:**

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-11-25))
| extend ActionVal = tostring(column_ifexists("ActionType", column_ifexists("Action", column_ifexists("ResultType",""))))
| project TimeGenerated, AccountName, LogonType = tostring(column_ifexists("LogonType","")), ActionVal, RemoteIP = tostring(coalesce(
    column_ifexists("RemoteIpAddress",""),
    column_ifexists("RemoteIP",""),
    column_ifexists("RemoteIp",""),
    column_ifexists("RemoteAddress",""),
    column_ifexists("IpAddress","")
  ))
| order by TimeGenerated asc
| take 10
```
<img width="934" height="172" alt="image" src="https://github.com/user-attachments/assets/656a4f0e-b90d-4382-948c-9ada1f833d59" />

**Flag 2 Answer:** The user account that was compromised for initial access: `kenji.sato`

---

## Flag 3 - Network Reconnaissance

**Objective:**
Attackers enumerate network topology to identify lateral movement opportunities and high-value targets. This reconnaissance activity is a key indicator of advanced persistent threats.

- **Observation:** The attacker ran `"ARP.EXE" -a` to enumerate local network neighbors.
- **Logical Flow:** Once inside, threat actors validate where they are — and what else is nearby.
- **Interpretation:** Standard discovery step to map internal hosts for lateral movement planning.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "arp"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="1363" height="167" alt="image" src="https://github.com/user-attachments/assets/5dd4b132-c544-45e9-af02-18f5e062568f" />

**Flag 3 Answer:** The command and argument used to enumerate network neighbours: `"ARP.EXE" -a`

---

## Flag 4 - Malware Staging Directory

**Objective:**
Attackers establish staging locations to organise tools and stolen data. Identifying these directories reveals the scope of compromise and helps locate additional malicious artefacts.

- **Observation:** A hidden staging folder `C:\ProgramData\WindowsCache` was created and concealed with attrib +h +s.
- **Logical Flow:** Recon is followed by setup. Where will the attacker store their tooling?
- **Interpretation:** The directory was intentionally hidden to evade detection and serve as the malware hub.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "mkdir"
       or ProcessCommandLine contains "New-Item"
       or ProcessCommandLine contains "attrib"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc

```
<img width="831" height="199" alt="image" src="https://github.com/user-attachments/assets/ae83bec8-1be4-4e01-9b64-e4b1cde1c859" />

**Flag 4 Answer:** The PRIMARY staging directory where malware was stored: `C:\ProgramData\WindowsCache`

---

## Flag 5 - File Extension Exclusions

**Objective:**
Attackers add file extension exclusions to Windows Defender to prevent scanning of malicious files. Counting these exclusions reveals the scope of the attacker's defense evasion strategy.

- **Observation:** 3 file extensions (`.bat, .ps1, .exe`) were added to Windows Defender exclusions.
- **Logical Flow:** To operate freely, the attacker cripples antivirus scanning.
- **Interpretation:** These exclusions prevented detection of their custom tooling, enabling stealth execution.

**KQL Query Used:**
```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryKey contains @"Windows Defender\Exclusions\Extensions"
| project TimeGenerated, ExclusionPath = RegistryKey, ExtensionName = RegistryValueName
| order by TimeGenerated asc

```
```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryKey contains @"Windows Defender\Exclusions\Extensions"
| project TimeGenerated, RegistryKey, RegistryValueName
| distinct RegistryValueName
| count

```

<img width="810" height="117" alt="image" src="https://github.com/user-attachments/assets/c50eb024-cea6-4b51-aa70-014bc6c47d58" />


<img width="244" height="113" alt="image" src="https://github.com/user-attachments/assets/e3002961-d4d6-4673-84f4-c3d6253ca230" />

**Flag 5 Answer:** How many file extensions were excluded from Windows Defender scanning: **3**

---

## Flag 6 - Temporary Folder Exclusion

**Objective:**
Attackers add folder path exclusions to Windows Defender to prevent scanning of directories used for downloading and executing malicious tools. These exclusions allow malware to run undetected.

- **Observation:** Windows Defender exclusion added for: `C:\Users\KENJI~1.SAT\AppData\Local\Temp`
- **Logical Flow:** Staging locations often include temp paths — especially for download/execution.
- **Interpretation:** Ensured malware dropped to Temp would not be scanned, facilitating later script execution.

**KQL Query Used:**

```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryKey contains @"Windows Defender\Exclusions\Paths"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```

<img width="685" height="172" alt="image" src="https://github.com/user-attachments/assets/003b6f65-c098-43fc-8f46-07b8cf6b9d1d" />


**Flag 6  Answer:** The temporary folder path excluded from Windows Defender scanning: `C:\Users\KENJI~1.SAT\AppData\Local\Temp`

---

## Flag 7 - Download Utility Abuse

**Objective:**
Legitimate system utilities are often weaponized to download malware while evading detection. Identifying these techniques helps improve defensive controls.

- **Observation:** The attacker used `certutil.exe` to download malware from a remote server.
- **Logical Flow:** With exclusions in place, an LOLBin is used to pull down payloads.
- **Interpretation:** Certutil is a classic dual-use tool abused for its built-in download capability.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "http" or ProcessCommandLine contains "https"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc

```

<img width="1023" height="138" alt="image" src="https://github.com/user-attachments/assets/a72d2252-0171-41ba-8baa-b67965e434ac" />

**Flag 7 Answer:** The Windows-native binary the attacker abused to download files: `certutil.exe`

---

## Flag 8 - Scheduled Task Name

**Objective:**
Scheduled tasks provide reliable persistence across system reboots. The task name often attempts to blend with legitimate Windows maintenance routines.

- **Observation:** A task named `"Windows Update Check`" was created to appear legitimate.
- **Logical Flow:** To survive reboots, attackers plant recurring execution mechanisms disguised as system tasks.
- **Interpretation:** This task likely ensured daily execution of the malicious binary.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc

```
<img width="1089" height="179" alt="image" src="https://github.com/user-attachments/assets/1df0413b-3d6a-4c9f-a9aa-56f307988c95" />

**Flag 8 Answer:** The name of the scheduled task created for persistence: `Windows Update Check`

---

## Flag 9 - Scheduled Task Target

**Objective:**
The scheduled task action defines what executes at runtime. This reveals the exact persistence mechanism and the malware location.

- **Observation:** The scheduled task executed: `C:\ProgramData\WindowsCache\svchost.exe`
- **Logical Flow:** Once the task exists, what exactly does it run?
- **Interpretation:** This malicious file (masquerading as `svchost.exe`) served as the core persistence implant.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```
<img width="944" height="171" alt="image" src="https://github.com/user-attachments/assets/25e9b210-fb22-44b7-bbdb-f5bbd0eec8f8" />

**Flag 9 Answer:** The executable path configured in the scheduled task: `C:\ProgramData\WindowsCache\svchost.exe`

---

## Flag 10 - C2 Server Address

**Objective:**
Command and control infrastructure allows attackers to remotely control compromised systems. Identifying C2 servers enables network blocking and infrastructure tracking.

- **Observation:** Outbound traffic from the malware connected to `78.141.196.6`.
- **Logical Flow:** After persistence, the malware reaches out — but to whom?
- **Interpretation:** This IP served as the remote command-and-control endpoint.

**KQL Query Used:**

```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessFileName == "svchost.exe"
| where InitiatingProcessFolderPath contains @"C:\ProgramData\WindowsCache"
| project TimeGenerated, RemoteIP, RemotePort, Protocol, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc

```
<img width="880" height="226" alt="image" src="https://github.com/user-attachments/assets/8249db59-35f1-45d3-86bf-95741b343b15" />

**Flag 10 Answer:** The IP address of the command and control server: `78.141.196.6`

---

## Flag 11 - C2 Communication Port

**Objective:**
C2 communication ports can indicate the framework or protocol used. This information supports network detection rules and threat intelligence correlation.

- **Observation:** The communication occurred over port 443.
- **Logical Flow:** C2 channels commonly mimic legitimate encrypted traffic.
- **Interpretation:** Using HTTPS allowed the attacker to blend in with normal outbound TLS activity.

**KQL Query Used:**

```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessFileName == "svchost.exe"
| where InitiatingProcessFolderPath contains @"C:\ProgramData\WindowsCache"
| project TimeGenerated, RemoteIP, RemotePort, Protocol, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="884" height="233" alt="image" src="https://github.com/user-attachments/assets/2e345308-dff7-452a-bda6-324832d151c4" />

**Flag 11 Answer:** The destination port used for command and control communications: `443`

---

## Flag 12 - Credential Theft Tool

**Objective:**
Credential dumping tools extract authentication secrets from system memory. These tools are typically renamed to avoid signature-based detection.

- **Observation:** A short-named executable mm.exe appeared in the staging directory.
- **Logical Flow:** After establishing C2, attackers expand privileges — often via credential theft.
- **Interpretation:** This file was likely a renamed Mimikatz binary used for credential extraction.

**KQL Query Used:**

```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FolderPath contains @"C:\ProgramData\WindowsCache"
| where FileName endswith ".exe"
| project TimeGenerated, FileName, FolderPath
| order by TimeGenerated asc
```
<img width="680" height="175" alt="image" src="https://github.com/user-attachments/assets/59c09a75-d2e6-4a2e-9f25-304153c31b7e" />

**Flag 12 Answer:** The filename of the credential dumping tool: `mm.exe`

---

## Flag 13 - Memory Extraction Module

**Objective:**
Credential dumping tools use specific modules to extract passwords from security subsystems. Documenting the exact technique used aids in detection engineering.

- **Observation:** The attacker invoked sekurlsa::logonpasswords.
- **Logical Flow:** Which exact technique was used to steal credentials from memory?
- **Interpretation:** Classic LSASS harvesting, indicating full credential compromise on the host.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessFileName == "mm.exe"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName endswith "mm.exe"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="750" height="147" alt="image" src="https://github.com/user-attachments/assets/084c8a1d-5690-40ea-a4ed-fe507f44fc08" />

**Flag 13 Answer:** The module used to extract logon passwords from memory: `sekurlsa::logonpasswords`

---

## Flag 14 - Data Staging Archive

**Objective:**
Attackers compress stolen data for efficient exfiltration. The archive filename often includes dates or descriptive names for the attacker's organisation.

- **Observation:** Stolen data was packaged into export-data.zip.
- **Logical Flow:** Credentials obtained, next comes data harvesting.
- **Interpretation:** Compressed archive likely contained sensitive shipping contract and pricing data.

**KQL Query Used:**

```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FolderPath contains @"C:\ProgramData\WindowsCache"
| where FileName endswith ".zip"
| project TimeGenerated, FileName, FolderPath
| order by TimeGenerated asc
```
<img width="711" height="145" alt="image" src="https://github.com/user-attachments/assets/7181121b-6a75-476b-bede-1375f97ce162" />

**Flag 14 Answer:** The compressed archive filename used for data exfiltration: `export-data.zip`

---

## Flag 15 - Exfiltration Channel

**Objective:**
Cloud services with upload capabilities are frequently abused for data theft. Identifying the service helps with incident scope determination and potential data recovery.

- **Observation:** Exfiltration occurred via Discord, leveraging HTTPS file upload features.
- **Logical Flow:** Staged data must leave the network — through a covert, user-friendly channel.
- **Interpretation:** Discord is often abused due to its CDN hosting and lack of enterprise monitoring.

**KQL Query Used:**

```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RemotePort == 443
| project TimeGenerated, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="1424" height="234" alt="image" src="https://github.com/user-attachments/assets/16ae64d8-bf0c-41a2-86fa-f2902d1ca40d" />

**Flag 15 Answer:** The cloud service used to exfiltrate stolen data: `Discord`

---

## Flag 16 - Log Tampering

**Objective:**
Clearing event logs destroys forensic evidence and impedes investigation efforts. The order of log clearing can indicate attacker priorities and sophistication.

- **Observation:** The Security event log was cleared first.
- **Logical Flow:** To cover their tracks, what evidence did the attacker attempt to erase first?
- **Interpretation:** Wiping the Security log removes authentication traces, hiding compromise and privilege escalation.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName =~ "wevtutil.exe"
| where ProcessCommandLine contains " cl "
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="435" height="175" alt="image" src="https://github.com/user-attachments/assets/435ff913-c97d-49e9-804d-7c0d1bae86e6" />

**Flag 16 Answer:** The first Windows event log cleared by the attacker: `Security`

---

## Flag 17 - Log Tampering

**Objective:**
Hidden administrator accounts provide alternative access for future operations. These accounts are often configured to avoid appearing in normal user interfaces.

- **Observation:** A hidden administrative backdoor account named support was created.
- **Logical Flow:** Even after C2, the attacker ensures future access independent of malware.
- **Interpretation:** This account allowed long-term, malware-less persistence — extremely dangerous.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "localgroup" and ProcessCommandLine contains "add"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="517" height="143" alt="image" src="https://github.com/user-attachments/assets/67bb0505-032c-4e89-8f11-465db5d54fee" />

**Flag 17 Answer:** The backdoor account username created by the attacker: `support`

---

## Flag 18 - Malicious Script

**Objective:**
Attackers often use scripting languages to automate their attack chain. Identifying the initial attack script reveals the entry point and automation method used in the compromise.

- **Observation:** Initial automation performed through wupdate.ps1.
- **Logical Flow:** To bootstrap the attack, a script downloads tools, sets exclusions, and deploys implants.
- **Interpretation:** This PowerShell script served as the attack’s orchestrator.

**KQL Query Used:**

```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName endswith ".ps1"
| where InitiatingProcessCommandLine contains "http" or InitiatingProcessCommandLine contains "download"
| project TimeGenerated, FileName, InitiatingProcessCommandLine
| order by TimeGenerated asc

```
<img width="1342" height="232" alt="image" src="https://github.com/user-attachments/assets/8e272a7b-a3db-4665-90e4-e29dcd0fbcbb" />

**Flag 18 Answer:** The PowerShell script file used to automate the attack chain: `wupdate.ps1`

---

## Flag 19 - Secondary Target

**Objective:**
Lateral movement targets are selected based on their access to sensitive data or network privileges. Identifying these targets reveals attacker objectives.

- **Observation:** The attacker attempted to access 10.1.0.188.
- **Logical Flow:** With credentials in hand, the actor expands into the internal network.
- **Interpretation:** 10.1.0.188 was likely a higher-privilege system or file server of interest.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine matches regex @"\b\d{1,3}(\.\d{1,3}){3}\b"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="720" height="121" alt="image" src="https://github.com/user-attachments/assets/d3bcf9b5-0676-4116-b493-5ebb5451e017" />

**Flag 19 Answer:** The IP address was targeted for lateral movement: `10.1.0.188`

---

## Flag 20 - Remote Access Tool

**Objective:**
Built-in remote access tools are preferred for lateral movement as they blend with legitimate administrative activity. This technique is harder to detect than custom tools.

- **Observation:** The attacker used mstsc.exe to initiate lateral RDP sessions.
- **Logical Flow:** With target identified, what tool did they use to pivot?
- **Interpretation:** The attack leveraged legitimate Remote Desktop Protocol for stealthy movement inside the network. Attackers commonly use mstsc.exe (Microsoft Terminal Services Client — the Windows Remote Desktop client). It appears near the end of the attack chain when connecting to the lateral movement target. This matches the behavior described in Flag 19 where an IP was used with /v: as argument.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine matches regex @"\b\d{1,3}(\.\d{1,3}){3}\b"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="401" height="86" alt="image" src="https://github.com/user-attachments/assets/351cafc5-7889-4397-8d31-a071ea594117" />

**Flag 20 Answer:** The remote access tool used for lateral movement: `mstsc.exe`

---

## MITRE ATT&CK Mapping 

| Tactic | Technique | ATT&CK ID | Evidence |
|---|---|---|---|
| Initial Access | Valid Accounts | T1078 | RDP success from external IP (**Flags 1, 2**) |
| Discovery | Network Service Scanning | T1046 | `arp -a` (**Flag 3**) |
| Defense Evasion | Impair Defenses | T1562 | Defender exclusions and hidden staging directory (**Flags 4, 5, 6**) |
| Execution | Command and Scripting Interpreter | T1059.001 | PowerShell script `wupdate.ps1` (**Flag 18**) |
| Persistence | Scheduled Task | T1053.005 | **Windows Update Check** scheduled task (**Flags 8, 9**) |
| Credential Access | OS Credential Dumping | T1003.001 | `mm.exe` + `sekurlsa::logonpasswords` (**Flags 12, 13**) |
| Collection | Data Staged | T1074 | `export-data.zip` (**Flag 14**) |
| Exfiltration | Exfiltration Over Web Service | T1567.002 | Upload to `discord.com` (**Flag 15**) |
| Impact | Account Manipulation | T1098 | `support` local administrator account (**Flag 17**) |
| Defense Evasion | Indicator Removal | T1070.001 | `wevtutil cl Security` (**Flag 16**) |
| Lateral Movement | Remote Services: RDP | T1021.001 | `mstsc.exe` to `10.1.0.188` (**Flags 19, 20**) |

---

## Recommendations

**1. Contain & eradicate**

- Isolate AZUKI-SL and collect full forensic images and EDR artifacts.
- Rotate credentials for affected accounts (kenji.sato, service accounts) and require MFA for remote access.
- Remove attacker-created scheduled tasks and backdoor local accounts.

**2. Hardening & prevention**

- Restrict RDP exposure and require VPN + MFA for remote admin access.
- Block or restrict LOLBins (certutil, bitsadmin) or monitor their network use.
- Enforce application control to prevent execution from C:\ProgramData\WindowsCache and user temp folders.

**3. Detection & monitoring**

- Create alerts on: certutil network downloads, scheduled task creations with suspicious names, archive creation in staging folders, use of sekurlsa/Mimikatz indicators, and outbound connections to unusual cloud services (Discord, etc.).
- Log and monitor registry changes to Defender exclusions.
- Retain full command line telemetry and enhance LSASS access detection.

**4. Post-incident**

- Notify affected suppliers and engage legal/PR if exfiltration of contracts was confirmed.
- Conduct a comprehensive review for lateral movement from 10.1.0.188 and other internal hosts.
- Run a thorough credential audit and force a password rotation across the estate.
