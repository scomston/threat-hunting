# Threat Hunt Report — Virtual Machine Compromise

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
| **9** | 2025-10-09T12:52:14Z | Scheduled Task Target | Privilege enumeration (`whoami /priv`) |
| **10** | 2025-10-09T12:55:05Z | Proof-of-Access & Egress Validation | Outbound Network Connection to `www.msftconnecttest.com` |
| **11** | 2025-10-09T12:58:17Z |  Bundling / Staging Artifacts | Creation of `ReconArtifacts.zip` |
| **12** | 2025-10-09T13:00:40Z |  Outbound Transfer Attempt (Simulated) | Outbound connections to `100.29.147.161` |
| **13** | 2025-10-09T13:01:28Z | Scheduled Re-Execution Persistence | Task name: `SupportToolUpdater` |
| **14** | ~same time |  Autorun Fallback Persistence | Fallback named `RemoteAssistUpdater` |
| **15** | 2025-10-09T13:02:41Z | Planted Narrative / Cover Artifact | `SupportChat_log.lnk` |

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



