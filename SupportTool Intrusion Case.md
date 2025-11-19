
# Threat Hunt Report — SupportTool Intrusion Analysis

<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/53f57d00-9a83-4c9f-ab56-8a37e11548e6" />


## Executive Summary

This investigation uncovered a well-orchestrated intrusion disguised as **remote support** activity. What initially appeared to be a support session was, in fact, an attacker gaining a foothold, probing system defenses, staging data, and establishing persistence — all under the guise of legitimate **“helpdesk”** tools. The actor planted cover artifacts, validated outbound connectivity, and set up recurring execution to maintain access.

**Target VM:** `gab-intern-vm`  
**Time Window:** 2025-10-01 → 2025-10-15  
**Data Sources:**  
- `DeviceProcessEvents`  
- `DeviceFileEvents`  
- `DeviceNetworkEvents`  
- `DeviceRegistryEvents`  

---
## Logical Flow & Analyst Reasoning

Here is the logical chain we followed, which informed how each flag was detected:

| Flag | Timestamp (UTC) | Description | Observed Artifact / Activity |
|---|---|---|---|
| **1** | 2025-10-09T12:22:27Z | Initial Execution Detection | PowerShell with `-ExecutionPolicy` CLI parameter |
| **2** | 2025-10-09T12:34:59Z | Defense Disabling | `DefenderTamperArtifact.lnk` |
| **3** | 2025-10-09T12:50:39Z |  Quick Data Probe | PowerShell `Get-Clipboard` command |
| **4** | 2025-10-09T12:51:44Z | Host Context Recon | `whoami /groups`, `qwinsta /query` session |
| **5** | 2025-10-09T12:51:18Z | Storage Surface Mapping | `wmic logicaldisk get …` |
| **6** | 2025-10-09T12:51:32Z | Connectivity & Name Resolution Check | DNS probe via `RuntimeBroker.exe` |
| **7** | 2025-10-09T12:51:44Z | Interactive Session Discovery | `qwinsta.exe` or `query session` |
| **8** | 2025-10-09T12:51:57Z | Runtime Application Inventory | `tasklist.exe` |
| **9** | 2025-10-09T12:52:14Z | Privilege Surface Check | Privilege enumeration (`whoami /priv`) |
| **10** | 2025-10-09T12:55:05Z | Proof-of-Access & Egress Validation | Outbound Network Connection to `www.msftconnecttest.com` |
| **11** | 2025-10-09T12:58:17Z |  Bundling / Staging Artifacts | Creation of `ReconArtifacts.zip` |
| **12** | 2025-10-09T13:00:40Z |  Outbound Transfer Attempt (Simulated) | Outbound connections to `100.29.147.161` |
| **13** | 2025-10-09T13:01:28Z | Scheduled Re-Execution Persistence | Task name: `SupportToolUpdater` |
| **14** | ~same time |  Autorun Fallback Persistence | Fallback named `RemoteAssistUpdater` |
| **15** | 2025-10-09T13:02:41Z | Planted Narrative / Cover Artifact | `SupportChat_log.lnk` |

---

## Flag 0 - Starting Point

In early October, several machines in the department began spawning unexpected processes from their **Downloads** folders — a suspicious pattern. These machines shared similarly named files (executables), particularly ones containing keywords like **“desk,”** **“help,”** **“support,”** and **“tool.”** Notably, intern-operated systems exhibited this behavior more than others. Given these factors, the most suspicious machine to focus on for the threat hunt is `gab-intern-vm`, as it aligns with the observed indicators of compromise.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where FolderPath has @"\Downloads\" or ProcessCommandLine has @"\Downloads\"
| where FileName matches regex @"(?i)(support|help|desk|tool)"
    or ProcessCommandLine matches regex @"(?i)(support|help|desk|tool)"
    or FolderPath matches regex @"(?i)(support|help|desk|tool)"
| project
    TimeGenerated,
    DeviceName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by TimeGenerated asc
```
**Flag 0 Answer:** 
<img width="1410" height="290" alt="image" src="https://github.com/user-attachments/assets/e61becca-1950-4170-acc7-657395b21861" />
Most suspicious machine based on the given conditions: `gab-intern-vm`

---

## Flag 1 - Initial Execution Detection

**Objective:**
Detect the earliest anomalous execution that could represent an entry point.

- **Observation:** A PowerShell command was run: `-ExecutionPolicy Bypass` to execute `SupportTool.ps1` from the Downloads folder.  
- **Interpretation:** The attacker likely used a script dropped in a “safe” folder and executed it with elevated trust, masquerading the activity as support-tool launch.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where FolderPath contains @"\Downloads\" or ProcessCommandLine contains @"\Downloads\"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by TimeGenerated asc
| take 20
```
**Flag 1 Answer:**
<img width="1463" height="304" alt="image" src="https://github.com/user-attachments/assets/a5c18338-cce8-4aa5-bd4b-1dc19f8268b1" />
The first CLI parameter name used during the execution of the suspicious program: `-ExecutionPolicy`

---

## Flag 2 - Defense Disabling

**Objective:**
Identify indicators that suggest attempts to imply or simulate changing security posture.

- **Observation:** Shortcut named `DefenderTamperArtifact.lnk` was created, possibly linking to a benign or misleading executable.  
- **Interpretation:** This looks like a cover artifact designed to explain away tampering or to pretend that security tooling was altered — a technique of misdirection.

**KQL Query Used:**

```kql
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:20:00Z) .. datetime(2025-10-09T13:00:00Z))
| where InitiatingProcessFileName in ("powershell.exe", "explorer.exe", "notepad.exe")
      and FileName contains "tamper"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
**Flag 2 Answer:**
<img width="1018" height="243" alt="image" src="https://github.com/user-attachments/assets/506968d0-2420-4061-a137-72f87e72cf69" />
The name of the file related to this exploit: `DefenderTamperArtifact.lnk`

---

## Flag 3 - Quick Data Probe

**Objective:**
Spot brief, opportunistic checks for readily available sensitive content.

- **Observation:** PowerShell used to run `Get-Clipboard | Out-Null`.  
- **Interpretation:** A clipboard check is low noise and can quickly expose credentials or other sensitive data, which is consistent with early-stage recon.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where Timestamp between (datetime(2025-10-01) .. datetime(2025-11-08))
| where ProcessCommandLine has_any ("clip", "Get-Clipboard", "Clipboard", "Paste", "-Clip", "clip.exe", "clip <")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```
**Flag 3 Answer:**

<img width="1318" height="229" alt="image" src="https://github.com/user-attachments/assets/ea05acf7-9e84-4c3d-b84f-0ec9a8922b8a" />
The command value tied to this particular exploit: "powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"

---

## Flag 4 - Host Context Recon

**Objective:**
Find activity that gathers basic host and user context to inform follow-up actions.
- **Observation:** Commands executed: `whoami /groups`, `qwinsta /query session`, etc.  
- **Interpretation:** The actor was mapping out user identity, sessions, and privileges to inform their next steps (persistence or escalation).

**KQL Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where Timestamp between (datetime(2025-09-01) .. datetime(2025-11-15))
| where FileName in ("whoami.exe","qwinsta.exe","quser.exe")
| where ProcessCommandLine has_any (
    "whoami", 
    "qwinsta",    // session enumeration
    "query session",  // may show via cmd usage
    "quser"
)
| project Timestamp, InitiatingProcessAccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

**Flag 4 Answer:**

<img width="782" height="377" alt="image" src="https://github.com/user-attachments/assets/8bddbeac-ceaa-44d2-b0bd-e67bf7b2a70c" />

The last recon attempt was: `2025-10-09T12:51:44.3425653Z`

---

## Flag 5 - Storage Surface Mapping

**Objective:**
Detect discovery of local or network storage locations that might hold interesting data.

- **Observation:** Execution of `wmic logicaldisk get name,freespace,size`.  
- **Interpretation:** By mapping local disks, the actor could identify optimal places to store tools, logs, or data for later retrieval.

**KQL Query Used:**

```kql

DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where Timestamp between (datetime(2025-09-01) .. datetime(2025-11-15))
| where FileName in ("powershell.exe", "cmd.exe", "wmic.exe")
| where ProcessCommandLine has_any (
    "logicaldisk",
    "Win32_LogicalDisk",
    "Get-PSDrive"
)
| project Timestamp, InitiatingProcessAccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```
**Flag 5 Answer:**

<img width="944" height="212" alt="image" src="https://github.com/user-attachments/assets/dc6f692c-0871-43ef-b644-27048fc60175" />

The 2nd command tied to this activity: "cmd.exe" /c wmic logicaldisk get name,freespace,size

---

## Flag 6 - Connectivity & Name Resolution Check

**Objective:**
Identify checks that validate network reachability and name resolution.

- **Observation:** DNS or connectivity probing (e.g., via `nslookup` or network checks).  
- **Interpretation:** Confirming connectivity ensures the attacker can later exfiltrate or communicate with a remote server.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where Timestamp between (datetime(2025-10-09) .. datetime(2025-10-31))
| where ProcessCommandLine has_any("nslookup", "ping", "tracert", "Resolve-DnsName")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by Timestamp asc

```

**Flag 6 Answer:**

<img width="1382" height="323" alt="image" src="https://github.com/user-attachments/assets/d718131e-011b-44a1-9dcc-009cb8fa99f8" />

The File Name of the initiating parent process: `RuntimeBroker.exe`

---

## Flag 7 - Interactive Session Discovery

**Objective:**
Reveal attempts to detect interactive or active user sessions on the host.

- **Observation:** Use of `qwinsta.exe` or `query session` to enumerate logged-in sessions.  
- **Interpretation:** Enumerating sessions helps the attacker decide when and how to act — for example, targeting a user’s active session or waiting for a privileged user.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where Timestamp between (datetime(2025-10-09) .. datetime(2025-10-15))
| where ProcessCommandLine has_any (
    "quser",
    "qwinsta",
    "query session",
    "tscon"
)
| project 
    Timestamp,
    FileName,
    ProcessCommandLine,
    InitiatingProcessId,
    InitiatingProcessUniqueId,
    InitiatingProcessFileName,
    InitiatingProcessParentId,
    InitiatingProcessParentFileName
| order by Timestamp desc

```

**Flag 7 Answer:**

<img width="1402" height="242" alt="image" src="https://github.com/user-attachments/assets/64162936-4b2a-408d-ada6-3d7bd2393748" />


The unique ID of the initiating process: `2533274790397065`

---

## Flag 8 - Runtime Application Inventory

**Objective:**
Detect enumeration of running applications and services to inform risk and opportunity.

- **Observation:** Execution of `tasklist.exe` to list running processes.  
- **Interpretation:** By listing processes, the attacker can discover running security tools, potential targets for lateral movement, or where to hide.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where Timestamp between (datetime(2025-10-09) .. datetime(2025-10-31))
| where FileName in ("sc.exe", "powershell.exe", "tasklist.exe", "wmic.exe")
| where ProcessCommandLine has_any (
    "sc query",
    "Get-Service",
    "tasklist",
    "wmic service"
)
| project Timestamp, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc

```

**Flag 8 Answer:**

<img width="984" height="234" alt="image" src="https://github.com/user-attachments/assets/ad4db46b-a270-4b72-a074-12f3c00e30cb" />

The file name of the process that best demonstrates a runtime process enumeration event on the target host: `tasklist.exe`

---

## Flag 9 - Privilege Surface Check

**Objective:**
Detect attempts to understand privileges available to the current actor.

- **Observation:** Queries like `whoami /priv` to check privileges and token rights.  
- **Interpretation:** Understanding privileges helps the attacker assess whether they need to escalate or if they already have enough rights.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where Timestamp between (datetime(2025-10-09) .. datetime(2025-10-31))
| where FileName in ("whoami.exe", "cmd.exe")
| where ProcessCommandLine has_any (
    "whoami /priv",
    "whoami /groups",
    "net localgroup",
    "net group",
    "net user"
)
| project Timestamp, InitiatingProcessAccountName, FileName, ProcessCommandLine
| order by Timestamp asc
| take 1

```

**Flag 9 Answer:**

<img width="808" height="208" alt="image" src="https://github.com/user-attachments/assets/305ddc9d-8465-4e1f-a0c6-1e925e2b57a7" />

The timestamp of the very first attempt: `2025-10-09T12:52:14.3135459Z`

---

## Flag 10 - Proof-of-Access & Egress Validation

**Objective:**
Find actions that both validate outbound reachability and attempt to capture host state for exfiltration value.

- **Observation:** Outbound network connection to `www.msftconnecttest.com` (or similar) to validate outbound reachability.  
- **Interpretation:** This connection could be a connectivity check. While not inherently malicious, in the context of other actions, it fits the pattern of validating egress capability.

**KQL Query Used:**

```kql

DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between(datetime(2025-10-09T12:52:00Z)..datetime(2025-10-09T13:00:00Z))
| where ActionType in ("ConnectionRequest", "ConnectionSuccess", "ConnectionAttempt", "ConnectionFound")
| project Timestamp, RemoteIP, RemoteUrl, InitiatingProcessFileName, ActionType
| order by Timestamp asc
```

**Flag 10 Answer:**

<img width="953" height="220" alt="image" src="https://github.com/user-attachments/assets/c0c2a134-4fe1-407d-871b-ebecb999a42c" />

The outbound destination was contacted first: `www.msftconnecttest.com`

---

## Flag 11 -  Bundling / Staging Artifacts

**Objective:**
Detect consolidation of artifacts into a single location or package for transfer.

- **Observation:** Creation or modification of a ZIP file (e.g., `ReconArtifacts.zip`) in a public or shared directory.  
- **Interpretation:** Staging suggests the attacker was preparing collected data or tools for later transfer or retrieval.

**KQL Query Used:**

```kql
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:58:00Z) .. datetime(2025-10-09T13:10:00Z))
| where ActionType == "FileCreated" or FileName contains ".zip"
| project TimeGenerated, FileName, FolderPath, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc

```

**Flag 11 Answer:**

<img width="1443" height="351" alt="image" src="https://github.com/user-attachments/assets/18d1980b-f88a-498d-a6bf-b4c6904b2b1a" />

The full folder path value where the artifact was first dropped into: `C:\Users\Public\ReconArtifacts.zip`

---

## Flag 12 -  Outbound Transfer Attempt (Simulated)

**Objective:**
 Identify attempts to move data off-host or test upload capability.
 - **Observation:** Network events indicating outbound connections that could correspond to upload attempts.  
 - **Interpretation:** Even if the upload wasn’t fully completed (or failed), the attempt is important—it shows intent to exfiltrate.

**KQL Query Used:**
```kql
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T13:00:00Z) .. datetime(2025-10-09T13:10:00Z))
| where isnotempty(RemoteIP) and RemoteIP contains "."
| where tolower(coalesce(RemoteUrl, "")) !contains "microsoft"
      and tolower(coalesce(RemoteUrl, "")) !contains "windows"
| project TimeGenerated, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
**Flag 12 Answer:**

<img width="1213" height="373" alt="image" src="https://github.com/user-attachments/assets/e96bd6a1-7db2-4a3c-a399-403d4532639b" />

The IP of the last unusual outbound connection: `100.29.147.161`

---

## Flag 13 -  Scheduled Re-Execution Persistence

**Objective:**
Detect creation of mechanisms that ensure the actor’s tooling runs again on reuse or sign-in.

- **Observation:** A scheduled task named `SupportToolUpdater` was created via `schtasks.exe /Create /TN SupportToolUpdater …`.  
- **Interpretation:** This task ensures the attacker’s tool will run again on login or on a schedule, maintaining their foothold.

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where Timestamp between (datetime(2025-10-09) .. datetime(2025-10-31))
| where FileName == "schtasks.exe" or FileName == "powershell.exe"
| where ProcessCommandLine has_any("/create","/change","/tn")
| project Timestamp, InitiatingProcessAccountName, ProcessCommandLine, FileName
| order by Timestamp asc
```
**Flag 13 Answer:**

<img width="1094" height="243" alt="image" src="https://github.com/user-attachments/assets/798eb71a-c626-4b29-8085-c9f4f55edc9e" />

The value of the task name down below: `SupportToolUpdater`

---

## Flag 14 -  Autorun Fallback Persistence

**Objective:**
Spot lightweight autorun entries placed as backup persistence in user scope.

- **Observation:** **(No registry autorun found in hunting data)** 
- **Interpretation:** While there was no explicit Run/RunOnce key detected, the hint implies a fallback named `RemoteAssistUpdater`. This suggests a persistence layer may exist even if not currently visible in registry telemetry.

**KQL Query Used:**
```kql
DeviceRegistryEvents
| where DeviceName == "gab-intern-vm"
| where RegistryKey contains "Run"
| where RegistryValueName contains "Assist" or RegistryValueName contains "Support"
```
**Flag 14 Answer:**

<img width="578" height="167" alt="image" src="https://github.com/user-attachments/assets/50acf6c9-a6ba-4a20-93e8-ef225b3baa7b" />

The name of the registry value: `RemoteAssistUpdater`

---

## Flag 15 -  Planted Narrative / Cover Artifact

**Objective:**
Identify a narrative or explanatory artifact intended to justify the activity.

- **Observation:** A shortcut `SupportChat_log.lnk` was created in the user’s Recent folder (via `explorer.exe`).  
- **Interpretation:** The shortcut is likely a misdirection — giving the impression of “support chat logs” to legitimize the attacker’s actions, making the intrusion seem intentional and benign.

**KQL Query Used:**
```kql
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:50:00Z) .. datetime(2025-10-09T13:10:00Z))
| where ActionType in ("FileCreated", "FileModified")
| where FileName endswith ".txt" or FileName endswith ".lnk" or FileName endswith ".log"
| project TimeGenerated, FileName, FolderPath, ActionType, InitiatingProcessFileName
| order by TimeGenerated asc
```

**Flag 15 Answer:**

<img width="985" height="321" alt="image" src="https://github.com/user-attachments/assets/be8f66c1-f7fb-42df-9a77-c11a6f9d761e" />

The file name of the artifact left behind: `SupportChat_log.lnk`

---

## MITRE ATT&CK Mapping



| Tactic | Technique | ID | Description |
|--------|-----------|----|-------------|
| Execution | Command and Scripting Interpreter | T1059 | Detection of atypical script or interactive command activity (e.g., unusual PowerShell/CLI runs) that likely represent the first anomalous execution and entry point. |
| Initial Access / Resource Development | Ingress Tool Transfer | T1105 | Files downloaded to `\Downloads\` (or execution from Downloads) — indicates tools or payloads brought onto the host from external sources. |
| Defense Evasion | Impair Defenses | T1562 | Files with names like `*tamper*` or activity that modifies/targets security-related files/processes — consistent with attempts to disable, tamper with, or evade security controls. |
| Collection / Exfiltration Preparation | Data Staged | T1074 | Creation of archive files (e.g., `.zip`) or staging artifacts — suggests data aggregation/preparation for exfiltration or moving toolsets. |
| Command and Control | Application Layer Protocol | T1071 | Network connections to external hosts (non-Microsoft/non-Windows domains) during the time window — could represent C2 channels over standard application protocols. |
| Persistence | Boot or Logon Autostart Execution (via shortcuts) | T1547 (or shortcut modification) | Creation/modification of `.lnk` files (and other innocuous artifacts like `.txt` or `.log` used to hide persistence) — LNKs are commonly abused for autorun/persistence or execution redirection. |

## Summary

The hunt identified a sequence of suspicious activities on `gab-intern-vm`, including unusual process execution from the Downloads folder, creation of files containing “tamper,” generation of archive files (`.zip`), modification of text/lnk/log files, and outbound network connections to non-Microsoft domains. These events suggest possible initial execution, defense evasion, data staging, and external communication attempts — patterns commonly associated with early-stage compromise or tool deployment.

---

## Recommendations

- **Harden execution controls:** Restrict script and executable launches from user directories like Downloads using AppLocker or WDAC.
- **Improve visibility:** Enable enhanced PowerShell logging, maintain full command-line auditing, and ensure all file/network events are captured.
- **Deploy targeted detections:** Create alerts for archive creation, tamper-related filenames, suspicious LNK modifications, and unexpected outbound network connections from user processes.
- **Investigate and contain:** Review parent/child process trees, validate the integrity of created files, check for persistence mechanisms, and analyze any external domains contacted.
- **Educate users:** Reinforce safe downloading practices and avoid running files directly from the Downloads folder.


