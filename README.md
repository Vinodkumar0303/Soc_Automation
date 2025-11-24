# Soc_Automation
A SOC automation pipeline integrating Wazuh, n8n, VirusTotal API, Telegram Bot, and JavaScript for alert triage and threat response.

Acknowledgment: This project benefited greatly from the insights and tutorials provided by the YouTube channel  Rajneesh Gupta . Their comprehensive videos were invaluable in understanding and implementing the various components of the SOC Automation Lab.

1. Introduction
1.1 Overview

The SOC Automation Project aims to build an automated Security Operations Center (SOC) workflow that reduces manual analyst effort, speeds up triage, and enhances real-time incident response.
This system integrates powerful open-source tools and APIs including Wazuh, n8n, VirusTotal, Telegram Bot, and custom JavaScript scripts.

The project uses Sysmon on a Windows client to generate detailed endpoint telemetry. Wazuh collects and analyzes log events and generates alerts when suspicious or high-risk activities are detected.
These alerts are forwarded to n8n, which orchestrates automated workflows—performing threat intelligence lookups using the VirusTotal API, enriching alert data, and scoring the severity.

Based on the severity, the automation sends a structured Telegram notification to the SOC analyst, containing indicators of compromise (IoCs), hash reputation results, and recommended actions. This enables fast, informed response without manual investigation.

![image alt](https://github.com/Vinodkumar0303/Soc_Automation/blob/095bbcd465e5a0f6b5560ffdc5044dd0344c506d/image/Gemini_Generated_Image_ngxc3ungxc3ungxc.png)

1.2 Purpose and Goals

Automate Event Collection and Analysis: Ensure security events are collected and analyzed in real-time with minimal manual intervention, enabling proactive threat detection and response.
Streamline Alerting Process: Automate the process of generating and forwarding alerts to relevant systems and personnel, reducing response times and minimizing the risk of overlooking critical incidents.
Enhance Incident Response Capabilities: Automate responsive actions to security incidents, improving reaction time, consistency, and effectiveness in mitigating threats.
Improve SOC Efficiency: Reduce the workload on SOC analysts by automating routine tasks, allowing them to focus on high-priority issues and strategic initiatives.

2. Prerequisites

2.1 Hardware Requirements
A host machine with enough CPU, RAM, and storage to run multiple virtual machines.

2.2 Software Requirements

Virtualization Platform (VMware/VirtualBox): Used to create and manage virtual machines.

Windows 10: Client machine for generating events with Sysmon.

Ubuntu 22.04: Server OS hosting Wazuh and n8n services.

Sysmon: Logs detailed endpoint activity for security analysis.

n8n: Automates workflows from Wazuh alerts and integrations.

VirusTotal API: Provides threat reputation for hashes, URLs, or domains.

Telegram API Bot: Sends real-time enriched security alerts to analysts.

2.4 Prior Knowledge
Basic Understanding of Virtual Machines: Familiarity with setting up and managing VMs using VMware or similar virtualization platforms.

Basic Linux Command Line Skills: Ability to perform essential tasks in a Linux environment, such as installing software packages and configuring services.

Knowledge of Security Operations and Tools: Foundational understanding of security monitoring, event logging, and incident response concepts and tools.

## 🔧 3. Setup Environment (Windows 10, Sysmon, Mimikatz)

### 3.1 Download Windows 10 ISO
1. Go to the official Microsoft Windows 10 download page.
2. Click **Download tool now**.
3. Run the Media Creation Tool.
4. Select **Create installation media (ISO)**.
5. Choose:
   - Edition: Windows 10
   - Architecture: 64-bit
6. Save the ISO file and use it to install Windows in a VM.

---

### 3.2 Install Sysmon on Windows 10

#### 📥 Step 1 — Download Sysmon
- Search **Microsoft Sysinternals Sysmon**.
- Download the ZIP file (Sysmon.zip).

#### 📥 Step 2 — Download Recommended Sysmon Config
- Search: **Sysmon config SwiftOnSecurity**
- Download the `sysmonconfig.xml` file (community maintained).

#### 🚀 Step 3 — Install Sysmon
Open **PowerShell as Administrator** in the folder where Sysmon is extracted:

```powershell
.\sysmon64.exe -i sysmonconfig.xml
✔ Step 4 — Verify Sysmon Status
Get-Service sysmon64
Status should be: Running

3.3 Installing Mimikatz (For Lab Use Only)

⚠️ Mimikatz is a penetration-testing tool.
Use it only on your own VM / lab.
Never on real or production systems.

📥 Step 1 — Download Official Repo

Search:
Mimikatz GitHub gentilkiwi

Open official repo

Go to Releases

Download mimikatz_trunk.zip

📦 Step 2 — Extract the ZIP

Extract to a folder inside your Windows 10 VM.

▶️ Step 3 — Run Mimikatz

Right-click: Run as Administrator  ```
vsjkdbvksdbvkjsd

