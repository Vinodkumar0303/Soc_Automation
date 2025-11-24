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

Right-click: Run as Administrator
Install Wazuh Agent (Windows 10)

Download from ⚙️ Dashboard → Agents → Deploy new agent

Or manual:

https://packages.wazuh.com/4.x/windows/wazuh-agent-4.x.msi


During setup:

Add Manager IP

Default port: 1514

Start service after install:

Restart-Service wazuh
```
🛡️ Wazuh Installation (Ubuntu 22.04)

This guide installs Wazuh Manager + Wazuh Indexer + Wazuh Dashboard using the official installation script.

```
📥 Step 1 — Update System
sudo apt update && sudo apt upgrade -y

🚀 Step 2 — Download Wazuh Installation Script
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh


⚠️ Replace 4.7 with current version if needed.

🔐 Step 3 — Make Script Executable
chmod +x wazuh-install.sh

▶️ Step 4 — Run Installer
sudo ./wazuh-install.sh -a

```

Installs:

Wazuh Manager

Wazuh Dashboard

Wazuh Indexer (OpenSearch)

⏳ Step 5 — Wait for Installation (5–15 mins)

Installer will:

Configure cluster automatically

Generate certificates

Start all services

🔑 Step 6 — Dashboard Credentials

After installation, run:

sudo cat /usr/share/wazuh-dashboard/data/users/admin.json


You will get:

Username: admin
Password: <random-generated-password>


Save the password.

🌐 Step 7 — Access the Wazuh Dashboard

Open in browser:

https://<your-server-ip>


Example:

https://192.168.1.100


Ignore browser warning → continue anyway.

📁 Wazuh ossec.conf File Path (Ubuntu)
```
/var/ossec/etc/ossec.conf

🔧 Open it with Nano editor
sudo nano /var/ossec/etc/ossec.conf
```
![imagw apt](https://github.com/Vinodkumar0303/Soc_Automation/blob/e4482fc9210cda0aaff9444ca30a5cef6261be93/image/WhatsApp%20Image%202025-11-23%20at%2021.36.36_1cf4bd77.jpg)
```

🔄 After making changes, restart Wazuh Manager
sudo systemctl restart wazuh-manager

🧪 Verify Services
Wazuh Manager
sudo systemctl restart wazuh-manager

Wazuh Indexer
sudo systemctl restart wazuh-indexer

Wazuh Dashboard
sudo systemctl restart wazuh-dashboard

And  check the status


All should show: Active (running).

```


🔥 What is n8n?

n8n is an open-source automation tool that lets you connect APIs, security tools, and workflows — similar to Zapier, but free and self-hosted.
We use n8n to automate SOC alerts, enrich incidents, and send notifications (e.g., Telegram).

```
🚀 1. Install Docker & Docker Compose (Ubuntu)
sudo apt update && sudo apt install -y ca-certificates curl gnupg lsb-release

Add Docker GPG Key
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
| sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

Add Docker Repository
echo \
"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu \
$(lsb_release -cs) stable" \
| sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

Install Docker
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

🐳 2. Create n8n Docker Setup

Create a folder:

mkdir ~/n8n && cd ~/n8n


Create a file:

nano docker-compose.yml


Paste:

version: '3'

services:
  n8n:
    image: n8nio/n8n:latest
    container_name: n8n
    restart: always
    environment:
      - N8N_BASIC_AUTH_ACTIVE=true
      - N8N_BASIC_AUTH_USER=admin
      - N8N_BASIC_AUTH_PASSWORD=admin123
      - N8N_PORT=5678
    ports:
      - "5678:5678"
    volumes:
      - ./data:/home/node/.n8n


📌 Change the username/password later.

▶️ 3. Start n8n
docker compose up -d

```

Check status:

docker ps

🌐 4. Access n8n

Open your browser:

http://YOUR_IP:5678


Example:

http://127.0.0.1:5678

🌉 5. Install ngrok
sudo snap install ngrok

🔐 6. Add Your Auth Token

Go to: https://dashboard.ngrok.com/get-started/setup

Copy your token → paste it:

ngrok config add-authtoken YOUR_TOKEN_HERE

🚀 7. Expose n8n to the Internet
ngrok http 5678


You will get:

Forwarding: https://xxxx.ngrok-free.app → http://localhost:5678


Use this HTTPS link for:

Telegram webhooks

VirusTotal callbacks

Wazuh → n8n triggers

Browser access outside your network

🔄 Restart Commands

Restart Docker container:

docker restart n8n


Stop:

docker compose down


Start again:

docker compose up -d

✔️ Notes

n8n runs on port 5678

Persistent data stored in ~/n8n/data

Use ngrok only for lab/testing — not production

![image apt](https://github.com/Vinodkumar0303/Soc_Automation/blob/4a16639480685b5e7245df4178a11a5d7698e1d0/image/WhatsApp%20Image%202025-11-23%20at%2021.36.38_7cc55102.jpg)

connection:

🔑 Login to n8n

After installing and running n8n:

👉 Open your browser:

http://YOUR_IP:5678


Example:

http://127.0.0.1:5678


Enter the credentials you set in docker-compose.yml:

Username: admin
Password: admin123


⚠️ Change the default password after first login.

🧠 Create Your First Workflow

Click New → Workflow

Click Add Node

Search for: Webhook

Select Webhook Trigger

Set:

HTTP Method: POST

Path: /alerts


![image apt](https://github.com/Vinodkumar0303/Soc_Automation/blob/77b8badd367533db87713deb044f2dde8fc4329e/image/Screenshot%202025-11-24%20162515.png)

When All Nodes Are Properly executed 
![image apt](https://github.com/Vinodkumar0303/Soc_Automation/blob/745e7995383135290869f7e9218df3ffc33e6c36/image/Screenshot%202025-11-24%20162952.png)

Final Alert

![image apt](https://github.com/Vinodkumar0303/Soc_Automation/blob/4a16639480685b5e7245df4178a11a5d7698e1d0/image/WhatsApp%20Image%202025-11-24%20at%2012.22.44_1cafc899.jpg)
