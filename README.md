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
3. 
2.1 Hardware Requirements
A host machine with enough CPU, RAM, and storage to run multiple virtual machines.

2.2 Software Requirements

Virtualization Platform (VMware/VirtualBox): Used to create and manage virtual machines.
Windows 10: Client machine for generating events with Sysmon.
Ubuntu 22.04: Server OS hosting Wazuh and n8n services.
Sysmon: Logs detailed endpoint activity for security analysis.
n8n: Automates workflows from Wazuh alerts and integrations.
VirusTotal API: Provides threat reputation for hashes, URLs, or domains.
Telegram Bot: Sends real-time enriched security alerts to analysts.

2.3 Tools and Platforms

Wazuh
Open-source security monitoring platform used to collect logs, detect threats, and generate alerts.
n8n
Automation platform used to build workflows that process alerts and integrate with external services.
VirusTotal API
Online threat intelligence service used to check file hashes, URLs, or domains for malicious activity.
Telegram Bot
Used for sending real-time alert notifications to analysts with enriched incident details.
Virtual Machines 
The environment can run on local VMs or cloud servers based on available resources.
