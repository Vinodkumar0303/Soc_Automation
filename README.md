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
A host machine capable of running multiple virtual machines simultaneously.
Sufficient CPU, RAM, and disk space to support the VMs and their expected workloads.

2.2 Software Requirements
Virtualization Platform (VMware / VirtualBox)

Used to create and manage virtual machines for the SOC environment.
Provides isolated systems for testing and automation.

Windows 10

Client machine where real activity and security events are generated.
Configured with Sysmon to collect detailed system logs.

Ubuntu 22.04

Server environment for hosting:

Wazuh Manager

n8n Automation Platform

Stable and widely supported for SOC deployments.

Sysmon

A Windows monitoring tool that logs process, file, and network events.
Used to generate high-quality security telemetry for analysis.

n8n

A workflow automation tool that processes Wazuh alerts, enriches them with external services, and triggers automated responses.

VirusTotal API

Provides threat reputation data for files, hashes, URLs, or domains.
Helps classify alerts and prioritize incidents.

Telegram Bot

Delivers real-time notifications to SOC analysts with enriched alert details.
Allows faster decision-making and response.

