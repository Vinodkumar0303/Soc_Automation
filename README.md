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

https://github.com/Vinodkumar0303/Soc_Automation/blob/095bbcd465e5a0f6b5560ffdc5044dd0344c506d/image/Gemini_Generated_Image_ngxc3ungxc3ungxc.png


