# Incident-Response-Project

This project demonstrates a full-lifecycle incident response to a cryptojacking attack on a Windows Server 2019 environment. Triggered by high CPU utilization and disrupted services, the investigation used Wazuh SIEM to identify the XMRig miner malware, which had been introduced via a phishing-originated social engineering campaign. Remediation involved terminating the malicious process, restoring Windows Defender via Group Policy, and hardening the network by configuring pfSense firewall rules to block unauthorized outbound traffic on port 3333. The exercise concluded with a formal technical report that categorized the incident's functional impact and established preventative strategies to improve the organization's overall security posture.

# Technologies
# Monitoring and Detection
1. Wazuh SIEM: Used to analyze logs, detect high CPU utilization alerts, and identify unauthorized remote network connections. Used to examine network traffic and identify malicious communication over specific ports (specifically port 3333). 
