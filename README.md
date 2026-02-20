# Incident-Response-Project

This project demonstrates a full-lifecycle incident response to a cryptojacking attack on a Windows Server 2019 environment. Triggered by high CPU utilization and disrupted services, the investigation used Wazuh SIEM to identify the XMRig miner malware, which had been introduced via a phishing-originated social engineering campaign. Remediation involved terminating the malicious process, restoring Windows Defender via Group Policy, and hardening the network by configuring pfSense firewall rules to block unauthorized outbound traffic on port 3333. The exercise concluded with a formal technical report that categorized the incident's functional impact and established preventative strategies to improve the organization's overall security posture.

# Technologies
# Monitoring and Detection
Wazuh SIEM: Used to analyze logs, detect high CPU utilization alerts, and identify unauthorized remote network connections. Used to examine network traffic and identify malicious communication over specific ports (specifically port 3333).

#Ennpoint Security & Administration
Windows Server 2019: The operating system of the compromised application server (Hostname: WIN-6JNN6RLT6IL).
Windows Defender: The primary antivirus/threat protection service that was re-enabled and used to scan and remove malware.
Group Policy Editor (GPO): Used to remediate the system by reversing changes where the attacker had disabled security services.
Windows Task Manager: Used to identify the malicious process (XMRig miner) and monitor real-time CPU utilization.

#Network Defense
pfSense Firewall: Used to configure and verify DMZ firewall rules to block unauthorized outbound TCP/UDP traffic.

#Project Summary
This incident response project involved the detection and mitigation of a cryptojacking attack on a Windows Server 2019 system used for critical engineering operations. After multiple users reported severe performance issues with CAD applications, an investigation using the Wazuh SIEM revealed high CPU utilization caused by an unauthorized XMRig miner process. Analysis of network metadata further identified malicious outbound communication to an external IP via port 3333, confirming that the server had been compromised through a phishing-originated social engineering campaign.

To remediate the threat, the response focused on restoring system integrity and hardening network defenses. This included using Group Policy to re-enable Windows Defender services that the attacker had disabled, terminating the malicious mining process, and performing a full system scan to remove malware remnants. To prevent future exfiltration and communication with the attacker’s infrastructure, pfSense firewall rules were implemented to block all unauthorized TCP/UDP traffic on the affected ports. The project concluded with a formal incident report that categorized the functional impact and established a proactive security posture for the organization.
