# elevate-labs-project
#TASK-1

🔐 Cyber Security Project Report Title: Port Scanning and Service Enumeration using Nmap

Internship: Elevate Labs - Cyber Security Internship

Date: 24th June 2025

Tool Used: Nmap v7.95 on Kali Linux

Target:  10.217.5.157(Local IP)

🧭 Objective To discover open ports, detect running services, and assess potential vulnerabilities on a local network host using different Nmap scanning techniques.

🛠️ Tools & Commands Used Command Purpose  nmap -sV  10.217.5.157 Version detection scan 
                                          nmap -sS  10.217.5.157 SYN stealth scan (quick and less detectable) 
                                          nmap -p- 10.217.5.157 Full port scan (1-65535 TCP ports)

📊 Results Summary

Service Version Detection (nmap -sV) Open Ports Detected: 135/tcp – Microsoft Windows RPC

139/tcp – NetBIOS Session Service

445/tcp – Microsoft-DS (SMB file sharing)

8000/tcp – Splunkd HTTP service

8009/tcp – Splunkd (remote login disabled)

OS Detected: Microsoft Windows

CPE Identifier: cpe:/o:microsoft:windows

SYN Stealth Scan (nmap -sS) Confirmed the same open ports: 135, 139, 445, 8000, 8009

Full Port Scan (nmap -p-) Total Open Ports Found: 135, 139, 445, 8000, 8009, 49665, 49666, 49667, 49673, 49674, 62391

Observation: Additional high-numbered ephemeral ports are open. These are usually used for dynamic client-server communication and can indicate active services or malware using open ports.

🔍 Security Risk Analysis Port Service Potential Risk 135, 139, 445 RPC/NetBIOS/SMB High — Often targeted for Windows exploits (e.g., EternalBlue) 8000, 8009 Splunk HTTP Medium — Web-based services could be exposed without authentication 49665–49674, 62391 Unknown Medium — Dynamic ports, possibly used by internal services or malware

🛡️ Recommendations Disable unused services and ports to reduce the attack surface.

Implement firewalls to filter inbound traffic.

Patch vulnerabilities associated with RPC and SMB services (if exposed externally).

Run vulnerability scan tools like OpenVAS or Nessus on the open ports.

Use authentication and encryption for web-based services (Splunk).

Based on your Nmap scan results of the host 192.168.56.1, here’s a comprehensive evaluation of the security risks associated with the discovered open ports and services:

🔍 Identified Open Ports & Security Risk Evaluation Port Service Description Risk Level Security Risks 135/tcp msrpc (Microsoft RPC) Handles DCOM and remote management 🔴 High - Used in remote attacks (e.g., MS03-026)

Vulnerable to DCOM buffer overflows Often exploited in lateral movement 139/tcp netbios-ssn NetBIOS session for file/printer sharing 🔴 High - Used in SMB attacks

Can allow information disclosure or unauthenticated file access 445/tcp microsoft-ds (SMB over TCP) File sharing and Active Directory 🔴 High - Critical vulnerabilities (EternalBlue, WannaCry)

Enables pass-the-hash, SMB relay attacks 8000/tcp Splunkd httpd Web interface for Splunk (free license) 🟠 Medium - May expose internal data/logs if unauthenticated

May be vulnerable to web exploits (XSS, injection) 8009/tcp Splunkd (unknown) Possibly AJP or alternate Splunk port 🟠 Medium - Could expose unauthenticated or misconfigured services

If AJP (Apache JServ Protocol), may be vulnerable to Ghostcat 49665-49674/tcp 62391/tcp Unknown (Ephemeral ports) High ports used by Windows for dynamic service binding 🟡 Low-Medium - Could indicate active services

If bound by malware or backdoor, may permit remote access Often used for RPC, WMI, or malware C2 traffic 🧨 Summary of Potential Threats Remote Code Execution (RCE):

Ports 135, 139, and 445 are common vectors for RCE exploits.

Attackers can exploit these to gain remote shell or control.

Privilege Escalation & Lateral Movement:

Open SMB ports allow attackers to extract credentials or move laterally within a network.

Unsecured Web Services (Port 8000/8009):

If Splunk or HTTP services are not secured with auth or encryption, data leaks or command injection may occur.

Misconfigured Ephemeral Ports:

High-numbered ports could expose internal services not meant for public use.

Malware often hides in these dynamic ports.

Denial of Service (DoS):

Unpatched RPC/SMB services could be DoS’d by sending malformed packets.

🛡️ Recommended Mitigations Action Description 🔒 Disable SMB v1 Prevent exploits like EternalBlue by disabling SMBv1 🔥 Use Firewall Rules Block unused ports (especially 135–139, 445) from external access 🧪 Service Audits Audit Splunk/web interfaces for authentication & vulnerabilities 🧼 Patch Management Ensure Windows and Splunk are up-to-date with latest security patches 🔍 Malware Scan Scan host for malware that may be using high ephemeral ports 🚧 Network Segmentation Isolate vulnerable services in DMZ or behind VPNs/firewalls

Here is the attachment of this task 1:
