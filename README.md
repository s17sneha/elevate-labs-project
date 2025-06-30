# 🔐 Cyber Security Internship Report – Elevate Labs

## 👩‍💻 Intern Name: Sneha Solanki  
**🧪 Internship Title:** Cyber Security Internship  
**📆 Date:** 24th June 2025  

---

## 📌 TASK 1: Port Scanning & Service Enumeration using Nmap

### 🎯 Target  
10.215.18.143 (Local IP)

### 🧭 Objective  
To discover open ports, detect running services, and assess potential vulnerabilities on a local network host using different Nmap scanning techniques.

---

### 🛠️ Tools & Environment  
- **Tool Used:** Nmap v7.95  
- **OS:** Kali Linux  

---

### ⚙️ Commands Used & Their Purpose  

 Command                          Purpose                                      |--------------------------------------------------------------------------------
 `nmap -sV 10.215.18.143         Version detection scan                       
 `nmap -sS 10.215.18.143`         SYN stealth scan (quick & less detectable)   
 `nmap -p- 10.215.18.143         Full TCP port scan (1–65535)                 

---

### 📊 Results Summary  

#### ➤ Service Version Detection (`-sV`)

| Port    | Service                         
|---------|----------------------------------
| 135/tcp | Microsoft Windows RPC            
| 139/tcp | NetBIOS Session Service         
| 445/tcp | Microsoft-DS (SMB File Sharing) 
| 8000/tcp| Splunkd HTTP                    
| 8009/tcp| Splunkd (Remote login disabled)  

- **OS Detected:** Microsoft Windows  
- **CPE Identifier:** `cpe:/o:microsoft:windows`

#### ➤ SYN Stealth Scan (`-sS`)  
Confirmed same open ports: `135, 139, 445, 8000, 8009`

#### ➤ Full Port Scan (`-p-`)  
Additional open ports: `49665–49667, 49673–49674, 62391`

> These high-numbered **ephemeral ports** are used for dynamic communication and may also be exploited by malware.

---

### 🔍 Security Risk Analysis  

| Port Range       | Service           | Risk Level | Notes                                                                
|-------------------|-------------------|-------------|-----------------------------------------------------------------------
| 135, 139, 445     | RPC/NetBIOS/SMB   | 🔴 High     | Vulnerable to exploits like **EternalBlue**, used in **RCE** attacks  
| 8000, 8009        | Splunk Web Ports  | 🟠 Medium   | Exposed internal services, possible **XSS / injection**               
| 49665–62391       | Ephemeral Ports   | 🟡 Medium   | Could be tied to **malware**, **C2 channels**, or RPC-related usage   

---

### 🛡️ Recommendations  

- 🔒 Disable unused ports/services (e.g., SMB v1)
- 🔥 Use firewalls to block unnecessary inbound traffic
- 🧪 Run **vulnerability scanners** like OpenVAS/Nessus
- ✅ Enable authentication/encryption for Splunk
- 🔄 Apply latest Windows & service-specific patches
- 🚧 Segment network services using **DMZ/firewall rules**

---

### 📸 Screenshots  
![image](https://github.com/user-attachments/assets/8dda4208-e160-4a3e-87a8-ef8ab003871b)
![image](https://github.com/user-attachments/assets/50861758-b8ee-4bb3-9380-66b5e98df324)



---

## 🚨 TASK 2: Phishing Email Analysis Report

### 📩 Email Analyzed  

| Field       | Value                          
|-------------|--------------------------------  
| **Subject** | Microsoft account password change 
| **Sender**  | support@msupdate.net           
| **Time**    | 4:09 PM                        
| **Recipient** | ethan@hooksecurity.co        

---

### 🔍 Phishing Indicators

| Indicator               | Description                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| Suspicious domain       | Domain `msupdate.net` is not Microsoft’s legitimate domain                  |
| Sense of urgency        | Message induces fear: “Your account has been compromised”                   |
| Clickable links         | May lead to phishing sites (malicious redirection possible)                 |
| Generic greeting        | No personalized name – common phishing tactic                               |
| Spoofed branding        | Uses Microsoft-like appearance to mislead users                             |

---

### 🔧 Tools Used  

- Manual inspection of email content  
- Header analysis (e.g., MXToolbox)  
- URL hover/preview checks (if applicable)

---

### 🧠 Key Learnings  

- How phishing emails **mimic brands** and induce urgency  
- Importance of **checking sender domain** and **email headers**  
- Awareness of **social engineering** in email attacks  
- Recognizing typical indicators like **fake domains**, **generic greetings**, etc.

---

### 📚 Interview Q&A  

**Q1: What is Phishing?**  
> A deceptive attack to steal personal information by impersonating trusted entities.

**Q2: What is Email Spoofing?**  
> Faking the sender's email to appear from a legitimate source.

**Q3: Why are Phishing Emails Dangerous?**  
> They can steal **credentials**, **infect with malware**, or **trick users into financial loss**.

**Q4: What to do if you receive one?**  
> Don’t click anything. Report it. Delete it. If clicked, change your passwords immediately.

---

### 🛠 Helpful Tools  

| Tool                         | Use Case                     |
|------------------------------|------------------------------|
| MXToolbox Header Analyzer    | Header & domain analysis     |
| Google Message Header Tool   | Source path inspection       |
| Microsoft Header Analyzer    | Outlook-specific analysis    |

---

### 🛡 Actions for Users on Phishing  

- 🚫 Don’t click suspicious links  
- 🚩 Report the message as phishing  
- 🗑️ Delete immediately  
- 🔐 Change credentials if compromised  
- 🛡 Educate users about **social engineering**

---

### 📸 Screenshot  
![image](https://github.com/user-attachments/assets/f7140a2a-7c11-4130-9555-cd60321febb3)



---

## 📎 Repository Info  

| Section        | Info                         |
|----------------|------------------------------|
| 👩‍🎓 Intern      | Sneha Solanki                |
| 🏢 Organization | Elevate Labs                 |
| 📂 Tasks        | Port Scanning, Email Analysis |
| 📅 Date         | 24th June 2025               |

---

## ⭐ Summary  
This project demonstrates hands-on experience in:

- 🔍 Network reconnaissance using **Nmap**
- 📧 Phishing detection and analysis
- 💡 Security risk evaluation and recommendations

> ✅ Practical understanding of cybersecurity threats and mitigation strategies.


Here’s a clean, formatted document combining **Task 3** and **Task 4** for your remote cybersecurity internship report. You can print it, submit it as a PDF, or upload it to your internship portal.

---

# 🛡️ Cybersecurity Internship Report

**Intern Name**: Sneha Solanki
**Mode**: Remote
**Tasks Covered**: Task 3 – Vulnerability Assessment using OpenVAS
Task 4 – Windows Firewall Configuration
**Tools Used**: OpenVAS, Windows Defender Firewall, PowerShell
**System Used**: Kali Linux & Windows 11
**Date**: \[Insert Date]

---

## ✅ **Task 3 – Vulnerability Assessment Using OpenVAS**

### 🎯 Objective:

To identify and analyze vulnerabilities in a local system using **OpenVAS (Greenbone Community Edition)**, classify them by severity using CVSS, and recommend basic remediations.

---

### 🔧 Tool Used: OpenVAS

**OpenVAS** (Open Vulnerability Assessment System) is an open-source vulnerability scanner used for system-wide scans. It leverages the Greenbone Security Feed to detect:

* Misconfigurations
* CVEs
* Outdated software
* Open ports and insecure services

---

### 🛠️ Steps Performed

#### 1. System Update

```bash
sudo apt update && sudo apt upgrade -y
```

#### 2. Install and Setup OpenVAS

```bash
sudo apt install openvas -y
sudo gvm-setup
sudo gvm-start
```

#### 3. Target Configuration

* **Host IP**: 127.0.0.1
* **Port Range**: Default (1–65535)
* **Scan Type**: Full and Fast

#### 4. Execution

* Accessed Dashboard: `https://127.0.0.1:9392`
* Created scan target and task for localhost
* Ran scan (\~45 minutes)
* Exported report as `scan_report.pdf`

> 📸 Screenshots
> ![image](https://github.com/user-attachments/assets/a927eb1b-fc46-4463-aedb-23844140964f)




---

### 📋 Interview Prep: OpenVAS

**1. What is Vulnerability Scanning?**
Automated detection of known security flaws in systems by comparing configurations with databases like CVE or NVT.

**2. Difference Between Vulnerability Scanning vs Penetration Testing**

| Scanning          | Penetration Testing |
| ----------------- | ------------------- |
| Automated         | Manual              |
| Finds known flaws | Exploits flaws      |
| Low risk          | Higher risk         |

**3. Common Vulnerabilities**

* Weak passwords
* Outdated OS
* SMBv1, Telnet, etc.

**4. CVSS Scoring Table**

| Score | Severity |
| ----- | -------- |
| 0–3.9 | Low      |
| 4–6.9 | Medium   |
| 7–8.9 | High     |
| 9–10  | Critical |

**5. Remediation Steps**

* Patch OS/services
* Close unused ports
* Use firewalls
* Disable vulnerable services

---

## ✅ **Task 4 – Windows Firewall Configuration on Windows 11**

### 🎯 Objective:

To configure basic Windows Defender Firewall rules to control network access via port filtering.

---

### 🧰 Tools Used:

* Windows 11
* Windows Defender Firewall
* Telnet (testing tool)
* PowerShell/CMD

---

### 🔨 Task Steps

#### 1. Open Firewall

```bash
Win + R → wf.msc
```

#### 2. Created Rules

✅ **Block Telnet Port 23** (Inbound Rule)
✅ **Allow SSH Port 22** (Inbound Rule)

#### 3. Enabled Telnet Client:

```bash
Settings → Optional Features → Add Telnet Client
```

#### 4. Tested in CMD:

```bash
telnet localhost 23

```
> 📸 Screenshots
> ![image](https://github.com/user-attachments/assets/112d1b02-daf3-428d-b997-95a8e80b9977)
> ![image](https://github.com/user-attachments/assets/04ea6d53-ca80-494c-b017-0feecd4a4cbb)
> ![image](https://github.com/user-attachments/assets/3382c05c-fee6-45c7-9753-3d6ce53e14e7)
> ![image](https://github.com/user-attachments/assets/fbebf3fb-a77a-4566-82c6-3f74afb57ca1)
> ![image](https://github.com/user-attachments/assets/2d5dbe7d-9af7-43c6-961d-60c0197f2e64)






---

### 📋 Interview Prep: Firewalls

**1. What is a Firewall?**
A security device/software that filters traffic based on rules.

**2. Stateful vs Stateless**

| Stateless  | Stateful           |
| ---------- | ------------------ |
| No context | Tracks connections |
| Faster     | More secure        |

**3. NAT in Firewalls**

* **SNAT**: Outbound IP mapping
* **DNAT**: Inbound mapping
* **PAT**: Port-based mapping

**4. Why Block Port 23 (Telnet)?**

* Unencrypted
* Vulnerable to sniffing
* Replaced by SSH (port 22)

**5. Common Firewall Mistakes**

* Allowing all traffic
* Ignoring outbound rules
* Misconfigured priorities

---

