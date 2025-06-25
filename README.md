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

---

