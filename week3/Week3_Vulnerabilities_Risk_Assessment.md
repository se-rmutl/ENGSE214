# Week 3: Vulnerabilities & Basic Risk Assessment
## ENGSE214 – ความมั่นคงปลอดภัยทางไซเบอร์เบื้องต้น

**เวลาการสอน:** 2-3 ชั่วโมง (รวม Demo และ Mini Lab)  
**CLO ที่เกี่ยวข้อง:** CLO2, CLO4

---

## 📚 ทบทวนเนื้อหาสัปดาห์ที่ผ่านมา

### Week 1: Introduction to Cybersecurity & CIA Triad
- **CIA Triad**: Confidentiality (ความลับ), Integrity (ความถูกต้องครบถ้วน), Availability (ความพร้อมใช้งาน)
- **Asset-Threat-Vulnerability-Risk**: ทรัพย์สิน → ภัยคุกคาม → ช่องโหว่ → ความเสี่ยง

### Week 2: Cyber Threat Types & Malware
- **ประเภทของ Malware**: Virus, Worm, Trojan, Ransomware
- **Social Engineering**: Phishing, Spear Phishing
- **APT (Advanced Persistent Threats)**: การโจมตีแบบมีเป้าหมายและต่อเนื่อง

```
┌─────────────────────────────────────────────────────┐
│  สัปดาห์ที่แล้ว: เราเรียนรู้เกี่ยวกับ THREATS        │
│  สัปดาห์นี้: เราจะเจาะลึก VULNERABILITIES           │
│  และเรียนรู้วิธีการประเมิน RISK                     │
└─────────────────────────────────────────────────────┘
```

---

## 🎯 วัตถุประสงค์การเรียนรู้ (Learning Objectives)

เมื่อจบ Week 3 นักศึกษาจะสามารถ:
1. อธิบายความหมายและประเภทของช่องโหว่ (Vulnerability) ได้
2. ค้นหาและอ่านข้อมูลจากฐานข้อมูล CVE/NVD ได้
3. เข้าใจกระบวนการ Risk Assessment และ Risk Management
4. อ่านและตีความค่า CVSS Score พื้นฐานได้
5. ประเมินความเสี่ยงของระบบอย่างง่ายได้

---

## 📖 Part 1: Vulnerability คืออะไร?

### 1.1 ความหมายของ Vulnerability

**Vulnerability (ช่องโหว่)** คือจุดอ่อนหรือข้อบกพร่องในระบบ ซอฟต์แวร์ เครือข่าย หรือกระบวนการที่สามารถถูกใช้ประโยชน์ (Exploit) เพื่อทำให้เกิดความเสียหายหรือการละเมิดความปลอดภัยได้

```
┌──────────────────────────────────────────────────────────┐
│                   สูตรความเสี่ยง                          │
│                                                            │
│   RISK = Threat × Vulnerability × Impact                  │
│                                                            │
│   ความเสี่ยง = ภัยคุกคาม × ช่องโหว่ × ผลกระทบ            │
│                                                            │
│   ไม่มีช่องโหว่ → แม้มีภัยคุกคาม ก็ไม่เกิดความเสี่ยง!    │
└──────────────────────────────────────────────────────────┘
```

### 1.2 ความแตกต่างระหว่าง Vulnerability กับ Threat

| แง่มุม | Vulnerability (ช่องโหว่) | Threat (ภัยคุกคาม) |
|--------|-------------------------|-------------------|
| **นิยาม** | จุดอ่อนในระบบ | สิ่งที่อาจก่อความเสียหาย |
| **ตัวอย่าง** | รหัสผ่านเป็น "admin" | Hacker พยายามเข้าระบบ |
| **การควบคุม** | สามารถแก้ไขได้ | ไม่สามารถควบคุมได้โดยตรง |
| **ลักษณะ** | อยู่ภายในระบบ | มาจากภายนอก |

### 1.3 ประเภทของ Vulnerability

```
        ┌─────────────────────────────────────┐
        │     Types of Vulnerabilities        │
        └──────────────┬──────────────────────┘
                       │
         ┌─────────────┼─────────────┐
         │             │             │
    ┌────▼───┐   ┌────▼────┐   ┌───▼────┐
    │Software│   │Hardware │   │ Human  │
    │Vulns   │   │ Vulns   │   │ Vulns  │
    └────┬───┘   └────┬────┘   └───┬────┘
         │            │            │
    ┌────▼─────┐ ┌───▼──────┐ ┌──▼──────┐
    │• Buffer  │ │• Faulty  │ │• Weak   │
    │  Overflow│ │  Firmware│ │  Passwords│
    │• SQL     │ │• Physical│ │• Social │
    │  Injection│ │  Access  │ │  Engineer│
    │• XSS     │ │• Side    │ │• Lack of│
    │• CSRF    │ │  Channel │ │  Training│
    └──────────┘ └──────────┘ └─────────┘
```

#### 1.3.1 Software Vulnerabilities (ช่องโหว่ในซอฟต์แวร์)
- **Buffer Overflow**: การเขียนข้อมูลเกินขนาดหน่วยความจำที่กำหนด
- **SQL Injection**: การแทรกคำสั่ง SQL ผ่าน input
- **Cross-Site Scripting (XSS)**: การแทรก JavaScript ที่เป็นอันตราย
- **Authentication Bypass**: การข้ามขั้นตอนการยืนยันตัวตน
- **Insecure Deserialization**: ช่องโหว่จากการแปลง object ที่ไม่ปลอดภัย

#### 1.3.2 Configuration Vulnerabilities (ช่องโหว่จากการตั้งค่า)
- **Default Credentials**: ใช้ username/password ที่มาพร้อมระบบ
- **Unnecessary Services**: เปิดบริการที่ไม่จำเป็น
- **Weak Encryption**: ใช้การเข้ารหัสที่อ่อนแอ
- **Missing Security Patches**: ไม่อัปเดตระบบ

#### 1.3.3 Human-Related Vulnerabilities (ช่องโหว่จากมนุษย์)
- **Weak Passwords**: รหัสผ่านที่เดาง่าย เช่น "123456", "password"
- **Lack of Security Awareness**: ขาดความรู้ด้านความปลอดภัย
- **Insider Threats**: ภัยคุกคามจากคนภายใน
- **Social Engineering Susceptibility**: ตกเป็นเหยื่อของ Social Engineering ง่าย

---

## 🔍 Part 2: CVE (Common Vulnerabilities and Exposures)

### 2.1 CVE คืออะไร?

**CVE** เป็นฐานข้อมูลมาตรฐานสากลที่รวบรวมช่องโหว่ด้านความปลอดภัยที่ถูกค้นพบและเปิดเผยต่อสาธารณะ โดยมีการกำหนด CVE ID ที่เป็นเอกลักษณ์เฉพาะสำหรับแต่ละช่องโหว่

```
┌────────────────────────────────────────────────────────┐
│              CVE Naming Convention                     │
│                                                        │
│           CVE-[YEAR]-[NUMBER]                          │
│                                                        │
│  ตัวอย่าง: CVE-2024-1234                              │
│           │    │    │                                  │
│           │    │    └─ เลขลำดับที่ (4-7 หลัก)         │
│           │    └────── ปี ค.ศ. ที่ประกาศ             │
│           └─────────── คำนำหน้า CVE                   │
└────────────────────────────────────────────────────────┘
```

### 2.2 ตัวอย่าง CVE ที่มีชื่อเสียง

#### CVE-2014-0160: Heartbleed
- **ช่องโหว่**: Buffer over-read ใน OpenSSL
- **ผลกระทบ**: สามารถอ่านหน่วยความจำของเซิร์ฟเวอร์ได้ รวมถึง private keys และรหัสผ่าน
- **ระบบที่ได้รับผลกระทบ**: เว็บไซต์นับล้านแห่งทั่วโลก

#### CVE-2017-0144: EternalBlue (WannaCry)
- **ช่องโหว่**: SMB protocol ใน Windows
- **ผลกระทบ**: ใช้แพร่กระจาย ransomware WannaCry
- **ความเสียหาย**: มากกว่า 200,000 คอมพิวเตอร์ใน 150 ประเทศ

#### CVE-2021-44228: Log4Shell
- **ช่องโหว่**: Remote Code Execution ใน Apache Log4j
- **ระดับความรุนแรง**: 10.0 (Critical)
- **ผลกระทบ**: ส่งผลกระทบต่อระบบนับล้านทั่วโลก รวมถึง Apple iCloud, Steam, Twitter

#### CVE-2024-3094: XZ Utils Backdoor
- **ช่องโหว่**: Backdoor ในไลบรารีการบีบอัด XZ Utils
- **ผลกระทบ**: อาจถูกใช้โจมตี SSH servers ได้
- **บทเรียน**: แสดงให้เห็นความสำคัญของ Supply Chain Security

### 2.3 แหล่งข้อมูล CVE

```
     ┌───────────────────────────────────────────┐
     │     CVE Information Sources               │
     └──────────────┬────────────────────────────┘
                    │
     ┌──────────────┼──────────────┐
     │              │              │
┌────▼─────┐  ┌────▼─────┐  ┌────▼─────┐
│   NVD    │  │   CVE    │  │  Vendor  │
│ (NIST)   │  │  MITRE   │  │  Sites   │
└──────────┘  └──────────┘  └──────────┘
     │              │              │
     └──────────────┼──────────────┘
                    │
     ┌──────────────▼────────────────┐
     │  Security Researchers/Teams   │
     └───────────────────────────────┘
```

**แหล่งข้อมูลหลัก:**
1. **NVD (National Vulnerability Database)**: https://nvd.nist.gov/
   - ดูแลโดย NIST (National Institute of Standards and Technology)
   - มีข้อมูลละเอียด รวมถึง CVSS Score

2. **CVE MITRE**: https://cve.mitre.org/
   - องค์กรที่กำหนดมาตรฐาน CVE ID
   - ข้อมูลพื้นฐานของแต่ละ CVE

3. **Vendor Security Advisories**: 
   - Microsoft Security Response Center
   - Apple Security Updates
   - Google Security Bulletins

---

## 💡 Part 3: Risk Assessment & Risk Management

### 3.1 Risk Assessment คืออะไร?

**Risk Assessment** คือกระบวนการระบุ วิเคราะห์ และประเมินความเสี่ยงที่อาจเกิดขึ้นกับระบบหรือองค์กร

```
┌────────────────────────────────────────────────────────┐
│          Risk Assessment Process                       │
│                                                        │
│    1. IDENTIFY    →   2. ANALYZE   →   3. EVALUATE    │
│    (ระบุความเสี่ยง)   (วิเคราะห์)      (ประเมิน)       │
│                                                        │
│         Assets            Impact         Priority      │
│         Threats           Likelihood     Risk Level    │
│         Vulnerabilities                                │
└────────────────────────────────────────────────────────┘
```

### 3.2 Risk Management Lifecycle

```
        ┌──────────────────────────────────────┐
        │    Risk Management Cycle             │
        │                                      │
        │         ┌──────────┐                 │
        │    ┌───▶│ IDENTIFY │──┐              │
        │    │    └──────────┘  │              │
        │    │                  ▼              │
        │    │    ┌──────────┐  │              │
        │    │    │ MONITOR  │  │              │
        │    │    │ & REVIEW │  │              │
        │    │    └──────────┘  │              │
        │    │         ▲        │              │
        │    │         │        ▼              │
        │    │    ┌────────┐ ┌─────────┐      │
        │    └────│ TREAT  │ │ ANALYZE │      │
        │         └────────┘ └─────────┘      │
        │              ▲          │            │
        │              │          ▼            │
        │         ┌────────────────┐           │
        │         │   EVALUATE     │           │
        │         └────────────────┘           │
        └──────────────────────────────────────┘
```

#### Phase 1: IDENTIFY (ระบุ)
- ระบุ Assets (ทรัพย์สิน)
- ระบุ Threats (ภัยคุกคาม)
- ระบุ Vulnerabilities (ช่องโหว่)

#### Phase 2: ANALYZE (วิเคราะห์)
- วิเคราะห์ Impact (ผลกระทบ)
- วิเคราะห์ Likelihood (โอกาสเกิด)
- วิเคราะห์ Existing Controls (มาตรการป้องกันที่มีอยู่)

#### Phase 3: EVALUATE (ประเมิน)
- จัดลำดับความสำคัญของความเสี่ยง
- กำหนด Risk Level (Low, Medium, High, Critical)
- ตัดสินใจว่าจะจัดการความเสี่ยงอย่างไร

#### Phase 4: TREAT (จัดการ)
มี 4 วิธีหลัก:
1. **Avoid**: หลีกเลี่ยง (ไม่ทำกิจกรรมที่เสี่ยง)
2. **Reduce/Mitigate**: ลดความเสี่ยง (ใช้มาตรการป้องกัน)
3. **Transfer**: โอนถ่ายความเสี่ยง (ซื้อประกัน, outsource)
4. **Accept**: ยอมรับความเสี่ยง (เมื่อต้นทุนการป้องกันสูงเกินไป)

#### Phase 5: MONITOR & REVIEW (ติดตามและทบทวน)
- ติดตามประสิทธิผลของมาตรการ
- ทบทวนความเสี่ยงเป็นระยะ
- ปรับปรุงมาตรการตามความจำเป็น

### 3.3 Risk Matrix

```
┌───────────────────────────────────────────────────────┐
│              Risk Assessment Matrix                   │
│                                                       │
│   Impact →    Low      Medium     High     Critical   │
│   Likelihood                                          │
│      ↓                                                │
│                                                       │
│   Very High │   M    │    H    │    H    │    C     │
│             │        │         │         │          │
│   High      │   L    │    M    │    H    │    H     │
│             │        │         │         │          │
│   Medium    │   L    │    L    │    M    │    H     │
│             │        │         │         │          │
│   Low       │   L    │    L    │    L    │    M     │
│                                                       │
│   L = Low Risk    M = Medium Risk                    │
│   H = High Risk   C = Critical Risk                  │
└───────────────────────────────────────────────────────┘
```

---

## 📊 Part 4: CVSS (Common Vulnerability Scoring System)

### 4.1 CVSS คืออะไร?

**CVSS** เป็นระบบมาตรฐานสากลสำหรับการให้คะแนนความรุนแรงของช่องโหว่ โดยใช้คะแนน 0-10

```
┌────────────────────────────────────────────────────┐
│            CVSS v3.1 Score Range                   │
│                                                    │
│   0.0        None         ไม่มีความเสี่ยง          │
│   0.1-3.9    Low          ความเสี่ยงต่ำ            │
│   4.0-6.9    Medium       ความเสี่ยงกลาง           │
│   7.0-8.9    High         ความเสี่ยงสูง            │
│   9.0-10.0   Critical     ความเสี่ยงวิกฤต          │
│                                                    │
│      ────────────────────────────────────────      │
│      0    1    2    3    4    5    6    7    8    9    10
│      └────┴────┴────┴────┴────┴────┴────┴────┴────┴────┘
│       None   Low      Medium      High    Critical │
└────────────────────────────────────────────────────┘
```

### 4.2 CVSS Metric Groups

CVSS v3.1 แบ่งเป็น 3 กลุ่มตัวชี้วัด:

#### 1. Base Metrics (ตัวชี้วัดพื้นฐาน)
ไม่เปลี่ยนแปลงตามเวลาหรือสภาพแวดล้อม

```
Base Metrics
├── Exploitability Metrics (ความง่ายในการโจมตี)
│   ├── Attack Vector (AV)
│   │   ├── Network (N) - โจมตีผ่านเครือข่าย
│   │   ├── Adjacent (A) - โจมตีจากเครือข่ายใกล้เคียง
│   │   ├── Local (L) - ต้องเข้าถึงเครื่องโดยตรง
│   │   └── Physical (P) - ต้องเข้าถึงทางกายภาพ
│   ├── Attack Complexity (AC)
│   │   ├── Low (L) - โจมตีง่าย
│   │   └── High (H) - โจมตียาก
│   ├── Privileges Required (PR)
│   │   ├── None (N) - ไม่ต้องมีสิทธิ์
│   │   ├── Low (L) - ต้องมีสิทธิ์พื้นฐาน
│   │   └── High (H) - ต้องมีสิทธิ์ระดับสูง
│   └── User Interaction (UI)
│       ├── None (N) - ไม่ต้องมีผู้ใช้กระทำการ
│       └── Required (R) - ต้องให้ผู้ใช้กระทำการ
│
└── Impact Metrics (ผลกระทบ)
    ├── Confidentiality (C)
    ├── Integrity (I)
    └── Availability (A)
        ├── None (N) - ไม่มีผลกระทบ
        ├── Low (L) - ผลกระทบเล็กน้อย
        └── High (H) - ผลกระทบรุนแรง
```

#### 2. Temporal Metrics (ตัวชี้วัดชั่วคราว)
เปลี่ยนแปลงตามเวลา เช่น มี patch แล้วหรือยัง

#### 3. Environmental Metrics (ตัวชี้วัดสภาพแวดล้อม)
ขึ้นอยู่กับสภาพแวดล้อมขององค์กร

### 4.3 ตัวอย่างการอ่าน CVSS Vector String

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

แปลความหมาย:
┌─────────────────────────────────────────────┐
│ CVSS Version 3.1                            │
│ AV:N  → Attack Vector: Network              │
│         (โจมตีผ่านเครือข่าย)                 │
│ AC:L  → Attack Complexity: Low              │
│         (โจมตีง่าย)                          │
│ PR:N  → Privileges Required: None           │
│         (ไม่ต้องมีสิทธิ์)                    │
│ UI:N  → User Interaction: None              │
│         (ไม่ต้องให้ผู้ใช้กระทำการ)          │
│ S:U   → Scope: Unchanged                    │
│ C:H   → Confidentiality Impact: High        │
│ I:H   → Integrity Impact: High              │
│ A:H   → Availability Impact: High           │
│                                             │
│ คะแนน: 9.8 (Critical)                        │
└─────────────────────────────────────────────┘
```

### 4.4 ตัวอย่าง CVE พร้อม CVSS Score

#### ตัวอย่างที่ 1: CVE-2024-1234 (สมมติ)
```
Vulnerability: SQL Injection in Login Form
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L
Base Score: 9.4 (Critical)

สาเหตุคะแนนสูง:
✓ โจมตีผ่านเครือข่ายได้ (AV:N)
✓ โจมตีง่าย ไม่ซับซ้อน (AC:L)
✓ ไม่ต้องมีสิทธิ์ (PR:N)
✓ ไม่ต้องให้ผู้ใช้กระทำการ (UI:N)
✓ ผลกระทบต่อ Confidentiality และ Integrity สูง
```

#### ตัวอย่างที่ 2: CVE-2024-5678 (สมมติ)
```
Vulnerability: Local Privilege Escalation
CVSS Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
Base Score: 7.8 (High)

สาเหตุคะแนนต่ำกว่า:
✓ ต้องเข้าถึง Local (AV:L)
✓ ต้องมีสิทธิ์พื้นฐานก่อน (PR:L)
✗ แต่ผลกระทบสูงทั้ง 3 ด้าน
```

---

## 🎮 Mini Lab: ค้นหา CVE และอ่าน CVSS

### Lab Objectives:
1. เรียนรู้วิธีค้นหาข้อมูล CVE จากฐานข้อมูล NVD
2. ฝึกอ่านและตีความ CVSS Vector String
3. เข้าใจความสัมพันธ์ระหว่างช่องโหว่กับคะแนน CVSS

### Lab Activities:

#### Activity 1: ค้นหา CVE ล่าสุด
1. เข้าไปที่ https://nvd.nist.gov/
2. ค้นหา CVE ที่เกี่ยวกับ "Apache" หรือ "MySQL"
3. เลือก CVE หนึ่งที่มีคะแนน CVSS > 7.0
4. บันทึกข้อมูล:
   - CVE ID
   - Description
   - CVSS Score
   - CVSS Vector String

#### Activity 2: วิเคราะห์ CVSS Metrics
```
แบบฟอร์มวิเคราะห์ CVE
─────────────────────────────────────────
CVE ID: _______________________________
Product/Service: _______________________
CVSS Score: ______ (___/Low/Med/High/Crit)

Base Metrics Analysis:
├─ Attack Vector (AV):    □ N  □ A  □ L  □ P
├─ Attack Complexity (AC): □ L  □ H
├─ Privileges Required (PR): □ N  □ L  □ H
├─ User Interaction (UI):  □ N  □ R
└─ Scope (S):             □ U  □ C

Impact:
├─ Confidentiality:  □ N  □ L  □ H
├─ Integrity:        □ N  □ L  □ H
└─ Availability:     □ N  □ L  □ H

คำถาม:
1. ทำไมช่องโหว่นี้ได้คะแนน CVSS สูง/ต่ำ?
2. ควรจัดการความเสี่ยงนี้อย่างไร? (Avoid/Reduce/Transfer/Accept)
3. มี patch หรือ workaround แล้วหรือยัง?
```

---

## 💼 Case Study: วิเคราะห์ช่องโหว่ในระบบ Login

### สถานการณ์:

คุณเป็น Software Engineer ที่ได้รับมอบหมายให้ตรวจสอบความปลอดภัยของระบบ Login ของบริษัท

```php
// โค้ดระบบ Login (ตัวอย่างที่มีช่องโหว่)
<?php
$username = $_POST['username'];
$password = $_POST['password'];

// ช่องโหว่ที่ 1: SQL Injection
$sql = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($conn, $sql);

if (mysqli_num_rows($result) > 0) {
    // ช่องโหว่ที่ 2: Session Management
    $_SESSION['user'] = $username;
    
    // ช่องโหว่ที่ 3: No Password Hashing
    // รหัสผ่านเก็บแบบ plaintext ในฐานข้อมูล
    
    echo "Login successful!";
} else {
    echo "Invalid credentials!";
}
?>
```

### แบบฝึกหัด: Risk Assessment

```
┌──────────────────────────────────────────────────────┐
│     Risk Assessment Worksheet                        │
└──────────────────────────────────────────────────────┘

1. IDENTIFY VULNERABILITIES
   ┌──────────────────────────────────────────┐
   │ ช่องโหว่ที่พบ:                            │
   │ V1: _________________________________    │
   │ V2: _________________________________    │
   │ V3: _________________________________    │
   └──────────────────────────────────────────┘

2. ANALYZE THREATS
   ┌──────────────────────────────────────────┐
   │ Threat 1: SQL Injection Attack           │
   │ Threat Actor: External Hacker            │
   │ Attack Method: ____________________      │
   │                                          │
   │ Threat 2: Password Cracking              │
   │ Threat Actor: _____________________      │
   │ Attack Method: ____________________      │
   └──────────────────────────────────────────┘

3. EVALUATE IMPACT & LIKELIHOOD
   ┌──────────────────────────────────────────────┐
   │ Vulnerability | Impact | Likelihood | Risk  │
   ├───────────────┼────────┼────────────┼───────┤
   │ SQL Injection │ High   │ High       │ HIGH  │
   │ No Hash       │ High   │ Medium     │ _?_   │
   │ Session Mgmt  │ Medium │ High       │ _?_   │
   └──────────────────────────────────────────────┘

4. RISK TREATMENT RECOMMENDATIONS
   ┌──────────────────────────────────────────┐
   │ V1 - SQL Injection:                      │
   │ • ใช้ Prepared Statements                │
   │ • ทำ Input Validation                    │
   │ • ใช้ ORM Framework                      │
   │                                          │
   │ V2 - No Password Hashing:                │
   │ • __________________________             │
   │ • __________________________             │
   │                                          │
   │ V3 - Session Management:                 │
   │ • __________________________             │
   │ • __________________________             │
   └──────────────────────────────────────────┘
```

---

## ❓ คำถามชวนคิด & แบบทดสอบความเข้าใจ

### ชุดที่ 1: ความเข้าใจพื้นฐาน

**คำถามที่ 1:** อะไรคือความแตกต่างหลักระหว่าง Threat และ Vulnerability?

<details>
<summary>คลิกเพื่อดูคำตอบ</summary>

**คำตอบ:**
- **Threat** คือสิ่งที่อาจก่อให้เกิดความเสียหาย (ภายนอกระบบ) เช่น hacker, malware, natural disaster
- **Vulnerability** คือจุดอ่อนในระบบ (ภายในระบบ) ที่ Threat สามารถใช้ประโยชน์ได้ เช่น รหัสผ่านอ่อน, bug ในโค้ด

**การเปรียบเทียบ:**
- Threat = "โจร" (อยู่ภายนอก)
- Vulnerability = "ประตูล็อกไม่ดี" (จุดอ่อนของบ้าน)
- Risk = โอกาสที่โจรจะใช้ประตูที่ล็อกไม่ดีเข้ามาขโมยของ
</details>

---

**คำถามที่ 2:** ทำไม CVE-2021-44228 (Log4Shell) ถึงได้คะแนน CVSS 10.0?

<details>
<summary>คลิกเพื่อดูคำตอบ</summary>

**คำตอบ:**
CVE-2021-44228 ได้คะแนนเต็ม 10.0 เพราะ:

1. **Attack Vector: Network (N)** - โจมตีผ่านอินเทอร์เน็ตได้
2. **Attack Complexity: Low (L)** - โจมตีง่ายมาก ใช้แค่ส่ง string พิเศษ
3. **Privileges Required: None (N)** - ไม่ต้องมีบัญชีหรือสิทธิ์ใดๆ
4. **User Interaction: None (N)** - ไม่ต้องให้ผู้ใช้กระทำการ
5. **Impact: High ทั้ง C, I, A** - สามารถ Remote Code Execution ได้เต็มที่

**Vector String:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`

ช่องโหว่นี้อันตรายมากเพราะ:
- ใช้ประโยชน์ง่าย
- แพร่กระจายได้รวดเร็ว
- ส่งผลกระทบต่อระบบนับล้าน
- Log4j ถูกใช้ในแอปพลิเคชันมากมายทั่วโลก
</details>

---

**คำถามที่ 3:** ถ้าพบช่องโหว่ที่มี CVSS Score 4.5 (Medium) ในระบบที่ไม่ได้ใช้งานแล้ว ควรจัดการความเสี่ยงแบบไหน?

<details>
<summary>คลิกเพื่อดูคำตอบ</summary>

**คำตอบ:**
ควรใช้วิธี **Avoid (หลีกเลี่ยง)** โดยปิดระบบหรือยกเลิกบริการนั้นเลย

**เหตุผล:**
- ระบบไม่ได้ใช้งาน = ไม่มี business value
- การรักษาระบบที่ไม่ใช้ = waste resources
- ปิดระบบ = ลดพื้นที่โจมตี (Attack Surface) ได้

**ขั้นตอนที่แนะนำ:**
1. ยืนยันว่าไม่มีใครใช้ระบบจริงๆ
2. Backup ข้อมูลสำคัญ (ถ้ามี)
3. ปิด/ลบระบบ
4. Update inventory และ documentation
5. Monitor ว่าไม่มีผลกระทบ

**บทเรียน:** บางครั้ง การ "ไม่ทำอะไร" (ปิดระบบ) ดีกว่า "ทำอะไรบางอย่าง" (patch ระบบที่ไม่ได้ใช้)
</details>

---

### ชุดที่ 2: การประยุกต์ใช้

**คำถามที่ 4:** เว็บไซต์ e-commerce มีช่องโหว่ 3 ข้อ:
- A: SQL Injection (CVSS 9.8)
- B: Stored XSS in comment (CVSS 7.2)
- C: Information Disclosure in error page (CVSS 5.3)

มีทรัพยากรจำกัด ควรแก้ช่องโหว่ใดก่อน?

<details>
<summary>คลิกเพื่อดูคำตอบ</summary>

**คำตอบ:**
ควรแก้ตามลำดับ: **A → B → C**

**การวิเคราะห์:**

**Priority 1: SQL Injection (CVSS 9.8)**
- ความเสี่ยง: Critical
- ผลกระทบ: อาจถูกขโมยข้อมูลลูกค้าทั้งหมด (ชื่อ, ที่อยู่, บัตรเครดิต)
- แนวทางแก้ไข:
  ```php
  // แทนที่
  $sql = "SELECT * FROM products WHERE id='$id'";
  
  // ด้วย Prepared Statement
  $stmt = $pdo->prepare("SELECT * FROM products WHERE id = ?");
  $stmt->execute([$id]);
  ```

**Priority 2: Stored XSS (CVSS 7.2)**
- ความเสี่ยง: High
- ผลกระทบ: ผู้ใช้อื่นอาจถูกโจมตี, ขโมย session
- แนวทางแก้ไข: ทำ Input Sanitization และ Output Encoding

**Priority 3: Information Disclosure (CVSS 5.3)**
- ความเสี่ยง: Medium
- ผลกระทบ: เปิดเผยข้อมูลทางเทคนิค ช่วยให้ผู้โจมตีวางแผนได้
- แนวทางแก้ไข: ใช้ custom error page, ปิด error reporting ใน production

**หลักการ:**
1. ให้ความสำคัญกับ CVSS Score
2. พิจารณา Business Impact (ข้อมูลลูกค้า > ข้อมูลทางเทคนิค)
3. พิจารณา Ease of Exploitation
</details>

---

**คำถามที่ 5:** อธิบายว่าทำไมการใช้ Default Password ถึงเป็นช่องโหว่ที่อันตราย และควรจัดการอย่างไร?

<details>
<summary>คลิกเพื่อดูคำตอบ</summary>

**คำตอบ:**

**ทำไมอันตราย:**

1. **ง่ายต่อการเดา**
   - Hacker มีรายการ default credentials ทั้งหมด
   - มีเครื่องมือสำหรับทดสอบอัตโนมัติ
   - เช่น: admin/admin, root/root, admin/password123

2. **เป็นเป้าหมายแรกของผู้โจมตี**
   - Automated scanning tools จะพยายาม default credentials ก่อน
   - Mirai botnet ใช้วิธีนี้โจมตี IoT devices

3. **ผลกระทบกว้างขวาง**
   - ถ้าใช้ default password เหมือนกันทุกอุปกรณ์
   - ถูกเจาะได้ทีเดียวทั้งระบบ

**ตัวอย่างจากข่าว:**
- Mirai Botnet (2016): ใช้ default credentials โจมตี IoT devices
- Asus Router Vulnerability: ใช้ default admin password

**แนวทางแก้ไข:**

```
Best Practices สำหรับ Password Management:

1. เปลี่ยน Default Password ทันที
   ┌────────────────────────────────────┐
   │ ✓ ก่อนเชื่อมต่อเข้าอินเทอร์เน็ต    │
   │ ✓ ใช้รหัสผ่านที่ซับซ้อน             │
   │ ✓ แต่ละระบบใช้รหัสต่างกัน          │
   └────────────────────────────────────┘

2. ใช้ Strong Password Policy
   ┌────────────────────────────────────┐
   │ • ความยาวอย่างน้อย 12 ตัวอักษร     │
   │ • ผสม uppercase, lowercase,        │
   │   numbers, special characters      │
   │ • ห้ามใช้รหัสผ่านที่เดาง่าย        │
   └────────────────────────────────────┘

3. ใช้ Multi-Factor Authentication (MFA)
   ┌────────────────────────────────────┐
   │ Something you know (password)      │
   │ + Something you have (token/phone) │
   │ + Something you are (biometric)    │
   └────────────────────────────────────┘

4. ใช้ Password Manager
   ┌────────────────────────────────────┐
   │ • 1Password, LastPass, Bitwarden   │
   │ • สร้างรหัสผ่านที่ซับซ้อนอัตโนมัติ │
   │ • จัดเก็บอย่างปลอดภัย              │
   └────────────────────────────────────┘
```

**สำหรับ Developers:**
```python
# ไม่ควรทำ ❌
default_password = "admin123"
if user_password == default_password:
    login_success()

# ควรทำ ✓
# 1. บังคับให้เปลี่ยนรหัสผ่านครั้งแรก
if user.is_first_login:
    force_password_change()

# 2. ใช้ Password Hashing
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# 3. ตรวจสอบความแข็งแรงของรหัสผ่าน
if not is_strong_password(new_password):
    reject_weak_password()
```

**Risk Score:**
```
Default Password Vulnerability:
├─ Attack Vector: Network (N)
├─ Attack Complexity: Low (L)
├─ Privileges Required: None (N)
├─ User Interaction: None (N)
└─ Impact: High (H) ทั้ง C, I, A

→ CVSS Score: 9.8 (Critical)
```
</details>

---

### ชุดที่ 3: Scenario-Based Questions

**คำถามที่ 6:** บริษัทของคุณใช้ WordPress version 5.8 ซึ่งมีช่องโหว่ CVE-2024-XXXX (CVSS 8.5) แต่การอัปเดตเป็น version ใหม่อาจทำให้ plugin บางตัวใช้งานไม่ได้ ควรตัดสินใจอย่างไร?

<details>
<summary>คลิกเพื่อดูคำตอบ</summary>

**คำตอบ:**

นี่คือสถานการณ์ที่ต้องทำ **Risk-Based Decision Making**

**ขั้นตอนการตัดสินใจ:**

```
Step 1: Assess Current Risk
┌──────────────────────────────────────┐
│ CVSS 8.5 = High Risk                 │
│ WordPress = Public-facing            │
│ → Likelihood: High                   │
│ → Impact: High                       │
│ → Current Risk: CRITICAL             │
└──────────────────────────────────────┘

Step 2: Analyze Options
┌──────────────────────────────────────────────────┐
│ Option A: อัปเดตทันที                            │
│ ├─ Pro: แก้ช่องโหว่ทันที                        │
│ └─ Con: plugins อาจใช้ไม่ได้                    │
│                                                  │
│ Option B: ใช้ Temporary Mitigation              │
│ ├─ Pro: ไม่กระทบ functionality                  │
│ └─ Con: ยังมีความเสี่ยงอยู่บ้าง                 │
│                                                  │
│ Option C: รอจนกว่า plugins จะรองรับ            │
│ ├─ Pro: ไม่มีปัญหา compatibility                │
│ └─ Con: เสี่ยงสูงมากที่จะถูกโจมตี                │
└──────────────────────────────────────────────────┘
```

**คำแนะนำ: ใช้ "Layered Security" Approach**

```
Immediate Actions (0-24 hours):
┌────────────────────────────────────────┐
│ 1. ใช้ Web Application Firewall (WAF)  │
│    • Cloudflare, AWS WAF               │
│    • สร้าง rules ป้องกันเฉพาะช่องโหว่  │
│                                        │
│ 2. ตรวจสอบ access logs                │
│    • มีการพยายามโจมตีหรือไม่            │
│    • ตั้ง alerts                       │
│                                        │
│ 3. Limit access                        │
│    • IP whitelist สำหรับ admin panel   │
│    • ใช้ VPN                           │
└────────────────────────────────────────┘

Short-term Actions (1-7 days):
┌────────────────────────────────────────┐
│ 1. ทดสอบใน staging environment        │
│    • สร้าง copy ของ production        │
│    • ทดสอบอัปเดต + plugins            │
│                                        │
│ 2. หา alternatives                     │
│    • หา plugins ที่รองรับ version ใหม่ │
│    • พิจารณาเอา features บางส่วนออก   │
│                                        │
│ 3. Backup ทุกอย่าง                    │
│    • Database + files                  │
│    • ทดสอบ restore                     │
└────────────────────────────────────────┘

Long-term Actions (1-4 weeks):
┌────────────────────────────────────────┐
│ 1. อัปเดต WordPress                   │
│    • ในช่วงเวลาที่ traffic ต่ำ         │
│    • มี rollback plan พร้อม           │
│                                        │
│ 2. Replace/Update plugins             │
│    • ใช้ alternative plugins           │
│    • หรือรอ plugins อัปเดต             │
│                                        │
│ 3. Implement DevSecOps                │
│    • Automated security scanning       │
│    • Regular updates schedule          │
└────────────────────────────────────────┘
```

**Decision Matrix:**

```
               High Business Impact   Low Business Impact
             ┌─────────────────────┬─────────────────────┐
High Security│  ⚠️ VERY CAREFUL    │  ✓ UPDATE NOW       │
Risk         │  Use mitigation     │                     │
             │  then update        │                     │
             ├─────────────────────┼─────────────────────┤
Low Security │  📅 Schedule        │  📅 Schedule        │
Risk         │  Update             │  Update             │
             │  (not urgent)       │  (low priority)     │
             └─────────────────────┴─────────────────────┘
```

**คำตอบสุดท้าย:**
สำหรับกรณีนี้ (CVSS 8.5 = High Risk):
1. ใช้ WAF และมาตรการชั่วคราวทันที
2. ทดสอบใน staging
3. วางแผนอัปเดตภายใน 7-14 วัน
4. ถ้า plugins สำคัญใช้ไม่ได้ → หา alternative หรือ develop custom solution

**Important:** ห้าม Option C (รอไปเรื่อยๆ) เพราะ:
- CVSS 8.5 = High Risk ไม่ควรทิ้งไว้นาน
- ยิ่งมีคนรู้จักช่องโหว่มากขึ้น ยิ่งเสี่ยงมากขึ้น
- อาจถูกโจมตีก่อนที่จะได้แก้
</details>

---

## 🎯 Demo: การใช้ NVD Database

### การค้นหาข้อมูล CVE

```
Demo Steps:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. เข้าไปที่ https://nvd.nist.gov/vuln/search
   
2. ค้นหา "Apache Log4j"
   ┌─────────────────────────────────────┐
   │ Search Box: Apache Log4j            │
   │ [🔍 Search]                          │
   └─────────────────────────────────────┘

3. เลือก CVE-2021-44228
   
4. สังเกตข้อมูลสำคัญ:
   ┌──────────────────────────────────────────┐
   │ Published: December 10, 2021             │
   │ Last Modified: November 02, 2024         │
   │                                          │
   │ CVSS 3.1 Base Score: 10.0 CRITICAL      │
   │ Vector String:                           │
   │ CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/       │
   │ C:H/I:H/A:H                              │
   │                                          │
   │ Description:                             │
   │ Apache Log4j2 2.0-beta9 through         │
   │ 2.15.0 JNDI features used in            │
   │ configuration, log messages, and        │
   │ parameters do not protect against        │
   │ attacker controlled LDAP and other       │
   │ JNDI related endpoints...                │
   └──────────────────────────────────────────┘

5. ดู References:
   • Patch information
   • Vendor advisories
   • Proof of Concept (PoC)

6. ดู CPE (Common Platform Enumeration):
   • รายชื่อผลิตภัณฑ์ที่ได้รับผลกระทบ
```

---

## 📝 Mini Assignment: Risk Assessment Exercise

### โจทย์:

วิเคราะห์ระบบ "Online Booking System" ของโรงพยาบาลขนาดเล็ก ที่มีฟีเจอร์ดังนี้:
- ผู้ป่วยสามารถจองคิวออนไลน์
- เก็บข้อมูลส่วนตัว (ชื่อ, เบอร์โทร, อาการ)
- มี Admin panel สำหรับเจ้าหน้าที่

### ให้นักศึกษา:

1. **ระบุ Assets** (อย่างน้อย 3 รายการ)
   ```
   Asset 1: _______________________________
   Asset 2: _______________________________
   Asset 3: _______________________________
   ```

2. **ระบุ Threats** (อย่างน้อย 3 รายการ)
   ```
   Threat 1: _______________________________
   Threat 2: _______________________________
   Threat 3: _______________________________
   ```

3. **ระบุ Vulnerabilities** (อย่างน้อย 3 รายการ)
   ```
   Vulnerability 1: _______________________________
   Vulnerability 2: _______________________________
   Vulnerability 3: _______________________________
   ```

4. **ทำ Risk Assessment Matrix**
   ```
   ┌──────────────┬────────┬──────────┬───────┬──────────┐
   │ Risk Item    │ Impact │ Likelihood│ Risk  │ Priority │
   │              │ (L/M/H)│  (L/M/H)  │ Level │  (1-9)   │
   ├──────────────┼────────┼──────────┼───────┼──────────┤
   │ SQL Injection│   H    │    H      │  HIGH │    1     │
   ├──────────────┼────────┼──────────┼───────┼──────────┤
   │              │        │           │       │          │
   ├──────────────┼────────┼──────────┼───────┼──────────┤
   │              │        │           │       │          │
   └──────────────┴────────┴──────────┴───────┴──────────┘
   ```

5. **เสนอมาตรการลดความเสี่ยง**
   ```
   Risk 1: _______________________________
   Mitigation:
   • __________________________________
   • __________________________________
   
   Risk 2: _______________________________
   Mitigation:
   • __________________________________
   • __________________________________
   ```

---

## 🔐 Best Practices: Vulnerability Management

```
╔══════════════════════════════════════════════════════╗
║        Vulnerability Management Lifecycle            ║
╚══════════════════════════════════════════════════════╝

    ┌─────────────────────────────────────┐
    │  1. DISCOVER                        │
    │  • Regular scanning                 │
    │  • Inventory all assets             │
    │  • Monitor security bulletins       │
    └───────────────┬─────────────────────┘
                    │
    ┌───────────────▼─────────────────────┐
    │  2. PRIORITIZE                      │
    │  • CVSS Score                       │
    │  • Business impact                  │
    │  • Exploitability                   │
    └───────────────┬─────────────────────┘
                    │
    ┌───────────────▼─────────────────────┐
    │  3. REMEDIATE                       │
    │  • Patch                            │
    │  • Mitigate                         │
    │  • Workaround                       │
    └───────────────┬─────────────────────┘
                    │
    ┌───────────────▼─────────────────────┐
    │  4. VERIFY                          │
    │  • Test patches                     │
    │  • Re-scan                          │
    │  • Confirm fix                      │
    └───────────────┬─────────────────────┘
                    │
    ┌───────────────▼─────────────────────┐
    │  5. DOCUMENT & REPORT               │
    │  • Update inventory                 │
    │  • Track metrics                    │
    │  • Lessons learned                  │
    └─────────────────────────────────────┘
```

### Service Level Agreements (SLA) ตามความรุนแรง

```
┌──────────────────────────────────────────────────────┐
│  Severity Level  │  Remediation Timeframe            │
├──────────────────┼───────────────────────────────────┤
│  Critical (9-10) │  ⚠️  24-48 hours                  │
│                  │  • Immediate action               │
│                  │  • Emergency patches              │
├──────────────────┼───────────────────────────────────┤
│  High (7-8.9)    │  📅  7-14 days                    │
│                  │  • Priority patching              │
│                  │  • Implement mitigations          │
├──────────────────┼───────────────────────────────────┤
│  Medium (4-6.9)  │  📅  30 days                      │
│                  │  • Regular patch cycle            │
│                  │  • Monitor for exploitation       │
├──────────────────┼───────────────────────────────────┤
│  Low (0.1-3.9)   │  📅  90 days or next cycle        │
│                  │  • Plan for regular update        │
│                  │  • Low priority                   │
└──────────────────┴───────────────────────────────────┘
```

---

## 🌟 Case Studies: Real-World Examples

### Case Study 1: Equifax Data Breach (2017)

```
┌─────────────────────────────────────────────────────┐
│          Equifax Data Breach Analysis               │
└─────────────────────────────────────────────────────┘

📅 Timeline:
├─ March 2017: CVE-2017-5638 ถูกเปิดเผย
│              (Apache Struts vulnerability)
├─ Mid-May 2017: Equifax ถูกเจาะ
├─ July 2017: Equifax ตรวจพบการเจาะ
└─ September 2017: เปิดเผยต่อสาธารณะ

💥 Impact:
├─ 147 million คน ข้อมูลรั่วไหล
├─ ข้อมูลที่รั่ว: SSN, วันเกิด, ที่อยู่, หมายเลขใบขับขี่
├─ ค่าใช้จ่าย: มากกว่า $1.4 billion
└─ ความเสียหายต่อชื่อเสียง: รุนแรงมาก

🔍 Root Cause Analysis:

Vulnerability Found:
├─ CVE-2017-5638 (Apache Struts)
├─ CVSS Score: 10.0 (Critical)
└─ Patch พร้อมใช้งานก่อนการโจมตี

What Went Wrong:
┌────────────────────────────────────────────┐
│ ❌ ไม่ได้ patch ทันเวลา                     │
│ ❌ ไม่มี asset inventory ที่ดี             │
│ ❌ monitoring ไม่เพียงพอ                   │
│ ❌ incident response ช้าเกินไป              │
└────────────────────────────────────────────┘

Lessons Learned:
┌────────────────────────────────────────────┐
│ ✓ Patch critical vulnerabilities ทันที    │
│ ✓ มี comprehensive asset inventory        │
│ ✓ implement proper monitoring            │
│ ✓ มี incident response plan ที่ดี         │
│ ✓ regular security audits                 │
└────────────────────────────────────────────┘
```

### Case Study 2: SolarWinds Supply Chain Attack (2020)

```
┌─────────────────────────────────────────────────────┐
│       SolarWinds Supply Chain Attack                │
└─────────────────────────────────────────────────────┘

🎯 Attack Method:
└─ Backdoor ใน SolarWinds Orion software update
   ├─ เหยื่อติดตั้ง update ที่มี backdoor
   └─ ผู้โจมตีเข้าถึงระบบได้

💥 Impact:
├─ 18,000+ organizations ได้รับผลกระทบ
├─ หน่วยงานรัฐบาลสหรัฐฯ ถูกโจมตี
└─ ข้อมูลลับรั่วไหล

🔍 Analysis:

Type of Vulnerability:
├─ Supply Chain Vulnerability
├─ Trojanized Software Update
└─ Advanced Persistent Threat (APT)

Why It's Dangerous:
┌────────────────────────────────────────────┐
│ • ผู้ใช้ trust software updates            │
│ • ยากต่อการตรวจจับ (signed updates)       │
│ • ส่งผลกระทบกว้างขวาง                      │
│ • ใช้เวลานานในการค้นพบ                     │
└────────────────────────────────────────────┘

Risk Assessment:
├─ Impact: CRITICAL
│  └─ ระบบ critical infrastructure
├─ Likelihood: LOW (แต่เกิดขึ้นแล้ว)
│  └─ APT group ที่มีความสามารถสูง
└─ Risk Level: CRITICAL

Mitigation Strategies:
┌────────────────────────────────────────────┐
│ ✓ Verify software signatures              │
│ ✓ Network segmentation                    │
│ ✓ Zero Trust Architecture                 │
│ ✓ Monitor for anomalies                   │
│ ✓ Least Privilege principle               │
└────────────────────────────────────────────┘
```

---

## 💻 Practical Tools & Resources

### 1. Vulnerability Databases

```
┌────────────────────────────────────────────────┐
│  Top Vulnerability Databases                   │
├────────────────────────────────────────────────┤
│                                                │
│  1. NVD (National Vulnerability Database)      │
│     🔗 https://nvd.nist.gov/                   │
│     • NIST official database                   │
│     • CVSS scores                              │
│     • Detailed technical info                  │
│                                                │
│  2. CVE MITRE                                  │
│     🔗 https://cve.mitre.org/                  │
│     • CVE IDs                                  │
│     • Standard naming                          │
│                                                │
│  3. Exploit Database                           │
│     🔗 https://www.exploit-db.com/             │
│     • Proof of Concepts                        │
│     • Exploit code                             │
│                                                │
│  4. VulnDB                                     │
│     🔗 https://vulndb.cyberriskanalytics.com/  │
│     • Commercial database                      │
│     • Detailed metadata                        │
│                                                │
│  5. Vendor Security Advisories                 │
│     • Microsoft Security Response Center       │
│     • Apple Security Updates                   │
│     • Red Hat Security Advisories              │
└────────────────────────────────────────────────┘
```

### 2. CVSS Calculators

```
Online CVSS Calculators:
━━━━━━━━━━━━━━━━━━━━━━━━━━
1. FIRST CVSS Calculator
   🔗 https://www.first.org/cvss/calculator/3.1
   
2. NVD CVSS Calculator
   🔗 https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator

3. How to Use:
   ┌──────────────────────────────────────┐
   │ Step 1: Select Base Metrics          │
   │ ├─ Attack Vector (AV)                │
   │ ├─ Attack Complexity (AC)            │
   │ ├─ Privileges Required (PR)          │
   │ ├─ User Interaction (UI)             │
   │ └─ Scope (S)                         │
   │                                      │
   │ Step 2: Select Impact Metrics        │
   │ ├─ Confidentiality (C)               │
   │ ├─ Integrity (I)                     │
   │ └─ Availability (A)                  │
   │                                      │
   │ Step 3: Get Results                  │
   │ ├─ Base Score (0-10)                 │
   │ ├─ Severity Rating                   │
   │ └─ Vector String                     │
   └──────────────────────────────────────┘
```

### 3. Vulnerability Scanning Tools

```
┌────────────────────────────────────────────────┐
│  Free/Open Source Scanners                     │
├────────────────────────────────────────────────┤
│                                                │
│  1. OpenVAS                                    │
│     • Comprehensive vulnerability scanner      │
│     • Free and open source                     │
│     • Good for network scanning                │
│                                                │
│  2. Nmap + NSE Scripts                         │
│     • Network discovery                        │
│     • Vuln scripts available                   │
│     • Lightweight                              │
│                                                │
│  3. OWASP ZAP                                  │
│     • Web application security                 │
│     • Active/passive scanning                  │
│     • Great for developers                     │
│                                                │
│  4. Nikto                                      │
│     • Web server scanner                       │
│     • Easy to use                              │
│     • Quick scans                              │
│                                                │
│  5. Trivy (for containers)                     │
│     • Container image scanning                 │
│     • Fast and accurate                        │
│     • CI/CD integration                        │
└────────────────────────────────────────────────┘
```

---

## 📚 Additional Learning Resources

### 📖 Recommended Reading

1. **NIST Cybersecurity Framework**
   - https://www.nist.gov/cyberframework
   - มาตรฐานการบริหารความเสี่ยง

2. **OWASP Top 10**
   - https://owasp.org/www-project-top-ten/
   - ช่องโหว่ web application ที่พบบ่อย

3. **CWE/SANS Top 25**
   - https://cwe.mitre.org/top25/
   - Software errors ที่อันตรายที่สุด

### 🎓 Certifications

```
Entry-Level Certifications:
├─ CompTIA Security+
├─ CEH (Certified Ethical Hacker)
└─ GIAC Security Essentials (GSEC)

Advanced Certifications:
├─ CISSP (Certified Information Systems Security Professional)
├─ OSCP (Offensive Security Certified Professional)
└─ CISM (Certified Information Security Manager)
```

---

## 📌 สรุปบทเรียน (Summary)

### สิ่งที่เราได้เรียนรู้ในสัปดาห์นี้:

```
┌─────────────────────────────────────────────────────┐
│            Week 3 Key Takeaways                     │
├─────────────────────────────────────────────────────┤
│                                                     │
│  1️⃣  Vulnerability คือจุดอ่อนในระบบที่สามารถ       │
│     ถูกใช้ประโยชน์ได้                               │
│                                                     │
│  2️⃣  CVE เป็นมาตรฐานในการระบุช่องโหว่              │
│     รูปแบบ: CVE-[YEAR]-[NUMBER]                     │
│                                                     │
│  3️⃣  Risk = Threat × Vulnerability × Impact        │
│     การจัดการความเสี่ยงต้องดูทั้งสามปัจจัย          │
│                                                     │
│  4️⃣  CVSS ให้คะแนนความรุนแรง 0-10                  │
│     • 0.0: None                                     │
│     • 0.1-3.9: Low                                  │
│     • 4.0-6.9: Medium                               │
│     • 7.0-8.9: High                                 │
│     • 9.0-10.0: Critical                            │
│                                                     │
│  5️⃣  Risk Management Lifecycle:                     │
│     Identify → Analyze → Evaluate →                │
│     Treat → Monitor                                 │
│                                                     │
│  6️⃣  มี 4 วิธีจัดการความเสี่ยง:                    │
│     • Avoid (หลีกเลี่ยง)                            │
│     • Reduce (ลด)                                   │
│     • Transfer (โอน)                                │
│     • Accept (ยอมรับ)                               │
└─────────────────────────────────────────────────────┘
```

### คำถามทบทวน:

1. อะไรคือความแตกต่างระหว่าง Vulnerability และ Threat?
2. CVE-2024-1234 หมายความว่าอย่างไร?
3. CVSS Score 8.5 อยู่ในระดับความรุนแรงใด?
4. ยกตัวอย่างช่องโหว่ที่พบบ่อยใน Web Application 3 ประเภท
5. อธิบายวงจร Risk Management Lifecycle

---

## 🔮 สัปดาห์หน้า: Operating System Security & Hardening

### Preview Week 4:

ในสัปดาห์หน้าเราจะเรียนรู้:

```
┌──────────────────────────────────────────────────┐
│         Week 4 Topics Preview                    │
├──────────────────────────────────────────────────┤
│                                                  │
│  🔐 Operating System Security                    │
│     • Windows vs Linux security models           │
│     • Access Control mechanisms                  │
│                                                  │
│  👤 User & Privilege Management                  │
│     • Principle of Least Privilege               │
│     • sudo/Run as Administrator                  │
│                                                  │
│  🛠️  OS Hardening Techniques                     │
│     • Disable unnecessary services               │
│     • Configure firewalls                        │
│     • Implement security policies                │
│                                                  │
│  💻 Hands-on Lab                                 │
│     • VM setup (VirtualBox/VMware)               │
│     • Windows/Linux hardening                    │
│     • Security configuration checklist           │
└──────────────────────────────────────────────────┘

เตรียมตัว:
✓ ติดตั้ง VirtualBox หรือ VMware
✓ Download Ubuntu ISO หรือ Windows 10 ISO
✓ อ่านเกี่ยวกับ CIS Benchmarks (ถ้ามีเวลา)
```

---

## ✍️ Homework & Assignments

### Assignment 1: Mini Risk Assessment (ส่งภายใน 7 วัน)

**คะแนน:** 10 คะแนน  
**รูปแบบ:** รายงาน 2-3 หน้า (PDF)

**โจทย์:**
เลือกระบบหนึ่งจาก:
1. ระบบ E-learning ของมหาวิทยาลัย
2. ระบบ Food Delivery app
3. ระบบ Online Banking

ทำการ:
1. ระบุ Assets, Threats, และ Vulnerabilities
2. ทำ Risk Assessment Matrix
3. เสนอมาตรการลดความเสี่ยงอย่างน้อย 5 ข้อ
4. อธิบายว่าทำไมเลือกมาตรการเหล่านั้น

### Quiz 2: CVE / Risk / CVSS (วันศุกร์หน้า)

**คะแนน:** 10 คะแนน  
**ระยะเวลา:** 30 นาที  
**รูปแบบ:** ออนไลน์ (Multiple choice + Short answer)

**หัวข้อที่ครอบคลุม:**
- ความหมายของ Vulnerability
- การอ่าน CVE ID
- CVSS Metrics และการตีความคะแนน
- Risk Assessment concepts
- Risk Management strategies

---

## 🙏 ขอบคุณและคำถาม

```
╔═══════════════════════════════════════════════════╗
║                                                   ║
║  มีคำถามหรือข้อสงสัยเพิ่มเติม?                   ║
║                                                   ║
║  📧 Email: instructor@university.ac.th            ║
║  💬 Discussion Forum: [LMS Link]                  ║
║  🕐 Office Hours: ทุกวันพุธ 14:00-16:00          ║
║                                                   ║
╚═══════════════════════════════════════════════════╝

        "Security is not a product,
         but a process."
                    - Bruce Schneier

┌─────────────────────────────────────────────────┐
│  Remember:                                      │
│  • Patch regularly                              │
│  • Monitor your systems                         │
│  • Stay informed about new vulnerabilities      │
│  • Think like an attacker (ethically!)          │
└─────────────────────────────────────────────────┘
```

---

**หมายเหตุ:** เอกสารนี้เป็นเวอร์ชัน 1.0 สำหรับ ENGSE214 Week 3  
**อัปเดตล่าสุด:** December 2024  
**ผู้สอน:** [ชื่ออาจารย์]  
**คณะ:** วิศวกรรมศาสตร์ สาขาวิศวกรรมซอฟต์แวร์

---

## 📎 Appendix: Additional Resources

### A. CVSS v3.1 Quick Reference Card

```
┌──────────────────────────────────────────────────────┐
│           CVSS v3.1 Metrics Quick Ref                │
├──────────────────────────────────────────────────────┤
│ Attack Vector (AV):                                  │
│ • Network (N) = 0.85        • Local (L) = 0.55       │
│ • Adjacent (A) = 0.62       • Physical (P) = 0.20    │
├──────────────────────────────────────────────────────┤
│ Attack Complexity (AC):                              │
│ • Low (L) = 0.77            • High (H) = 0.44        │
├──────────────────────────────────────────────────────┤
│ Privileges Required (PR):                            │
│ • None (N) = 0.85           • Low (L) = 0.62/0.68    │
│ • High (H) = 0.27/0.50                               │
├──────────────────────────────────────────────────────┤
│ User Interaction (UI):                               │
│ • None (N) = 0.85           • Required (R) = 0.62    │
├──────────────────────────────────────────────────────┤
│ Scope (S):                                           │
│ • Unchanged (U)             • Changed (C)            │
├──────────────────────────────────────────────────────┤
│ Impact Metrics (C/I/A):                              │
│ • None (N) = 0.00           • Low (L) = 0.22         │
│ • High (H) = 0.56                                    │
└──────────────────────────────────────────────────────┘
```

### B. Common Vulnerability Types Cheat Sheet

```
Type                | Example               | OWASP Rank
────────────────────┼──────────────────────┼────────────
SQL Injection       | ' OR '1'='1          | #1
XSS                 | <script>alert(1)</script> | #3
CSRF                | Forged requests      | #8
Auth Bypass         | Session hijacking    | #2
File Upload         | Malicious files      | -
Path Traversal      | ../../etc/passwd     | -
Command Injection   | ; rm -rf /           | -
XXE                 | XML External Entity  | -
Deserialization     | Untrusted data       | #8
```

### C. Risk Matrix Template (Excel/Google Sheets)

```
ดาวน์โหลด template ได้ที่:
📥 [LMS] → Week 3 → Risk_Assessment_Template.xlsx

มี sheets:
1. Asset Inventory
2. Threat List
3. Vulnerability Assessment
4. Risk Matrix
5. Mitigation Plan
```

---

**จบเนื้อหา Week 3**

```
  ╔════════════════════════════════════════╗
  ║                                        ║
  ║   🎓 Keep Learning, Stay Secure! 🔐    ║
  ║                                        ║
  ╚════════════════════════════════════════╝
```
