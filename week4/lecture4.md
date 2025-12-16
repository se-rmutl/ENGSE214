# Week 4: Operating System Security & Hardening
## ENGSE214 – ความมั่นคงปลอดภัยทางไซเบอร์เบื้องต้น

**เวลาการสอน:** 2-3 ชั่วโมง (รวม Demo และ Lab)  
**CLO ที่เกี่ยวข้อง:** CLO2, CLO3

---

## 📚 ทบทวนเนื้อหาสัปดาห์ที่ผ่านมา

### Week 3: Vulnerabilities & Basic Risk Assessment

เราได้เรียนรู้เกี่ยวกับ:

```
┌─────────────────────────────────────────────────────────┐
│  ✓ Vulnerability คืออะไร? (จุดอ่อนในระบบ)                  │
│  ✓ CVE & CVSS (การจัดการและประเมินช่องโหว่)                 │
│  ✓ Risk Assessment (การประเมินความเสี่ยง)                  │
│  ✓ Risk Management (การบริหารจัดการความเสี่ยง)              │
└─────────────────────────────────────────────────────────┘
```

**สูตรสำคัญ:**
```
Risk = Threat × Vulnerability × Impact
ความเสี่ยง = ภัยคุกคาม × ช่องโหว่ × ผลกระทบ
```

**Key Takeaway จาก Week 3:**
- การรู้จักช่องโหว่คือขั้นแรกของการป้องกัน
- การประเมินความเสี่ยงช่วยให้จัดลำดับความสำคัญในการแก้ไข
- **สัปดาห์นี้:** เราจะเรียนรู้วิธีการ "ปิดช่องโหว่" ที่ระดับ OS!

---

## 🎯 วัตถุประสงค์การเรียนรู้ (Learning Objectives)

เมื่อจบ Week 4 นักศึกษาจะสามารถ:
1. อธิบายหลักการรักษาความปลอดภัยระบบปฏิบัติการได้
2. เปรียบเทียบ Security Model ของ Windows และ Linux
3. เข้าใจและประยุกต์ใช้หลัก AAA (Authentication, Authorization, Accounting)
4. จัดการสิทธิ์ผู้ใช้ตามหลัก Least Privilege
5. ดำเนินการ OS Hardening เบื้องต้นได้ (Lab)

---

## 💭 คำถามชวนคิด

```
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║   🤔 "ถ้าคุณเป็น Hacker คุณจะโจมตี                         ║
║      ส่วนไหนของ OS ก่อน?"                               ║
║                                                       ║
║   คำตอบ: ส่วนใหญ่จะเริ่มที่...                              ║
║   1. User Accounts (รหัสผ่านอ่อนแอ)                      ║
║   2. Services ที่เปิดไว้ไม่จำเป็น                           ║
║   3. Unpatched Software (ช่องโหว่ที่ยังไม่ patch)           ║
║   4. Misconfiguration (การตั้งค่าผิดพลาด)                 ║
║                                                       ║
║   👉 สัปดาห์นี้เราจะเรียนรู้วิธีป้องกันทั้งหมดนี้!                   ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝
```

---

## 🖥️ Part 1: หลักการรักษาความปลอดภัยระบบปฏิบัติการ

### 1.1 ทำไม OS Security ถึงสำคัญ?

ระบบปฏิบัติการ (Operating System) เป็น **รากฐาน** ของทุกระบบคอมพิวเตอร์

```
         ┌─────────────────────────────────────┐
         │     Applications & Services         │
         │   (Web Server, Database, Apps)      │
         └──────────────┬──────────────────────┘
                        │
         ┌──────────────▼──────────────────────┐
         │      Operating System (OS)          │◄── 🎯 จุดนี้!
         │   (Windows, Linux, macOS)           │
         └──────────────┬──────────────────────┘
                        │
         ┌──────────────▼──────────────────────┐
         │           Hardware                  │
         │   (CPU, RAM, Disk, Network)         │
         └─────────────────────────────────────┘
```

**ถ้า OS ถูกเจาะ = ทุกอย่างบน OS นั้นก็อยู่ในความเสี่ยง!**

### 1.2 หลักการพื้นฐาน: Defense in Depth

```
┌────────────────────────────────────────────────────────┐
│            🛡️ Defense in Depth Layers                  │
│                                                        │
│  Layer 1: Physical Security (ล็อคห้องเซิร์ฟเวอร์)           │
│       │                                                │
│       ▼                                                │
│  Layer 2: OS Security (ที่เราจะเรียนวันนี้!)                 │
│       │                                                │
│       ▼                                                │
│  Layer 3: Network Security (Week 5)                    │
│       │                                                │
│       ▼                                                │
│  Layer 4: Application Security (Week 7)                │
│       │                                                │
│       ▼                                                │
│  Layer 5: Data Security (Encryption)                   │
└────────────────────────────────────────────────────────┘

💡 Concept: ไม่พึ่งพาการป้องกันเพียงชั้นเดียว!
```

### 1.3 CIA Triad ในมุมมอง OS

| CIA Component | ในระบบปฏิบัติการ | ตัวอย่างการละเมิด |
|---------------|------------------|-------------------|
| **Confidentiality** | การควบคุมการเข้าถึงไฟล์/โฟลเดอร์ | ผู้ใช้ทั่วไปอ่านไฟล์ password ได้ |
| **Integrity** | การป้องกันไฟล์ระบบถูกแก้ไข | Malware แก้ไข system32 |
| **Availability** | ระบบทำงานได้ตลอดเวลา | DoS attack ทำให้ OS ล่ม |

---

## 🔐 Part 2: AAA Framework (Authentication, Authorization, Accounting)

### 2.1 AAA คืออะไร?

```
╔═══════════════════════════════════════════════════════════╗
║                    AAA Framework                          ║
╠═══════════════════════════════════════════════════════════╣
║                                                           ║
║   1️⃣ Authentication (การยืนยันตัวตน)                         ║
║      "คุณคือใคร?"                                           ║
║      • Username + Password                                ║
║      • Biometrics (ลายนิ้วมือ, ใบหน้า)                        ║
║      • Multi-Factor Authentication (MFA)                  ║
║                                                           ║
║   2️⃣ Authorization (การอนุญาต)                             ║
║      "คุณทำอะไรได้บ้าง?"                                     ║
║      • File Permissions (Read, Write, Execute)            ║
║      • Role-Based Access Control (RBAC)                   ║
║      • Least Privilege Principle                          ║
║                                                           ║
║   3️⃣ Accounting (การบันทึก)                                 ║
║      "คุณทำอะไรไปบ้าง?"                                     ║
║      • Access Logs                                        ║
║      • Audit Trails                                       ║
║      • Security Event Logging                             ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
```

### 2.2 Authentication Methods

#### 2.2.1 Password-Based Authentication

**ความแข็งแรงของรหัสผ่าน:**
```
🔴 Weak:    "123456"         → Cracked in < 1 second
🟡 Medium:  "Password123"    → Cracked in ~ 2 hours
🟢 Strong:  "P@ssw0rd!2024"  → Cracked in ~ 3 months
🟢 Best:    "C0rrect-H0rse-B@ttery-St@ple!" → Years!
```

**Password Policy Best Practices:**
```
┌────────────────────────────────────────────────────┐
│  Password Policy Checklist:                        │
│                                                    │
│  ✓ ความยาวขั้นต่ำ: 12 ตัวอักษร                          │
│  ✓ ต้องมี: ตัวพิมพ์ใหญ่, เล็ก, ตัวเลข, สัญลักษณ์              │
│  ✓ ห้ามใช้รหัสผ่านเก่าซ้ำ (Password History)             │
│  ✓ บังคับเปลี่ยนรหัสผ่านทุก 90 วัน (ถ้าจำเป็น)               │
│  ✓ Lock Account หลัง Login ผิด 5 ครั้ง                 │
│  ✓ รองรับ MFA (Multi-Factor Authentication)         │
└────────────────────────────────────────────────────┘
```

#### 2.2.2 Multi-Factor Authentication (MFA)

```
       ┌─────────────────────────────────────┐
       │      🔐 MFA = 3 Factors             │
       └──────────────┬──────────────────────┘
                      │
       ┌──────────────┼──────────────┐
       │              │              │
  ┌────▼────┐   ┌────▼────┐   ┌────▼────┐
  │Something│   │Something│   │Something│
  │You KNOW │   │You HAVE │   │You ARE  │
  └─────────┘   └─────────┘   └─────────┘
       │              │              │
  • Password    • Phone OTP    • Fingerprint
  • PIN         • Hardware     • Face ID
                  Token         • Iris Scan

  💡 Best Practice: ใช้อย่างน้อย 2 factors!
```

### 2.3 Authorization (Access Control)

#### 2.3.1 File Permissions ใน Linux

```bash
# ตัวอย่าง Linux File Permissions
$ ls -la /home/user/document.txt
-rw-r--r-- 1 user staff 1024 Dec 15 10:00 document.txt
│││││││││
││││││││└─ Others: read only (r--)
│││││││└── Group: read only (r--)
││││││└─── Owner: read+write (rw-)
│││││└──── Links count
││││└───── Group name (staff)
│││└────── Owner name (user)
││└─────── File type (- = regular file)
│└──────── Permissions string
```

**Permission Bits:**
```
┌──────────────────────────────────────────┐
│  r = Read    (4)   │  4 + 2 + 1 = 7      │
│  w = Write   (2)   │  4 + 0 + 1 = 5      │
│  x = Execute (1)   │  4 + 2 + 0 = 6      │
└──────────────────────────────────────────┘

ตัวอย่าง:
  chmod 755 script.sh
        ││└─ Others: r-x (5)
        │└── Group:   r-x (5)
        └─── Owner:   rwx (7)
```

#### 2.3.2 Windows Access Control Lists (ACL)

```
┌──────────────────────────────────────────────┐
│      Windows Permissions Types               │
├──────────────────────────────────────────────┤
│  • Full Control      (ทำทุกอย่างได้)            │
│  • Modify            (แก้ไข + ลบได้)           │
│  • Read & Execute    (อ่าน + รันได้)            │
│  • Read              (อ่านอย่างเดียว)           │
│  • Write             (เขียนอย่างเดียว)          │
│  • Special Permissions (กำหนดเอง)            │
└──────────────────────────────────────────────┘

💡 Best Practice:
   • ใช้ Groups แทนการกำหนดสิทธิ์ให้ user ตรง ๆ
   • ปฏิบัติตามหลัก Least Privilege
```

---

## 👤 Part 3: User Privilege Management

### 3.1 Principle of Least Privilege

```
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║   🎯 Least Privilege Principle                        ║
║                                                       ║
║   "ให้สิทธิ์เท่าที่จำเป็นในการทำงานเท่านั้น"                     ║
║   (Give only the minimum permissions needed)          ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝
```

**ตัวอย่างการละเมิดหลักนี้:**
```
❌ BAD:
   Developer ใช้ root/admin account ในการเขียนโค้ดทุกวัน
   → ถ้า malware ทำงานในชื่อ root = ทุกอย่างพัง!

✅ GOOD:
   Developer ใช้ user account ธรรมดา
   → ใช้ sudo/Run as Admin เฉพาะเมื่อจำเป็น
   → ถ้า malware ทำงานในชื่อ user = จำกัดความเสียหาย
```

### 3.2 ประเภทของ User Accounts

```
    ┌─────────────────────────────────────────┐
    │         User Account Types              │
    └──────────────┬──────────────────────────┘
                   │
    ┌──────────────┼──────────────┐
    │              │              │
┌───▼────┐     ┌───▼───┐     ┌───▼────┐
│Standard│     │ Admin │     │ System │
│ User   │     │ User  │     │Account │
└────────┘     └───────┘     └────────┘
    │              │              │
• ใช้งาน     • ติดตั้ง       • Services
  ทั่วไป       โปรแกรม        • Processes
• เข้าถึง     • เปลี่ยน       • Background
  ข้อมูลตัวเอง  การตั้งค่า      Tasks
• จำกัด       ระบบ
  สิทธิ์       • จัดการ user
```

### 3.3 Linux: sudo Command

```bash
# 🔹 sudo = "SuperUser DO"
# ให้สิทธิ์ชั่วคระว่างในการทำงานแบบ root

# ตัวอย่างการใช้งาน:
$ sudo apt update                    # Update package list
$ sudo systemctl restart apache2     # Restart web server
$ sudo cat /etc/shadow               # Read sensitive file

# การตั้งค่า sudoers file (/etc/sudoers)
username  ALL=(ALL:ALL) ALL
  │        │   │   │    │
  │        │   │   │    └─ สามารถรันคำสั่งอะไรก็ได้
  │        │   │   └────── ในนามของ group ไหนก็ได้
  │        │   └────────── ในนามของ user ไหนก็ได้
  │        └────────────── บน host ไหนก็ได้
  └─────────────────────── username ที่ได้รับสิทธิ์

# 💡 Best Practice: ใช้ sudo แทน su (switch user)
# เพราะมี logging และควบคุมได้ละเอียดกว่า
```

**sudoers Configuration Examples:**
```bash
# Allow user to run specific commands without password
john ALL=(ALL) NOPASSWD: /usr/bin/apt update, /usr/bin/apt upgrade

# Allow group to run all commands
%admin ALL=(ALL:ALL) ALL

# Allow user to restart apache only
webadmin ALL=(ALL) NOPASSWD: /usr/sbin/service apache2 restart
```

### 3.4 Windows: Run as Administrator / UAC

```
┌────────────────────────────────────────────────────┐
│  User Account Control (UAC) ใน Windows             │
├────────────────────────────────────────────────────┤
│                                                    │
│  ┌──────────────────────────────────────────────┐  │
│  │  ⚠️  User Account Control                    │  │
│  │                                              │  │
│  │  Do you want to allow this app to make       │  │
│  │  changes to your device?                     │  │
│  │                                              │  │
│  │  Program: cmd.exe                            │  │
│  │  Verified publisher: Microsoft Corporation   │  │
│  │                                              │  │
│  │       [Yes]              [No]                │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│ 💡 UAC Levels:                                     │
│    1. Always notify (Most secure)                  │
│    2. Notify only when apps try to make changes    │
│    3. Same as 2 but no dimming                     │
│    4. Never notify (Least secure - NOT RECOMMENDED)│
└────────────────────────────────────────────────────┘
```

---

## 🔍 Part 4: เปรียบเทียบ Security Model - Windows vs Linux

### 4.1 ภาพรวมความแตกต่าง

```
╔═════════════════════════════════════════════════════════════════╗
║               Windows vs Linux Security                         ║
╠═════════════════════════════════════════════════════════════════╣
║                                                                 ║
║  Aspect          │  Windows              │  Linux               ║
║  ────────────────┼───────────────────────┼──────────────────────║
║  Users           │  Local Users          │  /etc/passwd         ║
║                  │  Domain Users (AD)    │  LDAP/NIS            ║
║  ────────────────┼───────────────────────┼──────────────────────║
║  Permissions     │  ACL (Access Control  │  Permission Bits     ║
║                  │  Lists)               │  (rwx + ACL)         ║
║  ────────────────┼───────────────────────┼──────────────────────║
║  Admin Account   │  Administrator        │  root                ║
║  ────────────────┼───────────────────────┼──────────────────────║
║  Elevation       │  UAC / Run as Admin   │  sudo / su           ║
║  ────────────────┼───────────────────────┼──────────────────────║
║  Firewall        │  Windows Defender     │  iptables / ufw      ║
║                  │  Firewall             │  firewalld           ║
║  ────────────────┼───────────────────────┼──────────────────────║
║  Updates         │  Windows Update       │  apt / yum / dnf     ║
║  ────────────────┼───────────────────────┼──────────────────────║
║  Security Tools  │  Event Viewer         │  syslog / journalctl ║
║                  │  Security Center      │  fail2ban            ║
║                                                                 ║
╚═════════════════════════════════════════════════════════════════╝
```

### 4.2 การจัดการ User Accounts

#### Windows:
```powershell
# สร้าง user ใหม่
net user john P@ssw0rd123! /add

# เพิ่ม user เข้า Administrators group
net localgroup Administrators john /add

# ดูรายชื่อ users
net user

# ลบ user
net user john /delete

# บังคับเปลี่ยน password ครั้งหน้า
net user john /logonpasswordchg:yes
```

#### Linux:
```bash
# สร้าง user ใหม่
sudo useradd -m -s /bin/bash john

# ตั้ง password
sudo passwd john

# เพิ่ม user เข้า sudo group
sudo usermod -aG sudo john

# ดูข้อมูล user
id john
groups john

# ลบ user (รวมทั้ง home directory)
sudo userdel -r john

# Lock/Unlock account
sudo usermod -L john    # Lock
sudo usermod -U john    # Unlock
```

### 4.3 File/Folder Permissions

#### Windows (PowerShell):
```powershell
# ดู permissions
Get-Acl C:\SecretFolder | Format-List

# กำหนด permissions ให้ user
$acl = Get-Acl C:\SecretFolder
$permission = "DOMAIN\User","Read","Allow"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$acl.SetAccessRule($accessRule)
Set-Acl C:\SecretFolder $acl

# เอา permissions ของ user ออก
icacls C:\SecretFolder /remove DOMAIN\User
```

#### Linux:
```bash
# เปลี่ยน permissions (symbolic)
chmod u+rwx,g+rx,o+r file.txt    # User: rwx, Group: rx, Others: r

# เปลี่ยน permissions (numeric)
chmod 754 file.txt                # User: rwx(7), Group: rx(5), Others: r(4)

# เปลี่ยน owner
chown john:developers file.txt    # Owner: john, Group: developers

# Recursive change
chmod -R 750 /var/www/html       # เปลี่ยนทั้ง folder และ subfolder
```

---

## 🛡️ Part 5: OS Hardening (การเสริมความแข็งแกร่งระบบ)

### 5.1 OS Hardening คืออะไร?

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║  🔧 OS Hardening = การทำให้ OS ปลอดภัยขึ้น                    ║
║                                                           ║
║  • ลดพื้นที่โจมตี (Attack Surface)                             ║
║  • ปิดช่องโหว่ที่ไม่จำเป็น                                       ║
║  • ตั้งค่าระบบให้เป็น Secure by Default                        ║
║  • ทำให้ Hacker เจาะยากขึ้น                                  ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
```

### 5.2 OS Hardening Checklist

```
    ┌─────────────────────────────────────────────┐
    │      🛡️ OS Hardening Checklist              │
    └──────────────┬──────────────────────────────┘
                   │
    ┌──────────────┼──────────────┐
    │              │              │
┌───▼─────┐   ┌────▼─────┐   ┌─────▼─────┐
│ Users   │   │Services  │   │ Updates   │
│         │   │          │   │           │
│ • Least │   │ • Disable│   │ • Apply   │
│   Priv  │   │   unused │   │   patches │
│ • Strong│   │ • Minimal│   │ • Auto    │
│   PWD   │   │   install│   │   update  │
│ • MFA   │   │          │   │           │
└─────────┘   └──────────┘   └───────────┘
    │              │               │
┌───▼─────┐   ┌────▼─────┐   ┌─────▼─────┐
│Firewall │   │ Logging  │   │  Backup   │
│         │   │          │   │           │
│ • Block │   │ • Enable │   │ • Regular │
│   ports │   │   audit  │   │ • Offsite │
│ • Allow │   │ • Monitor│   │ • Tested  │
│   needed│   │   events │   │           │
└─────────┘   └──────────┘   └───────────┘
```

### 5.3 Password Policy Configuration

#### Windows (via Local Security Policy):
```
┌────────────────────────────────────────────────────┐
│  Windows → secpol.msc → Account Policies           │
├────────────────────────────────────────────────────┤
│                                                    │
│  Password Policy:                                  │
│  ✓ Enforce password history: 24 passwords          │
│  ✓ Maximum password age: 90 days                   │
│  ✓ Minimum password age: 1 day                     │
│  ✓ Minimum password length: 12 characters          │
│  ✓ Password must meet complexity requirements      │
│  ✓ Store passwords using reversible encryption: ❌ │
│                                                    │
│  Account Lockout Policy:                           │
│  ✓ Account lockout duration: 30 minutes            │
│  ✓ Account lockout threshold: 5 invalid attempts   │
│  ✓ Reset account lockout counter after: 30 min     │
└────────────────────────────────────────────────────┘
```

#### Linux (via PAM - Pluggable Authentication Modules):
```bash
# Edit /etc/pam.d/common-password

# ตั้งค่า password complexity
password requisite pam_pwquality.so retry=3 minlen=12 \
         dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1
         # dcredit=-1: ต้องมีตัวเลขอย่างน้อย 1 ตัว
         # ucredit=-1: ต้องมีตัวพิมพ์ใหญ่อย่างน้อย 1 ตัว
         # ocredit=-1: ต้องมีสัญลักษณ์อย่างน้อย 1 ตัว
         # lcredit=-1: ต้องมีตัวพิมพ์เล็กอย่างน้อย 1 ตัว

# ตั้งค่า password expiry
sudo chage -M 90 -m 1 -W 7 john
#         │    │    └─ แจ้งเตือนก่อน 7 วัน
#         │    └────── เปลี่ยนได้หลัง 1 วัน
#         └─────────── expire ภายใน 90 วัน

# ดูการตั้งค่า
sudo chage -l john
```

### 5.4 การปิด Services ที่ไม่จำเป็น

#### Windows:
```powershell
# ดู services ที่กำลังทำงาน
Get-Service | Where-Object {$_.Status -eq "Running"}

# ปิด service ที่ไม่จำเป็น
Stop-Service -Name "RemoteRegistry"
Set-Service -Name "RemoteRegistry" -StartupType Disabled

# ตัวอย่าง services ที่อาจปิดได้:
# - Remote Registry (RemoteRegistry)
# - Print Spooler (Spooler) - ถ้าไม่ใช้ printer
# - Windows Search (WSearch) - ถ้าไม่ต้องการ indexing
# - Bluetooth Support Service - ถ้าไม่มี Bluetooth

# ⚠️ ระวัง: อย่าปิด services สำคัญ เช่น:
# - Windows Update
# - Windows Defender
# - Windows Firewall
```

#### Linux:
```bash
# ดู services ที่กำลังทำงาน (systemd)
systemctl list-units --type=service --state=running

# ปิด service
sudo systemctl stop service_name
sudo systemctl disable service_name

# ตัวอย่าง services ที่อาจปิดได้:
sudo systemctl disable cups          # Print service (ถ้าไม่พิมพ์)
sudo systemctl disable bluetooth     # Bluetooth
sudo systemctl disable avahi-daemon  # Zeroconf networking

# ดู network services ที่เปิด port
sudo netstat -tulpn
# หรือ
sudo ss -tulpn

# ⚠️ ระวัง: อย่าปิด services สำคัญ เช่น:
# - sshd (ถ้าต้องการ remote access)
# - network services
# - cron (scheduled tasks)
```

### 5.5 Firewall Configuration

#### Windows Firewall:
```powershell
# ดูสถานะ firewall
Get-NetFirewallProfile | Select-Object Name, Enabled

# เปิด firewall สำหรับทุก profile
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Block inbound connections (default deny)
Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow

# อนุญาต SSH (Port 22) - ตัวอย่าง
New-NetFirewallRule -DisplayName "Allow SSH" -Direction Inbound `
    -Protocol TCP -LocalPort 22 -Action Allow

# Block specific port
New-NetFirewallRule -DisplayName "Block Port 23" -Direction Inbound `
    -Protocol TCP -LocalPort 23 -Action Block

# ดู firewall rules
Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true}
```

#### Linux (UFW - Uncomplicated Firewall):
```bash
# ติดตั้ง UFW (Ubuntu/Debian)
sudo apt install ufw

# เปิดใช้งาน firewall
sudo ufw enable

# ตั้งค่า default policies
sudo ufw default deny incoming   # ปิดการเข้าทั้งหมด (default deny)
sudo ufw default allow outgoing  # อนุญาตการออกทั้งหมด

# อนุญาต services ที่จำเป็น
sudo ufw allow ssh              # Port 22 (SSH)
sudo ufw allow 80/tcp           # Port 80 (HTTP)
sudo ufw allow 443/tcp          # Port 443 (HTTPS)

# อนุญาต specific IP
sudo ufw allow from 192.168.1.100 to any port 22

# ดูสถานะ
sudo ufw status numbered

# ลบ rule
sudo ufw delete [number]

# 💡 Best Practice: Default Deny!
```

#### Linux (iptables - Advanced):
```bash
# ดู rules ปัจจุบัน
sudo iptables -L -v -n

# ล้าง rules ทั้งหมด (ระวัง!)
sudo iptables -F

# ตั้งค่า default policies
sudo iptables -P INPUT DROP      # Drop ทุกอย่างที่เข้ามา
sudo iptables -P FORWARD DROP    # Drop forward
sudo iptables -P OUTPUT ACCEPT   # อนุญาตออกทั้งหมด

# อนุญาต loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# อนุญาต established connections
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# อนุญาต SSH
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# บันทึก rules (Ubuntu/Debian)
sudo iptables-save > /etc/iptables/rules.v4
```

---

## 💻 Part 6: Lab Exercise - OS Hardening

### 6.1 Lab Overview

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║          🧪 Lab 1: OS Hardening Exercise                  ║
║                                                           ║
║  เป้าหมาย: ทำ security hardening บน VM                     ║
║  เวลา: 60-90 นาที                                          ║
║  เครื่องมือ: VirtualBox/VMware + Windows/Linux VM            ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
```

### 6.2 Lab Tasks (Windows)

#### Task 1: สร้าง User Accounts
```powershell
# 1. สร้าง standard user
net user john SecureP@ss123! /add
net user jane SecureP@ss456! /add

# 2. สร้าง admin user
net user admin_john SecureP@ss789! /add
net localgroup Administrators admin_john /add

# 3. Disable Guest account
net user Guest /active:no

# 4. ตรวจสอบ users
net user
```

#### Task 2: ตั้ง Password Policy
```
1. เปิด "Local Security Policy" (secpol.msc)
2. ไปที่ Account Policies → Password Policy
3. ตั้งค่าตาม checklist:
   • Enforce password history: 5 passwords
   • Maximum password age: 90 days
   • Minimum password length: 12 characters
   • Password must meet complexity requirements: Enabled

4. ไปที่ Account Policies → Account Lockout Policy
   • Account lockout threshold: 3 invalid attempts
   • Account lockout duration: 30 minutes
   • Reset account lockout counter after: 30 minutes

5. Apply และ Screenshot
```

#### Task 3: ปิด Unnecessary Services
```powershell
# ดู services ที่ทำงาน
Get-Service | Where-Object {$_.Status -eq "Running"} | 
    Select-Object Name, DisplayName

# ปิด Remote Registry (ตัวอย่าง)
Stop-Service -Name "RemoteRegistry"
Set-Service -Name "RemoteRegistry" -StartupType Disabled

# ปิด Telnet (ถ้ามี)
Stop-Service -Name "TlntSvr" -ErrorAction SilentlyContinue
Set-Service -Name "TlntSvr" -StartupType Disabled -ErrorAction SilentlyContinue

# Screenshot services ที่ปิดไป
```

#### Task 4: ตั้งค่า Windows Firewall
```powershell
# เปิด firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# ตั้ง default deny
Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow

# อนุญาต services ที่จำเป็น
# (ตัวอย่าง: อนุญาต RDP ถ้าจำเป็น)
New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound `
    -Protocol TCP -LocalPort 3389 -Action Allow -Profile Private

# ดูสถานะ
Get-NetFirewallProfile | Select-Object Name, Enabled
```

### 6.3 Lab Tasks (Linux/Ubuntu)

#### Task 1: สร้าง User Accounts
```bash
# 1. สร้าง standard user
sudo useradd -m -s /bin/bash john
sudo passwd john
# Enter: SecureP@ss123!

sudo useradd -m -s /bin/bash jane
sudo passwd jane
# Enter: SecureP@ss456!

# 2. สร้าง admin user
sudo useradd -m -s /bin/bash admin_john
sudo passwd admin_john
sudo usermod -aG sudo admin_john

# 3. ตรวจสอบ users
cat /etc/passwd | grep -E "john|jane"
groups admin_john

# 4. Disable root login via SSH (ในไฟล์ /etc/ssh/sshd_config)
sudo nano /etc/ssh/sshd_config
# เปลี่ยน: PermitRootLogin no
sudo systemctl restart sshd
```

#### Task 2: ตั้ง Password Policy
```bash
# 1. ติดตั้ง libpam-pwquality (ถ้ายังไม่มี)
sudo apt install libpam-pwquality

# 2. แก้ไข /etc/pam.d/common-password
sudo nano /etc/pam.d/common-password

# เพิ่มบรรทัด:
password requisite pam_pwquality.so retry=3 minlen=12 \
         dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1

# 3. ตั้งค่า password expiry
sudo chage -M 90 -m 1 -W 7 john
sudo chage -M 90 -m 1 -W 7 jane

# 4. ตรวจสอบ
sudo chage -l john

# 5. ตั้งค่า account lockout (ใช้ faillock)
sudo nano /etc/pam.d/common-auth

# เพิ่ม:
auth required pam_faillock.so preauth silent audit deny=3 unlock_time=1800
auth required pam_faillock.so authfail audit deny=3 unlock_time=1800
```

#### Task 3: ปิด Unnecessary Services
```bash
# 1. ดู services ที่ทำงาน
systemctl list-units --type=service --state=running

# 2. ปิด services ที่ไม่จำเป็น (ตัวอย่าง)
sudo systemctl stop bluetooth
sudo systemctl disable bluetooth

sudo systemctl stop cups
sudo systemctl disable cups

# 3. ตรวจสอบ network services
sudo netstat -tulpn
# หรือ
sudo ss -tulpn

# 4. บันทึกผลลัพธ์
systemctl list-units --type=service --state=running > services_after.txt
```

#### Task 4: ตั้งค่า UFW Firewall
```bash
# 1. ติดตั้ง UFW
sudo apt install ufw

# 2. ตั้งค่า default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# 3. อนุญาต SSH (สำคัญ! ไม่งั้นเข้า VM ไม่ได้)
sudo ufw allow ssh
# หรือ
sudo ufw allow 22/tcp

# 4. อนุญาต services อื่น ๆ ตามต้องการ
# ตัวอย่าง:
# sudo ufw allow 80/tcp   # HTTP
# sudo ufw allow 443/tcp  # HTTPS

# 5. เปิดใช้งาน firewall
sudo ufw enable

# 6. ตรวจสอบสถานะ
sudo ufw status verbose

# 7. Screenshot
```

### 6.4 Lab Report Template

```markdown
# Lab 1 Report: OS Hardening

## ข้อมูลนักศึกษา
- ชื่อ: _________________
- รหัส: ________________
- วันที่ทำ Lab: _________

## 1. VM Information
- OS: [ ] Windows / [ ] Linux (Ubuntu)
- Version: _______________
- VM Software: [ ] VirtualBox / [ ] VMware

## 2. User Account Management

### 2.1 Users Created
| Username    | Type          | Groups              |
|-------------|---------------|---------------------|
| john        | Standard User | -                   |
| jane        | Standard User | -                   |
| admin_john  | Admin User    | Administrators/sudo |

**Screenshot:** [แนบ screenshot ของ user list]

### 2.2 Password Policy
- Minimum length: ___ characters
- Complexity: [ ] Enabled
- Password history: ___ passwords
- Account lockout threshold: ___ attempts

**Screenshot:** [แนบ screenshot ของการตั้งค่า]

## 3. Services Management

### 3.1 Services Disabled
| Service Name      | Reason                          |
|-------------------|---------------------------------|
| RemoteRegistry    | ไม่จำเป็นสำหรับการใช้งานปกติ         |
| Bluetooth         | ไม่มี Bluetooth device            |
| ...               | ...                             |

**Screenshot:** [แนบ screenshot ของ services list]

## 4. Firewall Configuration

### 4.1 Firewall Rules
| Direction | Port  | Protocol | Action | Purpose    |
|-----------|-------|----------|--------|------------|
| Inbound   | 22    | TCP      | Allow  | SSH        |
| Inbound   | 80    | TCP      | Allow  | HTTP       |
| Inbound   | *     | *        | Deny   | Default    |

**Screenshot:** [แนบ screenshot ของ firewall rules]

## 5. Verification & Testing

### 5.1 Password Policy Test
- ลองสร้าง password ที่อ่อนแอ: [ ] Rejected / [ ] Accepted
- ลอง login ผิด 3 ครั้ง: [ ] Account locked / [ ] Not locked

### 5.2 Firewall Test
- ลอง connect ไป port ที่ blocked: [ ] Blocked / [ ] Allowed
- ลอง connect ไป port ที่ allowed: [ ] Success / [ ] Failed

## 6. บทสรุปและข้อสังเกต

[เขียนสรุปสิ่งที่ได้เรียนรู้จาก Lab นี้ ความยากง่าย และข้อควรระวัง]

**ลายเซ็น:** ________________
**วันที่:** __________________
```

---

## ❓ คำถามและคำตอบสำหรับทบทวน

### Q1: ทำไมต้องใช้ Least Privilege?
```
คำตอบ:
เพื่อลดความเสียหายถ้าเกิด account ถูกเจาะ
ถ้าใช้ user ธรรมดา malware ที่ทำงานจะมีสิทธิ์จำกัด
แต่ถ้าใช้ admin/root malware ก็จะมีสิทธิ์เต็ม = อันตรายมาก!

ตัวอย่างจริง:
• WannaCry Ransomware แพร่กระจายได้เร็ว
  เพราะหลายเครื่องใช้ admin account ในการทำงานปกติ
• ถ้าใช้ standard user จะจำกัดการแพร่กระจาย
```

### Q2: sudo vs su ต่างกันอย่างไร?
```
คำตอบ:

sudo (SuperUser DO):
✓ รันคำสั่งเดียวด้วยสิทธิ์ root
✓ ต้องใส่ password ของตัวเอง
✓ มี logging (บันทึกว่าใครทำอะไร)
✓ สามารถจำกัดคำสั่งที่รันได้
✓ แนะนำให้ใช้!

su (Switch User):
✗ เปลี่ยนเป็น root user ทั้ง session
✗ ต้องใส่ password ของ root
✗ ไม่มี logging ละเอียด
✗ ไม่สามารถจำกัดคำสั่งได้
✗ อันตรายกว่า

Best Practice: ใช้ sudo แทน su
```

### Q3: Default Deny vs Default Allow - ควรใช้แบบไหน?
```
คำตอบ: Default Deny!

Default Deny (แนะนำ):
✓ ปิดทุก port
✓ เปิดเฉพาะที่จำเป็น
✓ ปลอดภัยกว่า
✓ ถ้าลืมตั้งค่า = ปลอดภัย

Default Allow:
✗ เปิดทุก port
✗ ปิดเฉพาะที่อันตราย
✗ อันตรายกว่า
✗ ถ้าลืมตั้งค่า = เสี่ยง!

หลักการ:
"ปฏิเสธทุกอย่างก่อน แล้วค่อยอนุญาตที่จำเป็น"
(Deny by default, allow by exception)
```

### Q4: รหัสผ่านยาวกว่า vs ซับซ้อนกว่า - อันไหนดีกว่า?
```
คำตอบ: ยาวกว่า (Length > Complexity)!

เปรียบเทียบ:
🔴 Weak:    P@ssw0rd          (8 chars, complex)
                              → Cracked in ~ 3 days

🟢 Strong:  correcthorsebatterystaple (28 chars, simple)
                              → Cracked in ~ millions of years!

ทำไม?
• ความยาว เพิ่ม possibilities แบบ exponential
• Complexity เพิ่ม possibilities แบบ linear

Best Practice:
✓ ใช้ passphrase (วลียาว ๆ จำง่าย)
✓ ความยาวอย่างน้อย 12-16 ตัวอักษร
✓ ใช้ Password Manager
```

### Q5: ควร update OS บ่อยแค่ไหน?
```
คำตอบ: บ่อยที่สุดเท่าที่จะทำได้!

Critical Security Patches: ทันที! (within 24-48 hours)
Regular Updates: ทุกสัปดาห์-เดือน
Feature Updates: ตามแผนของ IT

ทำไมต้องรีบ?
• Zero-day vulnerabilities ถูก exploit ภายใน hours
• Automated attacks scan for unpatched systems
• ยิ่งรอนาน ยิ่งเสี่ยง

Best Practices:
✓ เปิด automatic updates สำหรับ security patches
✓ Test updates ใน non-production ก่อน
✓ Backup ก่อน update
✓ มี rollback plan
```

---

## 🚀 Part 7: Case Study - Real-World OS Security Incidents

### Case Study 1: WannaCry Ransomware (2017)

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║         💀 WannaCry Ransomware Attack                     ║
║                                                           ║
║  วันที่: พฤษภาคม 2017                                        ║
║  เหยื่อ: 200,000+ เครื่องใน 150 ประเทศ                        ║
║  ความเสียหาย: หลายพันล้านดอลลาร์                              ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

สาเหตุ:
• Exploit ช่องโหว่ EternalBlue ใน Windows SMBv1
• Microsoft ออก patch (MS17-010) มา 2 เดือนก่อน
• แต่หลายองค์กรไม่ได้ update!

ผลกระทบ:
• โรงพยาบาล NHS (UK): ยกเลิกการผ่าตัด
• Renault (France): หยุดการผลิต
• FedEx: ระบบล่ม

บทเรียน:
✓ Update/Patch ทันที!
✓ Backup data สม่ำเสมอ
✓ ปิด services ที่ไม่จำเป็น (SMBv1)
✓ Network Segmentation
```

### Case Study 2: Misconfigured AWS S3 Bucket (2019)

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║      ☁️ Capital One Data Breach                           ║
║                                                           ║
║  วันที่: มีนาคม 2019                                          ║
║  ข้อมูลรั่วไหล: 100 ล้านคน                                     ║
║  สาเหตุ: Misconfigured Firewall                            ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

สาเหตุ:
• AWS Firewall (Security Groups) ตั้งค่าผิดพลาด
• อนุญาตให้ access จาก internet ได้
• ไม่มี proper logging/monitoring

บทเรียน:
✓ Review firewall rules สม่ำเสมอ
✓ ใช้ Infrastructure as Code (IaC) มี version control
✓ Enable logging และ monitoring
✓ Regular security audits
✓ Principle of Least Privilege - ใช้กับ firewall ด้วย!
```

### Case Study 3: SolarWinds Supply Chain Attack (2020)

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        🔴 SolarWinds Orion Compromise                     ║
║                                                           ║
║  วันที่: มีนาคม-ธันวาคม 2020                                   ║
║  เหยื่อ: 18,000+ organizations                              ║
║  ผู้โจมตี: APT29 (รัฐบาลรัสเซีย - สันนิษฐาน)                      ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

วิธีการโจมตี:
1. ฝัง backdoor ใน SolarWinds Orion software update
2. องค์กรต่าง ๆ install update ที่มี malware
3. Malware ได้ admin privileges
4. ขโมยข้อมูลเป็นเวลานาน (9 months!)

บทเรียน:
✓ Trust but Verify - แม้ software update
✓ Monitor privileged accounts activities
✓ Network segmentation (Zero Trust)
✓ Principle of Least Privilege - แม้ admin accounts
✓ Regular security audits
```

---

## 📊 Part 8: OS Hardening Standards & Frameworks

### 8.1 CIS Benchmarks

```
┌─────────────────────────────────────────────────────────┐
│  CIS (Center for Internet Security) Benchmarks          │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  • แนวทางการตั้งค่าความปลอดภัยที่เป็นมาตรฐาน                   │
│  • มีให้สำหรับ OS หลากหลาย:                                │
│    - Windows 10, 11, Server                             │
│    - Ubuntu, RHEL, CentOS                               │
│    - macOS, AWS, Azure, GCP                             │
│                                                         │
│  Levels:                                                │
│  • Level 1: Basic (ไม่กระทบการใช้งาน)                     │
│  • Level 2: Advanced (security > convenience)           │
│                                                         │
│  📥 Download: https://www.cisecurity.org/cis-benchmarks │
└─────────────────────────────────────────────────────────┘
```

**ตัวอย่าง CIS Controls:**
```
1. Inventory and Control of Enterprise Assets
   → รู้ว่ามีเครื่องไหนบ้าง ทำอะไร

2. Inventory and Control of Software Assets
   → รู้ว่าติดตั้ง software อะไรบ้าง

3. Data Protection
   → Encrypt sensitive data

4. Secure Configuration of Enterprise Assets
   → Harden OS, disable unnecessary services

5. Account Management
   → Least Privilege, MFA, Password Policy

6. Access Control Management
   → RBAC, Regular review

7. Continuous Vulnerability Management
   → Scan, Patch, Monitor

... (18 controls ทั้งหมด)
```

### 8.2 NIST Cybersecurity Framework

```
┌────────────────────────────────────────────────────┐
│  NIST Framework - 5 Core Functions                 │
├────────────────────────────────────────────────────┤
│                                                    │
│  1. IDENTIFY (ระบุ)                                 │
│     • Asset Management                             │
│     • Risk Assessment                              │
│                                                    │
│  2. PROTECT (ป้องกัน)    ◄── OS Hardening ที่นี่!        │
│     • Access Control                               │
│     • Data Security                                │
│     • Protective Technology                        │
│                                                    │
│  3. DETECT (ตรวจจับ)                                │
│     • Monitoring                                   │
│     • Detection Processes                          │
│                                                    │
│  4. RESPOND (ตอบสนอง)                              │
│     • Incident Response Plan                       │
│     • Communications                               │
│                                                    │
│  5. RECOVER (กู้คืน)                                  │
│     • Recovery Planning                            │
│     • Improvements                                 │
│                                                    │
└────────────────────────────────────────────────────┘
```

---

## 🎓 Part 9: Career Path - OS Security

### 9.1 บทบาทที่เกี่ยวข้อง

```
        ┌───────────────────────────────┐
        │  OS Security Career Paths     │
        └─────────────┬─────────────────┘
                      │
       ┌──────────────┼──────────────┐
       │              │              │
  ┌────▼─────┐   ┌────▼─────┐   ┌────▼─────┐
  │ System   │   │ Security │   │ DevSecOps│
  │ Admin    │   │ Engineer │   │ Engineer │
  └──────────┘   └──────────┘   └──────────┘

🔹 System Administrator / SysAdmin
   • จัดการ OS servers
   • ตั้งค่าความปลอดภัย
   • Monitoring และ maintenance
   Salary: 25,000 - 60,000 THB/month

🔹 Security Engineer
   • Implement security controls
   • Vulnerability management
   • Security hardening
   Salary: 40,000 - 100,000 THB/month

🔹 DevSecOps Engineer
   • Automate security
   • Infrastructure as Code
   • CI/CD security
   Salary: 50,000 - 120,000 THB/month

🔹 Penetration Tester / Red Team
   • Test OS security
   • Exploit vulnerabilities
   • Security assessments
   Salary: 45,000 - 150,000 THB/month
```

### 9.2 Skills ที่ต้องการ

```
┌────────────────────────────────────────────────────┐
│  Skills for OS Security Professionals              │
├────────────────────────────────────────────────────┤
│                                                    │
│  Technical Skills:                                 │
│  ✓ OS internals (Windows, Linux)                   │
│  ✓ Networking (TCP/IP, Firewall)                   │
│  ✓ Scripting (PowerShell, Bash, Python)            │
│  ✓ Security tools (Nmap, Wireshark, Metasploit)    │
│  ✓ Cloud platforms (AWS, Azure, GCP)               │
│  ✓ Automation (Ansible, Terraform)                 │
│                                                    │
│  Certifications:                                   │
│  • CompTIA Security+                               │
│  • CompTIA Linux+                                  │
│  • Microsoft MCSA/MCSE                             │
│  • Red Hat RHCSA/RHCE                              │
│  • (ISC)² CISSP                                    │
│  • Offensive Security OSCP                         │
│                                                    │
└────────────────────────────────────────────────────┘
```

---

## 📚 Part 10: Additional Resources

### 10.1 Online Tools & Resources

```
🔧 Security Scanning Tools:
   • Lynis        - Linux security auditing
   • Windows Baseline Security Analyzer
   • OpenVAS      - Vulnerability scanner
   • Nessus       - Vulnerability scanner

📖 Documentation:
   • Microsoft Security Baselines
     docs.microsoft.com/en-us/windows/security
   
   • Ubuntu Security Guide
     ubuntu.com/security
   
   • CIS Benchmarks
     cisecurity.org

📺 Learning Platforms:
   • TryHackMe    - Hands-on labs
   • HackTheBox   - Pentesting practice
   • Linux Academy (A Cloud Guru)
   • Microsoft Learn

📰 Stay Updated:
   • CVE Database: cve.mitre.org
   • NVD: nvd.nist.gov
   • Krebs on Security: krebsonsecurity.com
   • The Hacker News: thehackernews.com
```

### 10.2 Recommended Reading

```
📚 Books:
1. "Linux Server Security" - Michael Boelen
2. "Windows Security Internals" - James Forshaw
3. "Practical Security" - Roman Zabicki

📄 Standards:
• NIST SP 800-123 (General Server Security)
• NIST SP 800-44 (Enterprise Patching)
• ISO 27001 (ISMS)
```

---

## 🎯 Part 11: สรุปและเตรียมตัวสัปดาห์หน้า

### 11.1 สรุป Week 4

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║           📝 Week 4 Key Takeaways                         ║
║                                                           ║
║  ✓ OS เป็นรากฐานของความปลอดภัย                              ║
║  ✓ AAA Framework: Authentication, Authorization,          ║
║    Accounting                                             ║
║  ✓ Least Privilege = ให้สิทธิ์แค่พอดี                           ║
║  ✓ OS Hardening = ลด Attack Surface                       ║
║  ✓ Default Deny > Default Allow                           ║
║  ✓ Password Policy + MFA = ป้องกันชั้นแรก                     ║
║  ✓ Disable unused services                                ║
║  ✓ Firewall = ประตูเข้าออกที่ควบคุมได้                          ║
║  ✓ Update & Patch = ซ่อมช่องโหว่                             ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
```

### 11.2 แนะนำเนื้อหาสัปดาห์หน้า

```
┌─────────────────────────────────────────────────────────┐
│                                                         │
│      🌐 Week 5: Network Security &                      │
│         Basic Packet Filtering                          │
│                                                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  หัวข้อที่จะเรียน:                                           │
│                                                         │
│  1. Network Security Concepts                           │
│     • OSI Model และ TCP/IP                              │
│     • Common Network Attacks                            │
│                                                         │
│  2. Firewall, IDS/IPS                                   │
│     • ความแตกต่างและการทำงาน                             │
│     • การตั้งค่า Firewall Rules                            │
│                                                         │
│  3. Virtual Private Network (VPN)                       │
│     • Tunneling และ Encryption                          │
│                                                         │
│  4. Network Segmentation                                │
│     • DMZ (Demilitarized Zone)                          │
│     • VLAN                                              │
│                                                         │
│  5. Lab: Packet Analysis with Wireshark                 │
│     • จับแพ็กเก็ต                                          │
│     • วิเคราะห์ traffic                                   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**Connection ระหว่าง Week 4 & 5:**
```
Week 4 (OS Security)  →  Week 5 (Network Security)
        │                        │
        │                        │
    Firewall                 Firewall
    (Host-based)            (Network-based)
        │                        │
        └────────────┬───────────┘
                     │
          Defense in Depth!
        (หลายชั้นป้องกัน)
```

---

## 📝 Assessment & Evaluation

### Quiz Questions (สำหรับทบทวน):

```
1. AAA ย่อมาจากอะไร? อธิบายแต่ละส่วน
   
2. Least Privilege Principle คืออะไร? ทำไมถึงสำคัญ?

3. เปรียบเทียบ sudo กับ su ใน Linux

4. Default Deny vs Default Allow - ควรใช้แบบไหนกับ Firewall?

5. Password Policy ที่ดีควรมีอะไรบ้าง?

6. ทำไมต้องปิด services ที่ไม่จำเป็น?

7. OS Hardening คืออะไร? ยกตัวอย่าง 5 ขั้นตอน

8. MFA คืออะไร? มีกี่ factors? ยกตัวอย่าง

9. จาก Case Study WannaCry - บทเรียนสำคัญคืออะไร?

10. CIS Benchmarks คืออะไร? ใช้ทำอะไร?
```

### Lab Assessment Criteria:

```
┌────────────────────────────────────────────────────────┐
│  Lab 1 Grading Rubric (Total: 20 points)               │
├────────────────────────────────────────────────────────┤
│                                                        │
│  1. User Account Management (5 points)                 │
│     • สร้าง users ครบ                       2 pts       │
│     • ตั้งค่า privileges ถูกต้อง                2 pts       │
│     • Screenshot และอธิบาย                  1 pt        │
│                                                        │
│  2. Password Policy Configuration (5 points)           │
│     • ตั้งค่าตาม checklist                    3 pts       │
│     • Test และ verify                      1 pt        │
│     • Screenshot                           1 pt        │
│                                                        │
│  3. Service Management (4 points)                      │
│     • ระบุ services ที่ปิด + เหตุผล             2 pts       │
│     • ปิด services ได้จริง                    1 pt        │
│     • Screenshot                           1 pt        │
│                                                        │
│  4. Firewall Configuration (4 points)                  │
│     • ตั้งค่า firewall rules                  2 pts       │
│     • Test และ verify                      1 pt        │
│     • Screenshot                           1 pt        │
│                                                        │
│  5. Report Quality (2 points)                          │
│     • ครบถ้วน ชัดเจน                         1 pt        │
│     • บทสรุปและข้อสังเกต                      1 pt        │
│                                                        │
└────────────────────────────────────────────────────────┘
```

---

## 🙏 ขอบคุณและคำถาม

```
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║  มีคำถามหรือข้อสงสัยเพิ่มเติม?                               ║
║                                                       ║
║  📧 Email: instructor@university.ac.th                ║
║  💬 Discussion Forum: [LMS Link]                      ║
║  🕐 Office Hours: ทุกวันพุธ 14:00-16:00                  ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝

        "The only secure system is one that
         is powered off, cast in a block of
         concrete and sealed in a lead-lined
         room with armed guards."
                    - Gene Spafford

┌──────────────────────────────────────────────────────┐
│  Remember:                                           │
│  • Security is a process, not a product              │
│  • Defense in Depth = หลายชั้นการป้องกัน                 │
│  • Least Privilege = ให้สิทธิ์เท่าที่จำเป็น                  │
│  • Update & Patch = ปิดช่องโหว่                         │
│  • Monitor & Review = ตรวจสอบสม่ำเสมอ                 │
└──────────────────────────────────────────────────────┘

       ขอให้ทุกคนสนุกกับการ Harden ระบบนะครับ!
              💪 Stay Secure! 🔐
```

---

**หมายเหตุ:** เอกสารนี้เป็นเวอร์ชัน 1.0 สำหรับ ENGSE214 Week 4  
**อัปเดตล่าสุด:** December 2025  
**ผู้สอน:** อาจารย์ธนิต เกตุแก้ว 
**คณะ:** วิศวกรรมศาสตร์ สาขาวิศวกรรมซอฟต์แวร์

---

## 🔗 Links & References

### Official Documentation:
- Microsoft Windows Security: https://docs.microsoft.com/en-us/windows/security
- Ubuntu Security: https://ubuntu.com/security
- Red Hat Security Guide: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening

### Tools:
- Lynis (Linux Auditing): https://cisofy.com/lynis/
- CIS-CAT (Benchmark Assessment): https://www.cisecurity.org/cybersecurity-tools/cis-cat-pro
- Windows Baseline Security Analyzer: https://www.microsoft.com/en-us/download/details.aspx?id=7558

### Standards & Frameworks:
- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- NIST SP 800-123: https://csrc.nist.gov/publications/detail/sp/800-123/final

### Learning Resources:
- TryHackMe: https://tryhackme.com
- HackTheBox: https://www.hackthebox.com
- SANS Reading Room: https://www.sans.org/reading-room

---

**จบเนื้อหา Week 4** ✅
