# สัปดาห์ที่ 4: การรักษาความปลอดภัยของระบบปฏิบัติการ

## [TASK1: LAB Assignment การรักษาความปลอดภัยของระบบปฏิบัติการ](lab.md)

---

## Slide 1: หัวข้อบรรยาย

### การรักษาความปลอดภัยของระบบปฏิบัติการ

**Operating System Security for Software Engineers**

**วัตถุประสงค์:**
- เข้าใจหลักการรักษาความปลอดภัยระบบปฏิบัติการ
- เรียนรู้ Access Control และ Authentication
- ฝึกปฏิบัติการจัดการสิทธิ์ผู้ใช้
- ตั้งค่าความปลอดภัยใน Windows และ Linux

---

## Slide 2: CIA Triad - รากฐานของความปลอดภัย

### ระบบความปลอดภัยต้องครอบคลุม 3 หลักการ

**🔒 Confidentiality (ความลับ)**
- ป้องกันการเข้าถึงข้อมูลโดยไม่ได้รับอนุญาต
- ข้อมูลส่วนตัวของผู้ใช้งานในระบบ

**✅ Integrity (ความถูกต้อง)**
- รักษาความถูกต้องและครบถ้วนของข้อมูล
- ป้องกันการแก้ไขข้อมูลโดยไม่ได้รับอนุญาต

**⚡ Availability (ความพร้อมใช้)**
- ระบบพร้อมให้บริการเมื่อต้องการ
- ป้องกัน DoS และ DDoS attacks

---

## Slide 3: ภัยคุมคามต่อระบบปฏิบัติการ

### ประเภทของภัยคุมคาม

**1. Malware**
- Virus, Worms, Trojans
- Ransomware, Spyware

**2. Unauthorized Access**
- Password attacks
- Privilege escalation

**3. Data Breach**
- การรั่วไหลของข้อมูล
- การขโมยข้อมูลสำคัญ

**4. Insider Threats**
- ภัยจากบุคลากรภายใน
- การใช้สิทธิ์ผิดประเภท

---

## Slide 4: หลักการรักษาความปลอดภัยระบบปฏิบัติการ

### 7 หลักการสำคัญ

**1. Defense in Depth**
- หลายชั้นการป้องกัน
- ไม่พึ่งระบบป้องกันชั้นเดียว

**2. Principle of Least Privilege**
- ให้สิทธิ์เท่าที่จำเป็น
- ลดความเสี่ยงจากการใช้งานผิด

**3. Fail-Safe Defaults**
- ค่าเริ่มต้นควรปลอดภัย
- ปิดบริการที่ไม่จำเป็น

**4. Complete Mediation**
- ตรวจสอบทุกการเข้าถึง
- ไม่มีช่องทางลัด

---

## Slide 5: User Account Management

### การจัดการบัญชีผู้ใช้

**Types of Accounts:**
- **Administrator/Root:** สิทธิ์เต็ม
- **Standard User:** สิทธิ์ปกติ
- **Service Account:** สำหรับบริการ
- **Guest Account:** สิทธิ์จำกัด

**Best Practices:**
- แยก user แต่ละคน
- ใช้ strong password
- เปิดใช้ account lockout policy
- ปิด/ลบ account ที่ไม่ใช้

---

## Slide 6: Password Security

### การสร้างรหัสผ่านที่ปลอดภัย

**📏 ความยาว:** อย่างน้อย 12 ตัวอักษร

**🔤 ความซับซ้อน:**
- ตัวพิมพ์เล็ก (a-z)
- ตัวพิมพ์ใหญ่ (A-Z) 
- ตัวเลข (0-9)
- อักขระพิเศษ (!@#$%^&*)

**❌ สิ่งที่ควรหลีกเลี่ยง:**
- password, 123456, admin
- วันเกิด, ชื่อ, เบอร์โทร
- ใช้รหัสเดิมหลายระบบ

---

## Slide 7: Multi-Factor Authentication (MFA)

### การยืนยันตัวตนหลายขั้น

**Something you know**
- Password, PIN

**Something you have**
- Smartphone, Token, Smart card

**Something you are**
- Fingerprint, Face recognition, Retina

**ตัวอย่างการใช้งาน:**
- SMS OTP
- Google Authenticator
- Hardware tokens
- Biometric scanners

---

## Slide 8: Access Control Models

### แบบจำลองการควบคุมการเข้าถึง

**1. Discretionary Access Control (DAC)**
- เจ้าของข้อมูลกำหนดสิทธิ์
- ยืดหยุ่น แต่ความปลอดภัยน้อย
- ใช้ใน Windows, Linux

**2. Mandatory Access Control (MAC)**
- ระบบกำหนดสิทธิ์
- ความปลอดภัยสูง แต่ยืดหยุ่นน้อย
- ใช้ใน SELinux, AppArmor

**3. Role-Based Access Control (RBAC)**
- กำหนดสิทธิ์ตาม role
- เหมาะกับองค์กรขนาดใหญ่

---

## Slide 9: Linux Permission System

### ระบบสิทธิ์ใน Linux

**File Permissions:**
```bash
rwx rwx rwx
│   │   └── Others
│   └────── Group  
└────────── Owner
```

**Permission Values:**
- **r (read):** 4
- **w (write):** 2  
- **x (execute):** 1

**ตัวอย่าง:**
```bash
chmod 755 script.sh  # rwxr-xr-x
chmod 644 data.txt   # rw-r--r--
chmod 600 secret.key # rw-------
```

---

## Slide 10: Advanced Linux Permissions

### Special Permissions

**SUID (Set User ID)**
```bash
chmod u+s /usr/bin/passwd
ls -l /usr/bin/passwd
# -rwsr-xr-x
```

**SGID (Set Group ID)**
```bash
chmod g+s /shared/directory
```

**Sticky Bit**
```bash
chmod +t /tmp
ls -ld /tmp
# drwxrwxrwt
```

**Access Control Lists (ACL)**
```bash
setfacl -m u:john:rw file.txt
getfacl file.txt
```

---

## Slide 11: User Management Commands (Linux)

### คำสั่งจัดการผู้ใช้

**สร้างผู้ใช้:**
```bash
sudo useradd -m -s /bin/bash newuser
sudo passwd newuser
```

**แก้ไขผู้ใช้:**
```bash
sudo usermod -aG sudo newuser    # เพิ่มใน sudo group
sudo usermod -l newname oldname  # เปลี่ยนชื่อ
```

**ลบผู้ใช้:**
```bash
sudo userdel -r username  # ลบพร้อม home directory
```

**จัดการ Group:**
```bash
sudo groupadd developers
sudo usermod -aG developers alice
```

---

## Slide 12: Sudo Configuration

### การตั้งค่า Sudo

**ไฟล์ /etc/sudoers:**
```bash
# ให้สิทธิ์ sudo แก่ user
username ALL=(ALL:ALL) ALL

# ไม่ต้องใส่รหัสผ่าน
username ALL=(ALL) NOPASSWD: ALL

# จำกัดคำสั่งเฉพาะ
username ALL=(ALL) /bin/systemctl, /usr/bin/apt
```

**Best Practices:**
- ใช้ `visudo` เสมอ
- ตั้งค่า timeout
- Log sudo activities
- ใช้ aliases สำหรับ commands ที่ซับซ้อน

---

## Slide 13: Windows User Account Control (UAC)

### การจัดการสิทธิ์ใน Windows

**UAC Levels:**
1. **Always notify:** แจ้งทุกการเปลี่ยนแปลง
2. **Notify when apps try to make changes:** (Default)
3. **Notify without dimming desktop**
4. **Never notify:** ไม่แนะนำ

**การตั้งค่า UAC:**
```powershell
# ตรวจสอบสถานะ UAC
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA

# เปิด UAC
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 1
```

---

## Slide 14: Windows User Management

### การจัดการผู้ใช้ Windows

**PowerShell Commands:**
```powershell
# สร้างผู้ใช้ใหม่
New-LocalUser -Name "NewUser" -Password (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force)

# เพิ่มเข้า group
Add-LocalGroupMember -Group "Administrators" -Member "NewUser"

# ลบผู้ใช้
Remove-LocalUser -Name "NewUser"

# ดูข้อมูล group
Get-LocalGroupMember -Group "Administrators"
```

**Group Policy Management:**
- Local Security Policy
- Domain Group Policy
- Password Policy
- Account Lockout Policy

---

## Slide 15: Windows Security Policies

### นโยบายความปลอดภัย

**Password Policy:**
```
- Minimum password length: 12 characters
- Password complexity: Enabled
- Maximum password age: 90 days
- Password history: 5 passwords
```

**Account Lockout Policy:**
```
- Account lockout threshold: 3 attempts
- Account lockout duration: 30 minutes
- Reset counter after: 30 minutes
```

**User Rights Assignment:**
- Log on as a service
- Log on locally
- Backup files and directories

---

## Slide 16: Firewall Configuration

### การตั้งค่า Firewall

**Linux (iptables):**
```bash
# ดูกฎปัจจุบัน
sudo iptables -L

# อนุญาต SSH
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# อนุญาต HTTP/HTTPS
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# ปิดการเข้าถึงอื่นๆ
sudo iptables -P INPUT DROP
```

**UFW (Uncomplicated Firewall):**
```bash
sudo ufw enable
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw deny 23/tcp
```

---

## Slide 17: Windows Firewall

### Windows Defender Firewall

**PowerShell Commands:**
```powershell
# ตรวจสอบสถานะ
Get-NetFirewallProfile

# เปิด/ปิด Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# อนุญาต application
New-NetFirewallRule -DisplayName "Allow App" -Direction Inbound -Program "C:\app.exe" -Action Allow

# อนุญาต port
New-NetFirewallRule -DisplayName "Allow Port 8080" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow
```

**GUI Configuration:**
- Windows Security > Firewall & network protection
- Advanced settings
- Inbound/Outbound rules

---

## Slide 18: System Monitoring & Logging

### การตรวจสอบระบบ

**Linux Logs:**
```bash
# System logs
sudo tail -f /var/log/syslog
sudo tail -f /var/log/auth.log

# Service logs
sudo journalctl -u ssh.service -f
sudo journalctl --since "1 hour ago"

# User activities
last
lastlog
who
w
```

**Windows Logs:**
```powershell
# Event Viewer
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4624}

# Failed login attempts
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4625}
```

---

## Slide 19: Antivirus & Anti-malware

### การป้องกัน Malware

**Linux:**
```bash
# ClamAV installation
sudo apt install clamav clamav-daemon

# Update virus definitions
sudo freshclam

# Scan system
sudo clamscan -r --infected --remove /home
```

**Windows:**
```powershell
# Windows Defender status
Get-MpComputerStatus

# Update definitions
Update-MpSignature

# Run scan
Start-MpScan -ScanType QuickScan
```

**Best Practices:**
- อัปเดต signatures ทุกวัน
- Schedule regular scans
- Real-time protection
- Quarantine suspicious files

---

## Slide 20: System Updates & Patch Management

### การอัปเดตระบบ

**Linux (Ubuntu/Debian):**
```bash
# อัปเดต package list
sudo apt update

# อัปเดต packages
sudo apt upgrade

# อัปเดต system
sudo apt dist-upgrade

# ตั้งค่า auto-update
sudo dpkg-reconfigure unattended-upgrades
```

**Windows:**
```powershell
# ตรวจสอบ updates
Get-WindowsUpdate

# ติดตั้ง updates
Install-WindowsUpdate -AcceptAll -AutoReboot
```

**อัปเดตอัตโนมัติ:**
- Security updates: เปิดเสมอ
- Feature updates: ทดสอบก่อน
- Driver updates: ระวัง compatibility

---

## Slide 21: Encryption & Data Protection

### การเข้ารหัสข้อมูล

**File/Folder Encryption:**

**Linux:**
```bash
# GPG encryption
gpg --symmetric --cipher-algo AES256 secret.txt

# LUKS disk encryption
sudo cryptsetup luksFormat /dev/sdb1
sudo cryptsetup luksOpen /dev/sdb1 encrypted_drive
```

**Windows:**
```cmd
# BitLocker
manage-bde -on C: -RecoveryPassword

# EFS (Encrypting File System)
cipher /e /s:C:\SecretFolder
```

**Best Practices:**
- เข้ารหัส sensitive data
- Backup encryption keys
- ใช้ strong encryption algorithms

---

## Slide 22: Network Security

### ความปลอดภัยเครือข่าย

**Network Configuration:**
```bash
# ปิด services ที่ไม่จำเป็น
sudo systemctl disable telnet
sudo systemctl disable ftp

# ตรวจสอบ open ports
netstat -tulpn
ss -tulpn

# Network monitoring
sudo netstat -i
sudo iftop
```

**Secure Protocols:**
- SSH แทน Telnet
- HTTPS แทน HTTP
- SFTP แทน FTP
- VPN สำหรับ remote access

---

## Slide 23: Backup & Recovery

### การสำรองและกู้คืนข้อมูล

**Linux Backup:**
```bash
# rsync backup
rsync -avz --delete /home/user/ /backup/user/

# tar backup
tar -czf backup_$(date +%Y%m%d).tar.gz /important/data

# Database backup
mysqldump -u root -p database_name > backup.sql
```

**Windows Backup:**
```powershell
# File History
Enable-ComputerRestore -Drive "C:\"

# System Image
wbadmin start backup -backupTarget:E: -include:C: -allCritical -quiet
```

**3-2-1 Rule:**
- 3 copies ของข้อมูล
- 2 สื่อเก็บข้อมูลต่างชนิด
- 1 copy offsite

---

## Slide 24: Incident Response

### การตอบสนองเหตุการณ์

**Incident Response Plan:**

**1. Preparation**
- มี incident response team
- เตรียม tools และ procedures

**2. Identification**
- ตรวจสอบและยืนยัน incident
- ประเมินผลกระทบ

**3. Containment**
- แยก affected systems
- ป้องกันการแพร่กระจาย

**4. Eradication**
- กำจัด root cause
- แก้ไข vulnerabilities

**5. Recovery**
- คืนค่าระบบสู่สภาพปกติ
- ตรวจสอบระบบ

**6. Lessons Learned**
- วิเคราะห์เหตุการณ์
- ปรับปรุง procedures

---

## Slide 25: ตัวอย่าง Case Study 1

### บริษัทพัฒนาซอฟต์แวร์ขนาดกลาง

**สถานการณ์:**
- มี developers 50 คน
- ใช้ Linux servers และ Windows workstations
- เก็บ source code ใน Git repositories
- มี customer database

**ปัญหาที่พบ:**
- Developers ใช้ sudo อย่างไม่เหมาะสม
- Password policies ไม่เข้มงวด
- ไม่มี MFA
- Log monitoring ไม่มี

**Solutions:**
- ตั้งค่า sudo policies ที่เหมาะสม
- บังคับใช้ strong password + MFA
- ติดตั้ง centralized logging
- Security awareness training

---

## Slide 26: ตัวอย่าง Case Study 2

### Startup ด้าน FinTech

**สถานการณ์:**
- ระบบ microservices บน Kubernetes
- ข้อมูลลูกค้าที่ sensitive
- Compliance requirements
- Remote work environment

**Security Requirements:**
- PCI DSS compliance
- SOC 2 Type II
- GDPR compliance

**Implementation:**
- Role-based access control
- Container security scanning
- Data encryption at rest และ in transit
- VPN + MFA สำหรับ remote access
- Regular security audits

---

## Slide 27: Best Practices Summary

### สรุป Best Practices

**User Management:**
- ใช้ principle of least privilege
- แยก accounts สำหรับงานต่างๆ
- Regular access reviews

**System Security:**
- อัปเดตระบบสม่ำเสมอ
- ใช้ strong authentication
- Monitor และ log activities

**Data Protection:**
- เข้ารหัสข้อมูล sensitive
- Regular backups
- Test recovery procedures

**Network Security:**
- ใช้ firewall
- Secure protocols only
- Network segmentation

---

## Slide 28: Security Tools สำหรับ Software Engineers

### เครื่องมือที่แนะนำ

**System Monitoring:**
- **Nagios/Zabbix:** Infrastructure monitoring
- **ELK Stack:** Log analysis
- **OSSEC:** Host-based intrusion detection

**Vulnerability Scanning:**
- **Nessus:** Vulnerability scanner
- **OpenVAS:** Open source scanner
- **Lynis:** Linux security auditing

**Password Management:**
- **Bitwarden:** Password manager
- **HashiCorp Vault:** Secrets management
- **CyberArk:** Enterprise solution

**Development Security:**
- **SonarQube:** Code security analysis
- **OWASP ZAP:** Web application security
- **Snyk:** Dependency vulnerability scanning

---

## Slide 29: LAB Assignment

### แบบฝึกหัด: ตั้งค่าความปลอดภัยระบบ

**Lab 1: Linux Security Configuration**
1. สร้าง user accounts สำหรับ team
2. ตั้งค่า sudo permissions
3. Configure SSH security
4. Set up firewall rules
5. Enable system monitoring

**Lab 2: Windows Security Hardening**
1. Configure User Account Control
2. Set up Group Policy
3. Enable Windows Defender
4. Configure firewall rules
5. Set up event monitoring

**Deliverables:**
- รายงานการตั้งค่า (10 หน้า)
- Screenshots ของการใช้งาน
- Security checklist
- ข้อเสนอแนะสำหรับการปรับปรุง

**กำหนดส่ง:** 2 สัปดาห์

---

## Slide 30: Q&A และการบ้าน

### คำถามสำหรับการทบทวน

1. อธิบาย CIA Triad และยกตัวอย่างการใช้งาน
2. เปรียบเทียบ DAC และ MAC access control
3. อธิบายการทำงานของ MFA
4. วิธีการตั้งค่า sudo ให้ปลอดภัย
5. ความแตกต่างระหว่าง authentication และ authorization

### การบ้าน
- อ่านเอกสาร OWASP Top 10
- ศึกษา NIST Cybersecurity Framework
- ฝึกใช้คำสั่ง Linux security commands

### แหล่งอ้างอิง
- NIST SP 800-53: Security Controls
- CIS Controls
- OWASP Security Guidelines
- Linux Security Cookbook
- Windows Security Best Practices