# Week 5: Network Security & Basic Packet Filtering
## ENGSE214 – ความมั่นคงปลอดภัยทางไซเบอร์เบื้องต้น

**เวลาการสอน:** 2-3 ชั่วโมง (รวม Demo และ Lab)  
**CLO ที่เกี่ยวข้อง:** CLO2, CLO3, CLO4

---

## 📚 ทบทวนเนื้อหาสัปดาห์ที่ผ่านมา

### Week 3: Vulnerabilities & Basic Risk Assessment
- **CVE/NVD**: ฐานข้อมูลช่องโหว่มาตรฐานสากล
- **CVSS**: ระบบให้คะแนนความรุนแรงของช่องโหว่ (0.0-10.0)
- **Risk Assessment**: การประเมินความเสี่ยง = Threat × Vulnerability × Impact
- **Risk Management**: Identify → Analyze → Evaluate → Treat → Monitor

### Week 4: Operating System Security & Hardening
- **Access Control**: การควบคุมการเข้าถึงระบบ (Authentication, Authorization)
- **Least Privilege**: หลักการให้สิทธิ์เท่าที่จำเป็น
- **OS Hardening**: การปรับแต่งระบบให้ปลอดภัย
  - สร้าง user แยก admin/user ปกติ
  - ตั้ง Password Policy
  - ปิด service ที่ไม่จำเป็น
  - ตั้งค่า Firewall พื้นฐาน

```
┌────────────────────────────────────────────────────────┐
│  สัปดาห์ที่แล้ว: เราเรียนรู้เกี่ยวกับการป้องกัน OS  │
│  สัปดาห์นี้: เราจะขยายไปที่ NETWORK SECURITY!        │
│  เพราะระบบไม่ได้อยู่โดดเดี่ยว แต่เชื่อมต่อกันทางเครือข่าย │
└────────────────────────────────────────────────────────┘
```

---

## 🎯 วัตถุประสงค์การเรียนรู้ (Learning Objectives)

เมื่อจบ Week 5 นักศึกษาจะสามารถ:

1. อธิบายหลักการความปลอดภัยของเครือข่าย (Network Security) ได้
2. แยกความแตกต่างระหว่าง Firewall, IDS, และ IPS ได้
3. เข้าใจการทำงานของ VPN และการใช้งานในชีวิตจริง
4. ออกแบบ Network Segmentation และ DMZ เบื้องต้นได้
5. ใช้ Wireshark ดู network traffic และวิเคราะห์ packet ได้
6. สร้าง Firewall Rules เบื้องต้นบน Windows/Linux ได้

---

## 🌐 Part 1: Network Security Concepts

### 1.1 ทำไมต้องมี Network Security?

ในยุคที่ทุกอย่างเชื่อมต่อกัน (Connected World):
- **มือถือ** → เชื่อมต่อกับ Wi-Fi, 4G/5G
- **คอมพิวเตอร์** → เชื่อมต่อกับ Internet, LAN ในออฟฟิศ
- **IoT Devices** → Smart TV, กล้อง, หลามไฟ
- **ระบบองค์กร** → Web Server, Database, Email Server

```
        📱 Smartphone
           │
           ├─── Wi-Fi ─────┐
           │               │
        💻 Laptop          │      ☁️  Cloud Services
           │               │       │
           └─── Router ────┼───────┼──── Internet
                          │       │
        🖥️  Server ────────┘       │
           │                       │
        🗄️  Database ──────────────┘
```

**ปัญหา**:
- ข้อมูลส่งผ่านเครือข่าย → มีโอกาสถูก **ดักจับ (Sniffing)**
- มีคนพยายาม **เข้าถึงระบบผ่าน Network (Unauthorized Access)**
- มีการโจมตีแบบ **ทำให้ระบบล่ม (DDoS)**
- ข้อมูลอาจถูก **แก้ไขระหว่างทาง (Man-in-the-Middle)**

### 1.2 องค์ประกอบของ Network Security

```
┌────────────────────────────────────────────────────────┐
│            Network Security Layers                     │
├────────────────────────────────────────────────────────┤
│  1. Physical Security                                  │
│     • ป้องกันการเข้าถึงอุปกรณ์ Network โดยตรง          │
│  2. Network Architecture                               │
│     • ออกแบบโครงสร้างเครือข่ายที่ปลอดภัย (Segmentation)│
│  3. Access Control                                     │
│     • กำหนดใครเข้าถึงอะไรได้บ้าง                       │
│  4. Threat Detection & Prevention                      │
│     • Firewall, IDS/IPS, Antivirus                    │
│  5. Encryption                                         │
│     • เข้ารหัสข้อมูลขณะส่งผ่านเครือข่าย (SSL/TLS, VPN)│
│  6. Monitoring & Logging                               │
│     • ติดตามและบันทึกกิจกรรมในเครือข่าย                │
└────────────────────────────────────────────────────────┘
```

### 1.3 ภัยคุกคามทางเครือข่ายที่พบบ่อย

| ประเภทการโจมตี | คำอธิบาย | ตัวอย่าง |
|----------------|----------|----------|
| **Sniffing** | ดักจับข้อมูลที่ส่งผ่านเครือข่าย | ดัก password ที่ส่งแบบ plain text |
| **Man-in-the-Middle** | แทรกตัวระหว่างการสื่อสาร | Fake Wi-Fi Hotspot |
| **DDoS** | โจมตีเพื่อทำให้ระบบล่ม | ส่ง request มหาศาลพร้อมกัน |
| **Port Scanning** | สแกนหา service ที่เปิดอยู่ | ใช้ Nmap สแกนหา vulnerable ports |
| **Session Hijacking** | ขโมย session ของผู้ใช้ | ขโมย Cookie เพื่อเข้าใช้บัญชี |
| **DNS Spoofing** | ปลอมแปลง DNS response | นำผู้ใช้ไปยังเว็บปลอม |

---

## 🔥 Part 2: Firewall – กำแพงไฟป้องกันเครือข่าย

### 2.1 Firewall คือ อะไร?

**Firewall** คืออุปกรณ์หรือซอฟต์แวร์ที่ทำหน้าที่:
- **กรอง traffic** ที่เข้า-ออก network ตามกฎที่กำหนด (Rules)
- **บล็อก** การเชื่อมต่อที่ไม่พึงประสงค์
- **อนุญาต** เฉพาะ traffic ที่ปลอดภัย

```
         Internet                Firewall               Internal Network
    (ไม่ปลอดภัย)                (กำแพงป้องกัน)           (ปลอดภัย)
         
    ☁️  External            ┌───────────────┐         💻 Workstation
         Threats    ────>   │   FIREWALL    │  ────>   📱 Devices
    🦹 Hackers     <────    │   Rules:      │  <────   🖥️  Servers
    🦠 Malware              │   - Allow HTTP │
                            │   - Allow HTTPS│
                            │   - Block SSH  │
                            │   - Block FTP  │
                            └───────────────┘
```

### 2.2 ประเภทของ Firewall

#### 1. **Packet Filtering Firewall**
- ตรวจสอบ packet แต่ละ packet ที่ผ่าน
- ดูที่ **Source IP, Destination IP, Port, Protocol**
- **ไม่ดู** เนื้อหาภายใน packet (stateless)

**ตัวอย่าง Rule**:
```
Rule 1: ALLOW TCP from 192.168.1.0/24 to ANY port 80
Rule 2: ALLOW TCP from ANY to 192.168.1.10 port 443
Rule 3: DENY all other traffic
```

#### 2. **Stateful Inspection Firewall**
- จำ "สถานะ" ของ connection (stateful)
- รู้ว่า packet นี้เป็นส่วนหนึ่งของ session ที่มีอยู่แล้วหรือไม่
- ปลอดภัยกว่า Packet Filtering

**ตัวอย่าง**:
```
Connection Table:
┌──────────┬──────────┬──────┬─────────┬────────┐
│ Source   │ Dest     │ Port │ State   │ Action │
├──────────┼──────────┼──────┼─────────┼────────┤
│192.168.1.5│8.8.8.8  │ 443  │ESTABLISHED│ALLOW│
│192.168.1.7│1.1.1.1  │ 80   │NEW      │ALLOW  │
│203.0.113.50│192.168.1.10│22│NEW    │DENY   │
└──────────┴──────────┴──────┴─────────┴────────┘
```

#### 3. **Application Layer Firewall (WAF)**
- ตรวจสอบ **เนื้อหา** ของ packet ในระดับ Application Layer
- สามารถบล็อก **SQL Injection, XSS** ได้
- ใช้กับ Web Application (WAF = Web Application Firewall)

#### 4. **Next-Generation Firewall (NGFW)**
- รวมความสามารถของ Firewall + IDS/IPS + Antivirus + DPI (Deep Packet Inspection)
- วิเคราะห์ traffic แบบซับซ้อน
- ตัวอย่าง: Palo Alto, Fortinet, Cisco Firepower

```
┌────────────────────────────────────────────────────┐
│         Firewall Comparison                        │
├──────────────┬─────────────────────────────────────┤
│ Type         │ What it checks                      │
├──────────────┼─────────────────────────────────────┤
│ Packet       │ IP + Port + Protocol                │
│ Filtering    │ (Header only)                       │
├──────────────┼─────────────────────────────────────┤
│ Stateful     │ Connection state                    │
│ Inspection   │ (Track sessions)                    │
├──────────────┼─────────────────────────────────────┤
│ Application  │ HTTP headers, payloads              │
│ Layer        │ (Deep inspection)                   │
├──────────────┼─────────────────────────────────────┤
│ NGFW         │ Everything + Threat Intelligence    │
│              │ (AI/ML-based)                       │
└──────────────┴─────────────────────────────────────┘
```

### 2.3 ตัวอย่างการตั้งค่า Firewall

#### **Linux (ufw - Uncomplicated Firewall)**
```bash
# ติดตั้ง ufw (Ubuntu)
sudo apt-get install ufw

# เปิดใช้งาน Firewall
sudo ufw enable

# อนุญาต SSH (port 22)
sudo ufw allow 22/tcp

# อนุญาต HTTP และ HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# บล็อก port 3389 (Remote Desktop)
sudo ufw deny 3389/tcp

# ดู status และ rules
sudo ufw status verbose

# อนุญาต IP เฉพาะเจาะจง
sudo ufw allow from 192.168.1.100

# ลบ rule
sudo ufw delete allow 80/tcp
```

#### **Windows Firewall (PowerShell)**
```powershell
# อนุญาต HTTP Inbound
New-NetFirewallRule -DisplayName "Allow HTTP" -Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow

# บล็อก Telnet
New-NetFirewallRule -DisplayName "Block Telnet" -Direction Inbound -LocalPort 23 -Protocol TCP -Action Block

# ดู Firewall Rules
Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'}

# ลบ Rule
Remove-NetFirewallRule -DisplayName "Allow HTTP"
```

### 2.4 🤔 คำถามชวนคิด

**Q1**: ถ้าคุณตั้ง Firewall ให้ ALLOW all traffic แล้วทำไม Firewall ถึงไร้ประโยชน์?

<details>
<summary>คำตอบ</summary>

**A**: เพราะ Firewall ทำงานโดย **default deny** แล้วอนุญาตเฉพาะที่จำเป็น (whitelist approach)
- ถ้า ALLOW all → ไม่มีการกรองอะไรเลย
- เหมือนมี "กำแพง" แต่เปิดประตูทุกบาน = ไม่มีกำแพง!

</details>

**Q2**: ระหว่าง "ปิด port ที่ไม่ใช้" กับ "ตั้ง Firewall block port" อันไหนดีกว่า?

<details>
<summary>คำตอบ</summary>

**A**: **ปิด port (ปิด service)** ดีกว่าเสมอ!
- Defense in Depth: หลายชั้น
- ถ้า Firewall มีปัญหา/ถูก bypass → port ยังปิดอยู่
- ถ้าเปิด port ไว้แต่ Firewall block → ถ้า Firewall fail = เสี่ยง!
- **Best Practice**: ปิด port ที่ไม่ใช้ + Firewall block = 2 ชั้น

</details>

---

## 🚨 Part 3: IDS/IPS – ระบบตรวจจับและป้องกันการบุกรุก

### 3.1 IDS vs IPS

```
┌──────────────────────────────────────────────────────┐
│  IDS = Intrusion Detection System                   │
│  📹 "กล้องวงจรปิด" ของ Network                       │
│  • ตรวจจับการโจมตี                                   │
│  • แจ้งเตือน (Alert) เมื่อเจอพฤติกรรมผิดปกติ        │
│  • ไม่ได้ BLOCK traffic โดยอัตโนมัติ                 │
│  • วิเคราะห์ภายหลัง (Passive)                        │
└──────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────┐
│  IPS = Intrusion Prevention System                  │
│  🛡️ "รปภ. + Firewall" ของ Network                  │
│  • ตรวจจับ + BLOCK การโจมตีทันที                     │
│  • วางอยู่ใน traffic path (Inline)                  │
│  • ทำงานแบบ Real-time                                │
│  • สามารถ DROP packet / BLOCK IP ได้                │
└──────────────────────────────────────────────────────┘
```

**เปรียบเทียบ**:
| ฟีเจอร์ | IDS | IPS |
|---------|-----|-----|
| **ตำแหน่ง** | นอก traffic path (Passive) | อยู่ใน traffic path (Inline) |
| **การทำงาน** | ตรวจจับ + แจ้งเตือน | ตรวจจับ + บล็อกทันที |
| **Response Time** | หลังเกิดเหตุ | Real-time |
| **Impact** | ไม่กระทบ traffic | อาจทำให้ traffic ช้าลง |
| **False Positive** | แจ้งเตือนผิด → ตรวจสอบเอง | บล็อกผิด → ผู้ใช้ปกติเข้าไม่ได้! |

### 3.2 วิธีการทำงานของ IDS/IPS

#### 1. **Signature-based Detection**
- มี "ลายเซ็น" (Signature) ของการโจมตีที่รู้จักอยู่แล้ว
- เหมือนฐานข้อมูล Pattern ของไวรัส
- ตรวจจับได้เร็ว แม่นยำสูง
- **ข้อจำกัด**: ตรวจจับเฉพาะการโจมตีที่รู้จักเท่านั้น (Zero-day attack ไม่จับได้)

**ตัวอย่าง Signature**:
```
alert tcp any any -> 192.168.1.0/24 80 (content:"SELECT * FROM users";
msg:"Possible SQL Injection"; sid:100001;)
```

#### 2. **Anomaly-based Detection**
- เรียนรู้พฤติกรรม "ปกติ" (Baseline) ของ network
- ตรวจจับสิ่งที่ "ผิดปกติ" (Anomaly)
- ใช้ Machine Learning / AI
- **ข้อดี**: จับ Zero-day attack ได้
- **ข้อจำกัด**: False Positive สูง (แจ้งเตือนผิดบ่อย)

**ตัวอย่าง Anomaly**:
```
Normal Behavior:
- Server X รับ traffic เฉลี่ย 100 requests/minute
- IP A เชื่อมต่อเข้ามา 5 connections/hour

Anomaly Detected:
- Server X รับ traffic 10,000 requests/minute → DDoS?
- IP B พยายามเชื่อมต่อ 1,000 connections ใน 1 นาที → Port Scan?
```

### 3.3 ตัวอย่าง IDS/IPS Tool

1. **Snort** (Open-source IDS/IPS)
2. **Suricata** (Open-source IDS/IPS)
3. **Zeek (Bro)** (Network Security Monitor)
4. **OSSEC** (Host-based IDS)

---

## 🔐 Part 4: VPN (Virtual Private Network)

### 4.1 VPN คือ อะไร?

**VPN** = สร้าง "อุโมงค์เข้ารหัส" (Encrypted Tunnel) ผ่าน Internet

```
         User                VPN Tunnel              Company Network
         
    💻 Laptop  ───────────────────────────────────> 🏢 Office
       (Home)  <───────────────────────────────────  (Database)
                     🔐 Encrypted Traffic
                     ☁️  ผ่าน Internet ที่ไม่ปลอดภัย
                     
Without VPN:
   👁️ ISP เห็นข้อมูลทุกอย่าง
   👁️ Hacker บน Wi-Fi เห็นข้อมูล
   
With VPN:
   ❌ ISP เห็นแค่ "Encrypted Data"
   ❌ Hacker ดักจับได้แต่อ่านไม่ได้
```

### 4.2 การใช้งาน VPN

#### 1. **Remote Access VPN**
- พนักงานที่บ้าน → เชื่อมต่อกับระบบบริษัท
- เหมือน "อยู่ใน LAN ของบริษัท" แม้จะอยู่บ้าน

**Use Case**:
- Work from Home
- เข้าถึงระบบภายในองค์กร
- ใช้ทรัพยากร (File Server, Printer) ของบริษัท

#### 2. **Site-to-Site VPN**
- เชื่อมต่อ 2 สาขาผ่าน Internet
- สาขา A ↔ VPN ↔ สาขา B

**Use Case**:
- บริษัทมีหลายสาขา
- ต้องการแชร์ข้อมูลระหว่างสาขา
- ถูกกว่าเช่า Leased Line

#### 3. **Consumer VPN (Privacy VPN)**
- ซื้อบริการ VPN เพื่อปกปิด IP และเข้ารหัส traffic
- ใช้เพื่อ Privacy / Bypass Geo-restriction

**Use Case**:
- ดู Netflix ของต่างประเทศ
- ป้องกันการติดตาม (Tracking) โดย ISP
- เข้าเว็บที่ถูกบล็อกในประเทศ

### 4.3 โปรโตคอล VPN ที่นิยม

| โปรโตคอล | คำอธิบาย | ข้อดี | ข้อเสีย |
|----------|----------|-------|---------|
| **OpenVPN** | Open-source, ใช้ SSL/TLS | ปลอดภัย, config ได้เยอะ | ตั้งค่ายาก |
| **IPsec** | รักษาความปลอดภัยใน IP layer | มาตรฐาน, รองรับกว้าง | Complex, ช้ากว่า |
| **WireGuard** | โปรโตคอลใหม่, เร็ว | เร็ว, โค้ดสั้น | ยังใหม่ |
| **L2TP/IPsec** | รวม L2TP + IPsec | ใช้งานง่าย | ช้า, Security ปานกลาง |
| **PPTP** | โปรโตคอลเก่า | ตั้งค่าง่าย | **ไม่ปลอดภัย!** (อย่าใช้) |

### 4.4 ข้อควรระวังเมื่อใช้ VPN

⚠️ **VPN ไม่ใช่ "ไอ้โล่วิเศษ"**:
- VPN ปกป้องเฉพาะ **traffic ระหว่าง device กับ VPN server**
- เมื่อ traffic ออกจาก VPN server → ไม่มี encryption แล้ว
- ถ้าเว็บเป้าหมายใช้ HTTP (ไม่ใช่ HTTPS) → ยังดักจับได้!

```
You → [VPN Encrypted] → VPN Server → [Plain HTTP] → Target Website
                                      ↑ จุดนี้ยังเสี่ยง!
```

⚠️ **เลือก VPN Provider ที่เชื่อถือได้**:
- บาง VPN เก็บ log การใช้งาน → ไม่ private
- บาง VPN แจก malware
- อ่าน Privacy Policy ก่อนใช้

---

## 🏗️ Part 5: Network Segmentation & DMZ

### 5.1 Network Segmentation คืออะไร?

**Network Segmentation** = แบ่งเครือข่ายเป็นส่วน ๆ (Segments) เพื่อ:
- **จำกัดการแพร่กระจาย** ของ malware/attack
- **ควบคุมการเข้าถึง** แต่ละส่วน
- **ง่ายต่อการ monitor** และ manage

```
     ❌ Flat Network (ไม่ดี)                ✅ Segmented Network (ดี)
     
  ┌─────────────────────┐                ┌──────────────────┐
  │   ALL Devices       │                │  Public Zone     │
  │   • Servers         │                │  • Web Server    │
  │   • Workstations    │                └────────┬─────────┘
  │   • IoT             │                         │ Firewall
  │   • Guest           │                ┌────────┴─────────┐
  │   อยู่ใน LAN เดียวกัน │                │  Internal Zone   │
  └─────────────────────┘                │  • App Server    │
         ↓                                 │  • Database      │
  ถ้ามี 1 จุดโดนแฮก                       └────────┬─────────┘
  → แพร่ไปทั้งเครือข่าย                          │ Firewall
                                          ┌────────┴─────────┐
                                          │  Management Zone │
                                          │  • Admin only    │
                                          └──────────────────┘
                                                 ↓
                                          ถ้า Web Server โดนแฮก
                                          → Database ยังปลอดภัย
```

### 5.2 DMZ (Demilitarized Zone)

**DMZ** คือ "เขตกันชน" (Buffer Zone) ระหว่าง Internet กับ Internal Network

```
        Internet                DMZ                Internal Network
       (Public)          (Semi-Trusted)              (Trusted)
       
    ☁️  Users         ┌────────────────┐      ┌────────────────┐
    🌐 Hackers ────>  │  🌐 Web Server │ ──>  │ 💾 Database    │
                      │  📧 Mail Server│      │ 🗂️  File Server│
                      │  🔒 VPN Gateway│      │ 💻 Workstation │
                      └────────────────┘      └────────────────┘
                            ↑ ↓                      ↑ ↓
                      [ Firewall 1 ]          [ Firewall 2 ]
                      
Firewall 1: ควบคุม Internet → DMZ
Firewall 2: ควบคุม DMZ → Internal
```

**ทำไมต้องมี DMZ?**
- **Web Server** ต้องให้คนทั่วไปเข้าถึงได้จาก Internet
- แต่ **Database** ต้องปกป้อง ไม่ให้เข้าถึงจาก Internet โดยตรง
- ถ้า Web Server โดนแฮก → Hacker ยังเข้า Internal Network ไม่ได้ง่าย ๆ

### 5.3 ตัวอย่าง DMZ Architecture

```
                  ┌──────────────────────────────────┐
                  │         INTERNET                 │
                  └─────────────┬────────────────────┘
                                │
                                ▼
                  ┌─────────────────────────────────┐
                  │    Firewall 1 (Border)          │
                  │    Rules:                       │
                  │    • ALLOW HTTP/HTTPS → DMZ     │
                  │    • DENY all other             │
                  └─────────────┬───────────────────┘
                                │
                                ▼
               ┌────────────────────────────────────┐
               │            DMZ Zone                │
               │                                    │
               │  📧 Mail Server (SMTP: 25, 587)   │
               │  🌐 Web Server (HTTP: 80, HTTPS: 443)│
               │  🔒 VPN Gateway (OpenVPN: 1194)   │
               │                                    │
               └────────────────┬───────────────────┘
                                │
                                ▼
                  ┌─────────────────────────────────┐
                  │    Firewall 2 (Internal)        │
                  │    Rules:                       │
                  │    • ALLOW Web → Database:3306  │
                  │    • DENY all other from DMZ    │
                  └─────────────┬───────────────────┘
                                │
                                ▼
               ┌────────────────────────────────────┐
               │       Internal Network             │
               │                                    │
               │  💾 Database Server (MySQL: 3306)  │
               │  🗂️  File Server (SMB: 445)        │
               │  💻 Workstations (RDP: 3389)       │
               │                                    │
               └────────────────────────────────────┘
```

### 5.4 VLAN (Virtual LAN)

**VLAN** = แบ่ง Physical Network เป็นหลาย Logical Network

```
     Physical Switch with VLANs
     
┌─────────────────────────────────────────┐
│          Switch (Layer 2)               │
│                                         │
│  VLAN 10 (Sales)    🔴🔴🔴              │
│  VLAN 20 (Dev)      🔵🔵🔵              │
│  VLAN 30 (Guest)    🟢🟢🟢              │
│                                         │
└─────────────────────────────────────────┘

• อุปกรณ์ใน VLAN เดียวกันเท่านั้นที่คุยกันได้
• ต้องผ่าน Router/Firewall เพื่อข้าม VLAN
• ใช้ Switch เครื่องเดียวแต่แยกเครือข่ายได้
```

**ประโยชน์ของ VLAN**:
- ลด broadcast traffic
- เพิ่มความปลอดภัย (แยก segment)
- จัดการง่าย (ไม่ต้องเปลี่ยน physical wiring)

---

## 🔬 Part 6: Lab 2 – Packet View & Filtering

### Lab 2.1: ใช้ Wireshark ดู Network Traffic

**วัตถุประสงค์**: เรียนรู้การดู packet และวิเคราะห์ traffic

#### ขั้นตอนที่ 1: ติดตั้ง Wireshark

**Windows/Mac**:
- ดาวน์โหลดจาก: https://www.wireshark.org/download.html
- ติดตั้งตามขั้นตอน

**Linux (Ubuntu)**:
```bash
sudo apt-get update
sudo apt-get install wireshark
sudo usermod -aG wireshark $USER
# Logout แล้ว Login ใหม่
```

#### ขั้นตอนที่ 2: Capture Packets

1. เปิด Wireshark
2. เลือก Network Interface (เช่น Wi-Fi, Ethernet)
3. คลิก "Start Capturing"
4. เปิดเบราว์เซอร์ เข้าเว็บ http://example.com
5. กลับมา Wireshark คลิก "Stop Capturing"

#### ขั้นตอนที่ 3: วิเคราะห์ Packets

**Filter ที่ควรลอง**:
```
# HTTP Traffic
http

# HTTPS Traffic (TLS)
tls

# DNS Query
dns

# Traffic จาก IP เฉพาะเจาะจง
ip.src == 192.168.1.100

# Traffic ไปยัง Port 443
tcp.port == 443

# HTTP GET Request
http.request.method == "GET"
```

**สิ่งที่ควรสังเกต**:
- **Source IP / Destination IP**: มาจากไหน ไปไหน
- **Protocol**: HTTP, HTTPS, DNS, TCP, UDP
- **Port Number**: 80 (HTTP), 443 (HTTPS), 53 (DNS)
- **Payload**: ข้อมูลที่ส่ง (HTTP ดูได้ชัด, HTTPS เป็น encrypted)

```
ตัวอย่าง HTTP Packet ใน Wireshark:

Frame 42: GET /index.html HTTP/1.1
    Source: 192.168.1.100:54321
    Destination: 93.184.216.34:80
    Protocol: HTTP
    Info: GET /index.html HTTP/1.1
    
Packet Details:
    Ethernet II
    Internet Protocol Version 4
        Source: 192.168.1.100
        Destination: 93.184.216.34
    Transmission Control Protocol
        Source Port: 54321
        Destination Port: 80
    Hypertext Transfer Protocol
        GET /index.html HTTP/1.1
        Host: example.com
        User-Agent: Mozilla/5.0 ...
        Accept: text/html ...
```

#### 🔍 คำถามสำหรับ Lab:

**Q1**: ทำไม HTTP Request มองเห็นข้อมูลได้ชัดเจน แต่ HTTPS ไม่ได้?
<details>
<summary>คำตอบ</summary>

**A**: HTTP ส่งข้อมูลแบบ **plain text** (ไม่เข้ารหัส)
HTTPS ใช้ **TLS/SSL encryption** → Wireshark เห็นแต่ encrypted data

นี่คือเหตุผลว่าทำไมเว็บสมัยนี้ต้องใช้ HTTPS!
</details>

**Q2**: ถ้าเราใช้ Wi-Fi สาธารณะและไม่มี VPN มีใครดัก traffic เราได้ไหม?
<details>
<summary>คำตอบ</summary>

**A**: **ได้!** ใคร ๆ ก็สามารถเปิด Wireshark บน Wi-Fi เดียวกัน และดัก packet ได้
- HTTP → ดูข้อมูลได้ทั้งหมด (username, password, message)
- HTTPS → เห็นแต่ encrypted data (ปลอดภัยกว่า)
- **Best Practice**: ใช้ VPN เมื่ออยู่บน Public Wi-Fi!
</details>

---

### Lab 2.2: สร้าง Firewall Rules

#### ขั้นตอนที่ 1: Linux (ufw)

**เปิด Firewall และตั้งค่าพื้นฐาน**:
```bash
# ตรวจสอบสถานะ
sudo ufw status

# เปิดใช้งาน (ระวัง! อาจทำให้ SSH ขาดได้)
sudo ufw enable

# กำหนด default policy
sudo ufw default deny incoming
sudo ufw default allow outgoing

# อนุญาต SSH (สำคัญ! ถ้าใช้ remote)
sudo ufw allow 22/tcp

# อนุญาต Web Server
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# อนุญาต ping (ICMP)
sudo ufw allow proto icmp

# ดู rules ที่ตั้งไว้
sudo ufw status numbered

# ลบ rule หมายเลข 3
sudo ufw delete 3
```

**ตั้งค่าขั้นสูง**:
```bash
# อนุญาต SSH เฉพาะจาก IP เฉพาะเจาะจง
sudo ufw allow from 192.168.1.100 to any port 22

# อนุญาต MySQL เฉพาะจาก subnet
sudo ufw allow from 192.168.1.0/24 to any port 3306

# บล็อก IP ที่ไม่ดี
sudo ufw deny from 203.0.113.50

# จำกัด rate (ป้องกัน brute force)
sudo ufw limit 22/tcp
```

#### ขั้นตอนที่ 2: Windows Firewall

**เปิด Windows Defender Firewall**:
```
1. Control Panel → System and Security → Windows Defender Firewall
2. Advanced Settings
```

**สร้าง Inbound Rule (ตัวอย่าง: บล็อก Telnet)**:
```
1. คลิก "Inbound Rules" → "New Rule"
2. Rule Type: Port
3. Protocol: TCP, Port: 23
4. Action: Block the connection
5. Profile: เลือกทั้งหมด (Domain, Private, Public)
6. Name: "Block Telnet"
7. Finish
```

**PowerShell Command**:
```powershell
# อนุญาต Port 8080
New-NetFirewallRule -DisplayName "Allow Port 8080" `
  -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow

# บล็อก IP Address
New-NetFirewallRule -DisplayName "Block IP 203.0.113.50" `
  -Direction Inbound -RemoteAddress 203.0.113.50 -Action Block

# ดู Rules
Get-NetFirewallRule | Select DisplayName,Enabled,Direction,Action

# ลบ Rule
Remove-NetFirewallRule -DisplayName "Allow Port 8080"
```

#### 📝 Assignment: Lab 2 Summary

**ส่งสิ่งต่อไปนี้**:
1. **Screenshot** จาก Wireshark แสดง:
   - HTTP packet ที่ชัดเจน (เห็น GET request)
   - HTTPS packet (เห็น TLS handshake)
2. **Screenshot** Firewall Rules ที่สร้าง:
   - อนุญาต HTTP/HTTPS
   - บล็อก Telnet หรือ FTP
3. **คำอธิบาย** (1-2 หน้า):
   - อธิบายว่า packet ที่เห็นใน Wireshark คือ อะไร
   - อธิบาย Firewall Rules แต่ละ rule ว่าทำอะไร
   - เขียนสรุปสิ่งที่เรียนรู้

**รูปแบบ**: PDF  
**คะแนน**: 15 คะแนน  
**ส่งภายใน**: สัปดาห์หน้า

---

## 👥 Part 7: Group Activity – ออกแบบ Mini DMZ

### โจทย์

บริษัท "SecureShop" ต้องการสร้างระบบ E-Commerce ขนาดเล็ก ประกอบด้วย:
- **Web Server** (รับ HTTP/HTTPS จาก Internet)
- **Application Server** (ประมวลผล order, ไม่ให้เข้าถึงจาก Internet)
- **Database Server** (เก็บข้อมูลลูกค้า, ต้องปกป้องสูงสุด)
- **Admin Workstation** (ใช้จัดการระบบ)

**ข้อกำหนด**:
1. Web Server ต้องอยู่ใน **DMZ**
2. Database ต้องอยู่ใน **Internal Network**
3. ใช้ **2 Firewall** (Border Firewall + Internal Firewall)
4. กำหนด **Firewall Rules** ให้เหมาะสม

### ตัวอย่างผลลัพธ์ที่ต้องส่ง

```
┌────────────────────────────────────────────────────┐
│                   INTERNET                         │
└────────────────────┬───────────────────────────────┘
                     │
                     ▼
        ┌────────────────────────────┐
        │  Border Firewall           │
        │  Rules:                    │
        │  1. ALLOW HTTP/HTTPS → DMZ │
        │  2. DENY all other         │
        └────────────┬───────────────┘
                     │
                     ▼
        ┌────────────────────────────┐
        │        DMZ Zone            │
        │  🌐 Web Server             │
        │     IP: 10.0.1.10          │
        │     Port: 80, 443          │
        └────────────┬───────────────┘
                     │
                     ▼
        ┌────────────────────────────┐
        │  Internal Firewall         │
        │  Rules:                    │
        │  1. ALLOW Web → App:8080   │
        │  2. ALLOW App → DB:3306    │
        │  3. ALLOW Admin → All      │
        │  4. DENY all other         │
        └────────────┬───────────────┘
                     │
                     ▼
        ┌────────────────────────────┐
        │  Internal Network          │
        │  🖥️  App Server            │
        │      IP: 192.168.1.20      │
        │  💾 Database Server        │
        │      IP: 192.168.1.30      │
        │  💻 Admin Workstation      │
        │      IP: 192.168.1.100     │
        └────────────────────────────┘
```

### Firewall Rules ตัวอย่าง

**Border Firewall**:
| Rule | Source | Destination | Port | Action | Description |
|------|--------|-------------|------|--------|-------------|
| 1 | Any | 10.0.1.10 | 80 | ALLOW | HTTP to Web |
| 2 | Any | 10.0.1.10 | 443 | ALLOW | HTTPS to Web |
| 3 | Any | Any | Any | DENY | Block all else |

**Internal Firewall**:
| Rule | Source | Destination | Port | Action | Description |
|------|--------|-------------|------|--------|-------------|
| 1 | 10.0.1.10 | 192.168.1.20 | 8080 | ALLOW | Web → App |
| 2 | 192.168.1.20 | 192.168.1.30 | 3306 | ALLOW | App → DB |
| 3 | 192.168.1.100 | Any | 22,3389 | ALLOW | Admin access |
| 4 | Any | Any | Any | DENY | Block all else |

### การส่งงาน Group Activity

**แต่ละกลุ่มส่ง** (3-4 คน):
1. **Diagram** (ใช้ draw.io หรือวาดมือ)
   - แสดงโครงสร้าง network ทั้งหมด
   - แสดง DMZ, Internal Network, Firewall ตำแหน่งต่าง ๆ
2. **Firewall Rules Table** (ตารางเหมือนตัวอย่างข้างบน)
3. **คำอธิบาย** (1-2 หน้า)
   - ทำไมออกแบบแบบนี้
   - แต่ละ rule มีเหตุผลอะไร
   - มีจุดอ่อนหรือไม่ อย่างไร

**รูปแบบ**: PDF  
**คะแนน**: 10 คะแนน  
**นำเสนอหน้าชั้น**: 5 นาที/กลุ่ม (สัปดาห์หน้า)

---

## 📊 Part 8: Assessment & Quiz

### Short Quiz: Firewall / IDS/IPS / DMZ

**จำนวน**: 10 ข้อ  
**เวลา**: 20 นาที  
**คะแนน**: 10 คะแนน  
**รูปแบบ**: Multiple Choice + Short Answer

**ตัวอย่างคำถาม**:

**Q1 (Multiple Choice)**: Firewall แบบใดที่ตรวจสอบ "state" ของ connection?
- A. Packet Filtering Firewall
- B. Stateful Inspection Firewall ✅
- C. Application Layer Firewall
- D. Circuit-Level Gateway

**Q2 (Short Answer)**: อธิบายความแตกต่างระหว่าง IDS และ IPS (3-5 ประโยค)

<details>
<summary>คำตอบตัวอย่าง</summary>

**IDS (Intrusion Detection System)** ทำหน้าที่เฉพาะ "ตรวจจับ" การโจมตีและแจ้งเตือน แต่ไม่ได้บล็อก traffic โดยตรง ส่วน **IPS (Intrusion Prevention System)** นอกจากตรวจจับแล้วยังสามารถ "บล็อก" การโจมตีได้ทันที IPS วางอยู่ใน traffic path (inline) จึงทำงานแบบ real-time แต่อาจทำให้ traffic ช้าลงเล็กน้อย ส่วน IDS อยู่นอก traffic path จึงไม่กระทบความเร็ว แต่ไม่สามารถหยุดการโจมตีได้ทันที
</details>

**Q3 (True/False)**: DMZ เป็น zone ที่มีความปลอดภัยสูงสุด เหมาะกับการวาง Database Server
- True
- False ✅

**Q4 (Matching)**: จับคู่โปรโตคอล VPN กับคำอธิบาย
- OpenVPN → A. Open-source, ใช้ SSL/TLS
- WireGuard → B. ใหม่, เร็ว, โค้ดสั้น
- PPTP → C. เก่า, ไม่ปลอดภัย
- IPsec → D. มาตรฐาน, ซับซ้อน

**Q5 (Short Answer)**: ทำไม Web Server จึงควรอยู่ใน DMZ ไม่ใช่ Internal Network?

<details>
<summary>คำตอบตัวอย่าง</summary>

Web Server ต้องเปิดให้คนทั่วไปจาก Internet เข้าถึงได้ ถ้าวางใน Internal Network และ Web Server โดนแฮก ผู้โจมตีจะสามารถเข้าถึง Internal Network ได้โดยตรง การวาง Web Server ใน DMZ ทำให้มี Firewall อีกชั้นหนึ่ง (Internal Firewall) คั่นกลาง ถึงแม้ Web Server จะโดนแฮกก็ยากที่จะเข้า Internal Network ได้ทันที
</details>

---

## 🤔 Part 9: คำถามชวนคิดเพิ่มเติม

### Q1: Zero Trust Network
**คำถาม**: แนวคิด "Zero Trust" คือ "ไม่เชื่อใครเลย ทุกคนต้องพิสูจน์ตัวตน" แตกต่างจาก Traditional Firewall (Trust Internal, Block External) อย่างไร? ข้อดี-ข้อเสียคืออะไร?

<details>
<summary>คำตอบ</summary>

**Traditional Approach**:
- เชื่อว่า "ข้างในปลอดภัย, ข้างนอกอันตราย"
- Firewall block external, allow internal ทุกอย่าง
- ปัญหา: ถ้ามีคนข้างในทำร้าย (Insider Threat) หรือ Malware เข้ามาได้ → แพร่กระจายทั่วเครือข่าย

**Zero Trust Approach**:
- "Never Trust, Always Verify" - ไม่เชื่อใครเลย
- ทุกคน/อุปกรณ์ต้องพิสูจน์ตัวตนทุกครั้ง แม้อยู่ภายใน
- ใช้ Micro-segmentation, MFA, Least Privilege

**ข้อดี**:
- ปลอดภัยกว่า แม้มี Insider Threat
- จำกัดการแพร่กระจายของ Malware

**ข้อเสีย**:
- ซับซ้อนในการ setup
- ผู้ใช้ต้อง authenticate บ่อย
- ต้นทุนสูง
</details>

### Q2: VPN vs Proxy
**คำถาม**: VPN และ Proxy ต่างกันอย่างไร? เมื่อไหร่ควรใช้อะไร?

<details>
<summary>คำตอบ</summary>

| ฟีเจอร์ | VPN | Proxy |
|---------|-----|-------|
| **เข้ารหัส** | ใช่ (ทุก traffic) | ไม่ (บางตัวมี) |
| **ระดับ** | OS-level (ทุก app) | App-level (เฉพาะ browser) |
| **ความเร็ว** | ช้ากว่า (encryption overhead) | เร็วกว่า |
| **Privacy** | สูง | ปานกลาง |
| **Use Case** | Remote work, Privacy | Bypass blocking, Caching |

**ใช้ VPN เมื่อ**:
- ต้องการ encryption ทุก traffic
- Remote work, เข้าถึงระบบบริษัท
- Privacy สำคัญ

**ใช้ Proxy เมื่อ**:
- แค่ต้องการเปลี่ยน IP
- Bypass geo-restriction
- Caching (เพื่อความเร็ว)
</details>

### Q3: Firewall ทุก Layer?
**คำถาม**: ถ้าเรามี Application Layer Firewall (WAF) แล้ว ยังต้องใช้ Network Firewall ไหม? ทำไม?

<details>
<summary>คำตอบ</summary>

**ต้องใช้ทั้งสอง!** → Defense in Depth

**Network Firewall (Layer 3-4)**:
- ป้องกัน network-level attacks (Port Scan, DDoS, Unauthorized IP)
- ทำงานเร็ว (ดู header เท่านั้น)
- Block traffic ก่อนถึง application

**Application Layer Firewall / WAF (Layer 7)**:
- ป้องกัน application-level attacks (SQL Injection, XSS, CSRF)
- ตรวจสอบ payload, HTTP headers, cookies
- ใช้กับ Web Application โดยเฉพาะ

**ตัวอย่าง**:
- Network Firewall block IP ที่ไม่ดี → WAF ไม่ต้องเสียเวลาตรวจสอบ
- ถ้า hacker เข้ามาผ่าน Network Firewall ได้ → WAF ยัง block SQL Injection ได้

**หลักการ**: ยิ่งหลายชั้นยิ่งปลอดภัย!
</details>

---

## 📝 สรุปการสอน Week 5

### สิ่งที่เราได้เรียนรู้วันนี้

```
┌────────────────────────────────────────────────────┐
│           Summary: Week 5                          │
├────────────────────────────────────────────────────┤
│  ✅ Network Security Concepts                     │
│     • ภัยคุกคามทางเครือข่าย                        │
│     • หลักการป้องกันหลายชั้น (Defense in Depth)  │
│                                                    │
│  ✅ Firewall                                       │
│     • ประเภท: Packet Filtering, Stateful, WAF     │
│     • การสร้าง Rules (Allow/Deny)                 │
│     • Best Practices                               │
│                                                    │
│  ✅ IDS/IPS                                        │
│     • IDS = Detect + Alert                        │
│     • IPS = Detect + Block                        │
│     • Signature-based vs Anomaly-based            │
│                                                    │
│  ✅ VPN                                            │
│     • Encrypted Tunnel                            │
│     • Remote Access VPN vs Site-to-Site VPN       │
│     • โปรโตคอล: OpenVPN, WireGuard, IPsec         │
│                                                    │
│  ✅ Network Segmentation & DMZ                    │
│     • แบ่ง network เป็น zones                     │
│     • DMZ = Buffer zone                           │
│     • Defense in Depth                            │
│                                                    │
│  ✅ Hands-on Lab                                  │
│     • Wireshark: ดู network packets               │
│     • Firewall Rules: ufw / Windows Firewall      │
│     • Group Activity: ออกแบบ DMZ                  │
└────────────────────────────────────────────────────┘
```

### Key Takeaways

🔑 **1. Network Security = หลายชั้น**
- ไม่มีเครื่องมือชิ้นเดียวที่ "ปลอดภัย 100%"
- Firewall + IDS/IPS + Segmentation + Encryption = Defense in Depth

🔑 **2. Firewall ไม่ใช่ทุกอย่าง**
- Firewall บล็อก traffic แต่ไม่สามารถตรวจจับ Malware ภายใน payload
- ต้องใช้ร่วมกับ Antivirus, IDS/IPS, Web Filtering

🔑 **3. VPN ≠ ความปลอดภัยสมบูรณ์**
- VPN เข้ารหัส traffic ระหว่าง device กับ VPN server เท่านั้น
- ยังต้องใช้ HTTPS, ระวัง Phishing, เลือก VPN provider ที่เชื่อถือได้

🔑 **4. DMZ ลด Blast Radius**
- ถ้า Web Server โดนแฮก → Database ยังปลอดภัย
- แบ่ง network เป็น zones ตามความสำคัญ

🔑 **5. Monitoring สำคัญเท่าการป้องกัน**
- ตั้ง Firewall แล้วต้อง monitor logs
- ตรวจสอบ unusual traffic, failed login attempts
- Incident Response Plan ต้องมีไว้ล่วงหน้า

---

## 🔮 สัปดาห์หน้าเราจะเรียนอะไร?

### Week 6: Cryptography Basics

ในสัปดาห์หน้าเราจะเรียนรู้เกี่ยวกับ **การเข้ารหัส (Cryptography)**:

```
┌────────────────────────────────────────────────────┐
│          Preview: Week 6                           │
├────────────────────────────────────────────────────┤
│  📚 หัวข้อที่จะเรียน:                              │
│                                                    │
│  1️⃣  หลักการเข้ารหัสพื้นฐาน                       │
│      • Symmetric vs Asymmetric Encryption         │
│      • Alice-Bob-Eve model                        │
│                                                    │
│  2️⃣  Symmetric Encryption                         │
│      • AES, DES                                   │
│      • Block Cipher vs Stream Cipher              │
│                                                    │
│  3️⃣  Asymmetric Encryption (Public Key)           │
│      • RSA, ECC                                   │
│      • Public Key + Private Key                   │
│                                                    │
│  4️⃣  Hash Function                                │
│      • SHA-256, MD5                               │
│      • Password Hashing                           │
│                                                    │
│  5️⃣  Digital Signature & Certificates             │
│      • PKI (Public Key Infrastructure)            │
│      • SSL/TLS Certificates                       │
│                                                    │
│  🔬 Lab 3:                                        │
│      • ใช้ OpenSSL เข้ารหัส/ถอดรหัส              │
│      • Inspect SSL Certificate จากเว็บไซต์       │
│      • Cipher Puzzle (เกมถอดรหัส)                │
└────────────────────────────────────────────────────┘
```

**ทำไมต้องเรียน Cryptography?**
- VPN ที่เรียนในสัปดาห์นี้ → ใช้ Encryption!
- HTTPS ที่เราเห็นใน Wireshark → ใช้ TLS!
- Password ที่เก็บใน Database → ใช้ Hash!

**สิ่งที่ควรทำก่อนเรียนสัปดาห์หน้า**:
- ลองอ่าน: "The Code Book" by Simon Singh (ประวัติการเข้ารหัส)
- ลองเล่น: Caesar Cipher / Substitution Cipher
- ตรวจสอบ Certificate ของเว็บไซต์ที่คุณชอบ (ดูว่าใช้ algorithm อะไร)

---

## 🎓 Tips & Best Practices จากสัปดาห์นี้

```
╔═══════════════════════════════════════════════════╗
║                                                   ║
║   🛡️  Security Tips: Network Edition             ║
║                                                   ║
║  1. ใช้ Firewall เสมอ - แม้ใน laptop ส่วนตัว     ║
║                                                   ║
║  2. Default Deny - อนุญาตเฉพาะที่จำเป็น          ║
║                                                   ║
║  3. ระวัง Public Wi-Fi - ใช้ VPN เสมอ            ║
║                                                   ║
║  4. อัปเดต Firmware ของ Router บ้าน             ║
║                                                   ║
║  5. เปลี่ยน Password Router จาก default          ║
║                                                   ║
║  6. ปิด WPS (Wi-Fi Protected Setup) - มีช่องโหว่  ║
║                                                   ║
║  7. ใช้ WPA3 (ถ้า Router รองรับ) แทน WPA2        ║
║                                                   ║
║  8. Segment network: Guest Wi-Fi แยกจาก Main      ║
║                                                   ║
╚═══════════════════════════════════════════════════╝
```

### ❌ สิ่งที่ไม่ควรทำ

- **อย่า** ปิด Firewall เพื่อให้เกม/แอปทำงานได้ → เปิด port เฉพาะที่จำเป็นแทน
- **อย่า** ใช้ Free VPN ที่ไม่รู้จัก → อาจเก็บ log หรือแจก malware
- **อย่า** ให้ port forwarding ทุก port → เปิดเฉพาะที่จำเป็น + ใช้ DMZ ถ้าจำเป็น
- **อย่า** ใช้ HTTP เมื่อส่งข้อมูลสำคัญ → ใช้ HTTPS เสมอ
- **อย่า** ใช้ password เดียวกันทุกระบบ → แม้อยู่ใน VPN ก็ตาม

---

## 📚 แหล่งข้อมูลเพิ่มเติม

### เอกสารและหนังสือแนะนำ

1. **Firewall**
   - pfSense Documentation: https://docs.netgate.com/pfsense/
   - iptables Tutorial: https://www.netfilter.org/documentation/

2. **IDS/IPS**
   - Snort User Manual: https://www.snort.org/documents
   - Suricata Documentation: https://suricata.io/

3. **VPN**
   - OpenVPN Documentation: https://openvpn.net/community-resources/
   - WireGuard: https://www.wireguard.com/

4. **Network Security**
   - SANS Network Security: https://www.sans.org/cyber-security-courses/
   - OWASP: https://owasp.org/

### วิดีโอแนะนำ

- **Computerphile**: Network Security Series (YouTube)
- **NetworkChuck**: VPN, Firewall Tutorials
- **LiveOverflow**: Network Hacking Basics

### Tools ที่ควรลอง

1. **Wireshark** - Packet Analysis
2. **pfSense** - Open-source Firewall (ทดลองใน VM)
3. **Snort** - IDS/IPS
4. **OpenVPN** - VPN Setup
5. **GNS3** - Network Simulator (สำหรับฝึกออกแบบ network)

---

## 💬 ข้อความจากอาจารย์

> "Network Security เป็นรากฐานสำคัญของ Cybersecurity ทุกวันนี้ ทุกอย่างเชื่อมต่อกัน ไม่ว่าจะเป็นมือถือ คอมพิวเตอร์ หรือแม้แต่ตู้เย็น (IoT) การเข้าใจว่า network ทำงานอย่างไร มีจุดอ่อนตรงไหน และป้องกันอย่างไร จะช่วยให้คุณสามารถออกแบบระบบที่ปลอดภัยได้
>
> อย่าลืมว่า **Security is a journey, not a destination** เทคโนโลยีเปลี่ยนแปลงตลอดเวลา ภัยคุกคามก็มีรูปแบบใหม่ ๆ ตลอดเวลา การเรียนรู้อย่างต่อเนื่องและติดตามข่าวสารด้าน Security จึงสำคัญมาก
>
> สุดท้ายนี้ อย่าลืมว่า Cybersecurity ไม่ใช่แค่เรื่องของเทคโนโลยี แต่เป็นเรื่องของ **คน (People)**, **กระบวนการ (Process)**, และ **เทคโนโลยี (Technology)** ทั้งสามส่วนต้องทำงานร่วมกันเพื่อให้เกิดความปลอดภัยอย่างแท้จริง"
>
> — อาจารย์ผู้สอน ENGSE214

---

## 🙋 คำถามและข้อสงสัย?

```
╔═══════════════════════════════════════════════════╗
║                                                   ║
║  มีคำถามหรือข้อสงสัยเพิ่มเติม?                   ║
║                                                   ║
║  📧 Email: instructor@university.ac.th            ║
║  💬 Discussion Forum: [LMS Link]                  ║
║  🕐 Office Hours: ทุกวันพุธ 14:00-16:00          ║
║  💻 GitHub Discussions: [Course Repo]             ║
║                                                   ║
╚═══════════════════════════════════════════════════╝

        "Security is not a product,
         but a process."
                    - Bruce Schneier

┌────────────────────────────────────────────────────┐
│  Remember:                                         │
│  • Keep your systems updated                      │
│  • Use strong, unique passwords                   │
│  • Enable multi-factor authentication             │
│  • Be cautious on public Wi-Fi                    │
│  • Think before you click                         │
│  • Report suspicious activities                   │
└────────────────────────────────────────────────────┘
```

---

**หมายเหตุ:** เอกสารนี้เป็นเวอร์ชัน 1.0 สำหรับ ENGSE214 Week 5  
**อัปเดตล่าสุด:** January 2025  
**ผู้สอน:** [ชื่ออาจารย์]  
**คณะ:** วิศวกรรมศาสตร์ สาขาวิศวกรรมซอฟต์แวร์

---

## 📎 Appendix: เอกสารอ้างอิง

### A. Firewall Configuration Cheat Sheet

```bash
# Linux ufw Quick Reference
sudo ufw status                    # ดูสถานะ
sudo ufw enable                    # เปิด
sudo ufw disable                   # ปิด
sudo ufw reset                     # รีเซ็ต
sudo ufw default deny incoming     # ตั้ง default
sudo ufw allow 22/tcp              # อนุญาต port
sudo ufw deny 23/tcp               # บล็อก port
sudo ufw delete allow 80/tcp       # ลบ rule
sudo ufw allow from 192.168.1.0/24 # อนุญาต subnet
sudo ufw limit 22/tcp              # Rate limiting
```

### B. Common Ports Reference

| Port | Service | Protocol | Description |
|------|---------|----------|-------------|
| 20-21 | FTP | TCP | File Transfer (ไม่ปลอดภัย) |
| 22 | SSH | TCP | Secure Shell |
| 23 | Telnet | TCP | Remote login (ไม่ปลอดภัย) |
| 25 | SMTP | TCP | Email (Send) |
| 53 | DNS | UDP/TCP | Domain Name System |
| 80 | HTTP | TCP | Web (ไม่เข้ารหัส) |
| 110 | POP3 | TCP | Email (Receive) |
| 143 | IMAP | TCP | Email (Receive) |
| 443 | HTTPS | TCP | Web (เข้ารหัส) |
| 445 | SMB | TCP | Windows File Sharing |
| 3306 | MySQL | TCP | Database |
| 3389 | RDP | TCP | Remote Desktop |
| 5432 | PostgreSQL | TCP | Database |
| 8080 | HTTP Alt | TCP | Web (Alternative) |

**🚨 Ports ที่ไม่ควรเปิดสู่ Internet**:
- 22 (SSH) - ใช้ VPN แทน หรือเปลี่ยน port + Key-based auth
- 23 (Telnet) - ห้ามใช้! ใช้ SSH แทน
- 3306 (MySQL), 5432 (PostgreSQL) - Database ต้องอยู่ใน Internal Network
- 3389 (RDP) - ควรใช้ผ่าน VPN
- 445 (SMB) - มักถูกโจมตีด้วย Ransomware

---

จบเนื้อหา Week 5! 🎉  
เตรียมพบกันสัปดาห์หน้าใน Week 6: Cryptography Basics! 🔐
