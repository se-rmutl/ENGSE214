# Week 5: Network Security Diagrams - User Guide

## 📊 รายการ Diagrams ทั้งหมด

เอกสารนี้มี **6 diagrams** สวยงามสำหรับใช้ทำ slides หรือประกอบการสอน Week 5: Network Security & Basic Packet Filtering

---

## 🎨 Diagram ที่ 1: Network Security Overview
**ไฟล์:** `Week5_Diagram1_Network_Security_Overview.drawio`

### เนื้อหา:
- แสดงภาพรวม Network Security แบบ 3 ชั้น
- Internet (Public) → Firewall → Internal Network
- รายการ Threats ทางซ้าย (Hackers, Malware, Phishing, DDoS, etc.)
- รายการ Defense ทางขวา (Firewall, IDS/IPS, VPN, Encryption, etc.)
- อุปกรณ์ต่าง ๆ ใน Internal Network (Laptop, Smartphone, Server, IoT, Database, File Server)

### ใช้เมื่อไร:
- เปิดตัว Week 5
- อธิบายภาพรวม Network Security
- แนะนำความสำคัญของ Defense in Depth

---

## 🔥 Diagram ที่ 2: Firewall Types Comparison
**ไฟล์:** `Week5_Diagram2_Firewall_Types.drawio`

### เนื้อหา:
- เปรียบเทียบ 4 ประเภทของ Firewall:
  1. **Packet Filtering** - ตรวจสอบ Header (IP, Port, Protocol)
  2. **Stateful Inspection** - จำ Connection State
  3. **Application Layer (WAF)** - ตรวจสอบ Payload (SQLi, XSS)
  4. **Next-Gen Firewall (NGFW)** - รวมทุกอย่าง + AI/ML
- ตารางเปรียบเทียบ Speed, Security, Cost, Complexity, Best For
- ใช้สีแยกแต่ละประเภทชัดเจน

### ใช้เมื่อไร:
- สอนเรื่อง Firewall Types
- อธิบายความแตกต่างของแต่ละประเภท
- ช่วยให้นักศึกษาเลือก Firewall ที่เหมาะสม

---

## 🚨 Diagram ที่ 3: IDS vs IPS Comparison
**ไฟล์:** `Week5_Diagram3_IDS_vs_IPS.drawio`

### เนื้อหา:
- เปรียบเทียบ IDS vs IPS แบบ Side-by-Side
- **IDS (Intrusion Detection System):**
  - "Security Camera" 📹
  - Passive Monitoring
  - Detects + Alerts
  - ไม่ Block traffic
- **IPS (Intrusion Prevention System):**
  - "Security Guard" 🛡️
  - Active Defense
  - Detects + Blocks
  - วางแบบ Inline

### ใช้เมื่อไร:
- สอนความแตกต่างระหว่าง IDS และ IPS
- อธิบายว่า IDS detect อย่างเดียว แต่ IPS detect + block

---

## 🔐 Diagram ที่ 4: VPN Tunnel Concept
**ไฟล์:** `Week5_Diagram4_VPN_Tunnel.drawio`

### เนื้อหา:
- เปรียบเทียบ 2 สถานการณ์:
  
**❌ WITHOUT VPN:**
- Traffic แบบ Plain Text
- ISP, Hackers, Government สามารถดูได้
- ไม่ปลอดภัย

**✅ WITH VPN:**
- Encrypted Tunnel 🔒
- Traffic เข้ารหัสทั้งหมด
- ISP, Hackers ดูไม่ได้

### Benefits ของ VPN:
- 🔐 Encrypts all traffic
- 👁️ Hides your IP address
- 🌐 Bypass geo-restrictions
- 🏢 Secure remote access

### ใช้เมื่อไร:
- สอนเรื่อง VPN
- อธิบายการทำงานของ Encrypted Tunnel
- แสดงข้อดีของการใช้ VPN

---

## 🏗️ Diagram ที่ 5: DMZ Architecture (3-Tier)
**ไฟล์:** `Week5_Diagram5_DMZ_Architecture.drawio`

### เนื้อหา:
- สถาปัตยกรรมแบบ 3-Tier:
  
**🔴 Zone 1: INTERNET (Public / Untrusted)**
- Users, Hackers, External Traffic

**🔥 Firewall 1 (Border):**
- Rules: ALLOW HTTP/HTTPS → DMZ, DENY all other

**🟡 Zone 2: DMZ (Semi-Trusted)**
- Web Server (🌐 :80, :443)
- Mail Server (📧 :25, :587)
- VPN Gateway (🔐 :1194)
- FTP Server (📁 :21)

**🔥 Firewall 2 (Internal):**
- Rules: ALLOW Web → DB:3306, ALLOW Admin → All, DENY all other from DMZ

**🟢 Zone 3: INTERNAL NETWORK (Trusted)**
- Database (💾 192.168.1.30:3306)
- App Server (🖥️ 192.168.1.20:8080)
- File Server (🗂️ 192.168.1.40:445)
- Workstations (💻)
- Admin PC (👨‍💼)

### ใช้เมื่อไร:
- สอนเรื่อง DMZ
- อธิบายทำไมต้องมี DMZ
- ออกแบบ Network Architecture

---

## 🔀 Diagram ที่ 6: Network Segmentation (Flat vs Segmented)
**ไฟล์:** `Week5_Diagram6_Network_Segmentation.drawio`

### เนื้อหา:
- เปรียบเทียบ 2 แนวทาง:

**❌ FLAT NETWORK (Bad Practice):**
- ทุกอุปกรณ์อยู่ใน Network เดียว (192.168.1.0/24)
- Malware แพร่ได้ทั้งเครือข่าย 🦠
- ไม่มีการแยกส่วน
- Blast Radius = 100%

**✅ SEGMENTED NETWORK (Best Practice):**
- แบ่งเป็น 6 Zones:
  1. **Public Zone** (10.0.1.0/24) - Web, Mail
  2. **App Zone** (192.168.10.0/24) - App Server, API
  3. **Database Zone** (192.168.20.0/24) - Database, Files
  4. **User Zone** (192.168.30.0/24) - Workstations
  5. **IoT Zone** (192.168.40.0/24) - Cameras, Sensors
  6. **Guest Zone** (192.168.99.0/24) - Guest Devices
- มี Firewall 🔥 แยกแต่ละ Zone
- Malware จำกัดอยู่ใน Zone เดียว
- Reduced Blast Radius

### ใช้เมื่อไร:
- สอนเรื่อง Network Segmentation
- อธิบายความแตกต่างระหว่าง Flat vs Segmented
- แสดงให้เห็นว่า Segmentation ช่วยลด Blast Radius

---

## 📥 วิธีใช้ Diagrams

### ขั้นตอนที่ 1: เปิดไฟล์
1. ไปที่ https://app.diagrams.net/ (draw.io)
2. คลิก **File → Open from → Device**
3. เลือกไฟล์ `.drawio` ที่ต้องการ

### ขั้นตอนที่ 2: แก้ไข (ถ้าต้องการ)
- แก้ไขข้อความ
- เปลี่ยนสี
- เพิ่ม/ลด องค์ประกอบ
- ปรับขนาด

### ขั้นตอนที่ 3: Export เป็นรูปภาพ
1. คลิก **File → Export as → PNG** (หรือ SVG, JPEG, PDF)
2. ตั้งค่า:
   - **Zoom:** 100% หรือมากกว่า (แนะนำ 150-200% สำหรับ slide คมชัด)
   - **Transparent Background:** ✅ (ถ้าต้องการพื้นโปร่งใส)
   - **Border Width:** 10-20 px
3. คลิก **Export**
4. บันทึกไฟล์

### ขั้นตอนที่ 4: นำไปใช้ใน Presentation
- **PowerPoint:** Insert → Pictures
- **Google Slides:** Insert → Image
- **Keynote:** Insert → Choose

---

## 🎯 Tips สำหรับการใช้งาน

### 1. สำหรับ Presentation Slides:
- Export เป็น **PNG** ความละเอียดสูง (200-300%)
- ใช้ **Transparent Background** เพื่อให้กลมกลืนกับ slide
- **Border Width:** 10-20 px เพื่อไม่ให้ชิดขอบ

### 2. สำหรับเอกสาร/Handout:
- Export เป็น **PDF** เพื่อความคมชัด
- หรือ **SVG** ถ้าต้องการขยายไม่เสีย

### 3. สำหรับ Web/LMS:
- Export เป็น **PNG** ขนาด 100-150%
- Optimize ขนาดไฟล์ด้วย TinyPNG หรือ ImageOptim

### 4. การปรับแต่ง:
- เปลี่ยนสีให้เข้ากับ Corporate Colors ของมหาวิทยาลัย
- เพิ่มโลโก้หรือ watermark ถ้าต้องการ
- แก้ไขข้อความเป็นภาษาอื่น ๆ

---

## 🎨 Color Scheme ที่ใช้

### สีแต่ละหมวดหมู่:

| หมวดหมู่ | สี | Hex Code |
|----------|-----|----------|
| **Danger/Threats** | 🔴 Red | #C62828, #FF5252 |
| **Warning/DMZ** | 🟡 Orange | #E65100, #FF9800 |
| **Safe/Trusted** | 🟢 Green | #388E3C, #4CAF50 |
| **Info/Network** | 🔵 Blue | #1976D2, #2196F3 |
| **Purple/App** | 🟣 Purple | #7B1FA2, #9C27B0 |
| **Yellow/IoT** | 🟡 Yellow | #F57F17, #FDD835 |
| **Grey/Guest** | ⚪ Grey | #616161, #9E9E9E |

---

## 📖 การใช้งานในบทเรียน

### แนะนำการใช้แต่ละ Diagram:

1. **Diagram 1** → เปิดตัว Week 5 (10 นาที)
2. **Diagram 2** → สอน Firewall Types (20 นาที)
3. **Diagram 3** → สอน IDS vs IPS (15 นาที)
4. **Diagram 4** → สอน VPN (20 นาที)
5. **Diagram 5** → สอน DMZ + Group Activity (30 นาที)
6. **Diagram 6** → สอน Network Segmentation (20 นาที)

**รวมเวลา:** ~115 นาที (≈ 2 ชั่วโมง)

---

## ✅ Checklist ก่อนใช้งาน

- [ ] เปิดทุกไฟล์ดูก่อนว่า render ถูกต้อง
- [ ] Export เป็นรูปภาพ (PNG/PDF) ความละเอียดสูง
- [ ] ตรวจสอบว่าข้อความถูกต้อง ไม่มี typo
- [ ] เตรียม Speaker Notes สำหรับแต่ละ diagram
- [ ] ทดสอบฉายใน classroom จริง (ดูว่าเห็นชัดพอไหม)

---

## 🆘 Troubleshooting

### ปัญหา: ไฟล์เปิดไม่ได้
**วิธีแก้:** ตรวจสอบว่าใช้ draw.io (diagrams.net) เวอร์ชันล่าสุด

### ปัญหา: สีไม่ตรงกับที่ต้องการ
**วิธีแก้:** Edit ใน draw.io → เลือก Element → คลิก Fill Color → ใส่ Hex Code ใหม่

### ปัญหา: Font หาย
**วิธีแก้:** draw.io ใช้ Web Font ดังนั้นต้องมี Internet เมื่อเปิดไฟล์

### ปัญหา: Export มีขนาดไฟล์ใหญ่มาก
**วิธีแก้:** 
- ลด Zoom % เมื่อ export
- หรือใช้ tool compress อย่าง TinyPNG

---

## 📞 ต้องการความช่วยเหลือ?

หากมีปัญหาหรือต้องการปรับแต่ง diagram เพิ่มเติม:
- ติดต่อ: [อีเมล IT Support]
- หรือ: [LINE Official มหาวิทยาลัย]

---

**สร้างโดย:** Claude AI  
**วันที่:** January 2025  
**Version:** 1.0

**หมายเหตุ:** Diagrams เหล่านี้สร้างขึ้นเพื่อใช้ในการสอน Week 5: Network Security & Basic Packet Filtering สำหรับรายวิชา ENGSE214 - Introduction to Cyber Security

---

## 🎉 ขอให้สอนสนุก!

Diagrams เหล่านี้ออกแบบมาเพื่อให้:
- **สวยงาม** และดึงดูดความสนใจ
- **ชัดเจน** เข้าใจง่าย
- **ครบถ้วน** ครอบคลุมเนื้อหา Week 5
- **ใช้งานง่าย** export ได้ทันที

หวังว่านักศึกษาจะเข้าใจ Network Security มากขึ้น! 🛡️🔒
