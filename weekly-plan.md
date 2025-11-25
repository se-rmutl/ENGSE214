# ENGSE214 Weekly Teaching & Assessment Plan
**Course:** ENGSE214 – ความมั่นคงปลอดภัยทางไซเบอร์เบื้องต้น (Introduction to Cyber Security)  
**Program:** วศ.บ. วิศวกรรมซอฟต์แวร์ – Year 2  
**Credits:** 3(3-0-6)

---

## 1. Course Information

- **Course Code / Name:** ENGSE214 – ความมั่นคงปลอดภัยทางไซเบ์อร์เบื้องต้น (Introduction to Cyber Security)  
- **Prerequisites:** None  
- **Course Description (TH):**  
  ศึกษาและปฏิบัติติพื้นฐานด้านความปลอดภัยทางไซเบอร์ หลักการเกี่ยวกับความมั่นคงปลอดภัยของระบบคอมพิวเตอร์และสารสนเทศ วิธีการปกป้องระบบปฏิบัติการคอมพิวเตอร์ ระบบเครือข่ายและข้อมูลจากการโจมตีทางไซเบอร์ วิธีตรวจสอบระบบและรับมือเมื่อเกิดภัยทางไซเบอร์ รวมถึงการปกป้องความเป็นส่วนตัวของผู้ใช้งาน  

- **Course Description (EN):**  
  Study the basics of cybersecurity, computer and information security principles, methods of protecting computer operating systems, network systems and data from cyber-attacks. Monitor and respond to cyber threats including protecting the privacy of users.

---

## 2. Course Learning Outcomes (CLO)

เมื่อจบรายวิชา นักศึกษาจะสามารถ:

- **CLO1 – Fundamental Concepts**  
  อธิบายแนวคิดพื้นฐานและหลักการด้านความมั่นคงปลอดภัยทางไซเบอร์ (CIA Triad, Threat, Vulnerability, Risk) ได้อย่างถูกต้อง

- **CLO2 – Threat & Vulnerability Analysis**  
  วิเคราะห์ภัยคุกคามและช่องโหว่ในระบบคอมพิวเตอร์และเครือข่ายจากกรณีศึกษา/สถานการณ์จำลองได้

- **CLO3 – Protection & Response Techniques**  
  ประยุกต์เทคนิคการป้องกันและตอบสนองต่อการโจมตีทางไซเบอร์กับระบบตัวอย่าง (OS, Network, Web) ในสภาพแวดล้อม Lab/VM ได้อย่างเหมาะสม

- **CLO4 – Risk & Security Evaluation**  
  ประเมินความเสี่ยงด้านความปลอดภัยของระบบสารสนเทศ และเสนอแนวทางลดความเสี่ยง (Countermeasures / Controls) ได้

- **CLO5 – Security Management, Privacy & Ethics**  
  ออกแบบมาตรการรักษาความปลอดภัยที่เหมาะสมในบริบทขององค์กร/ระบบซอฟต์แวร์ขนาดเล็ก โดยคำนึงถึงกฎหมาย ความเป็นส่วนตัว และจริยธรรมของผู้ใช้

---

## 3. Weekly Plan (15 Weeks)

> โครงสร้างสำหรับ README/แผนการสอนใน GitHub: แต่ละสัปดาห์ประกอบด้วย  
> - **Topic / Details**  
> - **Teaching & Learning Activities / Lab**  
> - **Assessment & CLO Mapping**

---

### Week 1 – Introduction to Cybersecurity & CIA Triad

**Topic / Details**

- ภาพรวม Cybersecurity ในชีวิตจริง + ตัวอย่างข่าวเหตุการณ์โจมตี
- แนวคิดพื้นฐาน: Asset, Threat, Vulnerability, Risk
- หลักการ **CIA Triad** (Confidentiality, Integrity, Availability)
- ภาพรวมเนื้อหาทั้งเทอม (OS, Network, Web, Cloud, Privacy ฯลฯ)

**Teaching & Learning Activities / Lab**

- Lecture: สไลด์พร้อม infographic, ยกตัวอย่างเหตุการณ์โจมตีจริง
- Activity: Poll / Kahoot / Mentimeter – รับรู้มุมมองของ นศ. ต่อ Cybersecurity
- Group Activity: ระบุ Asset–Threat–Vulnerability จากสิ่งใกล้ตัว
- Demo: ตัวอย่างการใช้รหัสผ่านง่าย ๆ / Wi-Fi สาธารณะให้เห็นความเสี่ยง

**Assessment & CLO Mapping**

- Mini Assignment: อธิบาย CIA Triad จาก case study (1 หน้า) → คะแนนในหมวด Assignments
- Participation: คะแนนจากการแลกเปลี่ยนในชั้น
- **CLO:** CLO1

---

### Week 2 – Cyber Threat Types & Malware

**Topic / Details**

- ประเภทของภัยคุกคาม (Threat Classification)
- Malware: Virus, Worm, Trojan, Ransomware
- Social Engineering, Phishing, Spear Phishing
- Advanced Persistent Threats (APT) – แนวคิดภาพรวม

**Teaching & Learning Activities / Lab**

- Lecture: ตัวอย่าง Malware + case study (เช่น WannaCry, Phishing mail)
- Group Case Study: วิเคราะห์เหตุการณ์โจมตี (โจทย์เตรียมให้)
  - ระบุ Target, Attack Vector, ประเภทภัยคุกคาม
- Demo: แสดง VM ที่จำลองพฤติกรรม Malware หรือใช้วิดีโอสาธิต

**Assessment & CLO Mapping**

- Quiz 1: ประเภท Threat / Malware / Social Engineering (ออนไลน์/ในชั้น)
- Participation: จากการวิเคราะห์ case study
- **CLO:** CLO1, CLO2

---

### Week 3 – Vulnerabilities & Basic Risk Assessment

**Topic / Details**

- ความหมายและประเภทของ Vulnerability
- Common Vulnerabilities and Exposures (CVE)
- แนวคิด Risk Assessment และ Risk Management
- Common Vulnerability Scoring System (CVSS) – ใช้อ่านค่าพื้นฐาน

**Teaching & Learning Activities / Lab**

- Lecture: วงจรการบริหารความเสี่ยง (Identify → Analyze → Evaluate → Treat/Monitor)
- Mini Lab: ค้นหา CVE จริงจากฐานข้อมูล (CVE/NVD) และอ่านค่า CVSS
- Activity: วิเคราะห์ช่องโหว่ใน “ระบบ login ง่าย ๆ” และลองประเมินความเสี่ยงคร่าว ๆ

**Assessment & CLO Mapping**

- Quiz 2: คำถามเกี่ยวกับ CVE / Risk / CVSS
- Assignment: Mini Risk Assessment ของระบบตัวอย่าง
- **CLO:** CLO2, CLO4

---

### Week 4 – Operating System Security & Hardening

**Topic / Details**

- หลักการรักษาความปลอดภัยระบบปฏิบัติการ
- Access Control, Authentication, Authorization
- User Privilege Management (Least Privilege, sudo/Run as)
- การตั้งค่าความปลอดภัยเบื้องต้นใน Windows / Linux

**Teaching & Learning Activities / Lab**

- Lecture: เปรียบเทียบ security model Windows vs Linux
- **Lab 1 – OS Hardening (ใช้ VM)**
  - สร้าง user ปกติ / admin
  - ตั้ง Password Policy
  - ปิด service ไม่จำเป็น
  - ตั้งค่า Firewall พื้นฐาน
- ใช้ VirtualBox/VMware + Windows / Linux VM

**Assessment & CLO Mapping**

- Lab 1 Report: OS Hardening Checklist & ผลการตั้งค่า
- Participation: จากการทำ Lab และถาม–ตอบในชั้น
- **CLO:** CLO2, CLO3

---

### Week 5 – Network Security & Basic Packet Filtering

**Topic / Details**

- Network Security Concepts
- Firewall, IDS/IPS – แนวคิดและตัวอย่าง
- Virtual Private Network (VPN)
- Network Segmentation, DMZ

**Teaching & Learning Activities / Lab**

- Lecture: โครงสร้างเครือข่ายองค์กร + จุดที่ใช้ Firewall/IDS/IPS
- **Lab 2 – Packet View & Filtering**
  - ใช้ Wireshark ดู packet ที่วิ่งใน network (ใน Lab/VM)
  - ทดลองสร้าง Rule ใน Firewall (ufw / Windows Firewall)
- Group Activity: ออกแบบ “mini DMZ” สำหรับเว็บเล็ก ๆ พร้อม Diagram

**Assessment & CLO Mapping**

- Lab 2 Summary: สกรีนช็อต + คำอธิบายผลการทดลอง
- Short Quiz: Firewall / IDS/IPS / DMZ
- **CLO:** CLO2, CLO3, CLO4

---

### Week 6 – Cryptography Basics

**Topic / Details**

- หลักการพื้นฐานการเข้ารหัสข้อมูล
- Symmetric vs Asymmetric Encryption
- Digital Signature & Certificates (PKI concept)
- Hash Function & Message Authentication

**Teaching & Learning Activities / Lab**

- Lecture: Infographic อธิบายการแลก key ระหว่าง Alice–Bob–Eve
- Demo:
  - ใช้ OpenSSL หรือเครื่องมือออนไลน์เข้ารหัส/ถอดรหัสข้อความสั้น ๆ
  - Inspect Certificate ของเว็บไซต์จริงผ่านเบราว์เซอร์
- In-class Activity: Cipher puzzle (เช่น Caesar / Substitution)

**Assessment & CLO Mapping**

- Quiz 3: Concepts Cryptography พื้นฐาน
- Participation: จาก Cipher puzzle
- **CLO:** CLO1, CLO3

---

### Week 7 – Web Application Security & OWASP Overview

**Topic / Details**

- OWASP Top 10 – ภาพรวม
- ตัวอย่างโจมตี: SQL Injection, Cross-Site Scripting (XSS)
- Input Validation, Parameterized Query
- Secure Coding แนวคิดเบื้องต้น

**Teaching & Learning Activities / Lab**

- Lecture: Mapping ช่องโหว่ OWASP กับ pattern โค้ดที่ นศ. เคยเขียน
- **Lab 3 – Web Vuln Demo**
  - ใช้ระบบทดลองเช่น DVWA / OWASP Juice Shop (ใน VM/Container ปลอดภัย)
  - ให้นักศึกษาลองทำ SQLi / XSS แบบควบคุม
- Group Activity: สรุปแนวทาง Secure Coding เพื่อป้องกันช่องโหว่ที่เจอใน Lab

**Assessment & CLO Mapping**

- Lab 3: Web Security Exercise Report
- Short Quiz: OWASP Top 10 Concepts
- **CLO:** CLO2, CLO3

---

### Week 8 – Midterm Examination

**Topic / Details**

- ทบทวนเนื้อหา Week 1–7
- สอบกลางภาค (Midterm Exam)

**Teaching & Learning Activities / Lab**

- Review Session: ตัวอย่างข้อสอบ/โจทย์, Q&A
- Midterm Exam: ข้อเขียน/ปรนัย/อัตนัยผสม

**Assessment & CLO Mapping**

- Midterm Exam (ประมาณ 25% ของคะแนนรวมรายวิชา)
- วัดผลหลัก ๆ ที่ CLO1, CLO2, CLO3

---

### Week 9 – Security Audit, Vulnerability Assessment & Log Analysis

**Topic / Details**

- Security Auditing & Vulnerability Assessment
- Penetration Testing Methodology (Recon → Exploit → Report)
- Security Scanning Tools (concept-level: Nmap, Nessus)
- Log Analysis & Monitoring

**Teaching & Learning Activities / Lab**

- Lecture: เปรียบเทียบ VA vs Pentest + จริยธรรมการทดสอบ
- Demo:
  - ใช้ Nmap สแกน VM ภายใน Lab (controlled)
  - แสดงตัวอย่าง Log จาก Web Server/OS ให้ดู pattern ผิดปกติ
- Mini Workshop: ให้อ่าน Log snippet และตอบว่าพบสิ่งผิดปกติใด

**Assessment & CLO Mapping**

- Quiz 4: Concepts VA / Pentest / Log
- Short Assignment: “Security Scan & Log Note”
- **CLO:** CLO2, CLO3, CLO4

---

### Week 10 – Incident Response & Basic Forensics

**Topic / Details**

- Incident Response Process  
  (Prepare → Detect → Contain → Eradicate → Recover → Lessons Learned)
- Basic Computer Forensics Concepts (Digital Evidence, Chain of Custody)
- Disaster Recovery & Business Continuity
- Crisis Management

**Teaching & Learning Activities / Lab**

- Lecture: ยกตัวอย่างเหตุการณ์จริงและ map ขั้นตอน Incident Response
- Tabletop Exercise (Group):
  - จำลองเหตุการณ์ Ransomware ในองค์กรขนาดเล็ก
  - ให้แต่ละกลุ่มออก Incident Response Action Plan
- Demo: แสดงตัวอย่าง artifacts ที่ใช้ใน Forensics (log, image แนวคิด, memory dump แนวคิด)

**Assessment & CLO Mapping**

- Group Work: Incident Response Plan (รายงาน/นำเสนอ)
- Participation: ถกแผน + Q&A
- **CLO:** CLO3, CLO4, CLO5

---

### Week 11 – Privacy, PDPA & Ethics

**Topic / Details**

- Security vs Privacy
- PDPA (กฎหมายคุ้มครองข้อมูลส่วนบุคคลของไทย) – เฉพาะส่วนที่เกี่ยวกับซอฟต์แวร์
- GDPR Concepts (เพื่อเทียบกับ PDPA)
- Privacy by Design
- Ethics สำหรับวิศวกรซอฟต์แวร์ด้านข้อมูลส่วนบุคคล

**Teaching & Learning Activities / Lab**

- Lecture: ประเด็น PDPA ที่กระทบต่อการออกแบบระบบ/ซอฟต์แวร์
- Case Study:
  - วิเคราะห์แอป/ระบบยอดนิยม → ระบุประเภทข้อมูลส่วนบุคคลที่เก็บ
  - ถกประเด็นด้านจริยธรรม (เช่น location, behavior tracking)
- Activity:
  - ปรับปรุง “หน้าฟอร์มสมัครสมาชิก” ให้สอดคล้องกับ PDPA/Privacy by Design

**Assessment & CLO Mapping**

- Quiz 5: Concepts PDPA / Privacy / Ethics
- Assignment: ฟอร์มสมัครสมาชิกฉบับปรับปรุง + เหตุผลการออกแบบ
- **CLO:** CLO4, CLO5

---

### Week 12 – Cloud, IoT & Mobile Security

**Topic / Details**

- Cloud Security Basics
- Shared Responsibility Model (IaaS / PaaS / SaaS)
- IoT Security Challenges (อุปกรณ์ราคาถูก, default setting, อัปเดตยาก)
- Mobile Device Security

**Teaching & Learning Activities / Lab**

- Lecture: Diagram แสดง Shared Responsibility + ตัวอย่าง Misconfiguration
- **Lab 4 – Cloud / IoT Security Checklist**
  - วิเคราะห์บริการ Cloud ตัวอย่าง (หรือ diagram) → ระบุส่วนที่ต้อง configure เอง
  - ออก Checklist สำหรับ secure configuration
- Group Activity: เลือกอุปกรณ์ IoT รอบตัว (CCTV, Smart Plug, Router บ้าน ฯลฯ) แล้วระบุความเสี่ยง/แนวทางลดความเสี่ยง

**Assessment & CLO Mapping**

- Lab 4: Cloud/IoT Security Checklist Report
- Participation: จากการอภิปรายกรณี IoT
- **CLO:** CLO3, CLO4, CLO5

---

### Week 13 – Security Management & ISO 27001 Overview

**Topic / Details**

- Information Security Management System (ISMS)
- ISO/IEC 27001 – Concept-level overview
- Security Policy, Standards, Procedures, Guidelines
- Security Awareness Training

**Teaching & Learning Activities / Lab**

- Lecture: โครงสร้างเอกสารความปลอดภัยในองค์กร (Policy → Standard → Procedure)
- Workshop: กลุ่มนักศึกษาสร้าง “Mini Security Policy” สำหรับห้อง Lab คณะหรือทีม Dev เล็ก ๆ
- Demo: ยกตัวอย่าง template Policy/ISMS (ตัดข้อมูลอ่อนไหวออก)

**Assessment & CLO Mapping**

- Group Assignment: Mini Security Policy Document
- Participation: การนำเสนอและแลกเปลี่ยน
- **CLO:** CLO4, CLO5

---

### Week 14 – Emerging Threats & Future of Cybersecurity

**Topic / Details**

- การใช้ AI/ML ด้าน Security (ทั้งฝั่งป้องกันและฝั่งโจมตี)
- ผลของ Quantum Computing ต่อ Cryptography (แนวคิด)
- Zero Trust Architecture – Concept
- แนวโน้มอาชีพและบทบาทในสาย Cybersecurity

**Teaching & Learning Activities / Lab**

- Lecture: Zero Trust Architecture + Example Architecture ง่าย ๆ
- Research Activity (Group):
  - แจกหัวข้อ Trend (AI in SOC, Quantum-safe crypto, Zero Trust in Cloud ฯลฯ)
  - ให้นักศึกษาค้นคว้าข่าว/บทความล่าสุดและทำ Lightning Talk 3–5 นาที
- Discussion: Path สายงาน Cybersecurity สำหรับวิศวกรซอฟต์แวร์

**Assessment & CLO Mapping**

- Group Presentation: Emerging Threats / Trend Report
- Participation: Q&A หลังการนำเสนอ
- **CLO:** CLO1, CLO4, CLO5

---

### Week 15 – Final Review & Secure-by-Design Workshop

**Topic / Details**

- ทบทวนภาพรวม: Foundation, Defense, Monitoring/Response, Privacy & Management
- Mapping เนื้อหากับ CLO1–CLO5 & แนวข้อสอบปลายภาค
- Q&A: จุดที่นักศึกษายังไม่มั่นใจ

**Teaching & Learning Activities / Lab**

- Review Game: Kahoot/Quiz-game ทบทวนเนื้อหาทั้งเทอม
- Mini Workshop:
  - ออกแบบ “Secure-by-Design Blueprint” สำหรับระบบขนาดเล็ก (เช่น ระบบยืม–คืนอุปกรณ์ของคณะ)
  - ระบุ Threats, Controls, Logging, Privacy considerations

**Assessment & CLO Mapping**

- Participation: กิจกรรมทบทวนและ Secure-by-Design Workshop
- ใช้ Workshop เป็นตัวเชื่อมให้เห็นการประยุกต์ CLO1–CLO5 รวมกัน
- **CLO:** CLO1–CLO5 (สรุปภาพรวม)

---

## 4. Assessment Summary

| Assessment Item                                           | Approx. Points | Weight |
| --------------------------------------------------------- | -------------: | -----: |
| Class Participation & In-class Activities (all weeks)     |           40   |   10%  |
| Quizzes (Week 2, 3, 6, 7, 9, 11 – online/in-class)        |           60   |   20%  |
| Labs & Assignments (Lab 1–4 + Group/Individual Work)      |          100   |   20%  |
| Midterm Exam (Week 8)                                     |           50   |   25%  |
| Final Exam (Exam Week, after Week 15)                     |           50   |   25%  |
| **Total**                                                 |       **300**  | **100%** |

> หมายเหตุ: รายละเอียดคะแนนย่อยของแต่ละ Lab/Assignment/Quiz สามารถปรับเพิ่มเติมในเอกสารเสริม (เช่น `labs/README.md`, `assignments/README.md`) ตามโครงสร้าง repo ของวิชา
