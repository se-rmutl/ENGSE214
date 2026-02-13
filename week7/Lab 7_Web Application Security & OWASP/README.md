# Lab 7: Web Application Security & OWASP
## ENGSE214 – Introduction to Cybersecurity

**🎯 ระบบ Vulnerable Blog สำหรับการเรียนรู้ Web Security**

---

## 📦 Package Contents

```
lab7-web-security/
├── README.md (ไฟล์นี้)
├── lab7_instructions.md (คำแนะนำสำหรับนักศึกษา - 40+ หน้า)
├── lab7_instructor_guide.md (คู่มือสำหรับอาจารย์)
├── lab7_assessment_rubric.md (เกณฑ์การให้คะแนน)
├── lab7_payloads_cheatsheet.md (สรุป Payloads & Defense)
├── lab7_sample_report_template.md (ตัวอย่าง Report)
└── setup-lab7.sh (Script สำหรับ setup อัตโนมัติ)
```

---

## 🎓 ภาพรวม Lab

### วัตถุประสงค์
Lab นี้ออกแบบมาให้นักศึกษา:
1. ✅ เข้าใจช่องโหว่ OWASP Top 10 อย่างลึกซึ้ง
2. ✅ ฝึกหาและ exploit ช่องโหว่จริง (SQL Injection & XSS)
3. ✅ นำเทคนิค Secure Coding มาใช้แก้ไขปัญหา
4. ✅ เขียน Security Assessment Report แบบมืออาชีพ

### เวลาที่ใช้
- 📚 **ทฤษฎี + Demo:** 45 นาที
- 🔧 **Hands-on Practice:** 90 นาที
- 📝 **Report Writing:** 45 นาที
- **รวม:** 3 ชั่วโมง

### CLO ที่เกี่ยวข้อง
- **CLO2:** วิเคราะห์และประเมินความเสี่ยงด้านความปลอดภัย
- **CLO3:** ประยุกต์ใช้เทคนิคการรักษาความปลอดภัยในการพัฒนาระบบ

---

## 🚀 Quick Start (สำหรับนักศึกษา)

### ขั้นตอนที่ 1: อ่านเอกสาร
```bash
1. เปิด lab7_instructions.md
2. อ่านทั้งหมดก่อนเริ่ม Lab (ใช้เวลา 15-20 นาที)
3. เตรียม text editor และ browser
```

### ขั้นตอนที่ 2: Setup Environment
```bash
# Option A: ใช้ Setup Script (แนะนำ)
chmod +x setup-lab7.sh
./setup-lab7.sh

# Option B: Manual Setup (ตามคำแนะนำใน lab7_instructions.md)
mkdir lab7-vulnblog
cd lab7-vulnblog
npm init -y
npm install express sqlite3 body-parser cookie-session
```

### ขั้นตอนที่ 3: เริ่ม Lab
```bash
1. สร้าง server.js ตามคำแนะนำ
2. ทดสอบหาช่องโหว่ (ใช้ payloads_cheatsheet.md)
3. แก้ไข code ให้ปลอดภัย
4. เขียน report (ใช้ sample_report_template.md)
```

---

## 👨‍🏫 Quick Start (สำหรับอาจารย์)

### ก่อนสอน (1 สัปดาห์)
```bash
1. อ่าน lab7_instructor_guide.md
2. ทดสอบ Lab ด้วยตัวเอง
3. เตรียม demo environment
4. ตรวจสอบ equipment (projector, internet)
```

### วันสอน
```bash
1. Session 1: Review OWASP + Live Demo (45 นาที)
2. Break (10 นาที)
3. Session 2: Hands-on Testing (60 นาที)
4. Break (10 นาที)
5. Session 3: Code Fixing (65 นาที)
```

### การให้คะแนน
```bash
1. ใช้ lab7_assessment_rubric.md
2. ตรวจ code + report
3. ให้ feedback ที่เป็นประโยชน์
```

---

## 🎯 สิ่งที่นักศึกษาจะได้เรียนรู้

### ทักษะด้านเทคนิค
```
✅ SQL Injection
   • Login bypass
   • UNION-based data extraction
   • Database enumeration

✅ Cross-Site Scripting (XSS)
   • Stored XSS
   • Reflected XSS
   • Cookie stealing
   • Phishing attacks

✅ Secure Coding
   • Parameterized queries
   • Output encoding
   • Input validation
   • Security headers (CSP)

✅ Tools & Technologies
   • Node.js + Express
   • SQLite
   • Browser DevTools
   • Git (version control)
```

### ทักษะด้าน Soft Skills
```
✅ Problem Solving
✅ Critical Thinking
✅ Technical Writing
✅ Documentation
✅ Professional Communication
```

---

## 📚 เอกสารแต่ละไฟล์

### 1. lab7_instructions.md (40+ หน้า)
**สำหรับ:** นักศึกษา  
**เนื้อหา:**
- คำแนะนำทีละขั้นตอน
- Code examples (vulnerable & secure)
- Screenshot placeholders
- Testing procedures
- Report guidelines

**จุดเด่น:**
- ✅ เขียนเป็นภาษาไทยทั้งหมด
- ✅ มี ASCII art infographics
- ✅ มี hints และ tips
- ✅ มี test accounts

---

### 2. lab7_instructor_guide.md
**สำหรับ:** อาจารย์ผู้สอน  
**เนื้อหา:**
- Teaching strategy
- Time management
- Common problems & solutions
- Grading guidelines
- Discussion topics

**จุดเด่น:**
- ✅ Pre-class checklist
- ✅ Walkthrough scripts
- ✅ Troubleshooting guide
- ✅ Success metrics

---

### 3. lab7_assessment_rubric.md
**สำหรับ:** อาจารย์ผู้ให้คะแนน  
**เนื้อหา:**
- Detailed rubric (10 คะแนน)
- Bonus criteria (+5 คะแนน)
- Grading guidelines
- Common mistakes

**จุดเด่น:**
- ✅ Clear scoring criteria
- ✅ Red flags checklist
- ✅ Plagiarism detection
- ✅ Grade distribution

---

### 4. lab7_payloads_cheatsheet.md
**สำหรับ:** นักศึกษา + อาจารย์  
**เนื้อหา:**
- SQL Injection payloads
- XSS payloads
- Defense techniques
- Code examples

**จุดเด่น:**
- ✅ Quick reference
- ✅ Explanation ของแต่ละ payload
- ✅ Legal warnings
- ✅ Testing checklist

---

### 5. lab7_sample_report_template.md
**สำหรับ:** นักศึกษา  
**เนื้อหา:**
- Professional report structure
- Example content
- Screenshot placeholders
- Before/after code comparison

**จุดเด่น:**
- ✅ Industry-standard format
- ✅ CVSS scoring examples
- ✅ Technical writing guidelines
- ✅ Submission checklist

---

### 6. setup-lab7.sh
**สำหรับ:** นักศึกษา + อาจารย์  
**เนื้อหา:**
- Automated setup script
- Dependency installation
- Project structure creation
- Sample data initialization

**จุดเด่น:**
- ✅ One-command setup
- ✅ Error handling
- ✅ Progress indicators
- ✅ Clean output

---

## 🛡️ ระบบ VulnBlog

### Technology Stack
```javascript
Backend:   Node.js + Express.js
Database:  SQLite3
Frontend:  HTML5 + CSS3 + Vanilla JavaScript
```

### Features
```
👤 User Management
   • Registration
   • Login/Logout
   • Profile viewing

📝 Blog System
   • Create posts
   • View posts
   • Search posts

💬 Comments
   • Post comments
   • View comments
   • Comment per post
```

### Intentional Vulnerabilities
```
🚨 SQL Injection (Critical)
   • Login form
   • Search feature

🚨 Stored XSS (High)
   • Comment system

🚨 Reflected XSS (Medium)
   • Search results

🚨 Broken Access Control (High)
   • User profile access
```

---

## 🧪 Lab Workflow

```
┌─────────────────────────────────────────────────────────┐
│  Phase 1: Setup & Understanding (20 นาที)               │
│  • Install dependencies                                 │
│  • Read documentation                                   │
│  • Explore application                                  │
└─────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│  Phase 2: Vulnerability Discovery (60 นาที)             │
│  • Test SQL Injection in login                          │
│  • Test SQL Injection in search                         │
│  • Test Stored XSS in comments                          │
│  • Test Reflected XSS in search                         │
│  • Document findings with screenshots                   │
└─────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│  Phase 3: Remediation (60 นาที)                         │
│  • Implement parameterized queries                      │
│  • Add output encoding                                  │
│  • Add input validation                                 │
│  • Implement security headers                           │
│  • Verify fixes work                                    │
└─────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│  Phase 4: Documentation (45 นาที)                       │
│  • Write comprehensive report                           │
│  • Include before/after code                            │
│  • Add screenshots                                      │
│  • Provide recommendations                              │
└─────────────────────────────────────────────────────────┘
```

---

## 📊 Assessment Criteria

### Total Points: 10

| Component | Points | Description |
|-----------|--------|-------------|
| **SQL Injection Testing** | 2.0 | ทดสอบและ document |
| **XSS Testing** | 2.0 | ทดสอบและ document |
| **SQL Injection Fix** | 2.0 | แก้ไข code ถูกต้อง |
| **XSS Fix** | 2.0 | แก้ไข code ถูกต้อง |
| **Report Quality** | 2.0 | รายงานครบถ้วนและชัดเจน |

### Bonus Points: +5 (Optional)
- 🎁 Broken Access Control fix (+2)
- 🎁 CSP implementation (+1)
- 🎁 Password hashing (+2)
- 🎁 Extra findings (+1-3)

---

## 💡 Tips for Success

### สำหรับนักศึกษา
```
✅ อ่านคำแนะนำทั้งหมดก่อนเริ่ม
✅ บันทึก screenshot ทุกขั้นตอน
✅ ทำทีละขั้นตอน อย่ารีบ
✅ ถามเมื่อสงสัย
✅ ทำ backup code ก่อนแก้ไข
✅ Test ทุกครั้งหลังแก้ไข
✅ เขียน report ตามไปด้วย
```

### สำหรับอาจารย์
```
✅ Demo ก่อนให้นักศึกษาลองเอง
✅ เดินดูและให้คำแนะนำ
✅ ให้ hints แต่อย่าให้คำตอบ
✅ Encourage collaboration
✅ ให้ feedback constructive
✅ เก็บ common mistakes สำหรับปีหน้า
```

---

## ⚠️ Important Notes

### ความปลอดภัย
```
🚨 ระบบนี้มีช่องโหว่จงใจ
🚨 ใช้เฉพาะใน Lab environment
🚨 ห้ามนำไป deploy production
🚨 ห้ามใช้กับระบบจริงโดยไม่ได้รับอนุญาต
```

### ข้อกฎหมาย
```
⚖️ การ hack ระบบโดยไม่ได้รับอนุญาตผิดกฎหมาย
⚖️ พ.ร.บ. คอมพิวเตอร์ พ.ศ. 2560
⚖️ โทษจำคุกและปรับ
⚖️ ใช้ความรู้อย่างมีจริยธรรม
```

---

## 🔗 Resources

### Official Documentation
- OWASP Top 10: https://owasp.org/Top10/
- OWASP Cheat Sheets: https://cheatsheetseries.owasp.org/
- Node.js Security: https://nodejs.org/en/docs/guides/security/

### Learning Platforms
- PortSwigger Academy: https://portswigger.net/web-security
- HackTheBox: https://www.hackthebox.com/
- TryHackMe: https://tryhackme.com/

### Tools
- Burp Suite: https://portswigger.net/burp
- OWASP ZAP: https://www.zaproxy.org/
- SQLmap: https://sqlmap.org/

---

## 📞 Support

### หากมีปัญหา
1. ตรวจสอบ Troubleshooting section ใน instructor_guide.md
2. ดู FAQ ใน instructions.md
3. ถามอาจารย์ หรือ TA
4. ปรึกษาเพื่อนร่วมชั้น

### การ Debug
```javascript
// เปิด Console Log ใน server.js
console.log('Query:', query);
console.log('User input:', req.body);

// ดู Network Tab ใน Browser DevTools
// ดู Console Tab สำหรับ JavaScript errors
```

---

## 📅 Timeline Suggestion

### Week 1: Preparation
- [ ] ส่งเอกสาร Lab ให้นักศึกษา
- [ ] แจ้งให้เตรียม laptop
- [ ] ตรวจสอบ equipment

### Week 2: Lab Session
- [ ] วันที่ 1: ทฤษฎี + Setup
- [ ] วันที่ 2-3: Practice
- [ ] วันที่ 4-5: Report writing

### Week 3: Submission & Grading
- [ ] Deadline: วันศุกร์ 23:59
- [ ] Grading: สัปดาห์ที่ 3
- [ ] Return feedback: สัปดาห์ที่ 4

---

## 🎓 Learning Outcomes Achievement

หลังจบ Lab นักศึกษาควรจะสามารถ:

### Technical Competence
```
✅ อธิบาย SQL Injection และ XSS ได้
✅ Exploit vulnerabilities ใน controlled environment
✅ Implement secure coding practices
✅ Use browser DevTools effectively
✅ Read and understand security documentation
```

### Professional Skills
```
✅ Write professional security reports
✅ Document findings clearly
✅ Communicate technical concepts
✅ Work systematically
✅ Think like an attacker (ethical hacking mindset)
```

---

## 🔄 Continuous Improvement

### Feedback Collection
- Student surveys after Lab
- TA observations during Lab
- Common mistakes tracking
- Time spent analysis

### Version Updates
```
v1.0 (Feb 2026): Initial release
  • Complete Lab instructions
  • All supporting documents
  • Setup automation

Future versions:
  • Docker containerization
  • Additional vulnerabilities
  • Automated testing scripts
  • Video tutorials
```

---

## 📜 License & Attribution

### Educational Use
```
✅ Free to use for educational purposes
✅ Can modify for your course
✅ Please attribute ENGSE214
✅ Share improvements back
```

### Credits
- Course: ENGSE214 - Introduction to Cybersecurity
- Institution: [Your University]
- Created: February 2026
- Inspired by: OWASP, PortSwigger, DVWA

---

## ✅ Pre-Lab Checklist

### For Students
- [ ] Laptop พร้อมใช้งาน
- [ ] Node.js ติดตั้งแล้ว
- [ ] Text editor เตรียมไว้ (VS Code แนะนำ)
- [ ] Browser มี DevTools (Chrome/Firefox)
- [ ] อ่านเอกสารทั้งหมดแล้ว
- [ ] เข้าใจวัตถุประสงค์ของ Lab

### For Instructors
- [ ] ทดสอบ Lab ครบทุก scenario
- [ ] เตรียม demo environment
- [ ] Projector/Screen working
- [ ] Internet connection stable
- [ ] Backup materials ready
- [ ] Assessment rubric printed
- [ ] TA briefed

---

## 🎯 Success Metrics

Lab ถือว่าประสบความสำเร็จถ้า:

```
✅ 70%+ นักศึกษา exploit ช่องโหว่ได้ทั้งหมด
✅ 80%+ นักศึกษาแก้ไข code ได้ถูกต้อง
✅ 60%+ นักศึกษาเข้าใจหลักการ
✅ 90%+ นักศึกษาส่งงานตรงเวลา
✅ 75%+ นักศึกษาพอใจกับ Lab
```

---

## 📞 Contact & Support

**Course Website:** [URL]  
**Instructor Email:** [Email]  
**Office Hours:** [Schedule]  
**TA Contact:** [Contact Info]

---

## 🎉 Final Notes

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🎓 ขอให้นักศึกษาทุกคนได้ประสบการณ์การเรียนรู้ที่ดี     ║
║                                                           ║
║   Remember: "Security is not a product, but a process"   ║
║              - Bruce Schneier                             ║
║                                                           ║
║   🛡️ Use your knowledge ethically and responsibly         ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
```

**Good luck with Lab 7! 🚀**

---

**Version:** 1.0  
**Last Updated:** February 2026  
**Status:** Ready for Use ✅
