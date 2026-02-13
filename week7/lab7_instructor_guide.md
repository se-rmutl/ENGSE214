# Lab 7 Instructor Guide
## Web Application Security - Vulnerable Blog System

**สำหรับอาจารย์ผู้สอน ENGSE214**

---

## 📋 ภาพรวม Lab

Lab นี้ออกแบบมาเพื่อให้นักศึกษาได้:
1. **เห็นช่องโหว่จริง** - ทำให้เข้าใจว่า vulnerability มีผลกระทบอย่างไร
2. **ฝึก exploit** - ในสภาพแวดล้อมที่ปลอดภัย
3. **ฝึกแก้ไข** - นำ secure coding practices มาใช้จริง
4. **เขียน report** - พัฒนาทักษะการสื่อสารด้าน security

---

## ⏰ Time Management (3 ชั่วโมง)

```
┌─────────────────────────────────────────────────────────────┐
│  Session 1: Introduction & Demo (45 นาที)                   │
│  ├─ Review OWASP Top 10 (15 นาที)                            │
│  ├─ Live Demo: SQL Injection (15 นาที)                      │
│  └─ Live Demo: XSS (15 นาที)                                │
├─────────────────────────────────────────────────────────────┤
│  Break (10 นาที)                                            │
├─────────────────────────────────────────────────────────────┤
│  Session 2: Setup & Testing (60 นาที)                       │
│  ├─ Setup Environment (15 นาที)                             │
│  ├─ SQL Injection Testing (20 นาที)                         │
│  └─ XSS Testing (25 นาที)                                   │
├─────────────────────────────────────────────────────────────┤
│  Break (10 นาที)                                            │
├─────────────────────────────────────────────────────────────┤
│  Session 3: Fixing & Reporting (65 นาที)                    │
│  ├─ Fix SQL Injection (25 นาที)                             │
│  ├─ Fix XSS (25 นาที)                                       │
│  └─ Report Writing (15 นาที)                                │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎯 Learning Outcomes Mapping

| Task | CLO | Bloom's Level | Assessment Method |
|------|-----|---------------|-------------------|
| SQL Injection Testing | CLO2 | Apply | Practical Test + Report |
| XSS Testing | CLO2 | Apply | Practical Test + Report |
| Code Fixing | CLO3 | Analyze/Create | Code Review |
| Report Writing | CLO3 | Evaluate | Report Quality |

---

## 🔧 Pre-Lab Preparation Checklist

### 1 สัปดาห์ก่อน:
- [ ] ทดสอบ Lab ทั้งหมดเอง
- [ ] ตรวจสอบว่า Node.js ติดตั้งได้บนเครื่องของนักศึกษา
- [ ] เตรียม USB drive สำรอง (มี installer)
- [ ] สร้าง backup code บน GitHub/Drive

### 1 วันก่อน:
- [ ] ทดสอบ projector/screen sharing
- [ ] เตรียม terminal windows สำหรับ demo
- [ ] เตรียม browser tabs (Burp Suite, Console)
- [ ] ตรวจสอบ internet connection

### ก่อน Lab เริ่ม:
- [ ] เปิด sample vulnerable app บนเครื่องตัวเอง
- [ ] เปิด code editor แสดง vulnerable code
- [ ] เตรียม payloads ใน text file
- [ ] ตรวจสอบว่านักศึกษามี laptop

---

## 🎓 Session 1: Introduction & Demo (45 นาที)

### Part 1: Review OWASP Top 10 (15 นาที)

**Key Points ที่ต้องเน้น:**
1. OWASP Top 10 เป็นมาตรฐานอุตสาหกรรม
2. Injection และ XSS อยู่ใน Top 5
3. Real-world impacts (Equifax, Sony, etc.)

**คำถามสำหรับนักศึกษา:**
- "มีใครเคยเจอ SQL Injection จริงไหม?"
- "ทำไม XSS อันตรายถึงแม้ไม่ได้เข้าถึง database?"

### Part 2: Live Demo - SQL Injection (15 นาที)

**สิ่งที่ต้อง Demo:**

1. **Login Bypass:**
```bash
# เปิด Browser Console เพื่อดู Network tab
# Login with:
Username: admin' OR '1'='1' --
Password: anything

# แสดง SQL Query ที่ execute:
SELECT * FROM users WHERE username = 'admin' OR '1'='1' --' AND password = 'anything'
```

**อธิบาย:**
- `'` ปิด string
- `OR '1'='1'` เป็นเงื่อนไขที่เป็นจริงเสมอ
- `--` เป็น SQL comment (ignore ส่วนที่เหลือ)

2. **Search Exploitation:**
```bash
# Search with:
' UNION SELECT id, username, password, email, '' FROM users --

# แสดงผลลัพธ์ว่า passwords หลุดทั้งหมด
```

**เน้นย้ำ:**
- นี่คือ "Classic" attack ที่ยังพบบ่อยมากในปี 2025
- Parameterized Query แก้ปัญหานี้ได้ 100%

### Part 3: Live Demo - XSS (15 นาที)

**สิ่งที่ต้อง Demo:**

1. **Stored XSS:**
```html
# Post comment:
<script>alert('Your cookie: ' + document.cookie)</script>

# รีเฟรชหน้า → alert ขึ้น!
```

**อธิบาย:**
- Script ถูกเก็บใน database
- ทุกคนที่เปิดหน้านี้จะโดน execute

2. **Reflected XSS:**
```html
# Search:
<img src=x onerror="alert('XSS')">

# ผลลัพธ์แสดง และ alert ขึ้นทันที
```

**เน้นย้ำ:**
- XSS สามารถขโมย session cookie
- ใช้ DOMPurify หรือ escapeHtml() ป้องกันได้

### Part 4: Security Headers (Bonus - 5 นาที ถ้ามีเวลา)

แสดง CSP header ใน DevTools:
```
Content-Security-Policy: default-src 'self'
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
```

---

## 👥 Session 2: Hands-on Practice (60 นาที)

### Teaching Strategy

**แบบ Guided Discovery:**
1. ให้นักศึกษาลองเองก่อน (10 นาที)
2. ถ้าติดหรือมีคำถามเยอะ → แสดง hint
3. อย่าให้คำตอบทันที → ให้คิดและลองต่อ

### Common Problems & Solutions

| ปัญหา | สาเหตุ | วิธีแก้ |
|-------|-------|--------|
| npm install error | Network/Proxy | ใช้ USB drive สำรอง |
| Port 3000 in use | Process ค้าง | `killall node` (Mac/Linux)<br>`taskkill /F /IM node.exe` (Windows) |
| Database locked | SQLite concurrent access | ลบ `database.db` แล้วรันใหม่ |
| SQL Injection ไม่ทำงาน | Syntax ผิด | ตรวจสอบ quotes และ spaces |
| XSS ไม่ execute | Browser XSS filter | ลอง Chrome Incognito |

### Hints ที่ควรให้เมื่อนักศึกษาติด

**SQL Injection Hints:**
1. "ลอง close quote ด้วย `'` ก่อน"
2. "SQL comment ใช้ `--` หรือ `#`"
3. "UNION ต้องมีจำนวน column เท่ากับ query หลัก"

**XSS Hints:**
1. "ลอง `<script>alert(1)</script>` ก่อน"
2. "ถ้า `<script>` โดนบล็อก ลอง `<img>` tag"
3. "ดูใน DevTools ว่า script ถูก escape หรือไม่"

### Walkthrough จุดสำคัญ

หลังจากนักศึกษาลองเอง 30 นาที ให้ walkthrough ทั้งห้อง:

1. **SQL Injection Success:**
   - เปิด browser console
   - แสดง Network tab → ดู request/response
   - แสดง server console → ดู actual SQL query
   - อธิบายว่าทำไม payload นี้ใช้ได้

2. **XSS Success:**
   - แสดง Elements tab → ดู HTML ที่ inject
   - แสดงความแตกต่าง innerHTML vs textContent
   - อธิบาย impact: cookie stealing, phishing

---

## 🛠️ Session 3: Fixing Vulnerabilities (65 นาที)

### Teaching Approach

**Pair Programming Style:**
- ให้นักศึกษาทำงานเป็นคู่
- คนหนึ่ง code คนหนึ่ง review
- สลับบทบาททุก 15 นาที

### Code Review Checklist (สำหรับอาจารย์)

เดินดูนักศึกษาทีละคู่ และตรวจสอบ:

**SQL Injection Fixes:**
- [ ] ใช้ `?` placeholders
- [ ] ส่ง values เป็น array parameter
- [ ] ไม่มี string concatenation ใน query

**XSS Fixes:**
- [ ] ใช้ `escapeHtml()` function
- [ ] หรือใช้ `textContent` แทน `innerHTML`
- [ ] ตรวจสอบ CSP headers (ถ้าทำ bonus)

### Common Mistakes ที่พบ

| Mistake | Why It's Wrong | Correct Approach |
|---------|----------------|------------------|
| ใช้ `escape()` JavaScript | ไม่ครบทุก context | ใช้ library หรือ `escapeHtml()` |
| Blacklist approach | Bypass ง่าย | Whitelist + parameterized query |
| ลืม encode ใน search | Reflected XSS ยังอยู่ | Encode ทุกจุดที่แสดง user input |
| Server-side เท่านั้น | Client-side ยัง vulnerable | แก้ทั้ง client และ server |

---

## 📊 Assessment & Grading

### Quick Grading Rubric

**SQL Injection (4 คะแนน):**
- ทดสอบได้ถูกต้อง (1)
- บันทึก payload และผลลัพธ์ (1)
- แก้ไข code ถูกต้อง (1.5)
- อธิบายเหตุผลชัดเจน (0.5)

**XSS (4 คะแนน):**
- ทดสอบ Stored XSS (0.75)
- ทดสอบ Reflected XSS (0.75)
- แก้ไข code ถูกต้อง (1.5)
- อธิบายและให้ recommendation (1)

**Report Quality (2 คะแนน):**
- Structure ชัดเจน (0.5)
- มี screenshot ประกอบ (0.5)
- Code comparison (0.5)
- Professional writing (0.5)

### Red Flags (ควรหักคะแนน)

- ❌ Copy-paste จากเพื่อนโดยไม่เข้าใจ → หัก 50%
- ❌ Payload ใช้ได้แต่อธิบายผิด → หัก 2 คะแนน
- ❌ แก้แค่ 1 จุด แต่ไม่แก้จุดอื่นที่มีปัญหา → หัก 1 คะแนน
- ❌ Report ไม่มี screenshot → หัก 1 คะแนน

### Outstanding Work (ควรให้ bonus)

- ✅ ทำ Bonus challenges (1-3 คะแนน)
- ✅ พบช่องโหว่เพิ่มเติมที่ไม่ได้บอก (2 คะแนน)
- ✅ เขียน automated test script (2 คะแนน)
- ✅ Research และนำเสนอ defense technique อื่น (1 คะแนน)

---

## 🎨 Optional Extensions

### Extension 1: OWASP ZAP Integration (Advanced)

สอนนักศึกษาใช้ OWASP ZAP scan vulnerable app:

```bash
# Install ZAP
# Start ZAP
# Configure browser proxy to localhost:8080
# Spider the site
# Active scan
# Review alerts
```

**Learning Outcome:**
- เข้าใจ automated security testing
- รู้จัก penetration testing tools

### Extension 2: Bug Bounty Simulation (Gamification)

แปลง Lab เป็น "Bug Bounty Program":

```
🏆 Bounty Prizes:

💰 $1000 (5 bonus คะแนน):
   - SQL Injection leading to admin access

💰 $500 (3 bonus คะแนน):
   - Stored XSS with cookie stealing

💰 $200 (2 bonus คะแนน):
   - Reflected XSS
   - Broken Access Control

💰 $100 (1 bonus คะแนน):
   - Any other vulnerability
```

**ทำให้ Lab สนุกขึ้น:**
- มี leaderboard
- First blood bonus
- Team competition

### Extension 3: Secure Code Review Workshop

หลัง Lab เสร็จ จัด Workshop:

1. แจก code snippets ที่ vulnerable
2. ให้นักศึกษา review และหาจุดที่มีปัญหา
3. Present findings
4. Discuss best practices

---

## 🔧 Troubleshooting Guide

### Installation Issues

**Problem:** npm install ใช้เวลานานหรือ error

**Solutions:**
```bash
# Option 1: ใช้ --legacy-peer-deps
npm install --legacy-peer-deps

# Option 2: Clear cache
npm cache clean --force
npm install

# Option 3: ใช้ yarn แทน
npm install -g yarn
yarn install
```

### Runtime Issues

**Problem:** Database ไม่ได้ถูกสร้าง

**Solution:**
```bash
# ลบ database เก่า
rm database.db

# รัน server ใหม่ (จะสร้าง database อัตโนมัติ)
node server.js
```

**Problem:** Port 3000 ถูกใช้งาน

**Solution:**
```bash
# หา process ที่ใช้ port 3000
# macOS/Linux:
lsof -i :3000
kill -9 <PID>

# Windows:
netstat -ano | findstr :3000
taskkill /PID <PID> /F

# หรือเปลี่ยน port ใน server.js
const PORT = 3001; // เปลี่ยนจาก 3000
```

---

## 📖 Additional Teaching Materials

### Recommended Videos (สำหรับนักศึกษา)

1. **SQL Injection:**
   - "SQL Injection Explained" - Computerphile (YouTube)
   - OWASP Top 10: Injection (OWASP Foundation)

2. **XSS:**
   - "Cross-Site Scripting (XSS) Explained" - PwnFunction
   - "XSS Attack Examples" - LiveOverflow

### Discussion Topics (หลัง Lab)

1. **Real-World Impact:**
   - "Equifax breach ที่เกิดจาก SQL Injection"
   - "Tesco Bank โดน XSS ขโมยเงิน 2.5 ล้านปอนด์"

2. **Ethics:**
   - "Responsible Disclosure คืออะไร?"
   - "Bug Bounty Programs"

3. **Career Paths:**
   - Security Engineer
   - Penetration Tester
   - Security Researcher

---

## 📝 Post-Lab Follow-up

### Week After Lab:

1. **Code Review Session:**
   - เลือก 2-3 reports ที่ดี present ให้ห้องฟัง
   - ให้นักศึกษาอื่น comment

2. **Q&A Session:**
   - ตอบคำถามที่นักศึกษาส่งมา
   - Clarify concepts ที่ยังสับสน

3. **Challenge Week:**
   - Post แนวข้อสอบ Midterm ที่เกี่ยวข้อง
   - ให้ทำแล้ว discuss

---

## 🎯 Success Metrics

Lab นี้ถือว่าสำเร็จถ้า:

- ✅ **70%+** ของนักศึกษา exploit vulnerabilities ได้ทุกอัน
- ✅ **80%+** ของนักศึกษาแก้ไข code ได้ถูกต้อง
- ✅ **60%+** ของนักศึกษาเข้าใจเหตุผลเบื้องหลัง
- ✅ **50%+** ของนักศึกษาสามารถอธิบายให้คนอื่นฟังได้

### Post-Lab Survey Questions:

1. ความยากของ Lab (1-5): _____
2. Lab ช่วยให้เข้าใจ OWASP Top 10 มากขึ้นไหม? (ใช่/ไม่)
3. เวลาที่ใช้เพียงพอไหม? (เพียงพอ/น้อยเกิน/มากเกิน)
4. อยากให้เพิ่มหัวข้ออะไร? (Open-ended)

---

## 📚 References for Instructors

### Essential Reading:
- OWASP Testing Guide v4.2
- "The Web Application Hacker's Handbook" - Dafydd Stuttard
- Node.js Security Best Practices (nodejs.org)

### Tools to Master:
- Burp Suite (Community Edition)
- OWASP ZAP
- SQLmap
- Browser Developer Tools

---

## 🔄 Continuous Improvement

### Things to Track:

1. **Common Mistakes:**
   - เก็บสถิติ errors ที่พบบ่อย
   - ปรับ instructions ให้ชัดเจนขึ้น

2. **Time Spent:**
   - ถ้านักศึกษาใช้เวลามากใน setup → ทำ pre-configured VM
   - ถ้าใช้เวลาน้อยเกิน → เพิ่ม challenges

3. **Student Feedback:**
   - อ่าน comments ใน survey
   - ปรับแต่ง Lab ในปีถัดไป

---

## 🎁 Bonus: Sample Vulnerabilities for Future Labs

นักศึกษาที่เก่งสามารถขยายผล Lab นี้โดย:

1. **Implement Authentication Bypass (Session Fixation)**
2. **Add CSRF Vulnerability**
3. **Insecure Direct Object Reference (IDOR)**
4. **Server-Side Request Forgery (SSRF)**
5. **File Upload Vulnerability**

---

## ✅ Pre-Class Checklist (สรุป)

**1 สัปดาห์ก่อน:**
- [ ] ทดสอบ Lab ทั้งหมด
- [ ] เตรียม backup materials
- [ ] แจ้งนักศึกษาให้เตรียม laptop

**1 วันก่อน:**
- [ ] ตรวจสอบ equipment
- [ ] เตรียม demo environment
- [ ] Review lecture slides

**วันสอน:**
- [ ] มาถึงก่อน 15 นาที
- [ ] ทดสอบ projector
- [ ] เตรียม terminal/browser tabs
- [ ] เปิด lab server

**หลัง Lab:**
- [ ] Collect feedback
- [ ] Grade reports
- [ ] Post solutions (ถ้ามี)

---

**Good luck with the lab! If you need any clarifications, feel free to ask. 🎓**
