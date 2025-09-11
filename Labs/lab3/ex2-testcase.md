# Pre-LAB3: Test Cases และการปรับปรุงความปลอดภัย

**วัตถุประสงค์:** สร้าง Test Cases ที่ครอบคลุมสำหรับการทดสอบช่องโหว่และการปรับปรุงให้ปลอดภัย

---

## Test Case Document Structure

### สำหรับแต่ละ Experiment:
1. **Vulnerability Test Cases** - ทดสอบช่องโหว่
2. **Security Improvement Test Cases** - ทดสอบการป้องกัน
3. **Code Improvement Guide** - คู่มือปรับปรุงโค้ด
4. **Student Exercise** - แบบฝึกหัดให้นักศึกษาทำ

---

## Experiment 2: XSS Test Cases

### 2.1 XSS Vulnerability Test Cases

<artifacts>
<artifact identifier="xss_test_cases" type="text/markdown" title="XSS Test Cases">
# XSS (Cross-Site Scripting) Test Cases

## Test Case Group 1: Stored XSS

### TC201: Basic Script Injection
**วัตถุประสงค์:** ทดสอบการแทรก JavaScript แบบพื้นฐาน

**Input Data:**
- Name: `Test User`
- Comment: `<script>alert('XSS Attack!');</script>`

**Expected Result (Vulnerable):**
- JavaScript ทำงาน (แสดง alert popup)
- Script ถูกเก็บในฐานข้อมูล
- ผู้ใช้อื่นที่เข้าดูจะโดน XSS

**Expected Result (Secure):**
- Script ถูก encode: `&lt;script&gt;alert('XSS Attack!');&lt;/script&gt;`
- แสดงเป็นข้อความธรรมดา
- ไม่มี JavaScript execution

### TC202: Event Handler Injection
**วัตถุประสงค์:** ทดสอบ XSS ผ่าน HTML event handlers

**Test Payloads:**
```html
<img src=x onerror=alert('XSS via IMG')>
<div onmouseover=alert('XSS on hover')>Hover me</div>
<input onfocus=alert('XSS on focus') autofocus>
<body onload=alert('XSS on load')>
<svg onload=alert('XSS via SVG')>
```

**การทดสอบ:**
1. ใส่ payload ในช่อง comment
2. Submit form
3. Reload page และสังเกต JavaScript execution

### TC203: JavaScript Protocol Injection
**Test Payloads:**
```html
<a href="javascript:alert('XSS via href')">Click me</a>
<iframe src="javascript:alert('XSS via iframe')"></iframe>
<form action="javascript:alert('XSS via form')">
```

### TC204: CSS Injection
**Test Payloads:**
```html
<style>body{background:url('javascript:alert("XSS")')}</style>
<div style="background:url('javascript:alert(\"XSS\")')">CSS XSS</div>
```

## Test Case Group 2: Reflected XSS

### TC205: URL Parameter XSS
**วัตถุประสงค์:** ทดสอบ XSS ผ่าน URL parameters

**Test URL:**
```
http://localhost:3002/search?q=<script>alert('Reflected XSS')</script>
```

**Expected Behavior:**
- Vulnerable: Script execute ทันที
- Secure: Parameter ถูก encode ก่อนแสดงผล

### TC206: Form Input Reflection
**Test Scenario:**
1. Submit form ด้วย XSS payload
2. Server ส่งกลับข้อมูลที่ user ใส่
3. สังเกตว่า payload ถูก execute หรือไม่

## Test Case Group 3: DOM-based XSS

### TC207: Client-side JavaScript Manipulation
**Test Code:**
```html
<script>
// Vulnerable code
var userInput = location.hash.substring(1);
document.getElementById('output').innerHTML = userInput;
</script>

<!-- Test URL: page.html#<img src=x onerror=alert('DOM XSS')> -->
```

## Advanced XSS Test Cases

### TC208: Filter Bypass Techniques
**Bypassing basic filters:**

```html
<!-- หากระบบกรอง <script> -->
<Script>alert('XSS')</Script>
<scr<script>ipt>alert('XSS')</script>
<img src="x" onerror="alert('XSS')">

<!-- หากระบบกรอง alert -->
<script>confirm('XSS')</script>
<script>prompt('XSS')</script>
<script>eval('alert("XSS")')</script>

<!-- หากระบบกรอง quotes -->
<script>alert(String.fromCharCode(88,83,83))</script>
<script>alert(/XSS/.source)</script>
```

### TC209: Context-specific XSS
**HTML Context:**
```html
<div>[USER_INPUT]</div>
Payload: <img src=x onerror=alert('XSS')>
```

**Attribute Context:**
```html
<input value="[USER_INPUT]">
Payload: " onmouseover="alert('XSS')
```

**JavaScript Context:**
```html
<script>var x = '[USER_INPUT]';</script>
Payload: '; alert('XSS'); //
```

**CSS Context:**
```html
<style>body { background: [USER_INPUT]; }</style>
Payload: red; background: url('javascript:alert("XSS")');
```

## นักศึกษาลองทำ

### Exercise 1: XSS Payload Creation
ให้นักศึกษาสร้าง XSS payload ที่:
1. ขโมย cookie: `document.cookie`
2. เปลี่ยนสี background ของหน้าเว็บ
3. Redirect ไปหน้าอื่น
4. แสดง input form ปลอม

**Template:**
```javascript
// 1. Cookie Stealing
<script>
// TODO: เขียนโค้ดส่ง cookie ไป attacker server
</script>

// 2. Background Color Change  
<script>
// TODO: เปลี่ยนสี background
</script>

// 3. Redirection
<script>
// TODO: redirect ไป google.com
</script>

// 4. Fake Login Form
<script>
// TODO: สร้าง fake login form
</script>
```

### Exercise 2: XSS Impact Analysis
ให้นักศึกษาทดสอบและอธิบายผลกระทบ:

| Payload | Impact Level (1-5) | Explanation |
|---------|-------------------|-------------|
| `<script>alert('XSS')</script>` | [นักศึกษาให้คะแนน] | [อธิบาย] |
| `<img src=x onerror=alert(document.cookie)>` | [นักศึกษาให้คะแนน] | [อธิบาย] |
| `<script>window.location='http://evil.com'</script>` | [นักศึกษาให้คะแนน] | [อธิบาย] |

### Exercise 3: Filter Bypass Challenge
ให้นักศึกษาทดสอบระบบที่มี basic filter และหาวิธี bypass:

**Scenario:** ระบบกรอง keyword `<script>`, `javascript:`, `onerror`

**Challenge:** สร้าง XSS payload ที่ bypass filter นี้

**Hints:**
- ใช้ encoding (HTML entities, URL encoding)
- ใช้ alternative tags และ events
- ใช้ case sensitivity
- ใช้ character insertion

## XSS Prevention Test Cases

### TC210: HTML Encoding Test
**วัตถุประสงค์:** ทดสอบการ encode HTML characters

**Input:** `<script>alert('test')</script>`
**Expected Output:** `&lt;script&gt;alert('test')&lt;/script&gt;`

### TC211: Content Security Policy (CSP) Test
**วัตถุประสงค์:** ทดสอบ CSP headers

**CSP Header:** `Content-Security-Policy: default-src 'self'; script-src 'self'`

**Test Cases:**
- Inline script: ควรถูกบล็อค
- External script จาก same origin: ควรทำงานได้
- External script จาก other domain: ควรถูกบล็อค

### TC212: Input Length Validation
**Test Data:**
```javascript
// Short input (ควรผ่าน)
const shortComment = "This is a normal comment";

// Long input (ควรถูกปฏิเสธ)
const longComment = "<script>" + "a".repeat(5000) + "</script>";
```

## คำถามวิเคราะห์

1. **XSS Types Comparison:**
   - Stored vs Reflected vs DOM-based XSS แตกต่างกันอย่างไร?
   - อันไหนอันตรายที่สุด? เพราะอะไร?

2. **Impact Assessment:**
   - XSS สามารถทำอะไรได้บ้างในเว็บแอพลิเคชันจริง?
   - ผลกระทบต่อผู้ใช้และองค์กรเป็นอย่างไร?

3. **Prevention Methods:**
   - HTML encoding vs Input validation - วิธีไหนดีกว่า?
   - CSP มีข้อจำกัดอะไรบ้าง?

4. **Real-world Scenarios:**
   - ในเว็บไซต์ที่นักศึกษาใช้ปกติ มีจุดไหนที่อาจเสี่ยงต่อ XSS?
   - Social media platforms ป้องกัน XSS อย่างไร?

## Test Results Template

| Test ID | Payload | Vulnerable Result | Secure Result | Notes |
|---------|---------|-------------------|---------------|-------|
| TC201 | `<script>alert('XSS')</script>` | [บันทึกผล] | [บันทึกผล] | [ข้อสังเกต] |
| TC202 | `<img src=x onerror=alert('XSS')>` | [บันทึกผล] | [บันทึกผล] | [ข้อสังเกต] |
| TC203 | `<a href="javascript:alert('XSS')">` | [บันทึกผล] | [บันทึกผล] | [ข้อสังเกต] |
</artifact>
</artifacts>

### 2.2 XSS Protection Implementation Guide

<artifacts>
<artifact identifier="xss_protection_guide" type="text/markdown" title="XSS Protection Guide">
# XSS Protection การปรับปรุงโค้ดให้ปลอดภัย

## หลักการป้องกัน XSS

### 1. Output Encoding (วิธีหลัก)

**ปัญหาเดิม (Vulnerable Code):**
```javascript
// ❌ Raw HTML output - อันตราย
app.get('/comments', (req, res) => {
    const comments = getCommentsFromDB();
    const html = comments.map(comment => 
        `<div class="comment">
            <strong>${comment.name}</strong>
            <p>${comment.content}</p>
        </div>`
    ).join('');
    res.send(html);
});
```

**วิธีแก้ไข (Secure Code):**
```javascript
// ✅ HTML encoding - ปลอดภัย
function htmlEncode(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
}

app.get('/comments', (req, res) => {
    const comments = getCommentsFromDB();
    const html = comments.map(comment => 
        `<div class="comment">
            <strong>${htmlEncode(comment.name)}</strong>
            <p>${htmlEncode(comment.content)}</p>
        </div>`
    ).join('');
    res.send(html);
});
```

**อธิบายหลักการ:**
- HTML encoding แปลงอักขระพิเศษเป็น HTML entities
- `<script>` กลายเป็น `&lt;script&gt;` จึงไม่ทำงานเป็น JavaScript
- Browser จะแสดงเป็นข้อความธรรมดา

### 2. Context-Aware Encoding

**HTML Context:**
```javascript
// สำหรับใส่ใน HTML content
function htmlEncode(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

// ใช้งาน: <div>${htmlEncode(userInput)}</div>
```

**HTML Attribute Context:**
```javascript
// สำหรับใส่ใน HTML attributes
function attributeEncode(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

// ใช้งาน: <input value="${attributeEncode(userInput)}">
```

**JavaScript Context:**
```javascript
// สำหรับใส่ใน JavaScript string
function jsEncode(str) {
    return str
        .replace(/\\/g, '\\\\')
        .replace(/'/g, '\\\'')
        .replace(/"/g, '\\"')
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r')
        .replace(/\t/g, '\\t')
        .replace(/\f/g, '\\f')
        .replace(/\v/g, '\\v');
}

// ใช้งาน: <script>var x = '${jsEncode(userInput)}';</script>
```

**URL Context:**
```javascript
// สำหรับใส่ใน URL
function urlEncode(str) {
    return encodeURIComponent(str);
}

// ใช้งาน: <a href="/search?q=${urlEncode(userInput)}">
```

### 3. Input Validation และ Sanitization

**Allowlist Approach (แนะนำ):**
```javascript
function validateAndSanitizeComment(input) {
    // 1. ตรวจสอบ type และ length
    if (!input || typeof input !== 'string') {
        throw new Error('Invalid input type');
    }
    
    if (input.length > 1000) {
        throw new Error('Comment too long');
    }
    
    // 2. Allowlist - อนุญาตเฉพาะอักขระที่ปลอดภัย
    const allowedChars = /^[a-zA-Z0-9\s.,!?()-]+$/;
    if (!allowedChars.test(input)) {
        throw new Error('Comment contains invalid characters');
    }
    
    return input.trim();
}
```

**Blocklist Approach (ใช้เป็นการเสริม):**
```javascript
function detectMaliciousContent(input) {
    const dangerousPatterns = [
        /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
        /javascript:/gi,
        /vbscript:/gi,
        /on\w+\s*=/gi,
        /<iframe/gi,
        /<object/gi,
        /<embed/gi,
        /<link/gi,
        /<meta/gi
    ];
    
    return dangerousPatterns.some(pattern => pattern.test(input));
}

// การใช้งาน
if (detectMaliciousContent(userInput)) {
    throw new Error('Content contains potentially dangerous code');
}
```

### 4. Content Security Policy (CSP)

**การตั้งค่า CSP Headers:**
```javascript
// Basic CSP
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', 
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data: https:; " +
        "font-src 'self'; " +
        "connect-src 'self'"
    );
    next();
});

// Advanced CSP with nonces
const crypto = require('crypto');

app.use((req, res, next) => {
    const nonce = crypto.randomBytes(16).toString('base64');
    res.locals.nonce = nonce;
    
    res.setHeader('Content-Security-Policy', 
        `default-src 'self'; ` +
        `script-src 'self' 'nonce-${nonce}'; ` +
        `style-src 'self' 'unsafe-inline'; ` +
        `img-src 'self' data: https:; ` +
        `object-src 'none'; ` +
        `base-uri 'self'`
    );
    next();
});
```

**การใช้งาน nonce ใน HTML:**
```html
<!-- Script ที่ปลอดภัย -->
<script nonce="<%= nonce %>">
    // JavaScript code ที่เราเขียนเอง
    console.log('This script is allowed');
</script>

<!-- Script inline ที่ไม่มี nonce จะถูกบล็อค -->
<script>alert('This will be blocked');</script>
```

### 5. การใช้ Template Engine ที่ปลอดภัย

**EJS (Automatic Escaping):**
```html
<!-- Auto-escape (ปลอดภัย) -->
<div><%= userInput %></div>

<!-- Raw output (อันตราย) -->
<div><%- userInput %></div>
```

**Handlebars (Automatic Escaping):**
```html
<!-- Auto-escape (ปลอดภัย) -->
<div>{{userInput}}</div>

<!-- Raw output (อันตราย) -->
<div>{{{userInput}}}</div>
```

**React (Automatic Escaping):**
```jsx
// React escape ข้อความใน JSX โดยอัตโนมัติ
function Comment({ content, name }) {
    return (
        <div className="comment">
            <strong>{name}</strong> {/* ปลอดภัย */}
            <p>{content}</p> {/* ปลอดภัย */}
        </div>
    );
}

// อันตราย - อย่าใช้ dangerouslySetInnerHTML กับ user input
function UnsafeComment({ content }) {
    return (
        <div dangerouslySetInnerHTML={{__html: content}} /> // ❌ อันตราย!
    );
}
```

## แบบฝึกหัดสำหรับนักศึกษา

### Exercise 1: ปรับปรุง Comment System
```javascript
// โค้ดเดิมที่มีช่องโหว่ - ให้นักศึกษาแก้ไข
app.post('/comments', (req, res) => {
    const { name, content } = req.body;
    
    // TODO: เพิ่ม input validation
    
    // TODO: เพิ่ม content sanitization
    
    // เก็บลงฐานข้อมูล
    db.run('INSERT INTO comments (name, content) VALUES (?, ?)', [name, content]);
    
    res.json({ success: true });
});

app.get('/comments', (req, res) => {
    db.all('SELECT * FROM comments', (err, rows) => {
        // TODO: เพิ่ม output encoding
        const html = rows.map(row => 
            `<div class="comment">
                <strong>${row.name}</strong>
                <p>${row.content}</p>
                <small>${row.created_at}</small>
            </div>`
        ).join('');
        
        res.send(`<div class="comments">${html}</div>`);
    });
});
```

**คำสั่งให้นักศึกษา:**
1. เพิ่ม input validation สำหรับ name และ content
2. เพิ่ม HTML encoding ใน output
3. เพิ่ม CSP headers
4. ทดสอบด้วย XSS payloads ต่างๆ
5. อธิบายเหตุผลการปรับปรุงแต่ละขั้นตอน

### Exercise 2: Context-Aware Encoding
ให้นักศึกษาใช้ encoding ที่เหมาะสมกับ context:

```html
<!-- Template ที่ต้องแก้ไข -->
<!DOCTYPE html>
<html>
<head>
    <!-- TODO: encode สำหรับ title attribute -->
    <title>User Profile - USER_NAME_HERE</title>
</head>
<body>
    <!-- TODO: encode สำหรับ HTML content -->
    <h1>Welcome USER_NAME_HERE</h1>
    
    <!-- TODO: encode สำหรับ attribute value -->
    <input type="text" value="USER_INPUT_HERE" placeholder="Enter text">
    
    <!-- TODO: encode สำหรับ URL parameter -->
    <a href="/search?q=USER_SEARCH_HERE">Search</a>
    
    <!-- TODO: encode สำหรับ JavaScript context -->
    <script>
        var userName = 'USER_NAME_HERE';
        console.log('Hello ' + userName);
    </script>
</body>
</html>
```

### Exercise 3: XSS Filter Bypass Testing
ให้นักศึกษาสร้างและทดสอบ XSS filter:

```javascript
// Basic XSS filter - ให้นักศึกษาหาวิธี bypass
function basicXSSFilter(input) {
    return input
        .replace(/<script>/gi, '')
        .replace(/javascript:/gi, '')
        .replace(/onerror/gi, '');
}

// TODO: นักศึกษาสร้าง payload ที่ bypass filter นี้
const testPayloads = [
    // เติม payload ที่ bypass filter
];

// TODO: ปรับปรุง filter ให้ครอบคลุมมากขึ้น
function improvedXSSFilter(input) {
    // นักศึกษาเขียน filter ที่ดีกว่า
}
```

### Exercise 4: CSP Implementation
ให้นักศึกษาออกแบบ CSP policy:

```javascript
// สถานการณ์: เว็บไซต์ e-commerce ที่มี:
// - โฆษณา Google Ads
// - Google Analytics
// - External payment gateway (Stripe)
// - CDN สำหรับ images
// - Web fonts จาก Google Fonts

// TODO: เขียน CSP policy ที่เหมาะสม
const cspPolicy = {
    'default-src': [/* TODO */],
    'script-src': [/* TODO */],
    'style-src': [/* TODO */],
    'img-src': [/* TODO */],
    'font-src': [/* TODO */],
    'connect-src': [/* TODO */],
    'frame-src': [/* TODO */]
};
```

## คำถามวิเคราะห์สำหรับนักศึกษา

1. **Defense in Depth:**
   - ทำไมต้องใช้ทั้ง input validation และ output encoding?
   - CSP สามารถแทน output encoding ได้หรือไม่?

2. **Performance Considerations:**
   - HTML encoding มีผลต่อประสิทธิภาพอย่างไร?
   - ควร encode ตอนบันทึกหรือตอนแสดงผล?

3. **User Experience:**
   - การป้องกัน XSS มีผลต่อ UX อย่างไร?
   - จะสมดุลระหว่างความปลอดภัยและการใช้งานได้อย่างไร?

4. **Real-world Applications:**
   - Social media platforms อนุญาตให้ใช้ HTML tag บางตัวได้อย่างไร?
   - Rich text editors ป้องกัน XSS อย่างไร?

## เฉลยแบบฝึกหัด

### Exercise 1 Solution:
```javascript
// การปรับปรุงที่สมบูรณ์
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const window = new JSDOM('').window;
const purify = DOMPurify(window);

// HTML encoding function
function htmlEncode(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}

// Input validation
function validateComment(name, content) {
    if (!name || !content) {
        throw new Error('Name and content are required');
    }
    
    if (name.length > 50 || content.length > 1000) {
        throw new Error('Input too long');
    }
    
    // ตรวจสอบอักขระที่อนุญาต
    const allowedPattern = /^[a-zA-Z0-9\s.,!?()-]+$/;
    if (!allowedPattern.test(name) || !allowedPattern.test(content)) {
        throw new Error('Invalid characters detected');
    }
}

// CSP middleware
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', 
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data:; " +
        "object-src 'none'"
    );
    next();
});

app.post('/comments', (req, res) => {
    try {
        const { name, content } = req.body;
        
        // Input validation
        validateComment(name, content);
        
        // Additional sanitization with DOMPurify
        const safeName = purify.sanitize(name);
        const safeContent = purify.sanitize(content);
        
        // บันทึกลงฐานข้อมูล
        db.run('INSERT INTO comments (name, content) VALUES (?, ?)', 
               [safeName, safeContent], function(err) {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            res.json({ success: true, id: this.lastID });
        });
        
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.get('/comments', (req, res) => {
    db.all('SELECT * FROM comments ORDER BY created_at DESC', (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        
        // HTML encoding สำหรับ output
        const html = rows.map(row => 
            `<div class="comment">
                <strong>${htmlEncode(row.name)}</strong>
                <p>${htmlEncode(row.content)}</p>
                <small>${htmlEncode(row.created_at)}</small>
            </div>`
        ).join('');
        
        res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Comments</title>
                <meta charset="UTF-8">
            </head>
            <body>
                <div class="comments">${html}</div>
            </body>
            </html>
        `);
    });
});
```

**การปรับปรุงสำคัญ:**
1. **Input Validation** - ตรวจสอบความยาวและอักขระที่อนุญาต
2. **DOMPurify Sanitization** - ทำความสะอาด HTML ที่ซับซ้อน
3. **Output Encoding** - Encode ทุกข้อมูลที่แสดงผล
4. **CSP Headers** - ป้องกัน inline scripts
5. **Error Handling** - ไม่เปิดเผยรายละเอียดระบบ
</artifact>
</artifacts>

### 2.3 Advanced XSS Protection Techniques

<artifacts>
<artifact identifier="advanced_xss_protection" type="text/markdown" title="Advanced XSS Protection">
# เทคนิคการป้องกัน XSS ขั้นสูง

## 1. DOMPurify Integration

### การติดตั้งและใช้งาน DOMPurify
```javascript
// ติดตั้ง: npm install dompurify jsdom
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

// Basic usage
function sanitizeHTML(dirty) {
    return DOMPurify.sanitize(dirty);
}

// Advanced configuration
function sanitizeWithConfig(dirty) {
    return DOMPurify.sanitize(dirty, {
        ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br'],
        ALLOWED_ATTR: ['class'],
        KEEP_CONTENT: true,
        RETURN_DOM: false,
        RETURN_DOM_FRAGMENT: false,
        RETURN_DOM_IMPORT: false,
        RETURN_TRUSTED_TYPE: false
    });
}

// ตัวอย่างการใช้งาน
const userInput = '<p>Hello <script>alert("XSS")</script> World!</p>';
const cleanHTML = sanitizeHTML(userInput);
// ผลลัพธ์: '<p>Hello  World!</p>'
```

### การปรับแต่ง DOMPurify สำหรับ Rich Text Editor
```javascript
// สำหรับ rich text editor ที่ต้องการ HTML tags บางตัว
function sanitizeRichText(dirty) {
    return DOMPurify.sanitize(dirty, {
        ALLOWED_TAGS: [
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
            'p', 'br', 'hr',
            'b', 'strong', 'i', 'em', 'u', 's',
            'ul', 'ol', 'li',
            'a', 'img',
            'blockquote', 'code', 'pre'
        ],
        ALLOWED_ATTR: {
            'a': ['href', 'title'],
            'img': ['src', 'alt', 'title', 'width', 'height'],
            '*': ['class']
        },
        ALLOWED_URI_REGEXP: /^(?:(?:(?:f|ht)tps?|mailto|tel|callto|cid|xmpp):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i,
        ADD_TAGS: [],
        ADD_ATTR: [],
        FORBID_TAGS: ['script', 'object', 'embed', 'iframe', 'form'],
        FORBID_ATTR: ['style', 'onerror', 'onload', 'onclick']
    });
}
```

## 2. Content Security Policy (CSP) Advanced

### CSP Nonce Implementation
```javascript
const crypto = require('crypto');

// Middleware สร้าง nonce
function generateCSPNonce(req, res, next) {
    const nonce = crypto.randomBytes(16).toString('base64');
    res.locals.cspNonce = nonce;
    
    const csp = [
        "default-src 'self'",
        `script-src 'self' 'nonce-${nonce}'`,
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: blob:",
        "font-src 'self' https://fonts.gstatic.com",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'"
    ].join('; ');
    
    res.setHeader('Content-Security-Policy', csp);
    next();
}

// ใช้งานใน template
app.get('/page', generateCSPNonce, (req, res) => {
    res.render('page', { nonce: res.locals.cspNonce });
});
```

### CSP Hash Implementation
```javascript
const crypto = require('crypto');

// สร้าง hash สำหรับ inline scripts
function generateScriptHash(script) {
    return crypto.createHash('sha256').update(script).digest('base64');
}

// ตัวอย่างการใช้งาน
const inlineScript = "console.log('Hello World');";
const scriptHash = generateScriptHash(inlineScript);

const csp = `script-src 'self' 'sha256-${scriptHash}'`;
res.setHeader('Content-Security-Policy', csp);
```

### CSP Reporting
```javascript
// CSP violation reporting endpoint
app.post('/csp-report', express.json(), (req, res) => {
    const report = req.body;
    
    // Log CSP violations
    console.log('CSP Violation:', {
        documentURI: report['document-uri'],
        violatedDirective: report['violated-directive'],
        blockedURI: report['blocked-uri'],
        originalPolicy: report['original-policy'],
        timestamp: new Date()
    });
    
    // อาจส่งไป monitoring system
    // sendToMonitoring(report);
    
    res.status(204).send();
});

// เพิ่ม report-uri ใน CSP
const csp = [
    "default-src 'self'",
    "script-src 'self'",
    "report-uri /csp-report"
].join('; ');
```

## 3. Template Security

### Safe Template Rendering
```javascript
// EJS with automatic escaping
app.set('view engine', 'ejs');

// Template file: views/comment.ejs
/*
<div class="comment">
    <h4><%- escapeHtml(comment.title) %></h4>
    <p><%= comment.content %></p>  <!-- Auto-escaped -->
    <small>By: <%= comment.author %></small>
</div>
*/

// Helper function
app.locals.escapeHtml = require('escape-html');

// Render with safe data
app.get('/comments/:id', (req, res) => {
    const comment = getCommentById(req.params.id);
    res.render('comment', { comment });
});
```

### Custom Template Security
```javascript
// สร้าง template engine ที่ปลอดภัย
class SecureTemplate {
    constructor() {
        this.helpers = {
            escape: this.escape.bind(this),
            escapeAttr: this.escapeAttribute.bind(this),
            escapeJS: this.escapeJavaScript.bind(this),
            escapeURL: this.escapeURL.bind(this)
        };
    }
    
    escape(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;');
    }
    
    escapeAttribute(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;');
    }
    
    escapeJavaScript(str) {
        return JSON.stringify(str).slice(1, -1);
    }
    
    escapeURL(str) {
        return encodeURIComponent(str);
    }
    
    render(template, data) {
        // Simple template processor
        return template.replace(/\{\{(\w+)\}\}/g, (match, key) => {
            return this.escape(data[key] || '');
        });
    }
}
```

## 4. Client-Side Protection

### Safe DOM Manipulation
```javascript
// Client-side XSS protection
class SafeDOM {
    static setText(element, text) {
        // ใช้ textContent แทน innerHTML
        element.textContent = text;
    }
    
    static setHTML(element, html) {
        // Sanitize ก่อนใส่ HTML
        if (typeof DOMPurify !== 'undefined') {
            element.innerHTML = DOMPurify.sanitize(html);
        } else {
            // Fallback: ใช้ textContent
            element.textContent = html;
        }
    }
    
    static setAttribute(element, name, value) {
        // ตรวจสอบ attribute ที่อันตราย
        const dangerousAttrs = ['onclick', 'onload', 'onerror', 'onmouseover'];
        if (dangerousAttrs.includes(name.toLowerCase())) {
            console.warn(`Blocked dangerous attribute: ${name}`);
            return;
        }
        
        element.setAttribute(name, value);
    }
    
    static createSafeLink(url, text) {
        const link = document.createElement('a');
        
        // ตรวจสอบ URL protocol
        try {
            const urlObj = new URL(url);
            if (!['http:', 'https:', 'mailto:'].includes(urlObj.protocol)) {
                throw new Error('Invalid protocol');
            }
            link.href = url;
        } catch (e) {
            link.href = '#';
            console.warn('Invalid URL provided:', url);
        }
        
        this.setText(link, text);
        link.rel = 'noopener noreferrer'; // Security best practice
        return link;
    }
}

// การใช้งาน
const userComment = getUserComment();
const commentElement = document.getElementById('comment');
SafeDOM.setText(commentElement, userComment); // ปลอดภัย
```

### Input Validation on Client-Side
```javascript
// Client-side validation (เสริมนอกจาก server-side)
class InputValidator {
    static validateComment(comment) {
        const errors = [];
        
        if (!comment || comment.trim().length === 0) {
            errors.push('Comment cannot be empty');
        }
        
        if (comment.length > 1000) {
            errors.push('Comment is too long (max 1000 characters)');
        }
        
        // ตรวจสอบ pattern ที่น่าสงสัย
        const suspiciousPatterns = [
            /<script/gi,
            /javascript:/gi,
            /vbscript:/gi,
            /on\w+\s*=/gi
        ];
        
        if (suspiciousPatterns.some(pattern => pattern.test(comment))) {
            errors.push('Comment contains potentially dangerous content');
        }
        
        return {
            isValid: errors.length === 0,
            errors: errors
        };
    }
    
    static sanitizeInput(input) {
        return input
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .trim();
    }
}

// การใช้งานใน form
document.getElementById('commentForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const comment = document.getElementById('commentInput').value;
    const validation = InputValidator.validateComment(comment);
    
    if (!validation.isValid) {
        showErrors(validation.errors);
        return;
    }
    
    // ส่งข้อมูลไป server
    submitComment(comment);
});
```

## นักศึกษาลองทำ: Advanced Exercise

### Exercise 1: CSP Policy Designer
```javascript
// สถานการณ์: Social Media Platform
// ต้องการ:
// - User สามารถ embed YouTube videos
// - รองรับ Google Analytics
// - ใช้ CDN สำหรับ images และ fonts
// - มี chat widget จาก third-party
// - รองรับ payment gateway

// TODO: ออกแบบ CSP policy ที่เหมาะสม
const socialMediaCSP = {
    'default-src': ['self'],
    'script-src': [
        // TODO: นักศึกษาเติม sources ที่จำเป็น
        // Hints: Google Analytics, YouTube API, Chat widget, Payment
    ],
    'style-src': [
        // TODO: เติม style sources
    ],
    'img-src': [
        // TODO: เติม image sources รวม CDN
    ],
    'media-src': [
        // TODO: YouTube videos
    ],
    'frame-src': [
        // TODO: YouTube embeds, Payment iframe
    ],
    'connect-src': [
        // TODO: API endpoints, Analytics
    ]
};

// แปลงเป็น CSP header string
function buildCSPHeader(policy) {
    // TODO: นักศึกษาเขียน function แปลง object เป็น CSP string
}
```

### Exercise 2: Multi-Context Encoder
```javascript
// สร้าง encoder ที่รองรับหลาย context
class MultiContextEncoder {
    // TODO: นักศึกษาเขียน method เหล่านี้
    
    encodeForHTML(input) {
        // สำหรับใส่ใน HTML content: <div>USER_INPUT</div>
    }
    
    encodeForHTMLAttribute(input) {
        // สำหรับใส่ใน HTML attribute: <input value="USER_INPUT">
    }
    
    encodeForJavaScript(input) {
        // สำหรับใส่ใน JavaScript string: var x = 'USER_INPUT';
    }
    
    encodeForURL(input) {
        // สำหรับใส่ใน URL: /search?q=USER_INPUT
    }
    
    encodeForCSS(input) {
        // สำหรับใส่ใน CSS: .class { background: USER_INPUT; }
    }
    
    // Challenge: Auto-detect context
    smartEncode(input, context) {
        // TODO: เขียน logic เลือก encoder ตาม context
        switch(context) {
            case 'html':
                return this.encodeForHTML(input);
            // TODO: เติม case อื่นๆ
        }
    }
}

// Test cases สำหรับนักศึกษา
const testInputs = [
    '<script>alert("xss")</script>',
    '"onmouseover="alert(1)"',
    'javascript:alert(1)',
    '\'; alert(1); //',
    'expression(alert(1))'
];

// TODO: ทดสอบแต่ละ encoder กับ test inputs
```

### Exercise 3: XSS Detection Engine
```javascript
// สร้างระบบตรวจจับ XSS patterns
class XSSDetector {
    constructor() {
        this.patterns = [
            // TODO: นักศึกษาเพิ่ม regex patterns สำหรับตรวจจับ XSS
        ];
        
        this.suspiciousKeywords = [
            // TODO: เพิ่ม keywords ที่น่าสงสัย
        ];
    }
    
    detectXSS(input) {
        const threats = [];
        
        // TODO: เขียน logic ตรวจจับ
        // 1. ตรวจสอบ script tags
        // 2. ตรวจสอบ event handlers
        // 3. ตรวจสอบ javascript: protocol
        // 4. ตรวจสอบ data: URIs
        // 5. ตรวจสอบ encoded payloads
        
        return {
            isThreating: threats.length > 0,
            threats: threats,
            riskLevel: this.calculateRisk(threats)
        };
    }
    
    calculateRisk(threats) {
        // TODO: คำนวณระดับความเสี่ยง 1-10
    }
    
    // Challenge: Bypass detection
    detectEncodedXSS(input) {
        // TODO: ตรวจจับ XSS ที่ encoded ด้วยวิธีต่างๆ
        // - HTML entities
        // - URL encoding
        // - Unicode encoding
        // - Base64
    }
}

// การทดสอบ
const detector = new XSSDetector();
const testCases = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    'javascript:alert(1)',
    '%3Cscript%3Ealert(1)%3C/script%3E', // URL encoded
    '&lt;script&gt;alert(1)&lt;/script&gt;', // HTML entities
    // TODO: เพิ่ม test cases ที่ซับซ้อนมากขึ้น
];
```

## คำถามวิเคราะห์ขั้นสูง

1. **Performance vs Security Trade-offs:**
   - การใช้ DOMPurify กับข้อมูลจำนวนมากมีผลต่อประสิทธิภาพอย่างไร?
   - CSP ที่เข้มงวดมากจะส่งผลต่อ user experience อย่างไร?

2. **Bypass Techniques Analysis:**
   - มีเทคนิค bypass XSS filters แบบไหนบ้างที่ยังใช้การได้?
   - ทำไม client-side validation อย่างเดียวไม่เพียงพอ?

3. **Real-world Implementation:**
   - Facebook, Twitter, YouTube ป้องกัน XSS อย่างไรในระบบที่ให้ user ใส่ rich content ได้?
   - Single Page Applications (SPA) มีความเสี่ยง XSS แตกต่างจาก traditional web apps อย่างไร?

4. **Future Considerations:**
   - Trusted Types API จะช่วยป้องกัน XSS ได้อย่างไร?
   - การใช้ WebAssembly มีผลต่อ XSS security อย่างไร?

---

## การประเมินผล Exercise

### เกณฑ์การให้คะแนน:

| หัวข้อ | คะแนน | รายละเอียด |
|--------|-------|------------|
| **Code Implementation** | 40% | เครื่องมือทำงานได้ถูกต้องและครบถ้วน |
| **Security Analysis** | 30% | วิเคราะห์ความปลอดภัยได้อย่างถูกต้อง |
| **Test Case Coverage** | 20% | ครอบคลุม test cases ที่กำหนด |
| **Documentation** | 10% | มีการอธิบายโค้ดและผลการทดลอง |

### สิ่งที่นักศึกษาควรส่ง:

1. **Working Code** - เครื่องมือที่เขียนขึ้นทำงานได้จริง
2. **Test Results** - ผลการทดสอบจาก exercises ทั้งหมด
3. **Comparison Analysis** - การเปรียบเทียบ HTTP vs HTTPS
4. **Security Recommendations** - ข้อเสนอแนะด้านความปลอดภัย
5. **Screenshots/Evidence** - หลักฐานการทำงานของเครื่องมือ

### การเตรียมความพร้อมสำหรับ LAB3:

หลังจากทำ Experiment 5 แล้ว นักศึกษาจะมีความเข้าใจ:
- ความแตกต่างระหว่าง HTTP และ HTTPS
- การ implement HTTPS อย่างถูกต้อง
- การใช้เครื่องมือวิเคราะห์ความปลอดภัย
- หลักการ network security monitoring

ความรู้เหล่านี้จะเป็นพื้นฐานสำคัญในการทำ LAB3 ที่ซับซ้อนมากขึ้น