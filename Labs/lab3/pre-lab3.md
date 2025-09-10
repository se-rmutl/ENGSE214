# Pre-LAB3: การรักษาความปลอดภัยเว็บแอปพลิเคชัน (งานเดี่ยว)

**หลักสูตร:** วิศวกรรมซอฟแวร์ปี 3  
**เวลาที่ใช้:** 2-3 ชั่วโมง  
**วัตถุประสงค์:** เตรียมความพร้อมสำหรับ LAB3 ด้วยการทำความเข้าใจช่องโหว่ความปลอดภัยพื้นฐาน

---

## ภาพรวม Pre-LAB

งานนี้แบ่งเป็น 5 ทดลองย่อย เพื่อให้นักศึกษาเข้าใจช่องโหว่ความปลอดภัยแต่ละประเภทแบบง่ายๆ ก่อนไปทำงานกลุ่มใน LAB3

**สิ่งที่ต้องส่ง:**
- Git repository ที่มีโค้ดและรายงานผลการทดลอง
- ไฟล์ `SECURITY_EXPERIMENTS.md` สรุปผลการทดลอง

---

## การเตรียมตัว

### ติดตั้ง Tools พื้นฐาน

```bash
# สร้างโปรเจค
mkdir pre-lab3-security
cd pre-lab3-security

# ติดตั้ง Node.js dependencies
npm init -y
npm install express sqlite3 cors
```

### สร้างโครงสร้างโปรเจค

```
pre-lab3-security/
├── experiment1/     # SQL Injection พื้นฐาน
├── experiment2/     # XSS พื้นฐาน  
├── experiment3/     # การป้องกัน Input Validation
├── experiment4/     # Password Security
├── experiment5/     # การเปรียบเทียบ HTTP vs HTTPS
├── database/        # ฐานข้อมูลทดสอบ
└── SECURITY_EXPERIMENTS.md
```

---

## Experiment 1: SQL Injection พื้นฐาน

### วัตถุประสงค์
เข้าใจว่า SQL Injection เกิดขึ้นได้อย่างไร และเห็นความแตกต่างระหว่างโค้ดที่มีช่องโหว่กับโค้ดที่ปลอดภัย

### Step 1.1: สร้างฐานข้อมูลทดสอบ

สร้างไฟล์ `database/setup.js`:

```javascript
// database/setup.js
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('test.db');

db.serialize(() => {
    // สร้างตาราง users
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        email TEXT
    )`);
    
    // เพิ่มข้อมูลทดสอบ
    db.run(`INSERT OR REPLACE INTO users VALUES 
        (1, 'admin', 'secret123', 'admin@example.com'),
        (2, 'john', 'password', 'john@example.com'),
        (3, 'jane', 'qwerty', 'jane@example.com')`);
    
    console.log('Database setup complete!');
});

db.close();
```

รัน: `node database/setup.js`

### Step 1.2: สร้างเซิร์ฟเวอร์ที่มีช่องโหว่

สร้างไฟล์ `experiment1/vulnerable-server.js`:

```javascript
// experiment1/vulnerable-server.js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const db = new sqlite3.Database(path.join(__dirname, '../database/test.db'));

app.use(express.json());
app.use(express.static('public'));

// 🚨 VULNERABLE: SQL Injection endpoint
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    // ❌ String concatenation - มีช่องโหว่ SQL Injection
    const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
    
    console.log('Executing query:', query);
    
    db.get(query, (err, row) => {
        if (err) {
            console.error(err);
            res.status(500).json({ error: err.message });
        } else if (row) {
            res.json({ 
                success: true, 
                message: 'Login successful!',
                user: row 
            });
        } else {
            res.json({ 
                success: false, 
                message: 'Invalid credentials' 
            });
        }
    });
});

app.listen(3001, () => {
    console.log('🚨 Vulnerable server running on http://localhost:3001');
    console.log('Try SQL injection: admin\'; --');
});
```

### Step 1.3: สร้างหน้าเว็บทดสอบ

สร้างไฟล์ `experiment1/public/index.html`:

```html
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Experiment 1: SQL Injection</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 600px; margin: 0 auto; }
        .test-case { 
            background: #f5f5f5; 
            padding: 20px; 
            margin: 20px 0; 
            border-radius: 8px; 
            border-left: 4px solid #ff6b6b;
        }
        .vulnerable { border-left-color: #ff6b6b; }
        .secure { border-left-color: #51cf66; }
        input, button { 
            padding: 10px; 
            margin: 5px; 
            border: 1px solid #ddd; 
            border-radius: 4px; 
        }
        button { background: #007bff; color: white; cursor: pointer; }
        .result { 
            margin-top: 10px; 
            padding: 10px; 
            border-radius: 4px; 
            background: #e9ecef; 
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🧪 Experiment 1: SQL Injection</h1>
        
        <div class="test-case vulnerable">
            <h3>🚨 Test Case 1: Vulnerable Login</h3>
            <p>ลองใส่ SQL injection payload ในช่อง username</p>
            
            <form id="loginForm">
                <input type="text" id="username" placeholder="Username" value="admin'; --">
                <input type="password" id="password" placeholder="Password" value="anything">
                <button type="submit">Login</button>
            </form>
            
            <div class="result" id="result"></div>
            
            <h4>💡 Test Cases ที่แนะนำ:</h4>
            <ul>
                <li><code>admin'; --</code> (bypass password)</li>
                <li><code>' OR '1'='1'; --</code> (login as first user)</li>
                <li><code>' UNION SELECT 1,2,3,4; --</code> (union injection)</li>
            </ul>
        </div>
        
        <div class="test-case">
            <h3>📝 คำถามสำหรับสังเกต:</h3>
            <ol>
                <li>เมื่อใส่ <code>admin'; --</code> ใน username เกิดอะไรขึ้น?</li>
                <li>ทำไมรหัสผ่านไม่สำคัญเมื่อใช้ payload นี้?</li>
                <li>ดูใน console ว่า SQL query ที่สร้างขึ้นเป็นอย่างไร?</li>
                <li>ลอง payload อื่นๆ และสังเกตผลลัพธ์</li>
            </ol>
        </div>
    </div>

    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                const data = await response.json();
                
                document.getElementById('result').innerHTML = `
                    <h4>Result:</h4>
                    <pre>${JSON.stringify(data, null, 2)}</pre>
                `;
            } catch (error) {
                document.getElementById('result').innerHTML = `
                    <h4>Error:</h4>
                    <p style="color: red;">${error.message}</p>
                `;
            }
        });
    </script>
</body>
</html>
```

### Step 1.4: ทดสอบและบันทึกผล

1. รัน: `node experiment1/vulnerable-server.js`
2. เปิด `http://localhost:3001`
3. ทดสอบ SQL injection payloads ต่างๆ
4. บันทึกผลการทดลองใน `SECURITY_EXPERIMENTS.md`

---

## Experiment 2: XSS (Cross-Site Scripting) พื้นฐาน

### วัตถุประสงค์
เข้าใจว่า XSS เกิดขึ้นได้อย่างไร และเห็นผลกระทบของการไม่ encode HTML

### Step 2.1: สร้างเซิร์ฟเวอร์ที่มีช่องโหว่ XSS

สร้างไฟล์ `experiment2/xss-server.js`:

```javascript
// experiment2/xss-server.js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const db = new sqlite3.Database(':memory:');

// สร้างตาราง comments ใน memory
db.serialize(() => {
    db.run(`CREATE TABLE comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        comment TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // ข้อมูลเริ่มต้น
    db.run(`INSERT INTO comments (name, comment) VALUES 
        ('Alice', 'สินค้าดีมาก แนะนำเลย!'),
        ('Bob', 'บริการประทับใจ จะมาซื้ออีก')`);
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// 🚨 VULNERABLE: XSS in comments
app.post('/comment', (req, res) => {
    const { name, comment } = req.body;
    
    // ❌ No sanitization - มีช่องโหว่ XSS
    db.run('INSERT INTO comments (name, comment) VALUES (?, ?)', [name, comment], function(err) {
        if (err) {
            res.status(500).json({ error: err.message });
        } else {
            res.json({ success: true, id: this.lastID });
        }
    });
});

// Get comments (vulnerable output)
app.get('/comments', (req, res) => {
    db.all('SELECT * FROM comments ORDER BY created_at DESC', (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
        } else {
            res.json(rows);
        }
    });
});

app.listen(3002, () => {
    console.log('🚨 XSS vulnerable server running on http://localhost:3002');
    console.log('Try XSS payload: <script>alert("XSS!")</script>');
});
```

### Step 2.2: สร้างหน้าเว็บทดสอบ XSS

สร้างไฟล์ `experiment2/public/index.html`:

```html
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Experiment 2: XSS</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .test-case { 
            background: #f5f5f5; 
            padding: 20px; 
            margin: 20px 0; 
            border-radius: 8px; 
            border-left: 4px solid #ff6b6b;
        }
        .comment-form { 
            background: white; 
            padding: 20px; 
            border-radius: 8px; 
            border: 1px solid #ddd; 
        }
        .comment { 
            background: white; 
            padding: 15px; 
            margin: 10px 0; 
            border-radius: 8px; 
            border-left: 3px solid #007bff; 
        }
        input, textarea, button { 
            padding: 10px; 
            margin: 5px 0; 
            border: 1px solid #ddd; 
            border-radius: 4px; 
            width: 100%; 
            box-sizing: border-box; 
        }
        button { background: #007bff; color: white; cursor: pointer; width: auto; }
        .dangerous { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🧪 Experiment 2: Cross-Site Scripting (XSS)</h1>
        
        <div class="test-case">
            <h3>🚨 Vulnerable Comment System</h3>
            <p>ระบบ comment นี้ไม่มีการป้องกัน XSS - JavaScript จะทำงาน!</p>
            
            <div class="comment-form">
                <h4>เพิ่ม Comment</h4>
                <form id="commentForm">
                    <input type="text" id="name" placeholder="ชื่อของคุณ" required>
                    <textarea id="comment" placeholder="ความคิดเห็น..." rows="3" required></textarea>
                    <button type="submit">ส่ง Comment</button>
                </form>
            </div>
            
            <h4>💡 XSS Payloads สำหรับทดสอบ:</h4>
            <div style="background: #fff3cd; padding: 15px; border-radius: 5px;">
                <p><strong>Basic XSS:</strong></p>
                <code>&lt;script&gt;alert('XSS Attack!')&lt;/script&gt;</code><br><br>
                
                <p><strong>Image XSS:</strong></p>
                <code>&lt;img src=x onerror=alert('XSS via IMG')&gt;</code><br><br>
                
                <p><strong>Cookie Stealing:</strong></p>
                <code>&lt;script&gt;alert('Cookie: ' + document.cookie)&lt;/script&gt;</code><br><br>
                
                <p><strong>DOM Manipulation:</strong></p>
                <code>&lt;script&gt;document.body.style.backgroundColor='red'&lt;/script&gt;</code>
            </div>
        </div>
        
        <div id="comments-section">
            <h3>💬 Comments</h3>
            <div id="comments-list"></div>
        </div>
        
        <div class="test-case">
            <h3>📝 คำถามสำหรับสังเกต:</h3>
            <ol>
                <li>เมื่อใส่ <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code> เกิดอะไรขึ้น?</li>
                <li>ลองใส่ payload อื่นๆ และสังเกตว่า JavaScript ทำงานอย่างไร?</li>
                <li>XSS สามารถเข้าถึง cookie ของผู้ใช้ได้หรือไม่?</li>
                <li>ถ้าเป็นเว็บไซต์จริง XSS จะอันตรายอย่างไร?</li>
            </ol>
        </div>
    </div>

    <script>
        // Load comments
        async function loadComments() {
            try {
                const response = await fetch('/comments');
                const comments = await response.json();
                
                const commentsList = document.getElementById('comments-list');
                commentsList.innerHTML = comments.map(comment => `
                    <div class="comment">
                        <strong>${comment.name}</strong>
                        <div>${comment.comment}</div>
                        <small>วันที่: ${new Date(comment.created_at).toLocaleString()}</small>
                    </div>
                `).join('');
            } catch (error) {
                console.error('Error loading comments:', error);
            }
        }
        
        // Add comment
        document.getElementById('commentForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const name = document.getElementById('name').value;
            const comment = document.getElementById('comment').value;
            
            try {
                const response = await fetch('/comment', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, comment })
                });
                
                if (response.ok) {
                    document.getElementById('commentForm').reset();
                    loadComments(); // Reload comments
                }
            } catch (error) {
                console.error('Error adding comment:', error);
            }
        });
        
        // Load comments on page load
        loadComments();
    </script>
</body>
</html>
```

### Step 2.3: ทดสอบและบันทึกผล

1. รัน: `node experiment2/xss-server.js`
2. เปิด `http://localhost:3002`
3. ทดสอบ XSS payloads ต่างๆ
4. สังเกตว่า JavaScript ทำงานหรือไม่
5. บันทึกผลการทดลอง

---

## Experiment 3: การป้องกันด้วย Input Validation

### วัตถุประสงค์
เรียนรู้วิธีการป้องกันช่องโหว่ด้วย input validation และ sanitization

### Step 3.1: สร้างเซิร์ฟเวอร์ที่มีการป้องกัน

สร้างไฟล์ `experiment3/secure-server.js`:

```javascript
// experiment3/secure-server.js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const db = new sqlite3.Database(':memory:');

// Setup database
db.serialize(() => {
    db.run(`CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        email TEXT
    )`);
    
    db.run(`CREATE TABLE comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        comment TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // Add test data
    const stmt = db.prepare('INSERT INTO users VALUES (?, ?, ?, ?)');
    stmt.run(1, 'admin', 'secret123', 'admin@example.com');
    stmt.run(2, 'john', 'password', 'john@example.com');
    stmt.finalize();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Input validation functions
function validateInput(input, maxLength = 100) {
    if (!input || typeof input !== 'string') {
        throw new Error('Invalid input');
    }
    
    if (input.length > maxLength) {
        throw new Error(`Input too long (max ${maxLength} characters)`);
    }
    
    // Check for suspicious patterns
    const dangerousPatterns = [
        /<script/gi,
        /javascript:/gi,
        /on\w+=/gi,
        /union\s+select/gi,
        /drop\s+table/gi,
        /insert\s+into/gi,
        /delete\s+from/gi
    ];
    
    for (const pattern of dangerousPatterns) {
        if (pattern.test(input)) {
            throw new Error('Input contains potentially dangerous content');
        }
    }
    
    return input.trim();
}

function sanitizeHTML(input) {
    return input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}

// ✅ SECURE: Login with prepared statements
app.post('/login', (req, res) => {
    try {
        const username = validateInput(req.body.username, 50);
        const password = validateInput(req.body.password, 100);
        
        // ✅ Using prepared statement - ป้องกัน SQL injection
        const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
        
        console.log('Secure query:', query);
        console.log('Parameters:', [username, password]);
        
        db.get(query, [username, password], (err, row) => {
            if (err) {
                console.error(err);
                res.status(500).json({ error: 'Database error' });
            } else if (row) {
                res.json({ 
                    success: true, 
                    message: 'Login successful!',
                    user: { id: row.id, username: row.username, email: row.email }
                });
            } else {
                res.json({ 
                    success: false, 
                    message: 'Invalid credentials' 
                });
            }
        });
    } catch (error) {
        res.status(400).json({ 
            success: false, 
            error: error.message 
        });
    }
});

// ✅ SECURE: Comment with sanitization
app.post('/comment', (req, res) => {
    try {
        const name = validateInput(req.body.name, 50);
        const comment = validateInput(req.body.comment, 500);
        
        // ✅ Sanitize HTML - ป้องกัน XSS
        const safeName = sanitizeHTML(name);
        const safeComment = sanitizeHTML(comment);
        
        db.run('INSERT INTO comments (name, comment) VALUES (?, ?)', 
               [safeName, safeComment], function(err) {
            if (err) {
                res.status(500).json({ error: err.message });
            } else {
                res.json({ 
                    success: true, 
                    id: this.lastID,
                    sanitized: true
                });
            }
        });
    } catch (error) {
        res.status(400).json({ 
            success: false, 
            error: error.message 
        });
    }
});

// Get comments
app.get('/comments', (req, res) => {
    db.all('SELECT * FROM comments ORDER BY created_at DESC', (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
        } else {
            res.json(rows);
        }
    });
});

app.listen(3003, () => {
    console.log('✅ Secure server running on http://localhost:3003');
    console.log('This server has security protections enabled');
});
```

### Step 3.2: สร้างหน้าเว็บเปรียบเทียบ

สร้างไฟล์ `experiment3/public/index.html`:

```html
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Experiment 3: Security Protection</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 1000px; margin: 0 auto; }
        .comparison { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .test-case { 
            background: #f5f5f5; 
            padding: 20px; 
            border-radius: 8px; 
        }
        .vulnerable { border-left: 4px solid #ff6b6b; }
        .secure { border-left: 4px solid #51cf66; }
        input, textarea, button { 
            padding: 10px; 
            margin: 5px 0; 
            border: 1px solid #ddd; 
            border-radius: 4px; 
            width: 100%; 
            box-sizing: border-box; 
        }
        button { background: #007bff; color: white; cursor: pointer; width: auto; }
        .result { 
            margin-top: 10px; 
            padding: 10px; 
            border-radius: 4px; 
            background: #e9ecef; 
        }
        .success { background: #d4edda; color: #155724; }
        .error { background: #f8d7da; color: #721c24; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🧪 Experiment 3: การป้องกันความปลอดภัย</h1>
        
        <h2>เปรียบเทียบ: ก่อนและหลังการป้องกัน</h2>
        
        <div class="comparison">
            <div class="test-case vulnerable">
                <h3>🚨 ระบบที่มีช่องโหว่</h3>
                <p>ทดสอบ login กับเซิร์ฟเวอร์ที่มีช่องโหว่ (port 3001)</p>
                
                <form id="vulnerableLogin">
                    <input type="text" placeholder="Username" value="admin'; --">
                    <input type="password" placeholder="Password" value="anything">
                    <button type="submit">Login (Vulnerable)</button>
                </form>
                
                <div class="result" id="vulnerableResult"></div>
            </div>
            
            <div class="test-case secure">
                <h3>✅ ระบบที่มีการป้องกัน</h3>
                <p>ทดสอบ login กับเซิร์ฟเวอร์ที่มีการป้องกัน</p>
                
                <form id="secureLogin">
                    <input type="text" placeholder="Username" value="admin'; --">
                    <input type="password" placeholder="Password" value="anything">
                    <button type="submit">Login (Secure)</button>
                </form>
                
                <div class="result" id="secureResult"></div>
            </div>
        </div>
        
        <div class="test-case">
            <h3>🧪 การทดสอบ Input Validation</h3>
            <p>ลองใส่ข้อมูลที่ผิดปกติและดูว่าระบบตอบสนองอย่างไร</p>
            
            <form id="validationTest">
                <input type="text" id="testName" placeholder="ชื่อ (ลอง XSS payload)">
                <textarea id="testComment" placeholder="ความคิดเห็น (ลอง script tag)" rows="3"></textarea>
                <button type="submit">ทดสอบ Validation</button>
            </form>
            
            <div class="result" id="validationResult"></div>
            
            <h4>💡 Test Cases แนะนำ:</h4>
            <ul>
                <li><code>&lt;script&gt;alert('test')&lt;/script&gt;</code></li>
                <li><code>' OR '1'='1</code></li>
                <li>ข้อความยาวเกิน 500 ตัวอักษร</li>
                <li><code>javascript:alert('xss')</code></li>
                <li><code>&lt;img src=x onerror=alert(1)&gt;</code></li>
            </ul>
        </div>
        
        <div class="test-case">
            <h3>📝 คำถามสำหรับสังเกต:</h3>
            <ol>
                <li>ระบบที่มีการป้องกันตอบสนองต่อ SQL injection อย่างไร?</li>
                <li>Input validation ป้องกันอะไรได้บ้าง?</li>
                <li>ความแตกต่างระหว่าง string concatenation กับ prepared statements คืออะไร?</li>
                <li>HTML sanitization ทำงานอย่างไร?</li>
                <li>การป้องกันแบบไหนที่มีประสิทธิภาพมากที่สุด?</li>
            </ol>
        </div>
    </div>

    <script>
        // Test vulnerable login (assuming server on port 3001 is running)
        document.getElementById('vulnerableLogin').addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            const username = e.target.querySelector('input[type="text"]').value;
            const password = e.target.querySelector('input[type="password"]').value;
            
            try {
                const response = await fetch('http://localhost:3001/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                const data = await response.json();
                document.getElementById('vulnerableResult').innerHTML = `
                    <div class="${data.success ? 'success' : 'error'}">
                        <strong>Vulnerable Server Response:</strong><br>
                        ${JSON.stringify(data, null, 2)}
                    </div>
                `;
            } catch (error) {
                document.getElementById('vulnerableResult').innerHTML = `
                    <div class="error">Error: ${error.message}<br>
                    <small>Make sure vulnerable server (port 3001) is running</small></div>
                `;
            }
        });
        
        // Test secure login
        document.getElementById('secureLogin').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = e.target.querySelector('input[type="text"]').value;
            const password = e.target.querySelector('input[type="password"]').value;
            
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                const data = await response.json();
                document.getElementById('secureResult').innerHTML = `
                    <div class="${data.success ? 'success' : 'error'}">
                        <strong>Secure Server Response:</strong><br>
                        ${JSON.stringify(data, null, 2)}
                    </div>
                `;
            } catch (error) {
                document.getElementById('secureResult').innerHTML = `
                    <div class="error">Error: ${error.message}</div>
                `;
            }
        });
        
        // Test validation
        document.getElementById('validationTest').addEventListener('submit', async (e) => {
            e.preventDefault();
            const name = document.getElementById('testName').value;
            const comment = document.getElementById('testComment').value;
            
            try {
                const response = await fetch('/comment', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, comment })
                });
                
                const data = await response.json();
                document.getElementById('validationResult').innerHTML = `
                    <div class="${data.success ? 'success' : 'error'}">
                        <strong>Validation Result:</strong><br>
                        ${JSON.stringify(data, null, 2)}
                        ${data.sanitized ? '<br><em>Content was sanitized for security</em>' : ''}
                    </div>
                `;
            } catch (error) {
                document.getElementById('validationResult').innerHTML = `
                    <div class="error">Error: ${error.message}</div>
                `;
            }
        });
    </script>
</body>
</html>
```

---

## Experiment 4: Password Security

### วัตถุประสงค์
เข้าใจความสำคัญของการเข้ารหัสรหัสผ่านและการจัดเก็บอย่างปลอดภัย

### Step 4.1: สร้างตัวอย่างการจัดการรหัสผ่าน

สร้างไฟล์ `experiment4/password-demo.js`:

```javascript
// experiment4/password-demo.js
const crypto = require('crypto');

// Simulate different password storage methods
class PasswordDemo {
    
    // ❌ INSECURE: Plain text storage
    storePlainText(password) {
        console.log('🚨 Plain Text Storage:');
        console.log(`Password: ${password}`);
        console.log(`Stored as: ${password}`);
        console.log('Risk: Anyone with database access can see passwords!\n');
        return password;
    }
    
    // ❌ INSECURE: Simple hash (MD5)
    storeMD5(password) {
        const hash = crypto.createHash('md5').update(password).digest('hex');
        console.log('🚨 MD5 Hash Storage:');
        console.log(`Password: ${password}`);
        console.log(`Stored as: ${hash}`);
        console.log('Risk: MD5 is fast, vulnerable to rainbow table attacks!\n');
        return hash;
    }
    
    // ❌ INSECURE: SHA-256 without salt
    storeSHA256(password) {
        const hash = crypto.createHash('sha256').update(password).digest('hex');
        console.log('🚨 SHA-256 without Salt:');
        console.log(`Password: ${password}`);
        console.log(`Stored as: ${hash}`);
        console.log('Risk: Still vulnerable to rainbow table attacks!\n');
        return hash;
    }
    
    // ✅ SECURE: SHA-256 with salt
    storeSaltedHash(password) {
        const salt = crypto.randomBytes(16).toString('hex');
        const hash = crypto.createHash('sha256').update(password + salt).digest('hex');
        const stored = `${salt}:${hash}`;
        
        console.log('✅ Salted Hash Storage:');
        console.log(`Password: ${password}`);
        console.log(`Salt: ${salt}`);
        console.log(`Hash: ${hash}`);
        console.log(`Stored as: ${stored}`);
        console.log('Better: Salt prevents rainbow table attacks\n');
        return stored;
    }
    
    // ✅ MOST SECURE: bcrypt-style (simulation)
    storeBcrypt(password) {
        const salt = crypto.randomBytes(16).toString('hex');
        const iterations = 12; // Cost factor
        
        // Simulate bcrypt (in real app, use actual bcrypt library)
        let hash = password + salt;
        for (let i = 0; i < Math.pow(2, iterations); i++) {
            hash = crypto.createHash('sha256').update(hash).digest('hex');
        }
        
        const stored = `$2b$${iterations}$${salt}$${hash}`;
        
        console.log('✅ bcrypt-style Storage:');
        console.log(`Password: ${password}`);
        console.log(`Cost factor: ${iterations} (2^${iterations} = ${Math.pow(2, iterations)} iterations)`);
        console.log(`Stored as: ${stored}`);
        console.log('Most secure: Slow hashing resists brute force attacks\n');
        return stored;
    }
    
    // Demonstrate password cracking difficulty
    demonstrateCracking() {
        const password = 'password123';
        
        console.log('='.repeat(60));
        console.log('🔓 PASSWORD CRACKING DEMONSTRATION');
        console.log('='.repeat(60));
        
        // Store password using different methods
        const plain = this.storePlainText(password);
        const md5 = this.storeMD5(password);
        const sha256 = this.storeSHA256(password);
        const salted = this.storeSaltedHash(password);
        const bcrypt = this.storeBcrypt(password);
        
        console.log('💡 Cracking Difficulty Analysis:');
        console.log('1. Plain text: ❌ Instant (0 seconds)');
        console.log('2. MD5: ❌ Very fast (~1 second with rainbow tables)');
        console.log('3. SHA-256: ❌ Fast (~5 seconds with rainbow tables)');
        console.log('4. Salted hash: ⚠️ Slow (~hours with brute force)');
        console.log('5. bcrypt: ✅ Very slow (~years with brute force)\n');
        
        // Show why same passwords hash differently with salt
        console.log('🔐 Why Salt Matters:');
        const samePassword = 'admin123';
        const hash1 = this.storeSaltedHash(samePassword);
        const hash2 = this.storeSaltedHash(samePassword);
        console.log('Notice: Same password, different hashes due to random salt!');
    }
    
    // Password strength checker
    checkPasswordStrength(password) {
        let score = 0;
        let feedback = [];
        
        if (password.length >= 8) score += 1;
        else feedback.push('Use at least 8 characters');
        
        if (/[a-z]/.test(password)) score += 1;
        else feedback.push('Include lowercase letters');
        
        if (/[A-Z]/.test(password)) score += 1;
        else feedback.push('Include uppercase letters');
        
        if (/[0-9]/.test(password)) score += 1;
        else feedback.push('Include numbers');
        
        if (/[^A-Za-z0-9]/.test(password)) score += 1;
        else feedback.push('Include special characters');
        
        const strength = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'][score];
        
        return { score, strength, feedback };
    }
}

// Run demonstration
const demo = new PasswordDemo();
demo.demonstrateCracking();

// Test password strength
console.log('='.repeat(60));
console.log('🔍 PASSWORD STRENGTH TESTING');
console.log('='.repeat(60));

const testPasswords = [
    'admin',
    'password',
    'Password123',
    'MySecure#Pass2024',
    'Tr0ub4dor&3'
];

testPasswords.forEach(pwd => {
    const result = demo.checkPasswordStrength(pwd);
    console.log(`Password: "${pwd}"`);
    console.log(`Strength: ${result.strength} (${result.score}/5)`);
    if (result.feedback.length > 0) {
        console.log(`Suggestions: ${result.feedback.join(', ')}`);
    }
    console.log('');
});

module.exports = PasswordDemo;
```

### Step 4.2: สร้างเว็บแอปทดสอบ Password Security

สร้างไฟล์ `experiment4/password-server.js`:

```javascript
// experiment4/password-server.js
const express = require('express');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

class PasswordManager {
    // Hash password with salt
    hashPassword(password) {
        const salt = crypto.randomBytes(16).toString('hex');
        const hash = crypto.createHash('sha256').update(password + salt).digest('hex');
        return `${salt}:${hash}`;
    }
    
    // Verify password
    verifyPassword(password, storedHash) {
        const [salt, hash] = storedHash.split(':');
        const testHash = crypto.createHash('sha256').update(password + salt).digest('hex');
        return hash === testHash;
    }
    
    // Check password strength
    checkStrength(password) {
        let score = 0;
        let feedback = [];
        
        if (password.length >= 8) score += 1;
        else feedback.push('ใช้อย่างน้อย 8 ตัวอักษร');
        
        if (password.length >= 12) score += 1;
        else if (password.length >= 8) feedback.push('ควรใช้ 12 ตัวอักษรขึ้นไป');
        
        if (/[a-z]/.test(password)) score += 1;
        else feedback.push('ใส่ตัวอักษรเล็ก (a-z)');
        
        if (/[A-Z]/.test(password)) score += 1;
        else feedback.push('ใส่ตัวอักษรใหญ่ (A-Z)');
        
        if (/[0-9]/.test(password)) score += 1;
        else feedback.push('ใส่ตัวเลข (0-9)');
        
        if (/[^A-Za-z0-9]/.test(password)) score += 1;
        else feedback.push('ใส่อักขระพิเศษ (!@#$%^&*)');
        
        // Check for common weak patterns
        const commonPatterns = [
            /123456/,
            /password/i,
            /admin/i,
            /qwerty/i,
            /abc/i
        ];
        
        if (commonPatterns.some(pattern => pattern.test(password))) {
            score = Math.max(0, score - 2);
            feedback.push('หลีกเลี่ยงรูปแบบที่ง่ายต่อการเดา');
        }
        
        const levels = ['อ่อนแอมาก', 'อ่อนแอ', 'ปานกลาง', 'ดี', 'แข็งแรง', 'แข็งแรงมาก'];
        const strength = levels[Math.min(score, levels.length - 1)];
        
        return { score, strength, feedback, maxScore: 6 };
    }
}

const passwordManager = new PasswordManager();

// API endpoints
app.post('/hash-password', (req, res) => {
    const { password, method } = req.body;
    
    let result = {};
    
    switch (method) {
        case 'plain':
            result = {
                method: 'Plain Text',
                stored: password,
                security: 'อันตรายมาก - เห็นรหัสผ่านได้ทันที',
                color: 'red'
            };
            break;
            
        case 'md5':
            const md5Hash = crypto.createHash('md5').update(password).digest('hex');
            result = {
                method: 'MD5',
                stored: md5Hash,
                security: 'อันตราย - แตกได้ง่ายด้วย rainbow table',
                color: 'orange'
            };
            break;
            
        case 'sha256':
            const sha256Hash = crypto.createHash('sha256').update(password).digest('hex');
            result = {
                method: 'SHA-256',
                stored: sha256Hash,
                security: 'อันตราย - ยังแตกได้ด้วย rainbow table',
                color: 'orange'
            };
            break;
            
        case 'salted':
            const saltedHash = passwordManager.hashPassword(password);
            result = {
                method: 'SHA-256 + Salt',
                stored: saltedHash,
                security: 'ปลอดภัย - salt ป้องกัน rainbow table',
                color: 'green'
            };
            break;
    }
    
    res.json(result);
});

app.post('/check-strength', (req, res) => {
    const { password } = req.body;
    const strength = passwordManager.checkStrength(password);
    res.json(strength);
});

app.listen(3004, () => {
    console.log('🔐 Password security demo running on http://localhost:3004');
});
```

### Step 4.3: สร้างหน้าเว็บทดสอบ

สร้างไฟล์ `experiment4/public/index.html`:

```html
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Experiment 4: Password Security</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 1000px; margin: 0 auto; }
        .test-case { 
            background: #f5f5f5; 
            padding: 20px; 
            margin: 20px 0; 
            border-radius: 8px; 
            border-left: 4px solid #007bff;
        }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        input, button, select { 
            padding: 10px; 
            margin: 5px 0; 
            border: 1px solid #ddd; 
            border-radius: 4px; 
            width: 100%; 
            box-sizing: border-box; 
        }
        button { background: #007bff; color: white; cursor: pointer; width: auto; }
        .result { 
            margin-top: 10px; 
            padding: 15px; 
            border-radius: 4px; 
            background: white;
            border: 1px solid #ddd;
        }
        .strength-meter {
            height: 10px;
            background: #e9ecef;
            border-radius: 5px;
            overflow: hidden;
            margin: 10px 0;
        }
        .strength-bar {
            height: 100%;
            transition: all 0.3s ease;
        }
        .very-weak { background: #dc3545; }
        .weak { background: #fd7e14; }
        .fair { background: #ffc107; }
        .good { background: #28a745; }
        .strong { background: #20c997; }
        .very-strong { background: #6f42c1; }
        .hash-demo { 
            font-family: monospace; 
            background: #f8f9fa; 
            padding: 10px; 
            border-radius: 4px;
            word-break: break-all;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Experiment 4: Password Security</h1>
        
        <div class="grid">
            <div class="test-case">
                <h3>🔍 Password Strength Checker</h3>
                <p>ทดสอบความแข็งแรงของรหัสผ่าน</p>
                
                <input type="password" id="passwordInput" placeholder="ใส่รหัสผ่านที่ต้องการทดสอบ">
                <button onclick="checkStrength()">ตรวจสอบความแข็งแรง</button>
                
                <div id="strengthResult"></div>
                
                <h4>🧪 รหัสผ่านทดสอบ:</h4>
                <ul>
                    <li><code>admin</code> - อ่อนแอมาก</li>
                    <li><code>password123</code> - อ่อนแอ</li>
                    <li><code>MyPass2024</code> - ปานกลาง</li>
                    <li><code>MySecure#Pass2024</code> - แข็งแรง</li>
                </ul>
            </div>
            
            <div class="test-case">
                <h3>🔐 Password Hashing Demo</h3>
                <p>ดูความแตกต่างของการเก็บรหัสผ่าน</p>
                
                <input type="text" id="hashPassword" placeholder="รหัสผ่านที่ต้องการ hash">
                <select id="hashMethod">
                    <option value="plain">Plain Text (ไม่ปลอดภัย)</option>
                    <option value="md5">MD5 (ไม่ปลอดภัย)</option>
                    <option value="sha256">SHA-256 (ไม่ปลอดภัย)</option>
                    <option value="salted">SHA-256 + Salt (ปลอดภัย)</option>
                </select>
                <button onclick="hashPassword()">สร้าง Hash</button>
                
                <div id="hashResult"></div>
            </div>
        </div>
        
        <div class="test-case">
            <h3>📊 การเปรียบเทียบ Password Storage Methods</h3>
            <p>ลองใส่รหัสผ่านเดียวกันและดูผลลัพธ์จากวิธีการต่างๆ</p>
            
            <input type="text" id="comparePassword" placeholder="รหัสผ่านสำหรับเปรียบเทียบ" value="mypassword123">
            <button onclick="compareAllMethods()">เปรียบเทียบทุกวิธี</button>
            
            <div id="comparisonResult"></div>
        </div>
        
        <div class="test-case">
            <h3>📝 คำถามสำหรับสังเกต:</h3>
            <ol>
                <li>ทำไม Plain Text ถึงอันตราย?</li>
                <li>ความแตกต่างระหว่าง MD5 กับ SHA-256 คืออะไร?</li>
                <li>Salt ช่วยป้องกันอะไร?</li>
                <li>ลองใส่รหัสผ่านเดียวกันใน Salted Hash หลายครั้ง ผลลัพธ์เป็นอย่างไร?</li>
                <li>รหัสผ่านที่แข็งแรงควรมีองค์ประกอบอะไรบ้าง?</li>
            </ol>
        </div>
    </div>

    <script>
        async function checkStrength() {
            const password = document.getElementById('passwordInput').value;
            
            if (!password) {
                alert('กรุณาใส่รหัสผ่าน');
                return;
            }
            
            try {
                const response = await fetch('/check-strength', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password })
                });
                
                const result = await response.json();
                
                const percentage = (result.score / result.maxScore) * 100;
                const strengthClass = result.strength.replace(/\s+/g, '-').toLowerCase();
                
                document.getElementById('strengthResult').innerHTML = `
                    <h4>ผลการวิเคราะห์:</h4>
                    <div class="strength-meter">
                        <div class="strength-bar ${strengthClass}" style="width: ${percentage}%"></div>
                    </div>
                    <p><strong>ระดับความแข็งแรง:</strong> ${result.strength} (${result.score}/${result.maxScore})</p>
                    ${result.feedback.length > 0 ? `
                        <p><strong>ข้อเสนอแนะ:</strong></p>
                        <ul>${result.feedback.map(f => `<li>${f}</li>`).join('')}</ul>
                    ` : '<p style="color: green;">✅ รหัสผ่านแข็งแรงดี!</p>'}
                `;
            } catch (error) {
                console.error('Error:', error);
            }
        }
        
        async function hashPassword() {
            const password = document.getElementById('hashPassword').value;
            const method = document.getElementById('hashMethod').value;
            
            if (!password) {
                alert('กรุณาใส่รหัสผ่าน');
                return;
            }
            
            try {
                const response = await fetch('/hash-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password, method })
                });
                
                const result = await response.json();
                
                document.getElementById('hashResult').innerHTML = `
                    <h4>${result.method}</h4>
                    <div class="hash-demo">${result.stored}</div>
                    <p style="color: ${result.color};">${result.security}</p>
                `;
            } catch (error) {
                console.error('Error:', error);
            }
        }
        
        async function compareAllMethods() {
            const password = document.getElementById('comparePassword').value;
            
            if (!password) {
                alert('กรุณาใส่รหัสผ่าน');
                return;
            }
            
            const methods = ['plain', 'md5', 'sha256', 'salted'];
            let results = '';
            
            for (const method of methods) {
                try {
                    const response = await fetch('/hash-password', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ password, method })
                    });
                    
                    const result = await response.json();
                    
                    results += `
                        <div style="margin: 15px 0; padding: 15px; border: 1px solid #ddd; border-radius: 4px;">
                            <h4>${result.method}</h4>
                            <div class="hash-demo">${result.stored}</div>
                            <p style="color: ${result.color};">${result.security}</p>
                        </div>
                    `;
                } catch (error) {
                    console.error('Error:', error);
                }
            }
            
            document.getElementById('comparisonResult').innerHTML = `
                <h4>ผลการเปรียบเทียบสำหรับรหัสผ่าน: "${password}"</h4>
                ${results}
                <div style="background: #e7f3ff; padding: 15px; border-radius: 4px; margin-top: 20px;">
                    <strong>💡 สังเกต:</strong> Salted hash จะให้ผลลัพธ์ที่แตกต่างกันทุกครั้ง เพราะ salt ถูกสร้างแบบสุ่ม
                </div>
            `;
        }
        
        // Real-time password strength checking
        document.getElementById('passwordInput').addEventListener('input', function() {
            if (this.value.length > 0) {
                setTimeout(checkStrength, 300);
            }
        });
    </script>
</body>
</html>
```

### Step 4.4: ทดสอบและบันทึกผล

1. รัน: `node experiment4/password-demo.js` (ดูผลใน console)
2. รัน: `node experiment4/password-server.js`
3. เปิด `http://localhost:3004`
4. ทดสอบรหัสผ่านต่างๆ และเปรียบเทียบวิธีการ hash
5. บันทึกผลการทดลอง

---

## Experiment 5: HTTP vs HTTPS Security

### วัตถุประสงค์
เข้าใจความแตกต่างระหว่าง HTTP และ HTTPS และเห็นความสำคัญของการเข้ารหัส

### Step 5.1: สร้างเซิร์ฟเวอร์ HTTP และ HTTPS

สร้างไฟล์ `experiment5/http-server.js`:

```javascript
// experiment5/http-server.js
const http = require('http');
const express = require('express');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ❌ HTTP Server - ไม่เข้ารหัส
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    console.log('🚨 HTTP LOGIN (ไม่เข้ารหัส):');
    console.log(`Username: ${username}`);
    console.log(`Password: ${password}`);
    console.log('⚠️ ข้อมูลนี้ส่งแบบ plain text ใครดักจับก็อ่านได้!');
    
    res.json({
        success: true,
        message: 'Login successful (HTTP)',
        warning: 'ข้อมูลไม่ได้เข้ารหัส!'
    });
});

const httpServer = http.createServer(app);

httpServer.listen(3005, () => {
    console.log('🚨 HTTP Server (ไม่ปลอดภัย) running on http://localhost:3005');
});
```

สร้างไฟล์ `experiment5/https-server.js`:

```javascript
// experiment5/https-server.js
const https = require('https');
const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ✅ HTTPS Server - เข้ารหัส
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    console.log('✅ HTTPS LOGIN (เข้ารหัส):');
    console.log(`Username: ${username}`);
    console.log(`Password: ${password}`);
    console.log('🔒 ข้อมูลนี้ถูกเข้ารหัสระหว่างการส่ง!');
    
    res.json({
        success: true,
        message: 'Login successful (HTTPS)',
        security: 'ข้อมูลถูกเข้ารหัส!'
    });
});

// สร้าง self-signed certificate สำหรับทดสอบ
const createSelfSignedCert = () => {
    const certPath = path.join(__dirname, 'cert.pem');
    const keyPath = path.join(__dirname, 'key.pem');
    
    if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
        console.log('Creating self-signed certificate...');
        const { execSync } = require('child_process');
        
        try {
            // สร้าง self-signed certificate
            execSync(`openssl req -x509 -newkey rsa:4096 -keyout ${keyPath} -out ${certPath} -days 365 -nodes -subj "/C=TH/ST=Bangkok/L=Bangkok/O=Security Lab/OU=IT/CN=localhost"`);
            console.log('✅ Self-signed certificate created');
        } catch (error) {
            console.log('❌ OpenSSL not found. Creating dummy certificates...');
            
            // สร้างไฟล์ dummy สำหรับการทดสอบ
            fs.writeFileSync(keyPath, '-----BEGIN PRIVATE KEY-----\nDUMMY KEY FOR DEMO\n-----END PRIVATE KEY-----');
            fs.writeFileSync(certPath, '-----BEGIN CERTIFICATE-----\nDUMMY CERT FOR DEMO\n-----END CERTIFICATE-----');
        }
    }
    
    return { certPath, keyPath };
};

// ถ้าไม่มี certificate ให้สร้างขึ้นมา
const { certPath, keyPath } = createSelfSignedCert();

// สำหรับการทดสอบ ใช้ HTTP แทน HTTPS
const httpServer = require('http').createServer(app);

httpServer.listen(3006, () => {
    console.log('✅ HTTPS-style Server running on http://localhost:3006');
    console.log('📝 Note: ในการทดสอบจริง ควรใช้ HTTPS กับ SSL certificate');
});
```

### Step 5.2: สร้าง Network Monitoring Demo

สร้างไฟล์ `experiment5/network-demo.js`:

```javascript
// experiment5/network-demo.js
const crypto = require('crypto');

class NetworkSecurityDemo {
    
    // จำลองการส่งข้อมูลผ่าน HTTP (ไม่เข้ารหัส)
    simulateHTTP(username, password) {
        console.log('🚨 HTTP TRANSMISSION (Plain Text):');
        console.log('='.repeat(50));
        
        const httpPacket = `
POST /login HTTP/1.1
Host: example.com
Content-Type: application/json
Content-Length: 45

{"username":"${username}","password":"${password}"}
        `.trim();
        
        console.log('📡 Data sent over network:');
        console.log(httpPacket);
        console.log('\n💡 Anyone monitoring network traffic can see:');
        console.log(`   Username: ${username}`);
        console.log(`   Password: ${password}`);
        console.log('\n❌ SECURITY RISK: Plain text transmission!\n');
        
        return httpPacket;
    }
    
    // จำลองการส่งข้อมูลผ่าน HTTPS (เข้ารหัส)
    simulateHTTPS(username, password) {
        console.log('✅ HTTPS TRANSMISSION (Encrypted):');
        console.log('='.repeat(50));
        
        // จำลองการเข้ารหัส (ในความเป็นจริงใช้ TLS)
        const plaintext = `{"username":"${username}","password":"${password}"}`;
        const encrypted = crypto.createHash('sha256')
            .update(plaintext + 'random-key')
            .digest('hex');
        
        const httpsPacket = `
TLS Handshake: [Certificate Exchange]
Encrypted Data: ${encrypted}
        `.trim();
        
        console.log('📡 Data sent over network:');
        console.log(httpsPacket);
        console.log('\n💡 Network monitoring shows only:');
        console.log('   ✅ Encrypted data (unreadable)');
        console.log('   ✅ Cannot see username/password');
        console.log('\n🔒 SECURE: Encrypted transmission!\n');
        
        return httpsPacket;
    }
    
    // เปรียบเทียบ HTTP vs HTTPS
    compareProtocols(username, password) {
        console.log('🔍 NETWORK SECURITY COMPARISON');
        console.log('='.repeat(60));
        console.log('Testing with credentials:');
        console.log(`Username: ${username}`);
        console.log(`Password: ${password}`);
        console.log('');
        
        this.simulateHTTP(username, password);
        this.simulateHTTPS(username, password);
        
        console.log('📊 COMPARISON SUMMARY:');
        console.log('='.repeat(60));
        console.log('HTTP:');
        console.log('  ❌ Data visible to anyone monitoring network');
        console.log('  ❌ Passwords sent in plain text');
        console.log('  ❌ Vulnerable to man-in-the-middle attacks');
        console.log('  ❌ No data integrity verification');
        console.log('');
        console.log('HTTPS:');
        console.log('  ✅ Data encrypted during transmission');
        console.log('  ✅ Passwords protected by encryption');
        console.log('  ✅ Certificate-based authentication');
        console.log('  ✅ Data integrity verification');
        console.log('');
    }
    
    // จำลองการโจมตี Man-in-the-Middle
    simulateMITMAttack() {
        console.log('👤 MAN-IN-THE-MIDDLE ATTACK SIMULATION');
        console.log('='.repeat(60));
        
        console.log('Scenario: Attacker intercepts network traffic');
        console.log('');
        
        console.log('🚨 HTTP (Vulnerable):');
        console.log('  1. User sends: POST /login {"username":"john","password":"secret123"}');
        console.log('  2. Attacker sees: Plain text data');
        console.log('  3. Attacker captures: Username=john, Password=secret123');
        console.log('  4. Result: ❌ CREDENTIALS STOLEN!');
        console.log('');
        
        console.log('🔒 HTTPS (Protected):');
        console.log('  1. User sends: Encrypted TLS data');
        console.log('  2. Attacker sees: Random encrypted bytes');
        console.log('  3. Attacker captures: Unreadable encrypted data');
        console.log('  4. Result: ✅ CREDENTIALS PROTECTED!');
        console.log('');
    }
}

// Run demonstrations
const demo = new NetworkSecurityDemo();

// Test with sample credentials
demo.compareProtocols('admin', 'mypassword123');
demo.simulateMITMAttack();

module.exports = NetworkSecurityDemo;
```

### Step 5.3: สร้างหน้าเว็บเปรียบเทียบ

สร้างไฟล์ `experiment5/public/index.html`:

```html
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Experiment 5: HTTP vs HTTPS</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .comparison { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .test-case { 
            padding: 20px; 
            border-radius: 8px; 
        }
        .http { background: #ffebee; border-left: 4px solid #f44336; }
        .https { background: #e8f5e8; border-left: 4px solid #4caf50; }
        .demo-section {
            background: #f5f5f5;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
            border-left: 4px solid #2196f3;
        }
        input, button { 
            padding: 10px; 
            margin: 5px 0; 
            border: 1px solid #ddd; 
            border-radius: 4px; 
            width: 100%; 
            box-sizing: border-box; 
        }
        button { background: #007bff; color: white; cursor: pointer; width: auto; }
        .network-packet {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 15px;
            margin: 10px 0;
            font-family: monospace;
            font-size: 14px;
            white-space: pre-wrap;
        }
        .vulnerable { color: #d32f2f; }
        .secure { color: #388e3c; }
        .result { 
            margin-top: 10px; 
            padding: 15px; 
            border-radius: 4px; 
            background: white;
            border: 1px solid #ddd;
        }
        .warning { background: #fff3cd; border-color: #ffeaa7; color: #856404; }
        .success { background: #d4edda; border-color: #c3e6cb; color: #155724; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Experiment 5: HTTP vs HTTPS Security</h1>
        
        <div class="demo-section">
            <h3>📡 Network Transmission Simulation</h3>
            <p>ดูความแตกต่างระหว่างการส่งข้อมูลผ่าน HTTP และ HTTPS</p>
            
            <div style="max-width: 400px;">
                <input type="text" id="demoUsername" placeholder="Username" value="admin">
                <input type="password" id="demoPassword" placeholder="Password" value="secret123">
                <button onclick="simulateTransmission()">จำลองการส่งข้อมูล</button>
            </div>
            
            <div id="transmissionResult"></div>
        </div>
        
        <div class="comparison">
            <div class="test-case http">
                <h3>🚨 HTTP Server (ไม่ปลอดภัย)</h3>
                <p>เซิร์ฟเวอร์ที่ไม่เข้ารหัสข้อมูล</p>
                
                <form id="httpForm">
                    <input type="text" placeholder="Username" value="testuser">
                    <input type="password" placeholder="Password" value="testpass">
                    <button type="submit">Login via HTTP</button>
                </form>
                
                <div class="result" id="httpResult"></div>
                
                <h4>⚠️ ความเสี่ยง HTTP:</h4>
                <ul>
                    <li>ข้อมูลส่งแบบ plain text</li>
                    <li>รหัสผ่านอ่านได้ง่าย</li>
                    <li>เสี่ยงต่อการดักจับข้อมูล</li>
                    <li>ไม่มีการยืนยันตัวตนเซิร์ฟเวอร์</li>
                </ul>
            </div>
            
            <div class="test-case https">
                <h3>✅ HTTPS Server (ปลอดภัย)</h3>
                <p>เซิร์ฟเวอร์ที่เข้ารหัสข้อมูล</p>
                
                <form id="httpsForm">
                    <input type="text" placeholder="Username" value="testuser">
                    <input type="password" placeholder="Password" value="testpass">
                    <button type="submit">Login via HTTPS</button>
                </form>
                
                <div class="result" id="httpsResult"></div>
                
                <h4>🔒 ความปลอดภัย HTTPS:</h4>
                <ul>
                    <li>ข้อมูลเข้ารหัสด้วย TLS</li>
                    <li>รหัสผ่านถูกป้องกัน</li>
                    <li>ป้องกันการดักจับข้อมูล</li>
                    <li>ยืนยันตัวตนเซิร์ฟเวอร์ด้วย Certificate</li>
                </ul>
            </div>
        </div>
        
        <div class="demo-section">
            <h3>👤 Man-in-the-Middle Attack Demo</h3>
            <p>จำลองการโจมตีดักจับข้อมูลระหว่างทาง</p>
            
            <button onclick="simulateMITM()">จำลองการโจมตี MITM</button>
            
            <div id="mitmResult"></div>
        </div>
        
        <div class="demo-section">
            <h3>📝 คำถามสำหรับสังเกต:</h3>
            <ol>
                <li>ถ้าคุณเป็นผู้โจมตีที่ดักจับ network traffic ข้อมูลไหนที่คุณเห็นได้?</li>
                <li>ทำไม HTTPS ถึงปลอดภัยกว่า HTTP?</li>
                <li>Certificate ใน HTTPS มีหน้าที่อะไร?</li>
                <li>ในชีวิตจริง เว็บไซต์ไหนที่ควรใช้ HTTPS เสมอ?</li>
                <li>การใช้ WiFi สาธารณะเสี่ยงอย่างไรกับ HTTP?</li>
            </ol>
        </div>
    </div>

    <script>
        function simulateTransmission() {
            const username = document.getElementById('demoUsername').value;
            const password = document.getElementById('demoPassword').value;
            
            if (!username || !password) {
                alert('กรุณาใส่ username และ password');
                return;
            }
            
            // จำลองการส่งข้อมูลแบบ HTTP
            const httpPacket = `POST /login HTTP/1.1
Host: example.com
Content-Type: application/json

{"username":"${username}","password":"${password}"}`;
            
            // จำลองการเข้ารหัสแบบ HTTPS (ง่ายๆ)
            const encrypted = btoa(JSON.stringify({username, password})) + '...encrypted...';
            const httpsPacket = `TLS Encrypted Data:
${encrypted}`;
            
            document.getElementById('transmissionResult').innerHTML = `
                <h4>📡 การส่งข้อมูลผ่าน Network:</h4>
                
                <div style="margin: 20px 0;">
                    <h5 class="vulnerable">🚨 HTTP Transmission (อันตราย):</h5>
                    <div class="network-packet vulnerable">${httpPacket}</div>
                    <p class="vulnerable">💡 ผู้โจมตีเห็น: Username="${username}", Password="${password}"</p>
                </div>
                
                <div style="margin: 20px 0;">
                    <h5 class="secure">🔒 HTTPS Transmission (ปลอดภัย):</h5>
                    <div class="network-packet secure">${httpsPacket}</div>
                    <p class="secure">💡 ผู้โจมตีเห็น: ข้อมูลที่เข้ารหัสแล้ว (อ่านไม่ได้)</p>
                </div>
            `;
        }
        
        function simulateMITM() {
            document.getElementById('mitmResult').innerHTML = `
                <h4>👤 Man-in-the-Middle Attack Scenario:</h4>
                
                <div style="background: #ffebee; padding: 15px; border-radius: 4px; margin: 10px 0;">
                    <h5>🚨 HTTP (เสี่ยงต่อการโจมตี):</h5>
                    <ol>
                        <li>ผู้ใช้ส่งข้อมูล: POST /login</li>
                        <li>ผู้โจมตี (ตัวกลาง) ดักจับ: {"username":"admin","password":"secret"}</li>
                        <li>ผู้โจมตีได้รับ: Username และ Password ชัดเจน</li>
                        <li>ผลลัพธ์: ❌ ข้อมูลถูกขโมย!</li>
                    </ol>
                </div>
                
                <div style="background: #e8f5e8; padding: 15px; border-radius: 4px; margin: 10px 0;">
                    <h5>✅ HTTPS (ป้องกันการโจมตี):</h5>
                    <ol>
                        <li>ผู้ใช้ส่งข้อมูลเข้ารหัส: TLS Encrypted Data</li>
                        <li>ผู้โจมตี (ตัวกลาง) ดักจับ: ข้อมูลที่เข้ารหัสแล้ว</li>
                        <li>ผู้โจมตีได้รับ: ข้อมูลที่อ่านไม่ได้</li>
                        <li>ผลลัพธ์: ✅ ข้อมูลปลอดภัย!</li>
                    </ol>
                </div>
                
                <div style="background: #fff3cd; padding: 15px; border-radius: 4px; margin: 10px 0;">
                    <strong>💡 ในชีวิตจริง:</strong>
                    <ul>
                        <li>WiFi สาธารณะ = ผู้โจมตีสามารถเป็นตัวกลางได้ง่าย</li>
                        <li>HTTP = ข้อมูลส่งแบบเปิด อ่านได้ทันที</li>
                        <li>HTTPS = ข้อมูลเข้ารหัส ป้องกันการดักจับ</li>
                    </ul>
                </div>
            `;
        }
        
        // HTTP Form submission
        document.getElementById('httpForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            const username = e.target.querySelector('input[type="text"]').value;
            const password = e.target.querySelector('input[type="password"]').value;
            
            try {
                const response = await fetch('http://localhost:3005/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                const data = await response.json();
                document.getElementById('httpResult').innerHTML = `
                    <div class="warning">
                        <h4>HTTP Response:</h4>
                        <pre>${JSON.stringify(data, null, 2)}</pre>
                        <p><strong>⚠️ คำเตือน:</strong> รหัสผ่านถูกส่งแบบ plain text!</p>
                    </div>
                `;
            } catch (error) {
                document.getElementById('httpResult').innerHTML = `
                    <div class="warning">
                        <p>❌ Error: ${error.message}</p>
                        <p><small>ตรวจสอบว่า HTTP server (port 3005) ทำงานอยู่หรือไม่</small></p>
                    </div>
                `;
            }
        });
        
        // HTTPS Form submission
        document.getElementById('httpsForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = e.target.querySelector('input[type="text"]').value;
            const password = e.target.querySelector('input[type="password"]').value;
            
            try {
                const response = await fetch('http://localhost:3006/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                const data = await response.json();
                document.getElementById('httpsResult').innerHTML = `
                    <div class="success">
                        <h4>HTTPS Response:</h4>
                        <pre>${JSON.stringify(data, null, 2)}</pre>
                        <p><strong>✅ ปลอดภัย:</strong> ข้อมูลถูกเข้ารหัสระหว่างการส่ง!</p>
                    </div>
                `;
            } catch (error) {
                document.getElementById('httpsResult').innerHTML = `
                    <div class="success">
                        <p>❌ Error: ${error.message}</p>
                        <p><small>ตรวจสอบว่า HTTPS server (port 3006) ทำงานอยู่หรือไม่</small></p>
                    </div>
                `;
            }
        });
    </script>
</body>
</html>
```

### Step 5.4: ทดสอบและบันทึกผล

1. รัน: `node experiment5/network-demo.js` (ดูผลใน console)
2. รัน: `node experiment5/http-server.js` (terminal 1)
3. รัน: `node experiment5/https-server.js` (terminal 2)
4. เปิด `http://localhost:3005` (หรือใช้หน้าเว็บรวม)
5. ทดสอบการส่งข้อมูลทั้ง HTTP และ HTTPS
6. บันทึกผลการทดลอง

---

## การสรุปผลและส่งงาน

### สร้างไฟล์รายงาน `SECURITY_EXPERIMENTS.md`

```markdown
# Pre-LAB3: รายงานการทดลองความปลอดภัยเว็บแอปพลิเคชัน

**ชื่อ:** [ชื่อนักศึกษา]  
**รหัสนักศึกษา:** [รหัส]  
**วันที่ทำการทดลอง:** [วันที่]

## Experiment 1: SQL Injection

### ผลการทดลอง
- **Payload ที่ทดสอบ:** `admin'; --`
- **ผลลัพธ์:** [อธิบายผลที่ได้]
- **SQL Query ที่เกิดขึ้น:** [คัดลอกจาก console]

### สิ่งที่สังเกต
1. [สังเกตการณ์ที่ 1]
2. [สังเกตการณ์ที่ 2]
3. [สังเกตการณ์ที่ 3]

### คำถามและคำตอบ
1. **เมื่อใส่ `admin'; --` ใน username เกิดอะไรขึ้น?**
   - [คำตอบของนักศึกษา]

2. **ทำไมรหัสผ่านไม่สำคัญเมื่อใช้ payload นี้?**
   - [คำตอบของนักศึกษา]

## Experiment 2: XSS (Cross-Site Scripting)

### ผลการทดลอง
- **Payload ที่ทดสอบ:** `<script>alert('XSS!')</script>`
- **ผลลัพธ์:** [อธิบายผลที่ได้]

### สิ่งที่สังเกต
[บันทึกสิ่งที่สังเกตเห็น]

## Experiment 3: การป้องกันด้วย Input Validation

### การเปรียบเทียบ
| ประเภทการโจมตี  | Vulnerable Server | Secure Server | ความแตกต่าง |
|----------------|-------------------|---------------|------------|
| SQL Injection  |    [ผลลัพธ์]        |   [ผลลัพธ์]     |  [อธิบาย]   |
| XSS            |    [ผลลัพธ์]        |   [ผลลัพธ์]     |  [อธิบาย]   |

### วิธีการป้องกันที่เรียนรู้
1. [วิธีที่ 1]
2. [วิธีที่ 2]
3. [วิธีที่ 3]

## Experiment 4: Password Security

### การเปรียบเทียบวิธีการเก็บรหัสผ่าน
|     วิธีการ         | ระดับความปลอดภัย  |   ข้อดี   |  ข้อเสีย  |
|-------------------|-----------------|---------|---------|
| Plain Text        | [ประเมิน]        | [ข้อดี]   | [ข้อเสีย] |
| MD5               | [ประเมิน]        | [ข้อดี]   | [ข้อเสีย] |
| SHA-256           | [ประเมิน]        | [ข้อดี]   | [ข้อเสีย] |
| SHA-256 + Salt    | [ประเมิน]        | [ข้อดี]   | [ข้อเสีย] |


### Password Strength Testing
- **รหัสผ่านที่ทดสอบ:** [ระบุรหัสผ่าน]
- **คะแนนความแข็งแรง:** [คะแนน/6]
- **ข้อเสนอแนะที่ได้:** [ข้อเสนอแนะ]

## Experiment 5: HTTP vs HTTPS

### การเปรียบเทียบความปลอดภัย
|    ประเด็น         | HTTP         | HTTPS        |
|-------------------|--------------|--------------|
| การเข้ารหัสข้อมูล     | [อธิบาย]      | [อธิบาย]      |
| ความปลอดภัยรหัสผ่าน  | [อธิบาย]      | [อธิบาย]      |
| การป้องกัน MITM     | [อธิบาย]      | [อธิบาย]      |


### ผลกระทบของ Man-in-the-Middle Attack
[อธิบายผลกระทบที่เข้าใจ]

## สรุปการเรียนรู้

### ช่องโหว่ที่สำคัญที่สุด 3 อันดับแรก
1. [ช่องโหว่ที่ 1] - เพราะ [เหตุผล]
2. [ช่องโหว่ที่ 2] - เพราะ [เหตุผล]  
3. [ช่องโหว่ที่ 3] - เพราะ [เหตุผล]

### วิธีการป้องกันที่มีประสิทธิภาพ
1. [วิธีการ 1]
2. [วิธีการ 2]
3. [วิธีการ 3]

### สิ่งที่จะนำไปประยุกต์ใช้
[อธิบายว่าจะนำความรู้ไปใช้อย่างไร]

## ความยากและปัญหาที่พบ
[อธิบายปัญหาที่พบระหว่างทำการทดลอง และวิธีแก้ไข]

## ข้อเสนอแนะสำหรับการปรับปรุง
[ข้อเสนอแนะสำหรับการทำ Lab ครั้งต่อไป]
```

### การส่งงาน

1. **อัปโหลด Git Repository ที่มี:**
   - โค้ดทั้ง 5 experiments
   - ไฟล์ `SECURITY_EXPERIMENTS.md`
   - Screenshot ผลการทดลอง (ถ้ามี)

2. **ตั้งชื่อ Repository:** `pre-lab3-security-[รหัสนักศึกษา]`

3. **README.md ควรมี:**
   - วิธีการรันแต่ละ experiment
   - ข้อมูลสรุปสั้นๆ
   - Link ไปยังรายงานหลัก

---

## เกณฑ์การประเมิน

| หัวข้อ | คะแนน | เกณฑ์ |
|--------|-------|-------|
| การทำงานของโค้ด | 25% | ทุก experiment ทำงานได้ถูกต้อง |
| ความเข้าใจช่องโหว่ | 25% | อธิบายช่องโหว่ได้ถูกต้องและชัดเจน |
| การวิเคราะห์เปรียบเทียบ | 25% | เปรียบเทียบ vulnerable vs secure ได้ดี |
| รายงานและเอกสาร | 15% | รายงานครบถ้วน อธิบายชัดเจน |
| Git Repository | 10% | จัดเก็บโค้ดเป็นระเบียบ มี README |

### คะแนนพิเศษ (ไม่เกิน 5%)
- ทดลองเพิ่มเติมนอกเหนือจากที่กำหนด
- การใช้เครื่องมือ security testing เพิ่มเติม
- การเสนอวิธีป้องกันใหม่ๆ

---

## ข้อควรระวังในการทำ Pre-LAB

### ด้านเทคนิค
1. **ทดสอบบน localhost เท่านั้น** - อย่าทดสอบช่องโหว่กับเว็บไซต์จริง
2. **ปิด server หลังใช้งาน** - เพื่อความปลอดภัย
3. **ใช้ข้อมูลทดสอบ** - อย่าใส่รหัสผ่านจริงในการทดลอง

### ด้านการเรียนรู้
1. **ทำความเข้าใจก่อนลอกโค้ด** - อ่านโค้ดและเข้าใจการทำงาน
2. **ทดลองด้วยตนเอง** - แก้ไขโค้ดและดูผลลัพธ์
3. **บันทึกสิ่งที่สังเกต** - เขียนรายงานตามความเข้าใจจริง

---

## การเตรียมตัวสำหรับ LAB3

หลังจากทำ Pre-LAB3 แล้ว นักศึกษาจะมีความรู้พื้นฐานเพื่อ:

1. **เข้าใจช่องโหว่หลัก** - SQL Injection, XSS, IDOR
2. **รู้วิธีการป้องกัน** - Input validation, prepared statements, encoding
3. **เห็นความสำคัญของ security** - รู้จักผลกระทบของช่องโหว่
4. **มีประสบการณ์ hands-on** - เคยใช้เครื่องมือและเขียนโค้ดแล้ว

### ทักษะที่ได้รับ
- **Technical Skills:** การเขียนโค้ดที่มีช่องโหว่และการแก้ไข
- **Analysis Skills:** การวิเคราะห์และเปรียบเทียบความปลอดภัย
- **Documentation Skills:** การเขียนรายงานเทคนิค
- **Security Mindset:** การคิดในมุมมองความปลอดภัย

---

## ทรัพยากรเพิ่มเติม

### เอกสารอ้างอิง
1. **OWASP Top 10** - https://owasp.org/Top10/
2. **SQL Injection Prevention** - OWASP SQL Injection Prevention Cheat Sheet
3. **XSS Prevention** - OWASP XSS Prevention Cheat Sheet
4. **Password Storage** - OWASP Password Storage Cheat Sheet

### เครื่องมือที่แนะนำ
1. **Burp Suite Community** - สำหรับทดสอบความปลอดภัย
2. **OWASP ZAP** - Open source security testing proxy
3. **SQLMap** - Automated SQL injection testing tool
4. **Firefox Developer Tools** - สำหรับดู network traffic

### การศึกษาต่อ
หลังจากทำ Pre-LAB3 สำเร็จ สามารถศึกษาเพิ่มเติม:
1. **CSRF Protection** - การป้องกัน Cross-Site Request Forgery
2. **Session Management** - การจัดการ session อย่างปลอดภัย
3. **Authentication & Authorization** - ระบบยืนยันตัวตนที่แข็งแรง
4. **Security Headers** - การใช้ HTTP security headers
5. **Penetration Testing** - การทดสอบเจาะระบบแบบมืออาชีพ

---

## สรุป

Pre-LAB3 นี้ออกแบบให้นักศึกษา:
- **เรียนรู้ทีละขั้นตอน** จากช่องโหว่พื้นฐานไปสู่การป้องกัน
- **ได้ลงมือปฏิบัติจริง** ไม่ใช่แค่ทฤษฎี
- **เห็นผลกระทบชัดเจน** ของช่องโหว่แต่ละประเภท
- **เตรียมพร้อมสำหรับ LAB3** ที่ซับซ้อนมากขึ้น

การทำ Pre-LAB3 อย่างจริงจังจะช่วยให้การทำ LAB3 งานกลุ่มราบรื่นและมีประสิทธิภาพมากขึ้น เพราะสมาชิกทุกคนจะมีพื้นฐานความรู้และประสบการณ์ hands-on เหมือนกัน
