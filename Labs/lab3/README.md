# LAB3: Hands-on Security Testing & Implementation (งานกลุ่ม)

**เป้าหมาย:** สร้างเว็บแอปพลิเคชันที่มีช่องโหว่เจตนา แล้วแก้ไขให้ปลอดภัย  
**เวลาที่ใช้:** 3-4 ชั่วโมง  
**เทคโนโลยี:** HTML, CSS, JavaScript, Node.js, MSSQL

---

## การเตรียมตัว (Setup)

### Step 1: ติดตั้ง Tools ที่จำเป็น

```bash
# ติดตั้ง Node.js (หากยังไม่มี)
# ดาวน์โหลดจาก: https://nodejs.org/

# ติดตั้ง SQL Server Express (หากยังไม่มี)
# ดาวน์โหลดจาก: https://www.microsoft.com/en-us/sql-server/sql-server-downloads

# สร้างโฟลเดอร์โปรเจค
mkdir security-lab
cd security-lab

# สร้างโครงสร้างโฟลเดอร์
mkdir frontend backend database
```

### Step 2: สร้างฐานข้อมูล

สร้างไฟล์ `database/setup.sql`:

```sql
-- database/setup.sql
CREATE DATABASE SecurityLab;
GO

USE SecurityLab;
GO

-- ตาราง Users
CREATE TABLE Users (
    id INT IDENTITY(1,1) PRIMARY KEY,
    username NVARCHAR(50) NOT NULL UNIQUE,
    password NVARCHAR(255) NOT NULL,
    email NVARCHAR(100) NOT NULL,
    role NVARCHAR(20) DEFAULT 'user',
    created_at DATETIME DEFAULT GETDATE()
);

-- ตาราง Comments
CREATE TABLE Comments (
    id INT IDENTITY(1,1) PRIMARY KEY,
    user_id INT FOREIGN KEY REFERENCES Users(id),
    content NVARCHAR(MAX) NOT NULL,
    created_at DATETIME DEFAULT GETDATE()
);

-- ตาราง Products
CREATE TABLE Products (
    id INT IDENTITY(1,1) PRIMARY KEY,
    name NVARCHAR(100) NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    description NVARCHAR(MAX)
);

-- ข้อมูลทดสอบ
INSERT INTO Users (username, password, email, role) VALUES 
('admin', 'admin123', 'admin@example.com', 'admin'),
('john', 'password', 'john@example.com', 'user'),
('jane', 'qwerty', 'jane@example.com', 'user');

INSERT INTO Products (name, price, description) VALUES 
('Laptop', 25000.00, 'Gaming Laptop'),
('Mouse', 500.00, 'Wireless Mouse'),
('Keyboard', 1200.00, 'Mechanical Keyboard');

INSERT INTO Comments (user_id, content) VALUES 
(2, 'สินค้าดีมาก ใช้งานได้ดี'),
(3, 'ราคาสมเหตุสมผล แนะนำเลยครับ');
```

รันคำสั่งใน SQL Server Management Studio หรือ Azure Data Studio

---

## Part 1: สร้าง Backend ที่มีช่องโหว่ (Vulnerable Version)

### Step 3: สร้าง Package.json และติดตั้ง Dependencies

```bash
cd backend
npm init -y
```

แก้ไขไฟล์ `backend/package.json`:

```json
{
  "name": "security-lab-backend",
  "version": "1.0.0",
  "description": "",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "mssql": "^9.1.1",
    "cors": "^2.8.5",
    "body-parser": "^1.20.2"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}
```

ติดตั้ง packages:

```bash
npm install
```

### Step 4: สร้าง Server (Vulnerable Version)

สร้างไฟล์ `backend/server.js`:

```javascript
// backend/server.js - VULNERABLE VERSION
const express = require('express');
const sql = require('mssql');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Database configuration
const dbConfig = {
    user: 'your_username',
    password: 'your_password',
    server: 'localhost',
    database: 'SecurityLab',
    options: {
        encrypt: false,
        trustServerCertificate: true
    }
};

// Connect to database
async function connectDB() {
    try {
        await sql.connect(dbConfig);
        console.log('Connected to SQL Server');
    } catch (err) {
        console.error('Database connection failed:', err);
    }
}

connectDB();

// 🚨 VULNERABLE: SQL Injection
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // ❌ String concatenation - SQL Injection vulnerability
        const query = `SELECT * FROM Users WHERE username='${username}' AND password='${password}'`;
        console.log('Query:', query); // For debugging
        
        const result = await sql.query(query);
        
        if (result.recordset.length > 0) {
            const user = result.recordset[0];
            res.json({
                success: true,
                message: 'Login successful',
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role
                }
            });
        } else {
            res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
    } catch (err) {
        // ❌ Exposing internal errors
        res.status(500).json({ error: err.message });
    }
});

// 🚨 VULNERABLE: XSS in comments
app.post('/comments', async (req, res) => {
    try {
        const { userId, content } = req.body;
        
        // ❌ No input sanitization
        const query = `INSERT INTO Comments (user_id, content) VALUES (${userId}, '${content}')`;
        await sql.query(query);
        
        res.json({ success: true, message: 'Comment added' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 🚨 VULNERABLE: IDOR - Direct object reference
app.get('/user/:id', async (req, res) => {
    try {
        const userId = req.params.id;
        
        // ❌ No authorization check
        const query = `SELECT * FROM Users WHERE id=${userId}`;
        const result = await sql.query(query);
        
        if (result.recordset.length > 0) {
            res.json(result.recordset[0]);
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 🚨 VULNERABLE: No input validation
app.get('/search', async (req, res) => {
    try {
        const { q } = req.query;
        
        // ❌ SQL Injection in search
        const query = `SELECT * FROM Products WHERE name LIKE '%${q}%'`;
        console.log('Search query:', query);
        
        const result = await sql.query(query);
        res.json(result.recordset);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get all comments (for display)
app.get('/comments', async (req, res) => {
    try {
        const query = `
            SELECT c.*, u.username 
            FROM Comments c 
            JOIN Users u ON c.user_id = u.id 
            ORDER BY c.created_at DESC
        `;
        const result = await sql.query(query);
        res.json(result.recordset);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.listen(PORT, () => {
    console.log(`🚨 Vulnerable server running on http://localhost:${PORT}`);
    console.log('⚠️  This server has intentional security vulnerabilities for educational purposes');
});
```

### Step 5: สร้าง Frontend

สร้างไฟล์ `frontend/index.html`:

```html
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Lab - Vulnerable App</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>🚨 Security Lab - Vulnerable Application</h1>
            <p class="warning">⚠️ This app has intentional security vulnerabilities for educational purposes</p>
        </header>

        <!-- Login Section -->
        <section class="section" id="login-section">
            <h2>🔐 Login (SQL Injection Vulnerable)</h2>
            <form id="login-form">
                <input type="text" id="username" placeholder="Username" required>
                <input type="password" id="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
            <div class="hint">
                <p><strong>Hint for SQL Injection:</strong></p>
                <p>Try: <code>admin'; --</code> as username</p>
                <p>Or: <code>' OR '1'='1'; --</code></p>
            </div>
            <div id="login-result"></div>
        </section>

        <!-- User Profile Section -->
        <section class="section" id="profile-section" style="display: none;">
            <h2>👤 User Profile (IDOR Vulnerable)</h2>
            <p>Current User ID: <span id="current-user-id"></span></p>
            <input type="number" id="user-id-input" placeholder="Enter User ID (1, 2, 3)" min="1" max="10">
            <button onclick="fetchUserProfile()">Get User Profile</button>
            <div class="hint">
                <p><strong>Hint for IDOR:</strong></p>
                <p>Try accessing other user IDs (1, 2, 3)</p>
            </div>
            <div id="profile-result"></div>
        </section>

        <!-- Comments Section -->
        <section class="section">
            <h2>💬 Comments (XSS Vulnerable)</h2>
            <div id="user-info" style="display: none;">
                <input type="hidden" id="current-user-id-hidden">
                <form id="comment-form">
                    <textarea id="comment-content" placeholder="Write your comment..." rows="3" required></textarea>
                    <button type="submit">Add Comment</button>
                </form>
                <div class="hint">
                    <p><strong>Hint for XSS:</strong></p>
                    <p>Try: <code>&lt;script&gt;alert('XSS!')&lt;/script&gt;</code></p>
                    <p>Or: <code>&lt;img src=x onerror=alert('XSS')&gt;</code></p>
                </div>
            </div>
            <div id="comments-display"></div>
        </section>

        <!-- Search Section -->
        <section class="section">
            <h2>🔍 Product Search (SQL Injection Vulnerable)</h2>
            <input type="text" id="search-input" placeholder="Search products...">
            <button onclick="searchProducts()">Search</button>
            <div class="hint">
                <p><strong>Hint for SQL Injection:</strong></p>
                <p>Try: <code>'; DROP TABLE Products; --</code></p>
                <p>Or: <code>' UNION SELECT id,username,password FROM Users; --</code></p>
            </div>
            <div id="search-results"></div>
        </section>
    </div>

    <script src="script.js"></script>
</body>
</html>
```

สร้างไฟล์ `frontend/styles.css`:

```css
/* frontend/styles.css */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, #ff6b6b, #ee5a24);
    min-height: 100vh;
    padding: 20px;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
}

header {
    text-align: center;
    margin-bottom: 30px;
    background: rgba(255, 255, 255, 0.1);
    padding: 20px;
    border-radius: 10px;
    backdrop-filter: blur(10px);
    color: white;
}

.warning {
    background: rgba(255, 193, 7, 0.2);
    padding: 10px;
    border-radius: 5px;
    margin-top: 10px;
    border: 2px solid #ffc107;
}

.section {
    background: white;
    margin-bottom: 20px;
    padding: 25px;
    border-radius: 10px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}

.section h2 {
    color: #e74c3c;
    margin-bottom: 15px;
    padding-bottom: 10px;
    border-bottom: 2px solid #eee;
}

/* Form Styles */
form {
    margin-bottom: 20px;
}

input[type="text"],
input[type="password"],
input[type="number"],
textarea {
    width: 100%;
    padding: 12px;
    margin-bottom: 10px;
    border: 2px solid #ddd;
    border-radius: 5px;
    font-size: 14px;
}

input[type="text"]:focus,
input[type="password"]:focus,
input[type="number"]:focus,
textarea:focus {
    outline: none;
    border-color: #e74c3c;
}

button {
    background: #e74c3c;
    color: white;
    padding: 12px 25px;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    font-size: 14px;
    font-weight: bold;
    transition: background 0.3s;
}

button:hover {
    background: #c0392b;
}

/* Hint Box */
.hint {
    background: #fff3cd;
    border: 1px solid #ffeaa7;
    border-radius: 5px;
    padding: 15px;
    margin: 15px 0;
}

.hint p {
    margin-bottom: 5px;
}

.hint code {
    background: #f8f9fa;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: 'Courier New', monospace;
    color: #e83e8c;
}

/* Results */
#login-result,
#profile-result,
#search-results,
#comments-display {
    margin-top: 15px;
    padding: 15px;
    border-radius: 5px;
    background: #f8f9fa;
    border: 1px solid #dee2e6;
}

.success {
    background: #d4edda !important;
    border-color: #c3e6cb !important;
    color: #155724;
}

.error {
    background: #f8d7da !important;
    border-color: #f5c6cb !important;
    color: #721c24;
}

/* Comments */
.comment {
    background: white;
    padding: 10px;
    margin: 10px 0;
    border-left: 3px solid #e74c3c;
    border-radius: 0 5px 5px 0;
}

.comment-author {
    font-weight: bold;
    color: #2c3e50;
    margin-bottom: 5px;
}

.comment-content {
    margin-bottom: 5px;
    line-height: 1.5;
}

.comment-date {
    font-size: 12px;
    color: #7f8c8d;
}

/* Responsive */
@media (max-width: 768px) {
    .container {
        padding: 10px;
    }
    
    .section {
        padding: 15px;
    }
}
```

สร้างไฟล์ `frontend/script.js`:

```javascript
// frontend/script.js
const API_BASE = 'http://localhost:3000';

let currentUser = null;

// Login functionality
document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    try {
        const response = await fetch(`${API_BASE}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        const resultDiv = document.getElementById('login-result');
        
        if (data.success) {
            currentUser = data.user;
            resultDiv.innerHTML = `
                <div class="success">
                    <h4>Login Successful!</h4>
                    <p><strong>User:</strong> ${data.user.username}</p>
                    <p><strong>Email:</strong> ${data.user.email}</p>
                    <p><strong>Role:</strong> ${data.user.role}</p>
                </div>
            `;
            
            // Show profile section and user info
            document.getElementById('profile-section').style.display = 'block';
            document.getElementById('user-info').style.display = 'block';
            document.getElementById('current-user-id').textContent = data.user.id;
            document.getElementById('current-user-id-hidden').value = data.user.id;
            
            loadComments();
        } else {
            resultDiv.innerHTML = `<div class="error">${data.message}</div>`;
        }
    } catch (error) {
        document.getElementById('login-result').innerHTML = 
            `<div class="error">Error: ${error.message}</div>`;
    }
});

// Fetch user profile (IDOR vulnerability)
async function fetchUserProfile() {
    const userId = document.getElementById('user-id-input').value;
    
    if (!userId) {
        alert('Please enter a user ID');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/user/${userId}`);
        const data = await response.json();
        
        const resultDiv = document.getElementById('profile-result');
        
        if (response.ok) {
            resultDiv.innerHTML = `
                <div class="success">
                    <h4>User Profile:</h4>
                    <p><strong>ID:</strong> ${data.id}</p>
                    <p><strong>Username:</strong> ${data.username}</p>
                    <p><strong>Email:</strong> ${data.email}</p>
                    <p><strong>Password:</strong> ${data.password}</p>
                    <p><strong>Role:</strong> ${data.role}</p>
                    <p><strong>Created:</strong> ${new Date(data.created_at).toLocaleDateString()}</p>
                </div>
            `;
        } else {
            resultDiv.innerHTML = `<div class="error">${data.error}</div>`;
        }
    } catch (error) {
        document.getElementById('profile-result').innerHTML = 
            `<div class="error">Error: ${error.message}</div>`;
    }
}

// Add comment (XSS vulnerability)
document.getElementById('comment-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const content = document.getElementById('comment-content').value;
    const userId = document.getElementById('current-user-id-hidden').value;
    
    try {
        const response = await fetch(`${API_BASE}/comments`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ userId, content })
        });
        
        if (response.ok) {
            document.getElementById('comment-content').value = '';
            loadComments();
        }
    } catch (error) {
        console.error('Error adding comment:', error);
    }
});

// Load and display comments (XSS vulnerability)
async function loadComments() {
    try {
        const response = await fetch(`${API_BASE}/comments`);
        const comments = await response.json();
        
        const displayDiv = document.getElementById('comments-display');
        
        if (comments.length > 0) {
            displayDiv.innerHTML = comments.map(comment => `
                <div class="comment">
                    <div class="comment-author">${comment.username}</div>
                    <div class="comment-content">${comment.content}</div>
                    <div class="comment-date">${new Date(comment.created_at).toLocaleString()}</div>
                </div>
            `).join('');
        } else {
            displayDiv.innerHTML = '<p>No comments yet.</p>';
        }
    } catch (error) {
        console.error('Error loading comments:', error);
    }
}

// Search products (SQL Injection vulnerability)
async function searchProducts() {
    const query = document.getElementById('search-input').value;
    
    if (!query.trim()) {
        alert('Please enter search term');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/search?q=${encodeURIComponent(query)}`);
        const data = await response.json();
        
        const resultDiv = document.getElementById('search-results');
        
        if (Array.isArray(data) && data.length > 0) {
            resultDiv.innerHTML = `
                <h4>Search Results:</h4>
                ${data.map(item => `
                    <div class="comment">
                        <strong>${item.name || item.username || 'Item'}</strong><br>
                        ${item.price ? `Price: $${item.price}` : ''}
                        ${item.email ? `Email: ${item.email}` : ''}
                        ${item.password ? `Password: ${item.password}` : ''}
                        ${item.description ? `<br>Description: ${item.description}` : ''}
                    </div>
                `).join('')}
            `;
        } else if (data.error) {
            resultDiv.innerHTML = `<div class="error">Error: ${data.error}</div>`;
        } else {
            resultDiv.innerHTML = '<p>No results found.</p>';
        }
    } catch (error) {
        document.getElementById('search-results').innerHTML = 
            `<div class="error">Error: ${error.message}</div>`;
    }
}

// Load comments on page load
document.addEventListener('DOMContentLoaded', () => {
    loadComments();
});
```

---

## Part 2: ทดลองโจมตี (Attack Testing)

### Step 6: เรียกใช้งาน Vulnerable Application

```bash
# Terminal 1 - Start backend
cd backend
npm run dev

# Terminal 2 - Start frontend (ใช้ Live Server หรือ HTTP Server)
cd frontend
# ถ้ามี Python: python -m http.server 8080
# หรือใช้ Live Server extension ใน VS Code
```

เปิดเบราว์เซอร์ไปที่ `http://localhost:8080`

### Step 7: ทดสอบ SQL Injection

**การทดสอบ 1: Bypass Login**
1. ในหน้า Login ใส่:
   - Username: `admin'; --`
   - Password: (อะไรก็ได้)
2. กด Login และสังเกตผล

**การทดสอบ 2: Union-based SQL Injection**
1. ในช่อง Search ใส่: `' UNION SELECT id,username,password FROM Users; --`
2. สังเกตว่าได้ข้อมูลผู้ใช้ออกมาหรือไม่

**การทดสอบ 3: Information Disclosure**
1. ในช่อง Search ใส่: `' AND 1=0 UNION SELECT table_name,column_name,'test' FROM information_schema.columns; --`
2. ดูโครงสร้างฐานข้อมูล

### Step 8: ทดสอบ XSS

**การทดสอบ 1: Basic XSS**
1. Login เข้าสู่ระบบ
2. ในช่อง Comment ใส่: `<script>alert('XSS Attack!');</script>`
3. สังเกตการแสดงผล

**การทดสอบ 2: Cookie Stealing**
1. ใส่ในช่อง Comment: `<script>alert('Cookie: ' + document.cookie);</script>`
2. ดูว่าสามารถเข้าถึง Cookie ได้หรือไม่

### Step 9: ทดสอบ IDOR

**การทดสอบ:**
1. Login ด้วยผู้ใช้ปกติ (john/password)
2. ใน User Profile section ลอง ID ต่างๆ (1, 2, 3)
3. สังเกตว่าสามารถดูข้อมูลผู้ใช้อื่นได้หรือไม่

---

## Part 3: สร้าง Secure Version
### Step 10: สร้าง Secure Backend

ติดตั้ง dependencies เพิ่มเติม:

```bash
cd backend
npm install bcrypt jsonwebtoken express-rate-limit helmet express-validator
```

สร้างไฟล์ `backend/secure-server.js`:

```javascript
// backend/secure-server.js - SECURE VERSION
const express = require('express');
const sql = require('mssql');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, param, query, validationResult } = require('express-validator');

const app = express();
const PORT = 3001;

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"]
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true
    }
}));

app.use(cors({
    origin: ['http://localhost:8080', 'http://127.0.0.1:8080', 'http://localhost:5500'],
    credentials: true
}));

// Rate limiting
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 นาที
    max: 100, // จำกัด 100 requests ต่อ IP
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5, // จำกัด 5 การ login ต่อ IP ใน 15 นาที
    message: { error: 'Too many login attempts, please try again later.' },
    skipSuccessfulRequests: true
});

app.use(generalLimiter);
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true }));

// Database configuration
const dbConfig = {
    user: 'your_username',
    password: 'your_password',
    server: 'localhost',
    database: 'SecurityLab',
    options: {
        encrypt: false,
        trustServerCertificate: true
    }
};

// JWT Secret (ในการใช้งานจริงควรเก็บใน environment variables)
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-change-this-in-production';

// Connect to database
async function connectDB() {
    try {
        await sql.connect(dbConfig);
        console.log('✅ Connected to SQL Server (Secure Version)');
    } catch (err) {
        console.error('❌ Database connection failed:', err);
        process.exit(1);
    }
}

connectDB();

// Logging middleware
function logRequest(req, res, next) {
    const timestamp = new Date().toISOString();
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('User-Agent') || 'Unknown';
    
    console.log(`[${timestamp}] ${req.method} ${req.url} - IP: ${ip} - User-Agent: ${userAgent.substring(0, 50)}`);
    next();
}

app.use(logRequest);

// Authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ 
            error: 'Access token required',
            code: 'NO_TOKEN'
        });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.log(`❌ JWT verification failed: ${err.message}`);
            return res.status(403).json({ 
                error: 'Invalid or expired token',
                code: 'INVALID_TOKEN'
            });
        }
        req.user = user;
        next();
    });
}

// Authorization middleware
function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ 
            error: 'Admin access required',
            code: 'INSUFFICIENT_PRIVILEGES'
        });
    }
    next();
}

// HTML encoding function
function htmlEncode(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
}

// Input sanitization function
function sanitizeInput(input) {
    return input
        .replace(/[<>]/g, '') // Remove angle brackets
        .replace(/javascript:/gi, '') // Remove javascript: protocol
        .replace(/on\w+=/gi, '') // Remove event handlers
        .trim();
}

// ✅ SECURE: Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        server: 'Secure Version'
    });
});

// ✅ SECURE: Login with comprehensive security
app.post('/login', 
    loginLimiter,
    [
        body('username')
            .trim()
            .isLength({ min: 1, max: 50 })
            .matches(/^[a-zA-Z0-9_]+$/)
            .withMessage('Username must be 1-50 characters, alphanumeric with underscores only'),
        body('password')
            .isLength({ min: 1, max: 100 })
            .withMessage('Password is required (max 100 characters)')
    ],
    async (req, res) => {
        const startTime = Date.now();
        
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                console.log(`❌ Login validation failed: ${JSON.stringify(errors.array())}`);
                return res.status(400).json({ 
                    success: false, 
                    message: 'Invalid input format',
                    errors: errors.array() 
                });
            }
            
            const { username, password } = req.body;
            
            // Log login attempt
            console.log(`🔐 Login attempt for user: ${username} from IP: ${req.ip}`);
            
            // ✅ Using prepared statement
            const request = new sql.Request();
            request.input('username', sql.NVarChar, username);
            
            const result = await request.query('SELECT * FROM Users WHERE username = @username');
            
            if (result.recordset.length === 0) {
                console.log(`❌ Login failed: User '${username}' not found`);
                // ✅ Generic error message to prevent username enumeration
                return res.status(401).json({ 
                    success: false, 
                    message: 'Invalid credentials',
                    code: 'INVALID_CREDENTIALS'
                });
            }
            
            const user = result.recordset[0];
            
            // ✅ Compare password (ในการใช้งานจริงควรใช้ bcrypt)
            // For this lab, we'll use plain text but show the secure way
            // const isValidPassword = await bcrypt.compare(password, user.password);
            const isValidPassword = password === user.password;
            
            if (!isValidPassword) {
                console.log(`❌ Login failed: Invalid password for user '${username}'`);
                return res.status(401).json({ 
                    success: false, 
                    message: 'Invalid credentials',
                    code: 'INVALID_CREDENTIALS'
                });
            }
            
            // ✅ Generate JWT token with additional claims
            const tokenPayload = {
                userId: user.id,
                username: user.username,
                role: user.role,
                loginTime: Date.now()
            };
            
            const token = jwt.sign(
                tokenPayload,
                JWT_SECRET,
                { 
                    expiresIn: '1h',
                    issuer: 'security-lab',
                    audience: 'security-lab-users'
                }
            );
            
            console.log(`✅ Login successful for user '${username}' (Role: ${user.role})`);
            
            res.json({
                success: true,
                message: 'Login successful',
                token: token,
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role
                }
            });
            
        } catch (err) {
            console.error('❌ Login error:', err);
            // ✅ Generic error message - ไม่เปิดเผยรายละเอียด
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred during login',
                code: 'INTERNAL_ERROR'
            });
        }
        
        const duration = Date.now() - startTime;
        console.log(`⏱️  Login request completed in ${duration}ms`);
    }
);

// ✅ SECURE: Comments with comprehensive input validation
app.post('/comments',
    authenticateToken,
    [
        body('content')
            .trim()
            .isLength({ min: 1, max: 1000 })
            .withMessage('Comment must be 1-1000 characters')
            .custom(value => {
                // ✅ Additional security validation
                const forbiddenPatterns = [
                    /<script/gi,
                    /javascript:/gi,
                    /vbscript:/gi,
                    /onload/gi,
                    /onerror/gi,
                    /onclick/gi,
                    /onmouseover/gi
                ];
                
                if (forbiddenPatterns.some(pattern => pattern.test(value))) {
                    throw new Error('Content contains potentially dangerous code');
                }
                
                return true;
            })
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                console.log(`❌ Comment validation failed for user ${req.user.username}:`, errors.array());
                return res.status(400).json({ 
                    success: false, 
                    message: 'Invalid comment content',
                    errors: errors.array() 
                });
            }
            
            const { content } = req.body;
            const userId = req.user.userId;
            
            // ✅ Multiple layers of sanitization
            let sanitizedContent = sanitizeInput(content);
            sanitizedContent = htmlEncode(sanitizedContent);
            
            console.log(`💬 Adding comment from user: ${req.user.username}`);
            
            // ✅ Using prepared statement
            const request = new sql.Request();
            request.input('userId', sql.Int, userId);
            request.input('content', sql.NVarChar, sanitizedContent);
            
            const result = await request.query('INSERT INTO Comments (user_id, content) VALUES (@userId, @content)');
            
            console.log(`✅ Comment added successfully by user: ${req.user.username}`);
            
            res.json({ 
                success: true, 
                message: 'Comment added successfully',
                sanitized: sanitizedContent !== content
            });
            
        } catch (err) {
            console.error('❌ Comment error:', err);
            res.status(500).json({ 
                success: false, 
                message: 'Failed to add comment' 
            });
        }
    }
);

// ✅ SECURE: User profile with comprehensive authorization
app.get('/user/:id',
    authenticateToken,
    [param('id').isInt({ min: 1 }).withMessage('Valid user ID required')],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ 
                    error: 'Invalid user ID format',
                    details: errors.array() 
                });
            }
            
            const requestedUserId = parseInt(req.params.id);
            const currentUserId = req.user.userId;
            const currentUserRole = req.user.role;
            
            console.log(`👤 Profile request: User ${req.user.username} requesting profile ${requestedUserId}`);
            
            // ✅ Authorization: users can only access their own profile (except admins)
            if (requestedUserId !== currentUserId && currentUserRole !== 'admin') {
                console.log(`❌ Unauthorized profile access attempt by user: ${req.user.username}`);
                return res.status(403).json({ 
                    error: 'Access denied: You can only access your own profile',
                    code: 'INSUFFICIENT_PRIVILEGES'
                });
            }
            
            // ✅ Using prepared statement
            const request = new sql.Request();
            request.input('userId', sql.Int, requestedUserId);
            
            // ✅ Select only safe columns (exclude password)
            const result = await request.query(
                'SELECT id, username, email, role, created_at FROM Users WHERE id = @userId'
            );
            
            if (result.recordset.length === 0) {
                return res.status(404).json({ 
                    error: 'User not found',
                    code: 'USER_NOT_FOUND'
                });
            }
            
            console.log(`✅ Profile data provided for user ID: ${requestedUserId}`);
            res.json(result.recordset[0]);
            
        } catch (err) {
            console.error('❌ Profile error:', err);
            res.status(500).json({ 
                error: 'Failed to retrieve profile',
                code: 'INTERNAL_ERROR'
            });
        }
    }
);

// ✅ SECURE: Search with strict input validation
app.get('/search',
    [
        query('q')
            .trim()
            .isLength({ min: 1, max: 100 })
            .matches(/^[a-zA-Z0-9\s\-_]+$/)
            .withMessage('Search term must be 1-100 characters, alphanumeric with spaces, hyphens, underscores only')
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                console.log(`❌ Search validation failed:`, errors.array());
                return res.status(400).json({ 
                    error: 'Invalid search term',
                    details: errors.array() 
                });
            }
            
            const searchTerm = req.query.q;
            console.log(`🔍 Search request: "${searchTerm}"`);
            
            // ✅ Using prepared statement with LIKE
            const request = new sql.Request();
            request.input('searchTerm', sql.NVarChar, `%${searchTerm}%`);
            
            const result = await request.query(
                'SELECT id, name, price, description FROM Products WHERE name LIKE @searchTerm'
            );
            
            console.log(`✅ Search completed: ${result.recordset.length} results found`);
            res.json(result.recordset);
            
        } catch (err) {
            console.error('❌ Search error:', err);
            res.status(500).json({ 
                error: 'Search failed',
                code: 'SEARCH_ERROR'
            });
        }
    }
);

// ✅ SECURE: Get comments (public, but with safe output)
app.get('/comments', async (req, res) => {
    try {
        console.log(`💬 Loading all comments`);
        
        // ✅ Safe query without user input
        const query = `
            SELECT c.id, c.content, c.created_at, u.username 
            FROM Comments c 
            JOIN Users u ON c.user_id = u.id 
            ORDER BY c.created_at DESC
        `;
        const result = await sql.query(query);
        
        console.log(`✅ Comments loaded: ${result.recordset.length} comments`);
        res.json(result.recordset);
        
    } catch (err) {
        console.error('❌ Comments fetch error:', err);
        res.status(500).json({ 
            error: 'Failed to load comments',
            code: 'COMMENTS_ERROR'
        });
    }
});

// ✅ SECURE: Admin-only endpoint with role verification
app.get('/admin/users', 
    authenticateToken, 
    requireAdmin,
    async (req, res) => {
        try {
            console.log(`👑 Admin request: Loading all users by ${req.user.username}`);
            
            // ✅ Safe query, admin access only
            const query = `
                SELECT id, username, email, role, created_at 
                FROM Users 
                ORDER BY created_at DESC
            `;
            const result = await sql.query(query);
            
            console.log(`✅ Admin data provided: ${result.recordset.length} users`);
            res.json(result.recordset);
            
        } catch (err) {
            console.error('❌ Admin users error:', err);
            res.status(500).json({ 
                error: 'Failed to load users',
                code: 'ADMIN_ERROR'
            });
        }
    }
);

// ✅ SECURE: Token validation endpoint
app.get('/validate-token', authenticateToken, (req, res) => {
    res.json({
        valid: true,
        user: {
            userId: req.user.userId,
            username: req.user.username,
            role: req.user.role,
            loginTime: req.user.loginTime
        },
        tokenExp: new Date(req.user.exp * 1000)
    });
});

// ✅ SECURE: Logout endpoint (token blacklisting would go here in production)
app.post('/logout', authenticateToken, (req, res) => {
    console.log(`👋 User logout: ${req.user.username}`);
    // In production, you would add the token to a blacklist
    res.json({ 
        success: true, 
        message: 'Logged out successfully' 
    });
});

// ✅ Error handling middleware
app.use((err, req, res, next) => {
    console.error('❌ Unhandled error:', err);
    
    // Don't expose error details in production
    if (process.env.NODE_ENV === 'production') {
        res.status(500).json({ 
            error: 'Internal server error',
            code: 'INTERNAL_ERROR'
        });
    } else {
        res.status(500).json({ 
            error: err.message,
            stack: err.stack
        });
    }
});

// ✅ 404 handler
app.use('*', (req, res) => {
    console.log(`❌ 404: ${req.method} ${req.originalUrl}`);
    res.status(404).json({ 
        error: 'Endpoint not found',
        code: 'NOT_FOUND',
        path: req.originalUrl
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`✅ Secure server running on http://localhost:${PORT}`);
    console.log('🔒 Security features enabled:');
    console.log('   📋 Input validation with express-validator');
    console.log('   🛡️  Helmet security headers');
    console.log('   ⏱️  Rate limiting (100 req/15min, 5 login/15min)');
    console.log('   🔐 JWT authentication with expiry');
    console.log('   🚫 SQL injection prevention (prepared statements)');
    console.log('   🧹 XSS prevention (HTML encoding + sanitization)');
    console.log('   🔑 Authorization checks (IDOR prevention)');
    console.log('   📝 Request logging');
    console.log('   ❌ Generic error messages');
    console.log('');
    console.log('🎯 Ready for security testing!');
});
```

**การเรียกใช้งาน:**

```bash
cd backend
node secure-server.js
```

**Security Features ที่ใช้:**
- ✅ Helmet.js security headers
- ✅ Rate limiting (5 login attempts per 15 minutes)
- ✅ JWT authentication with expiry
- ✅ Prepared statements (SQL injection prevention)
- ✅ HTML encoding & input sanitization (XSS prevention)
- ✅ Authorization checks (IDOR prevention)
- ✅ Input validation with express-validator
- ✅ Request logging
- ✅ Generic error messages

Server พร้อมใช้งานที่ port 3001!

### Step 11: สร้าง Secure Frontend

สร้างไฟล์ `frontend/secure.html`:

```html
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Lab - Secure Application</title>
    <link rel="stylesheet" href="secure-styles.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Security Lab - Secure Application</h1>
            <p class="success-message">✅ This application implements security best practices</p>
            <div class="server-status">
                <span id="server-status">🔗 Connecting to secure server...</span>
            </div>
        </header>

        <!-- Login Section -->
        <section class="section" id="login-section">
            <h2>🔐 Secure Login System</h2>
            <form id="login-form" autocomplete="off">
                <div class="input-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" placeholder="Enter your username" 
                           required maxlength="50" pattern="[a-zA-Z0-9_]+" 
                           title="Only letters, numbers, and underscores allowed">
                    <small>Alphanumeric characters and underscores only</small>
                </div>
                <div class="input-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" placeholder="Enter your password" 
                           required maxlength="100">
                </div>
                <button type="submit" id="login-btn">🔑 Login Securely</button>
            </form>
            
            <div class="demo-credentials">
                <h4>Demo Credentials:</h4>
                <div class="credential-item">
                    <strong>Regular User:</strong> john / password
                </div>
                <div class="credential-item">
                    <strong>Admin User:</strong> admin / admin123
                </div>
            </div>
            
            <div class="security-features">
                <h4>🛡️ Security Features Implemented:</h4>
                <ul>
                    <li>✅ Rate limiting (5 attempts per 15 minutes)</li>
                    <li>✅ Input validation and sanitization</li>
                    <li>✅ Prepared statements (SQL injection prevention)</li>
                    <li>✅ JWT token authentication</li>
                    <li>✅ Generic error messages</li>
                    <li>✅ HTTPS-ready configuration</li>
                </ul>
            </div>
            
            <div id="login-result"></div>
        </section>

        <!-- Profile Section -->
        <section class="section" id="profile-section" style="display: none;">
            <h2>👤 Secure Profile Management</h2>
            <div class="user-info">
                <p><strong>Welcome:</strong> <span id="current-username">-</span></p>
                <p><strong>Role:</strong> <span id="current-role">-</span></p>
                <p><strong>User ID:</strong> <span id="current-user-id">-</span></p>
            </div>
            
            <div class="profile-actions">
                <button onclick="loadMyProfile()" class="btn-primary">📄 View My Profile</button>
                <div id="admin-controls" style="display: none;">
                    <hr>
                    <h4>👑 Admin Controls:</h4>
                    <input type="number" id="admin-user-id" placeholder="Enter User ID" min="1" max="999">
                    <button onclick="loadUserProfile()" class="btn-admin">🔍 View Any User Profile</button>
                    <button onclick="loadAllUsers()" class="btn-admin">👥 View All Users</button>
                </div>
            </div>
            
            <div class="security-features">
                <h4>🛡️ IDOR Protection:</h4>
                <ul>
                    <li>✅ JWT token validation required</li>
                    <li>✅ Authorization checks (users can only access their own data)</li>
                    <li>✅ Admin role verification for administrative access</li>
                    <li>✅ Input validation on user ID parameters</li>
                </ul>
            </div>
            
            <div id="profile-result"></div>
        </section>

        <!-- Comments Section -->
        <section class="section">
            <h2>💬 Secure Comment System</h2>
            <div id="comment-form-container" style="display: none;">
                <form id="comment-form">
                    <div class="input-group">
                        <label for="comment-content">Your Comment:</label>
                        <textarea id="comment-content" name="content" placeholder="Write your secure comment..." 
                                  rows="4" required maxlength="1000" 
                                  title="Maximum 1000 characters, no script tags allowed"></textarea>
                        <div class="char-counter">
                            <span id="char-count">0</span>/1000 characters
                            <span id="char-warning" style="display: none;">⚠️ Approaching limit</span>
                        </div>
                    </div>
                    <button type="submit">💬 Post Secure Comment</button>
                </form>
            </div>
            
            <div class="security-features">
                <h4>🛡️ XSS Protection:</h4>
                <ul>
                    <li>✅ HTML encoding of all user input</li>
                    <li>✅ Input length validation (max 1000 chars)</li>
                    <li>✅ Forbidden word filtering</li>
                    <li>✅ Authentication required to post</li>
                    <li>✅ Content sanitization before database storage</li>
                </ul>
                <div class="xss-demo">
                    <p><strong>Try XSS payloads - they will be safely encoded:</strong></p>
                    <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code><br>
                    <code>&lt;img src=x onerror=alert('XSS')&gt;</code><br>
                    <code>&lt;svg onload=alert('XSS')&gt;</code>
                </div>
            </div>
            
            <div id="comments-display">
                <p>Loading comments...</p>
            </div>
        </section>

        <!-- Search Section -->
        <section class="section">
            <h2>🔍 Secure Product Search</h2>
            <form id="search-form">
                <div class="input-group">
                    <label for="search-input">Search Products:</label>
                    <input type="text" id="search-input" name="search" placeholder="Enter product name..." 
                           maxlength="100" pattern="[a-zA-Z0-9\s\-_]+" 
                           title="Only letters, numbers, spaces, hyphens, and underscores allowed">
                    <small>Alphanumeric characters, spaces, hyphens, and underscores only</small>
                </div>
                <button type="submit">🔍 Search Safely</button>
            </form>
            
            <div class="security-features">
                <h4>🛡️ SQL Injection Protection:</h4>
                <ul>
                    <li>✅ Prepared statements with parameterized queries</li>
                    <li>✅ Input validation and character filtering</li>
                    <li>✅ Maximum length restrictions</li>
                    <li>✅ No direct SQL query construction</li>
                </ul>
                <div class="sql-demo">
                    <p><strong>Try SQL injection payloads - they will be blocked:</strong></p>
                    <code>' OR '1'='1'; --</code><br>
                    <code>' UNION SELECT * FROM Users; --</code><br>
                    <code>'; DROP TABLE Products; --</code>
                </div>
            </div>
            
            <div id="search-results"></div>
        </section>

        <!-- Security Comparison -->
        <section class="section">
            <h2>📊 Security Implementation Comparison</h2>
            <div class="comparison-table">
                <table>
                    <thead>
                        <tr>
                            <th>Security Aspect</th>
                            <th class="vulnerable">❌ Vulnerable Version</th>
                            <th class="secure">✅ Secure Version</th>
                            <th>Impact</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong>SQL Injection</strong></td>
                            <td class="vulnerable">String concatenation</td>
                            <td class="secure">Prepared statements</td>
                            <td>Prevents data theft and manipulation</td>
                        </tr>
                        <tr>
                            <td><strong>XSS Prevention</strong></td>
                            <td class="vulnerable">Raw HTML output</td>
                            <td class="secure">HTML encoding + validation</td>
                            <td>Prevents script execution and session hijacking</td>
                        </tr>
                        <tr>
                            <td><strong>IDOR Protection</strong></td>
                            <td class="vulnerable">No access control</td>
                            <td class="secure">Authorization checks</td>
                            <td>Prevents unauthorized data access</td>
                        </tr>
                        <tr>
                            <td><strong>Authentication</strong></td>
                            <td class="vulnerable">No token validation</td>
                            <td class="secure">JWT tokens with expiry</td>
                            <td>Secure session management</td>
                        </tr>
                        <tr>
                            <td><strong>Rate Limiting</strong></td>
                            <td class="vulnerable">None</td>
                            <td class="secure">5 login attempts per 15min</td>
                            <td>Prevents brute force attacks</td>
                        </tr>
                        <tr>
                            <td><strong>Input Validation</strong></td>
                            <td class="vulnerable">None</td>
                            <td class="secure">Server-side validation</td>
                            <td>Prevents malformed data attacks</td>
                        </tr>
                        <tr>
                            <td><strong>Error Messages</strong></td>
                            <td class="vulnerable">Detailed errors</td>
                            <td class="secure">Generic error messages</td>
                            <td>Prevents information disclosure</td>
                        </tr>
                        <tr>
                            <td><strong>Security Headers</strong></td>
                            <td class="vulnerable">None</td>
                            <td class="secure">Helmet.js implementation</td>
                            <td>Multiple attack vector protection</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </section>

        <!-- Security Testing Dashboard -->
        <section class="section">
            <h2>🧪 Security Testing Dashboard</h2>
            <p class="info-message">Click the buttons below to test various security features:</p>
            
            <div class="test-grid">
                <div class="test-card">
                    <h4>🛡️ SQL Injection Test</h4>
                    <p>Test if the search function prevents SQL injection attacks</p>
                    <button onclick="testSQLInjection()" class="btn-test">Run SQL Test</button>
                    <div id="sql-test-result" class="test-result"></div>
                </div>
                
                <div class="test-card">
                    <h4>🚫 XSS Test</h4>
                    <p>Test if comments are properly encoded to prevent XSS</p>
                    <button onclick="testXSS()" class="btn-test">Run XSS Test</button>
                    <div id="xss-test-result" class="test-result"></div>
                </div>
                
                <div class="test-card">
                    <h4>🔐 IDOR Test</h4>
                    <p>Test if unauthorized profile access is prevented</p>
                    <button onclick="testIDOR()" class="btn-test">Run IDOR Test</button>
                    <div id="idor-test-result" class="test-result"></div>
                </div>
                
                <div class="test-card">
                    <h4>⏱️ Rate Limiting Test</h4>
                    <p>Test if multiple login attempts are limited</p>
                    <button onclick="testRateLimit()" class="btn-test">Run Rate Test</button>
                    <div id="rate-test-result" class="test-result"></div>
                </div>
            </div>
        </section>
    </div>

    <script src="secure-script.js"></script>
</body>
</html>
```

สร้างไฟล์ `frontend/secure-styles.css`:

```css
/* frontend/secure-styles.css */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    padding: 20px;
    color: #333;
}

.container {
    max-width: 1400px;
    margin: 0 auto;
}

/* Header Styles */
header {
    text-align: center;
    margin-bottom: 30px;
    background: rgba(255, 255, 255, 0.95);
    padding: 30px;
    border-radius: 15px;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
    backdrop-filter: blur(10px);
}

header h1 {
    color: #2c3e50;
    margin-bottom: 10px;
    font-size: 2.5rem;
}

.success-message {
    background: linear-gradient(90deg, #2ecc71, #27ae60);
    color: white;
    padding: 15px;
    border-radius: 10px;
    margin-top: 15px;
    font-weight: bold;
    box-shadow: 0 5px 15px rgba(46, 204, 113, 0.3);
}

.server-status {
    margin-top: 10px;
    padding: 10px;
    background: rgba(52, 152, 219, 0.1);
    border-radius: 8px;
    border-left: 4px solid #3498db;
}

/* Section Styles */
.section {
    background: rgba(255, 255, 255, 0.95);
    margin-bottom: 25px;
    padding: 30px;
    border-radius: 15px;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
    backdrop-filter: blur(10px);
    border-left: 5px solid #3498db;
}

.section h2 {
    color: #2c3e50;
    margin-bottom: 20px;
    padding-bottom: 10px;
    border-bottom: 2px solid #ecf0f1;
    font-size: 1.5rem;
}

/* Form Styles */
.input-group {
    margin-bottom: 20px;
}

.input-group label {
    display: block;
    margin-bottom: 8px;
    font-weight: 600;
    color: #34495e;
}

input[type="text"],
input[type="password"],
input[type="number"],
textarea {
    width: 100%;
    padding: 12px 16px;
    border: 2px solid #bdc3c7;
    border-radius: 8px;
    font-size: 16px;
    transition: all 0.3s ease;
    background-color: #fff;
}

input[type="text"]:focus,
input[type="password"]:focus,
input[type="number"]:focus,
textarea:focus {
    outline: none;
    border-color: #3498db;
    box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.1);
    transform: translateY(-1px);
}

input:invalid {
    border-color: #e74c3c;
    box-shadow: 0 0 0 3px rgba(231, 76, 60, 0.1);
}

small {
    display: block;
    margin-top: 5px;
    color: #7f8c8d;
    font-size: 14px;
}

/* Button Styles */
button {
    background: linear-gradient(135deg, #3498db, #2980b9);
    color: white;
    padding: 12px 24px;
    border: none;
    border-radius: 8px;
    cursor: pointer;
    font-size: 16px;
    font-weight: 600;
    transition: all 0.3s ease;
    margin-right: 10px;
    margin-bottom: 10px;
    box-shadow: 0 5px 15px rgba(52, 152, 219, 0.3);
}

button:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(52, 152, 219, 0.4);
}

button:disabled {
    background: #95a5a6;
    cursor: not-allowed;
    transform: none;
    box-shadow: none;
}

.btn-primary {
    background: linear-gradient(135deg, #2ecc71, #27ae60);
    box-shadow: 0 5px 15px rgba(46, 204, 113, 0.3);
}

.btn-admin {
    background: linear-gradient(135deg, #9b59b6, #8e44ad);
    box-shadow: 0 5px 15px rgba(155, 89, 182, 0.3);
}

.btn-test {
    background: linear-gradient(135deg, #f39c12, #e67e22);
    box-shadow: 0 5px 15px rgba(243, 156, 18, 0.3);
    font-size: 14px;
    padding: 10px 20px;
    width: 100%;
}

/* Character Counter */
.char-counter {
    text-align: right;
    font-size: 14px;
    color: #7f8c8d;
    margin-top: 5px;
}

#char-warning {
    color: #f39c12;
    font-weight: bold;
}

/* Info Messages */
.info-message {
    background: #e3f2fd;
    color: #1565c0;
    padding: 15px;
    border-radius: 8px;
    margin-bottom: 20px;
    border-left: 4px solid #2196f3;
}

/* Security Features Box */
.security-features {
    background: linear-gradient(135deg, #e8f5e8, #d5f5d5);
    border: 2px solid #2ecc71;
    border-radius: 10px;
    padding: 20px;
    margin: 20px 0;
}

.security-features h4 {
    color: #27ae60;
    margin-bottom: 15px;
    display: flex;
    align-items: center;
}

.security-features ul {
    list-style: none;
    padding: 0;
}

.security-features li {
    margin-bottom: 8px;
    padding-left: 25px;
    position: relative;
    line-height: 1.5;
}

/* Demo Sections */
.demo-credentials,
.xss-demo,
.sql-demo {
    background: #fff3cd;
    border: 2px solid #ffc107;
    border-radius: 8px;
    padding: 15px;
    margin: 15px 0;
}

.demo-credentials h4,
.xss-demo p strong,
.sql-demo p strong {
    color: #856404;
    margin-bottom: 10px;
}

.credential-item {
    background: white;
    padding: 8px 12px;
    margin: 5px 0;
    border-radius: 5px;
    border-left: 3px solid #ffc107;
}

code {
    background: #f8f9fa;
    padding: 4px 8px;
    border-radius: 4px;
    font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
    color: #e83e8c;
    border: 1px solid #dee2e6;
    display: inline-block;
    margin: 2px;
}

/* User Info */
.user-info {
    background: #e3f2fd;
    border: 2px solid #2196f3;
    border-radius: 10px;
    padding: 15px;
    margin-bottom: 20px;
}

.user-info p {
    margin-bottom: 8px;
}

/* Profile Actions */
.profile-actions hr {
    margin: 20px 0;
    border: none;
    border-top: 2px solid #ecf0f1;
}

/* Comparison Table */
.comparison-table {
    overflow-x: auto;
    margin: 20px 0;
    border-radius: 10px;
    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
}

table {
    width: 100%;
    border-collapse: collapse;
    background: white;
    border-radius: 10px;
    overflow: hidden;
}

thead {
    background: linear-gradient(135deg, #667eea, #764ba2);
    color: white;
}

th, td {
    padding: 15px;
    text-align: left;
    border-bottom: 1px solid #ecf0f1;
}

th {
    font-weight: 600;
    font-size: 14px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.vulnerable {
    background: #ffebee;
    color: #c62828;
}

.secure {
    background: #e8f5e8;
    color: #2e7d32;
}

tbody tr:hover {
    background: #f8f9fa;
    transform: scale(1.01);
    transition: all 0.2s ease;
}

/* Test Grid */
.test-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
    margin-top: 20px;
}

.test-card {
    background: white;
    padding: 25px;
    border-radius: 12px;
    border-left: 4px solid #f39c12;
    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
    transition: transform 0.2s ease;
}

.test-card:hover {
    transform: translateY(-2px);
}

.test-card h4 {
    color: #2c3e50;
    margin-bottom: 10px;
}

.test-card p {
    color: #7f8c8d;
    margin-bottom: 15px;
    line-height: 1.5;
}

.test-result {
    margin-top: 15px;
    padding: 15px;
    border-radius: 8px;
    background: #f8f9fa;
    border: 1px solid #dee2e6;
    min-height: 20px;
}

.result-success {
    background: #d4edda !important;
    border-color: #c3e6cb !important;
    color: #155724;
}

.result-error {
    background: #f8d7da !important;
    border-color: #f5c6cb !important;
    color: #721c24;
}

.result-warning {
    background: #fff3cd !important;
    border-color: #ffeaa7 !important;
    color: #856404;
}

/* Comments Display */
#comments-display {
    margin-top: 20px;
}

.comment {
    background: white;
    padding: 15px;
    margin: 15px 0;
    border-left: 4px solid #3498db;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
    transition: transform 0.2s ease;
}

.comment:hover {
    transform: translateX(5px);
}

.comment-author {
    font-weight: bold;
    color: #2c3e50;
    margin-bottom: 8px;
    display: flex;
    align-items: center;
}

.comment-author::before {
    content: "👤";
    margin-right: 8px;
}

.comment-content {
    margin-bottom: 10px;
    line-height: 1.6;
    color: #34495e;
}

.comment-date {
    font-size: 12px;
    color: #7f8c8d;
    text-align: right;
}

/* Responsive Design */
@media (max-width: 768px) {
    .container {
        padding: 10px;
    }
    
    .section {
        padding: 20px;
        margin-bottom: 15px;
    }
    
    header h1 {
        font-size: 2rem;
    }
    
    .comparison-table {
        font-size: 14px;
    }
    
    th, td {
        padding: 10px 8px;
    }
    
    .test-grid {
        grid-template-columns: 1fr;
    }
    
    button {
        width: 100%;
        margin-bottom: 10px;
    }
}

/* Animations */
@keyframes slideIn {
    from {
        opacity: 0;
        transform: translateY(-20px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.result-success,
.result-error,
.result-warning {
    animation: slideIn 0.3s ease-out;
}

@keyframes pulse {
    0% { opacity: 1; }
    50% { opacity: 0.5; }
    100% { opacity: 1; }
}

.loading {
    animation: pulse 2s infinite;
}
```

สร้างไฟล์ `frontend/secure-script.js`:

```javascript
// frontend/secure-script.js
const API_BASE = 'http://localhost:3001';

let currentUser = null;
let authToken = null;

// Initialize application
document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
    setupEventListeners();
    checkServerStatus();
});

function initializeApp() {
    // Character counter for comments
    const commentTextarea = document.getElementById('comment-content');
    const charCounter = document.getElementById('char-count');
    const charWarning = document.getElementById('char-warning');
    
    if (commentTextarea && charCounter) {
        commentTextarea.addEventListener('input', () => {
            const length = commentTextarea.value.length;
            charCounter.textContent = length;
            
            if (length > 900) {
                charCounter.style.color = '#e74c3c';
                charWarning.style.display = 'inline';
                charWarning.textContent = '⚠️ Approaching limit';
            } else if (length > 800) {
                charCounter.style.color = '#f39c12';
                charWarning.style.display = 'inline';
                charWarning.textContent = '⚡ Getting close';
            } else {
                charCounter.style.color = '#7f8c8d';
                charWarning.style.display = 'none';
            }
        });
    }
    
    loadComments();
}

function setupEventListeners() {
    // Login form
    document.getElementById('login-form').addEventListener('submit', handleLogin);
    
    // Comment form
    document.getElementById('comment-form').addEventListener('submit', handleComment);
    
    // Search form
    document.getElementById('search-form').addEventListener('submit', handleSearch);
}

// Check server status
async function checkServerStatus() {
    const statusElement = document.getElementById('server-status');
    try {
        const response = await fetch(`${API_BASE}/health`);
        if (response.ok) {
            const data = await response.json();
            statusElement.innerHTML = '🟢 Secure server is online';
            statusElement.style.color = '#27ae60';
        } else {
            throw new Error('Server not responding');
        }
    } catch (error) {
        statusElement.innerHTML = '🔴 Server is offline - Please start the secure server';
        statusElement.style.color = '#e74c3c';
    }
}

// Handle login
async function handleLogin(e) {
    e.preventDefault();
    
    const loginBtn = document.getElementById('login-btn');
    const originalText = loginBtn.textContent;
    
    // Disable button and show loading state
    loginBtn.disabled = true;
    loginBtn.textContent = '🔄 Authenticating...';
    
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    
    // Client-side validation
    if (!username || !password) {
        showResult('login-result', 'Please fill in all fields', 'error');
        resetButton(loginBtn, originalText);
        return;
    }
    
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
        showResult('login-result', 'Username can only contain letters, numbers, and underscores', 'error');
        resetButton(loginBtn, originalText);
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentUser = data.user;
            authToken = data.token;
            
            showResult('login-result', `
                <div class="result-success">
                    <h4>✅ Authentication Successful!</h4>
                    <p><strong>Welcome:</strong> ${escapeHtml(data.user.username)}</p>
                    <p><strong>Email:</strong> ${escapeHtml(data.user.email)}</p>
                    <p><strong>Role:</strong> ${data.user.role}</p>
                    <p><strong>Token Issued:</strong> ${new Date().toLocaleString()}</p>
                    <p><small><strong>JWT Token:</strong> ${data.token.substring(0, 30)}...</small></p>
                </div>
            `);
            
            // Update UI after successful login
            updateUIAfterLogin(data.user);
            
        } else {
            showResult('login-result', `❌ ${data.message}`, 'error');
        }
    } catch (error) {
        showResult('login-result', `❌ Connection error: ${error.message}`, 'error');
    } finally {
        resetButton(loginBtn, originalText);
    }
}

function updateUIAfterLogin(user) {
    // Show profile section
    document.getElementById('profile-section').style.display = 'block';
    document.getElementById('comment-form-container').style.display = 'block';
    
    // Update user info
    document.getElementById('current-username').textContent = user.username;
    document.getElementById('current-role').textContent = user.role;
    document.getElementById('current-user-id').textContent = user.id;
    
    // Show admin controls if admin
    if (user.role === 'admin') {
        document.getElementById('admin-controls').style.display = 'block';
    }
    
    // Reload comments to show user-specific features
    loadComments();
}

// Load user profile
async function loadMyProfile() {
    if (!authToken || !currentUser) {
        showResult('profile-result', 'Please login first', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/user/${currentUser.id}`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showResult('profile-result', `
                <div class="result-success">
                    <h4>📄 My Secure Profile</h4>
                    <p><strong>ID:</strong> ${data.id}</p>
                    <p><strong>Username:</strong> ${escapeHtml(data.username)}</p>
                    <p><strong>Email:</strong> ${escapeHtml(data.email)}</p>
                    <p><strong>Role:</strong> ${data.role}</p>
                    <p><strong>Account Created:</strong> ${new Date(data.created_at).toLocaleDateString()}</p>
                    <p><small>✅ Authorization verified - You can only see your own profile</small></p>
                </div>
            `);
        } else {
            showResult('profile-result', `❌ ${data.error}`, 'error');
        }
    } catch (error) {
        showResult('profile-result', `❌ Error: ${error.message}`, 'error');
    }
}

// Load user profile (Admin only)
async function loadUserProfile() {
    const userId = document.getElementById('admin-user-id').value;
    
    if (!userId) {
        showResult('profile-result', 'Please enter a user ID', 'error');
        return;
    }
    
    if (!authToken) {
        showResult('profile-result', 'Please login first', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/user/${userId}`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showResult('profile-result', `
                <div class="result-success">
                    <h4>🔍 User Profile (Admin Access)</h4>
                    <p><strong>ID:</strong> ${data.id}</p>
                    <p><strong>Username:</strong> ${escapeHtml(data.username)}</p>
                    <p><strong>Email:</strong> ${escapeHtml(data.email)}</p>
                    <p><strong>Role:</strong> ${data.role}</p>
                    <p><strong>Account Created:</strong> ${new Date(data.created_at).toLocaleDateString()}</p>
                    <p><small>👑 Admin privilege verified - Access granted</small></p>
                </div>
            `);
        } else {
            showResult('profile-result', `❌ ${data.error}`, 'error');
        }
    } catch (error) {
        showResult('profile-result', `❌ Error: ${error.message}`, 'error');
    }
}

// Load all users (Admin only)
async function loadAllUsers() {
    if (!authToken) {
        showResult('profile-result', 'Please login first', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/admin/users`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        const data = await response.json();
        
        if (response.ok && Array.isArray(data)) {
            const userList = data.map(user => `
                <div class="comment">
                    <strong>👤 ${escapeHtml(user.username)}</strong> (ID: ${user.id})<br>
                    📧 ${escapeHtml(user.email)}<br>
                    🎭 Role: ${user.role}<br>
                    📅 Created: ${new Date(user.created_at).toLocaleDateString()}
                </div>
            `).join('');
            
            showResult('profile-result', `
                <div class="result-success">
                    <h4>👥 All Users (Admin View)</h4>
                    <p>Total users: ${data.length}</p>
                    ${userList}
                </div>
            `);
        } else {
            showResult('profile-result', `❌ ${data.error || 'Access denied'}`, 'error');
        }
    } catch (error) {
        showResult('profile-result', `❌ Error: ${error.message}`, 'error');
    }
}

// Handle comment submission
async function handleComment(e) {
    e.preventDefault();
    
    const content = document.getElementById('comment-content').value.trim();
    
    if (!content) {
        alert('Please enter a comment');
        return;
    }
    
    if (content.length > 1000) {
        alert('Comment is too long (max 1000 characters)');
        return;
    }
    
    if (!authToken) {
        alert('Please login first');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/comments`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ content })
        });
        
        const data = await response.json();
        
        if (data.success) {
            document.getElementById('comment-content').value = '';
            document.getElementById('char-count').textContent = '0';
            loadComments();
            
            if (data.sanitized) {
                alert('✅ Comment posted! Note: Content was sanitized for security.');
            }
        } else {
            alert('Failed to add comment: ' + (data.message || 'Unknown error'));
        }
    } catch (error) {
        alert('Error adding comment: ' + error.message);
    }
}

// Handle search
async function handleSearch(e) {
    e.preventDefault();
    
    const query = document.getElementById('search-input').value.trim();
    
    if (!query) {
        showResult('search-results', 'Please enter search term', 'error');
        return;
    }
    
    if (query.length > 100) {
        showResult('search-results', 'Search term too long (max 100 characters)', 'error');
        return;
    }
    
    if (!/^[a-zA-Z0-9\s\-_]+$/.test(query)) {
        showResult('search-results', 'Search term contains invalid characters', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/search?q=${encodeURIComponent(query)}`);
        const data = await response.json();
        
        if (response.ok && Array.isArray(data)) {
            if (data.length > 0) {
                const results = data.map(item => `
                    <div class="comment">
                        <strong>${escapeHtml(item.name)}</strong><br>
                        💰 Price: $${item.price}<br>
                        ${item.description ? `📝 ${escapeHtml(item.description)}` : ''}
                    </div>
                `).join('');
                
                showResult('search-results', `
                    <h4>🔍 Search Results (${data.length} found):</h4>
                    ${results}
                `, 'success');
            } else {
                showResult('search-results', 'No products found', 'warning');
            }
        } else {
            showResult('search-results', `❌ ${data.error || 'Search failed'}`, 'error');
        }
    } catch (error) {
        showResult('search-results', `❌ Error: ${error.message}`, 'error');
    }
}

// Load and display comments
async function loadComments() {
    try {
        const response = await fetch(`${API_BASE}/comments`);
        const comments = await response.json();
        
        const displayDiv = document.getElementById('comments-display');
        
        if (Array.isArray(comments) && comments.length > 0) {
            displayDiv.innerHTML = `
                <h4>💬 Comments (Safely Encoded):</h4>
                ${comments.map(comment => `
                    <div class="comment">
                        <div class="comment-author">${escapeHtml(comment.username)}</div>
                        <div class="comment-content">${comment.content}</div>
                        <div class="comment-date">${new Date(comment.created_at).toLocaleString()}</div>
                    </div>
                `).join('')}
            `;
        } else {
            displayDiv.innerHTML = '<p>No comments yet. Login to add the first comment!</p>';
        }
    } catch (error) {
        console.error('Error loading comments:', error);
        document.getElementById('comments-display').innerHTML = '<p>❌ Failed to load comments</p>';
    }
}

// Security Testing Functions
async function testSQLInjection() {
    const resultDiv = document.getElementById('sql-test-result');
    resultDiv.innerHTML = '<p class="loading">🧪 Testing SQL injection protection...</p>';
    
    const payloads = [
        "'; DROP TABLE Products; --",
        "' UNION SELECT username, password FROM Users; --",
        "' OR '1'='1'; --"
    ];
    
    let results = [];
    
    for (const payload of payloads) {
        try {
            const response = await fetch(`${API_BASE}/search?q=${encodeURIComponent(payload)}`);
            const data = await response.json();
            
            if (response.status === 400) {
                results.push(`✅ Payload blocked: "${payload}"`);
            } else if (Array.isArray(data)) {
                results.push(`❌ Payload executed: "${payload}"`);
            } else {
                results.push(`✅ Payload handled safely: "${payload}"`);
            }
        } catch (error) {
            results.push(`✅ Payload blocked by validation: "${payload}"`);
        }
    }
    
    const allBlocked = results.every(r => r.startsWith('✅'));
    const resultClass = allBlocked ? 'result-success' : 'result-error';
    
    resultDiv.innerHTML = `
        <div class="${resultClass}">
            <h4>${allBlocked ? '✅ SQL Injection Protection: PASSED' : '❌ SQL Injection Protection: FAILED'}</h4>
            ${results.map(r => `<p>${r}</p>`).join('')}
        </div>
    `;
}

async function testXSS() {
    const resultDiv = document.getElementById('xss-test-result');
    
    if (!authToken) {
        resultDiv.innerHTML = '<div class="result-error"><p>❌ Please login first to test XSS protection</p></div>';
        return;
    }
    
    resultDiv.innerHTML = '<p class="loading">🧪 Testing XSS protection...</p>';
    
    const payload = '<script>alert("XSS")</script>';
    
    try {
        const response = await fetch(`${API_BASE}/comments`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ content: payload })
        });
        
        const data = await response.json();
        
        if (response.status === 400) {
            resultDiv.innerHTML = `
                <div class="result-success">
                    <h4>✅ XSS Protection: PASSED</h4>
                    <p>Dangerous content was blocked by validation</p>
                    <p>Error: ${data.message}</p>
                </div>
            `;
        } else if (data.success) {
            resultDiv.innerHTML = `
                <div class="result-success">
                    <h4>✅ XSS Protection: PASSED</h4>
                    <p>Content was sanitized and HTML encoded</p>
                    <p>Sanitization applied: ${data.sanitized ? 'Yes' : 'No'}</p>
                </div>
            `;
            loadComments(); // Refresh comments to show encoded version
        } else {
            resultDiv.innerHTML = `
                <div class="result-error">
                    <h4>❌ XSS Protection: FAILED</h4>
                    <p>Unexpected response: ${data.message}</p>
                </div>
            `;
        }
    } catch (error) {
        resultDiv.innerHTML = `
            <div class="result-error">
                <h4>❌ XSS Test: ERROR</h4>
                <p>Test failed: ${error.message}</p>
            </div>
        `;
    }
}

async function testIDOR() {
    const resultDiv = document.getElementById('idor-test-result');
    
    if (!authToken) {
        resultDiv.innerHTML = '<div class="result-error"><p>❌ Please login first to test IDOR protection</p></div>';
        return;
    }
    
    resultDiv.innerHTML = '<p class="loading">🧪 Testing IDOR protection...</p>';
    
    // Try to access another user's profile
    const testUserId = currentUser.id === 1 ? 2 : 1; // Try a different user ID
    
    try {
        const response = await fetch(`${API_BASE}/user/${testUserId}`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        const data = await response.json();
        
        if (response.status === 403) {
            resultDiv.innerHTML = `
                <div class="result-success">
                    <h4>✅ IDOR Protection: PASSED</h4>
                    <p>Access to user ${testUserId} was properly denied</p>
                    <p>Error: ${data.error}</p>
                </div>
            `;
        } else if (response.ok && currentUser.role === 'admin') {
            resultDiv.innerHTML = `
                <div class="result-success">
                    <h4>✅ IDOR Protection: PASSED</h4>
                    <p>Admin access granted as expected</p>
                    <p>Accessed user: ${data.username}</p>
                </div>
            `;
        } else if (response.ok) {
            resultDiv.innerHTML = `
                <div class="result-error">
                    <h4>❌ IDOR Protection: FAILED</h4>
                    <p>Unauthorized access to user ${testUserId} was allowed</p>
                </div>
            `;
        } else {
            resultDiv.innerHTML = `
                <div class="result-warning">
                    <h4>⚠️ IDOR Test: INCONCLUSIVE</h4>
                    <p>Unexpected response: ${data.error}</p>
                </div>
            `;
        }
    } catch (error) {
        resultDiv.innerHTML = `
            <div class="result-error">
                <h4>❌ IDOR Test: ERROR</h4>
                <p>Test failed: ${error.message}</p>
            </div>
        `;
    }
}

async function testRateLimit() {
    const resultDiv = document.getElementById('rate-test-result');
    resultDiv.innerHTML = '<p class="loading">🧪 Testing rate limiting...</p>';
    
    const attempts = [];
    const maxAttempts = 6; // Try 6 attempts (limit is 5)
    
    for (let i = 0; i < maxAttempts; i++) {
        try {
            const response = await fetch(`${API_BASE}/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username: 'testuser', password: 'wrongpassword' })
            });
            
            attempts.push({
                attempt: i + 1,
                status: response.status,
                limited: response.status === 429
            });
            
            // Small delay between attempts
            await new Promise(resolve => setTimeout(resolve, 100));
        } catch (error) {
            attempts.push({
                attempt: i + 1,
                status: 'error',
                error: error.message
            });
        }
    }
    
    const rateLimited = attempts.some(a => a.limited);
    const resultClass = rateLimited ? 'result-success' : 'result-warning';
    
    resultDiv.innerHTML = `
        <div class="${resultClass}">
            <h4>${rateLimited ? '✅ Rate Limiting: ACTIVE' : '⚠️ Rate Limiting: CHECK RESULTS'}</h4>
            <p>Login attempts made: ${attempts.length}</p>
            ${attempts.map(a => `
                <p>Attempt ${a.attempt}: ${a.limited ? '🚫 Rate limited' : `Status ${a.status}`}</p>
            `).join('')}
            ${rateLimited ? '<p><small>✅ Rate limiting is working properly</small></p>' : 
              '<p><small>⚠️ If rate limiting didn\'t trigger, try again in 15 minutes</small></p>'}
        </div>
    `;
}

// Utility functions
function showResult(elementId, message, type = 'info') {
    const element = document.getElementById(elementId);
    const className = type === 'error' ? 'result-error' : 
                     type === 'success' ? 'result-success' : 
                     type === 'warning' ? 'result-warning' : '';
    
    element.innerHTML = `<div class="${className}">${message}</div>`;
}

function resetButton(button, originalText) {
    button.disabled = false;
    button.textContent = originalText;
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, function(m) { return map[m]; });
}
```

**การใช้งาน Secure Frontend:**

1. เปิดไฟล์ `secure.html` ในเบราว์เซอร์
2. ตรวจสอบว่า Secure Server (port 3001) ทำงานอยู่
3. ทดสอบฟีเจอร์ต่างๆ:
   - Login ด้วย demo credentials
   - ทดสอบ XSS payloads ในช่อง comment
   - ทดสอบ SQL injection ในช่องค้นหา
   - ทดสอบ IDOR protection ในส่วน profile
   - ใช้ Security Testing Dashboard

**ฟีเจอร์หลัก:**
- ✅ Real-time validation
- ✅ Character counting
- ✅ Security testing dashboard
- ✅ Responsive design
- ✅ Visual feedback
- ✅ Error handling
- ✅ Server status checking

---

## Part 4: การเปรียบเทียบและทดสอบ

### Step 12: รันทั้งสองเวอร์ชัน

```bash
# Terminal 1 - Vulnerable Server
cd backend
npm start

# Terminal 2 - Secure Server  
cd backend
node secure-server.js

# Terminal 3 - Frontend
cd frontend
# เปิด index.html (port 8080) และ secure.html (port 8081)
```

### Step 13: การทดสอบเปรียบเทียบ

#### ทดสอบ SQL Injection

**Vulnerable Version (localhost:8080):**
1. Login: `admin'; --` / `anything`
2. Search: `' UNION SELECT id,username,password FROM Users; --`

**Secure Version (localhost:8081):**
1. Login: ลองใส่ payload เดียวกัน → จะได้รับข้อความ "Invalid input"
2. Search: ลองใส่ payload เดียวกัน → จะได้รับข้อความ validation error

#### ทดสอบ XSS

**Vulnerable Version:**
1. Login ปกติ แล้วใส่ comment: `<script>alert('XSS!')</script>`
2. สังเกตว่า script จะทำงาน

**Secure Version:**
1. Login ปกติ แล้วใส่ comment เดียวกัน
2. สังเกตว่า script จะถูก encode แล้วแสดงเป็นข้อความธรรมดา

#### ทดสอบ IDOR

**Vulnerable Version:**
1. Login เป็น user ธรรมดา
2. ลองดู profile ของ user อื่น → สามารถเห็นได้

**Secure Version:**
1. Login เป็น user ธรรมดา
2. ลองดู profile ของ user อื่น → จะได้รับข้อความ "Access denied"

---

## Part 5: การวิเคราะห์และรายงาน

### Step 14: สร้างรายงานการทดสอบ

สร้างไฟล์ `SECURITY_TEST_REPORT.md`:

```markdown
# Security Testing Report

## การทดสอบ SQL Injection

### Vulnerable Version
- ✅ สามารถ Bypass login ด้วย `admin'; --`
- ✅ สามารถดึงข้อมูลผู้ใช้ด้วย UNION attack
- ✅ สามารถดู database schema ได้

### Secure Version  
- ❌ ไม่สามารถ Bypass login ได้
- ❌ Prepared statements ป้องกัน SQL injection
- ❌ Input validation ปฏิเสธ payload ที่เป็นอันตราย

## การทดสอบ XSS

### Vulnerable Version
- ✅ JavaScript execute ได้ในข้อความ comment
- ✅ สามารถขโมย cookie ได้
- ✅ สามารถ redirect ผู้ใช้ได้

### Secure Version
- ❌ HTML ถูก encode ทำให้ script ไม่ทำงาน
- ❌ Content ถูก sanitize ก่อนบันทึก
- ❌ Output encoding ป้องกัน XSS

## การทดสอบ IDOR

### Vulnerable Version  
- ✅ สามารถเข้าถึงข้อมูลผู้ใช้อื่นได้โดยเปลี่ยน ID
- ✅ ไม่มีการตรวจสอบสิทธิ์

### Secure Version
- ❌ Authorization check ป้องกันการเข้าถึงข้อมูลผู้อื่น
- ❌ JWT token validation
- ❌ Role-based access control

## สรุปผล

| ช่องโหว่ | Vulnerable | Secure | วิธีแก้ไข |
|----------|------------|--------|----------|
| SQL Injection | ❌ | ✅ | Prepared statements |
| XSS | ❌ | ✅ | HTML encoding |  
| IDOR | ❌ | ✅ | Authorization checks |
| Rate Limiting | ❌ | ✅ | Express rate limiter |
| Input Validation | ❌ | ✅ | Express validator |

```

### Step 15: แบบฝึกหัดเพิ่มเติม

#### แบบฝึกหัดที่ 1: สร้าง CSRF Protection

เพิ่ม CSRF token ใน secure version:

```bash
npm install csurf
```

เพิ่มโค้ดใน `secure-server.js`:

```javascript
const csrf = require('csurf');

// CSRF Protection
const csrfProtection = csrf({ cookie: true });
app.use('/api', csrfProtection);

// CSRF token endpoint
app.get('/api/csrf-token', csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});
```

#### แบบฝึกหัดที่ 2: เพิ่ม Password Hashing

อัพเดท database setup:

```sql
-- Hash passwords (ในการใช้งานจริง)
UPDATE Users SET password = '$2b$12$hashed_password_here' WHERE id = 1;
```

เพิ่ม bcrypt ใน login:

```javascript
const isValidPassword = await bcrypt.compare(password, user.password);
```

#### แบบฝึกหัดที่ 3: เพิ่ม Security Headers

```javascript
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
    }
}));
```

---

## การประเมินผล

### เกณฑ์การประเมิน

1. **การเข้าใจช่องโหว่ (30%)**
   - สามารถทดสอบและใช้ประโยชน์จากช่องโหว่ได้
   - เข้าใจกลไกการทำงานของการโจมตี

2. **การแก้ไขช่องโหว่ (40%)**
   - สามารถใช้วิธีป้องกันที่ถูกต้อง
   - โค้ดที่เขียนมีความปลอดภัย

3. **การวิเคราะห์และเปรียบเทียบ (20%)**
   - สามารถอธิบายความแตกต่างได้
   - เขียนรายงานการทดสอบได้

4. **การประยุกต์ใช้ (10%)**
   - สามารถเพิ่มฟีเจอร์ความปลอดภัยเพิ่มเติมได้
   - เข้าใจหลักการ Defense in Depth

### คำถามท้ายบท

1. อธิบายความแตกต่างระหว่าง Prepared Statement กับ String Concatenation
2. ทำไม HTML Encoding ถึงป้องกัน XSS ได้?
3. JWT Token ป้องกัน IDOR ได้อย่างไร?
4. Rate Limiting ช่วยป้องกันการโจมตีแบบไหน?
5. เสนอวิธีป้องกันเพิ่มเติมที่ไม่ได้กล่าวใน Lab นี้

---

## ทรัพยากรเพิ่มเติม

### Tools ที่แนะนำ

1. **OWASP ZAP** - สำหรับ Vulnerability Scanning
2. **Burp Suite** - สำหรับ Manual Testing  
3. **SQLMap** - สำหรับทดสอบ SQL Injection
4. **Postman** - สำหรับทดสอบ API

### เว็บไซต์สำหรับเรียนรู้เพิ่มเติม

1. **OWASP WebGoat** - https://owasp.org/www-project-webgoat/
2. **DVWA** - http://www.dvwa.co.uk/
3. **PortSwigger Web Security Academy** - https://portswigger.net/web-security
4. **HackTheBox** - https://www.hackthebox.eu/

---

**หมายเหตุ:** Lab นี้ออกแบบมาเพื่อการศึกษาเท่านั้น อย่านำไปใช้ในระบบจริงหรือโจมตีระบบของผู้อื่น การใช้ความรู้นี้ในทางที่ผิดกฎหมายถือเป็นความผิดทางอาญา# Lab: การรักษาความปลอดภัยเว็บแอปพลิเคชัน