# LAB: Multi-Factor Authentication (MFA) Implementation

## 🎯 **วัตถุประสงค์**
- เข้าใจหลักการทำงานของ Multi-Factor Authentication
- ฝึกการพัฒนา MFA system ด้วย HTML, CSS, JavaScript และ Node.js
- เรียนรู้การใช้งาน TOTP (Time-based One-Time Password)
- ปฏิบัติการส่ง OTP ผ่าน Email
- เข้าใจ security best practices ในการทำ authentication

---

## 📋 **ข้อกำหนด Lab**

### **Technology Stack:**
- **Frontend:** HTML5, CSS3, Vanilla JavaScript
- **Backend:** Node.js, Express.js
- **Database:** SQLite (เพื่อความง่าย)
- **MFA Methods:** 
  - Email OTP
  - TOTP (Google Authenticator compatible)
- **Additional Libraries:**
  - speakeasy (TOTP generation)
  - nodemailer (Email sending)
  - bcrypt (Password hashing)
  - jsonwebtoken (JWT tokens)

### **ระยะเวลา:** 1 วัน (8 ชั่วโมง)

---

## 🚀 **Part 1: Project Setup (45 นาที)**

### **1.1 Initialize Project**
```bash
mkdir mfa-lab
cd mfa-lab

# Initialize Node.js project
npm init -y

# Install dependencies
npm install express sqlite3 bcrypt jsonwebtoken speakeasy nodemailer qrcode
npm install --save-dev nodemon

# Create project structure
mkdir public css js views
touch server.js
touch public/index.html public/login.html public/register.html public/dashboard.html
touch css/style.css
touch js/auth.js js/mfa.js
```

### **1.2 Package.json Scripts**
```json
{
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  }
}
```

### **ที่ต้องทำ:**
- สร้าง project structure
- ติดตั้ง dependencies ทั้งหมด
- ทดสอบ `npm run dev` ให้ทำงานได้

---

## 🔧 **Part 2: Backend Implementation (2.5 ชั่วโมง)**

### **2.1 Database Setup (30 นาที)**

**database.js**
```javascript
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

class Database {
    constructor() {
        this.db = new sqlite3.Database('mfa_lab.db');
        this.init();
    }

    init() {
        // Users table
        this.db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                mfa_enabled BOOLEAN DEFAULT 0,
                mfa_secret TEXT,
                backup_codes TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Login attempts table (for rate limiting)
        this.db.run(`
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                success BOOLEAN NOT NULL,
                attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Email OTP table
        this.db.run(`
            CREATE TABLE IF NOT EXISTS email_otps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                otp_code TEXT NOT NULL,
                expires_at DATETIME NOT NULL,
                used BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        `);
    }

    // User operations
    async createUser(username, email, password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        return new Promise((resolve, reject) => {
            this.db.run(
                'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                [username, email, hashedPassword],
                function(err) {
                    if (err) reject(err);
                    else resolve(this.lastID);
                }
            );
        });
    }

    async getUserByUsername(username) {
        return new Promise((resolve, reject) => {
            this.db.get(
                'SELECT * FROM users WHERE username = ?',
                [username],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                }
            );
        });
    }

    async updateUserMFA(userId, secret, backupCodes) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'UPDATE users SET mfa_enabled = 1, mfa_secret = ?, backup_codes = ? WHERE id = ?',
                [secret, JSON.stringify(backupCodes), userId],
                function(err) {
                    if (err) reject(err);
                    else resolve(this.changes);
                }
            );
        });
    }

    // Email OTP operations
    async saveEmailOTP(userId, otpCode, expiresAt) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'INSERT INTO email_otps (user_id, otp_code, expires_at) VALUES (?, ?, ?)',
                [userId, otpCode, expiresAt],
                function(err) {
                    if (err) reject(err);
                    else resolve(this.lastID);
                }
            );
        });
    }

    async verifyEmailOTP(userId, otpCode) {
        return new Promise((resolve, reject) => {
            this.db.get(
                `SELECT * FROM email_otps 
                 WHERE user_id = ? AND otp_code = ? AND used = 0 AND expires_at > datetime('now')
                 ORDER BY created_at DESC LIMIT 1`,
                [userId, otpCode],
                (err, row) => {
                    if (err) reject(err);
                    else if (row) {
                        // Mark as used
                        this.db.run('UPDATE email_otps SET used = 1 WHERE id = ?', [row.id]);
                        resolve(true);
                    } else {
                        resolve(false);
                    }
                }
            );
        });
    }

    // Rate limiting
    async logLoginAttempt(username, ipAddress, success) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, ?)',
                [username, ipAddress, success],
                function(err) {
                    if (err) reject(err);
                    else resolve(this.lastID);
                }
            );
        });
    }

    async getRecentFailedAttempts(username, ipAddress, minutes = 15) {
        return new Promise((resolve, reject) => {
            this.db.get(
                `SELECT COUNT(*) as count FROM login_attempts 
                 WHERE (username = ? OR ip_address = ?) 
                 AND success = 0 
                 AND attempted_at > datetime('now', '-${minutes} minutes')`,
                [username, ipAddress],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row.count);
                }
            );
        });
    }
}

module.exports = Database;
```

### **2.2 Email Service (30 นาที)**

**emailService.js**
```javascript
const nodemailer = require('nodemailer');

class EmailService {
    constructor() {
        // ใช้ Gmail SMTP (ในการใช้งานจริงควรใช้ environment variables)
        this.transporter = nodemailer.createTransporter({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER || 'your-email@gmail.com',
                pass: process.env.EMAIL_PASS || 'your-app-password'
            }
        });
    }

    generateOTP() {
        return Math.floor(100000 + Math.random() * 900000).toString();
    }

    async sendOTP(email, username, otpCode) {
        const mailOptions = {
            from: process.env.EMAIL_USER || 'your-email@gmail.com',
            to: email,
            subject: 'Your MFA Verification Code',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #333;">MFA Verification Code</h2>
                    <p>Hello ${username},</p>
                    <p>Your verification code is:</p>
                    <div style="background: #f5f5f5; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
                        ${otpCode}
                    </div>
                    <p style="color: #666;">This code will expire in 5 minutes.</p>
                    <p style="color: #666;">If you didn't request this code, please ignore this email.</p>
                </div>
            `
        };

        try {
            await this.transporter.sendMail(mailOptions);
            return true;
        } catch (error) {
            console.error('Email sending failed:', error);
            return false;
        }
    }

    // สำหรับ testing โดยไม่ส่ง email จริง
    async mockSendOTP(email, username, otpCode) {
        console.log(`\n=== MOCK EMAIL ===`);
        console.log(`To: ${email}`);
        console.log(`Subject: Your MFA Verification Code`);
        console.log(`OTP Code: ${otpCode}`);
        console.log(`===================\n`);
        return true;
    }
}

module.exports = EmailService;
```

### **2.3 Main Server (90 นาที)**

**server.js**
```javascript
const express = require('express');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const Database = require('./database');
const EmailService = require('./emailService');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key';

// Initialize services
const db = new Database();
const emailService = new EmailService();

// Middleware
app.use(express.json());
app.use(express.static('public'));
app.use(express.static('css'));
app.use(express.static('js'));

// Rate limiting middleware
const rateLimitMiddleware = async (req, res, next) => {
    const { username } = req.body;
    const ipAddress = req.ip || req.connection.remoteAddress;
    
    const failedAttempts = await db.getRecentFailedAttempts(username, ipAddress);
    
    if (failedAttempts >= 5) {
        return res.status(429).json({ 
            error: 'Too many failed attempts. Please try again in 15 minutes.' 
        });
    }
    
    next();
};

// Routes

// Home page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Register endpoint
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        // Validation
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        
        if (password.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters' });
        }
        
        // Check if user exists
        const existingUser = await db.getUserByUsername(username);
        if (existingUser) {
            return res.status(400).json({ error: 'Username already exists' });
        }
        
        // Create user
        const userId = await db.createUser(username, email, password);
        
        res.json({ success: true, message: 'User registered successfully', userId });
        
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Login step 1: Username and Password
app.post('/api/login', rateLimitMiddleware, async (req, res) => {
    try {
        const { username, password } = req.body;
        const ipAddress = req.ip || req.connection.remoteAddress;
        
        // Get user
        const user = await db.getUserByUsername(username);
        if (!user) {
            await db.logLoginAttempt(username, ipAddress, false);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Verify password
        const passwordValid = await bcrypt.compare(password, user.password);
        if (!passwordValid) {
            await db.logLoginAttempt(username, ipAddress, false);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Check if MFA is enabled
        if (!user.mfa_enabled) {
            // Complete login without MFA
            const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
            await db.logLoginAttempt(username, ipAddress, true);
            return res.json({ 
                success: true, 
                token, 
                mfaRequired: false,
                message: 'Login successful' 
            });
        }
        
        // Generate temporary token for MFA process
        const tempToken = jwt.sign({ 
            userId: user.id, 
            username: user.username, 
            step: 'mfa_required' 
        }, JWT_SECRET, { expiresIn: '10m' });
        
        res.json({ 
            success: true, 
            tempToken, 
            mfaRequired: true,
            message: 'Please complete MFA verification' 
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Setup TOTP MFA
app.post('/api/setup-totp', authenticateToken, async (req, res) => {
    try {
        const { userId, username } = req.user;
        
        // Generate secret
        const secret = speakeasy.generateSecret({
            name: `MFA Lab (${username})`,
            issuer: 'MFA Lab'
        });
        
        // Generate backup codes
        const backupCodes = [];
        for (let i = 0; i < 8; i++) {
            backupCodes.push(Math.random().toString(36).substr(2, 8).toUpperCase());
        }
        
        // Generate QR code
        const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
        
        // Store secret temporarily (not yet activated)
        req.session = req.session || {};
        req.session.pendingMFASecret = secret.base32;
        req.session.pendingBackupCodes = backupCodes;
        
        res.json({
            success: true,
            secret: secret.base32,
            qrCode: qrCodeUrl,
            backupCodes: backupCodes
        });
        
    } catch (error) {
        console.error('TOTP setup error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Verify TOTP setup
app.post('/api/verify-totp-setup', authenticateToken, async (req, res) => {
    try {
        const { token } = req.body;
        const { userId } = req.user;
        
        const secret = req.session?.pendingMFASecret;
        const backupCodes = req.session?.pendingBackupCodes;
        
        if (!secret) {
            return res.status(400).json({ error: 'No pending MFA setup found' });
        }
        
        // Verify token
        const verified = speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: token,
            window: 2
        });
        
        if (!verified) {
            return res.status(400).json({ error: 'Invalid verification code' });
        }
        
        // Save to database
        await db.updateUserMFA(userId, secret, backupCodes);
        
        // Clear session
        delete req.session?.pendingMFASecret;
        delete req.session?.pendingBackupCodes;
        
        res.json({ success: true, message: 'MFA setup completed successfully' });
        
    } catch (error) {
        console.error('TOTP verification error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Send Email OTP
app.post('/api/send-email-otp', async (req, res) => {
    try {
        const { tempToken } = req.body;
        
        // Verify temp token
        const decoded = jwt.verify(tempToken, JWT_SECRET);
        if (decoded.step !== 'mfa_required') {
            return res.status(401).json({ error: 'Invalid token' });
        }
        
        const user = await db.getUserByUsername(decoded.username);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Generate OTP
        const otpCode = emailService.generateOTP();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
        
        // Save OTP to database
        await db.saveEmailOTP(user.id, otpCode, expiresAt);
        
        // Send email (use mock for testing)
        const emailSent = await emailService.mockSendOTP(user.email, user.username, otpCode);
        
        if (!emailSent) {
            return res.status(500).json({ error: 'Failed to send email' });
        }
        
        res.json({ success: true, message: 'OTP sent to your email' });
        
    } catch (error) {
        console.error('Email OTP error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Verify MFA (TOTP or Email OTP)
app.post('/api/verify-mfa', async (req, res) => {
    try {
        const { tempToken, code, method } = req.body;
        
        // Verify temp token
        const decoded = jwt.verify(tempToken, JWT_SECRET);
        if (decoded.step !== 'mfa_required') {
            return res.status(401).json({ error: 'Invalid token' });
        }
        
        const user = await db.getUserByUsername(decoded.username);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        let verified = false;
        
        if (method === 'totp') {
            // Verify TOTP
            verified = speakeasy.totp.verify({
                secret: user.mfa_secret,
                encoding: 'base32',
                token: code,
                window: 2
            });
        } else if (method === 'email') {
            // Verify Email OTP
            verified = await db.verifyEmailOTP(user.id, code);
        } else if (method === 'backup') {
            // Verify backup code
            const backupCodes = JSON.parse(user.backup_codes || '[]');
            verified = backupCodes.includes(code.toUpperCase());
            
            if (verified) {
                // Remove used backup code
                const updatedCodes = backupCodes.filter(c => c !== code.toUpperCase());
                await db.updateUserMFA(user.id, user.mfa_secret, updatedCodes);
            }
        }
        
        if (!verified) {
            const ipAddress = req.ip || req.connection.remoteAddress;
            await db.logLoginAttempt(user.username, ipAddress, false);
            return res.status(401).json({ error: 'Invalid verification code' });
        }
        
        // Generate final auth token
        const token = jwt.sign({ 
            userId: user.id, 
            username: user.username 
        }, JWT_SECRET, { expiresIn: '24h' });
        
        const ipAddress = req.ip || req.connection.remoteAddress;
        await db.logLoginAttempt(user.username, ipAddress, true);
        
        res.json({ success: true, token, message: 'Login successful' });
        
    } catch (error) {
        console.error('MFA verification error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Protected route example
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const user = await db.getUserByUsername(req.user.username);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({
            id: user.id,
            username: user.username,
            email: user.email,
            mfaEnabled: user.mfa_enabled,
            createdAt: user.created_at
        });
        
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Middleware function
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
}

// Session simulation (in production use express-session)
app.use((req, res, next) => {
    req.session = req.session || {};
    next();
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
```

### **ที่ต้องทำ:**
- ทดสอบ API endpoints ด้วย Postman หรือ curl
- ตรวจสอบการสร้าง database tables
- ทดสอบการ register user
- ทดสอบการ login แบบไม่มี MFA

---

## 🎨 **Part 3: Frontend Implementation (2.5 ชั่วโมง)**

### **3.1 Common CSS (30 นาที)**

**css/style.css**
```css
/* Reset และ Base Styles */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    padding: 20px;
}

.container {
    max-width: 800px;
    margin: 0 auto;
    padding: 20px;
}

/* Card Components */
.card {
    background: white;
    border-radius: 12px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
    padding: 40px;
    margin: 20px 0;
    backdrop-filter: blur(10px);
}

.card-header {
    text-align: center;
    margin-bottom: 30px;
}

.card-header h1 {
    color: #333;
    font-size: 2rem;
    margin-bottom: 10px;
}

.card-header p {
    color: #666;
    font-size: 1.1rem;
}

/* Form Styles */
.form-group {
    margin-bottom: 20px;
}

label {
    display: block;
    color: #333;
    font-weight: 600;
    margin-bottom: 8px;
}

input[type="text"],
input[type="email"],
input[type="password"],
input[type="number"] {
    width: 100%;
    padding: 12px 16px;
    border: 2px solid #e1e5e9;
    border-radius: 8px;
    font-size: 16px;
    transition: all 0.3s ease;
}

input:focus {
    outline: none;
    border-color: #667eea;
    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
}

/* Button Styles */
.btn {
    padding: 12px 24px;
    border: none;
    border-radius: 8px;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s ease;
    text-decoration: none;
    display: inline-block;
    text-align: center;
}

.btn-primary {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
}

.btn-primary:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
}

.btn-secondary {
    background: #6c757d;
    color: white;
}

.btn-success {
    background: #28a745;
    color: white;
}

.btn-warning {
    background: #ffc107;
    color: #212529;
}

.btn-block {
    width: 100%;
    margin: 10px 0;
}

/* Alert Styles */
.alert {
    padding: 12px 16px;
    border-radius: 8px;
    margin: 15px 0;
    font-weight: 500;
}

.alert-success {
    background: #d4edda;
    color: #155724;
    border: 1px solid #c3e6cb;
}

.alert-error {
    background: #f8d7da;
    color: #721c24;
    border: 1px solid #f5c6cb;
}

.alert-info {
    background: #cce7ff;
    color: #004085;
    border: 1px solid #b3d7ff;
}

.alert-warning {
    background: #fff3cd;
    color: #856404;
    border: 1px solid #ffeaa7;
}

/* MFA Specific Styles */
.mfa-options {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
    margin: 20px 0;
}

.mfa-option {
    padding: 20px;
    border: 2px solid #e1e5e9;
    border-radius: 8px;
    text-align: center;
    cursor: pointer;
    transition: all 0.3s ease;
}

.mfa-option:hover {
    border-color: #667eea;
    background: #f8f9ff;
}

.mfa-option.selected {
    border-color: #667eea;
    background: #667eea;
    color: white;
}

.qr-code-container {
    text-align: center;
    margin: 20px 0;
    padding: 20px;
    background: #f8f9fa;
    border-radius: 8px;
}

.backup-codes {
    background: #f8f9fa;
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}

.backup-codes-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 10px;
    margin: 15px 0;
}

.backup-code {
    padding: 8px 12px;
    background: white;
    border: 1px solid #dee2e6;
    border-radius: 4px;
    font-family: 'Courier New', monospace;
    font-weight: bold;
    text-align: center;
}

/* Loading Spinner */
.loading {
    display: inline-block;
    width: 20px;
    height: 20px;
    border: 3px solid #f3f3f3;
    border-top: 3px solid #667eea;
    border-radius: 50%;
    animation: spin 1s linear infinite;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

/* Responsive Design */
@media (max-width: 768px) {
    .container {
        padding: 10px;
    }
    
    .card {
        padding: 20px;
        margin: 10px 0;
    }
    
    .card-header h1 {
        font-size: 1.5rem;
    }
    
    .mfa-options {
        grid-template-columns: 1fr;
    }
    
    .backup-codes-grid {
        grid-template-columns: 1fr;
    }
}

/* Utility Classes */
.text-center {
    text-align: center;
}

.text-muted {
    color: #6c757d;
}

.mb-3 {
    margin-bottom: 1rem;
}

.mt-3 {
    margin-top: 1rem;
}

.hidden {
    display: none;
}

.flex {
    display: flex;
}

.justify-center {
    justify-content: center;
}

.items-center {
    align-items: center;
}

.gap-2 {
    gap: 0.5rem;
}
```

### **3.2 Authentication JavaScript (45 นาที)**

**js/auth.js**
```javascript
class AuthManager {
    constructor() {
        this.baseURL = '';
        this.token = localStorage.getItem('auth_token');