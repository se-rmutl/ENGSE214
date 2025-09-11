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

## Experiment 1: SQL Injection Test Cases

### 1.1 Vulnerability Test Cases

<artifacts>
<artifact identifier="sql_injection_test_cases" type="text/markdown" title="SQL Injection Test Cases">
# SQL Injection Test Cases

## Test Case Group 1: Basic SQL Injection

### TC001: Authentication Bypass
**วัตถุประสงค์:** ทดสอบการข้าม authentication ด้วย SQL injection

**Input Data:**
- Username: `admin'; --`
- Password: `anything`

**Expected Result (Vulnerable):**
- Login สำเร็จ
- ได้รับข้อมูล user admin
- SQL Query: `SELECT * FROM users WHERE username='admin'; --' AND password='anything'`

**Expected Result (Secure):**
- Login ไม่สำเร็จ
- ได้รับ error message: "Invalid input format"
- ไม่มี SQL injection เกิดขึ้น

**เหตุผล:** ส่วน `--` เป็น comment ใน SQL ทำให้เงื่อนไข password ถูกข้ามไป

### TC002: Union-Based SQL Injection
**วัตถุประสงค์:** ทดสอบการดึงข้อมูลจากตารางอื่น

**Input Data:**
- Username: `' UNION SELECT id,username,password,email FROM users; --`
- Password: `test`

**Expected Result (Vulnerable):**
- แสดงข้อมูลผู้ใช้ทั้งหมด
- เห็นรหัสผ่านของผู้ใช้อื่น

**Expected Result (Secure):**
- Validation error
- ไม่แสดงข้อมูลเพิ่มเติม

### TC003: Boolean-Based Blind SQL Injection
**วัตถุประสงค์:** ทดสอบการดึงข้อมูลแบบ blind injection

**Input Data:**
- Username: `admin' AND LENGTH(password)>5; --`
- Password: `test`

**การทดสอบ:**
1. ลองความยาว password ต่างๆ
2. สังเกต response ที่แตกต่างกัน

**นักศึกษาลองทำ:**
```
ให้นักศึกษาทดสอบ payload เหล่านี้และบันทึกผล:
1. admin' AND LENGTH(password)>3; --
2. admin' AND LENGTH(password)>10; --
3. admin' AND SUBSTRING(password,1,1)='s'; --

คำถาม: จากผลการทดสอบ สามารถเดาความยาวรหัสผ่านได้หรือไม่?
```

### TC004: Error-Based SQL Injection
**วัตถุประสงค์:** ทดสอบการดึงข้อมูลจาก error message

**Input Data:**
- Username: `admin' AND (SELECT COUNT(*) FROM information_schema.tables)>1000; --`
- Password: `test`

**Expected Result (Vulnerable):**
- Error message เปิดเผยโครงสร้างฐานข้อมูล

**Expected Result (Secure):**
- Generic error message
- ไม่เปิดเผยรายละเอียดฐานข้อมูล

## Test Case Group 2: Advanced SQL Injection

### TC005: Time-Based Blind SQL Injection
**Input Data:**
- Username: `admin'; WAITFOR DELAY '00:00:05'; --`
- Password: `test`

**การวัดผล:**
- วัดเวลา response
- Vulnerable: ช้าลง 5 วินาที
- Secure: เวลาปกติ

### TC006: Second-Order SQL Injection
**วัตถุประสงค์:** ทดสอบ SQL injection ที่เกิดขึ้นในขั้นตอนที่ 2

**ขั้นตอน:**
1. สมัครสมาชิกด้วย username: `admin'--`
2. Login ด้วย account ที่สร้าง
3. ดู profile หรือทำการอื่นที่ใช้ username

## Security Test Cases

### TC007: Input Validation Test
**วัตถุประสงค์:** ทดสอบการตรวจสอบ input

**Test Data:**
```
Valid inputs:
- Username: "admin", "user123", "test_user"
- Password: "password", "123456", "mypass"

Invalid inputs:
- Username: "", "admin'; DROP TABLE users; --", "<script>alert('xss')</script>"
- Password: "", "' OR '1'='1", "'; DELETE FROM users; --"
```

**Expected Behavior (Secure):**
- Valid inputs: ผ่านการ validation
- Invalid inputs: ถูกปฏิเสธพร้อม error message

### TC008: Prepared Statement Test
**วัตถุประสงค์:** ยืนยันว่าใช้ prepared statement

**การทดสอบ:**
1. ดู query log ในฐานข้อมูล
2. ตรวจสอบว่า parameter ถูก bind แยกจาก SQL command

**นักศึกษาลองทำ:**
```
ให้นักศึกษาเปรียบเทียบ query ที่เกิดขึ้นระหว่าง:
1. String concatenation: "SELECT * FROM users WHERE username='" + username + "'"
2. Prepared statement: "SELECT * FROM users WHERE username=?" with parameter [username]

อธิบายความแตกต่างและข้อดีของแต่ละแบบ
```

## Test Results Template

### นักศึกษาบันทึกผล:

| Test Case ID | Input | Vulnerable Result | Secure Result | Pass/Fail |
|--------------|-------|-------------------|---------------|-----------|
| TC001 | admin'; -- | [บันทึกผล] | [บันทึกผล] | [P/F] |
| TC002 | UNION SELECT | [บันทึกผล] | [บันทึกผล] | [P/F] |
| TC003 | Blind injection | [บันทึกผล] | [บันทึกผล] | [P/F] |

### คำถามวิเคราะห์:
1. ทำไม payload `admin'; --` ถึงสามารถ bypass authentication ได้?
2. UNION injection ทำงานอย่างไร?
3. Prepared statement ป้องกัน SQL injection ได้อย่างไร?
4. การ validate input มีข้อจำกัดอะไรบ้าง?

### แบบฝึกหัด:
ให้นักศึกษาสร้าง SQL injection payload ใหม่ที่ไม่ได้กล่าวถึงและทดสอบกับระบบ
</artifact>
</artifacts>

### 1.2 Code Improvement Guide

<artifacts>
<artifact identifier="sql_injection_fix_guide" type="text/markdown" title="SQL Injection Fix Guide">
# SQL Injection การปรับปรุงโค้ดให้ปลอดภัย

## หลักการป้องกัน SQL Injection

### 1. Prepared Statements (วิธีหลัก)

**ปัญหาเดิม (Vulnerable Code):**
```javascript
// ❌ String concatenation - อันตราย
const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
db.query(query, callback);
```

**วิธีแก้ไข (Secure Code):**
```javascript
// ✅ Prepared statement - ปลอดภัย
const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
db.query(query, [username, password], callback);
```

**อธิบายหลักการ:**
- Prepared statement แยก SQL command ออกจาก data
- Database engine จะ treat parameter เป็น data เท่านั้น ไม่ใช่ SQL command
- ป้องกันไม่ให้ attacker แทรก SQL code ได้

### 2. Input Validation

**การตรวจสอบ Input ที่ครอบคลุม:**
```javascript
function validateInput(input, type, maxLength = 100) {
    // 1. ตรวจสอบ type และ null/undefined
    if (!input || typeof input !== 'string') {
        throw new Error('Invalid input type');
    }
    
    // 2. ตรวจสอบความยาว
    if (input.length > maxLength) {
        throw new Error(`Input too long (max ${maxLength} characters)`);
    }
    
    // 3. ตรวจสอบ pattern ตาม type
    switch(type) {
        case 'username':
            // อนุญาตเฉพาะ a-z, A-Z, 0-9, underscore
            if (!/^[a-zA-Z0-9_]+$/.test(input)) {
                throw new Error('Username contains invalid characters');
            }
            break;
            
        case 'email':
            // ตรวจสอบรูปแบบ email
            if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input)) {
                throw new Error('Invalid email format');
            }
            break;
            
        default:
            // ตรวจสอบ SQL keywords และอักขระอันตราย
            const sqlKeywords = /\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|OR|AND)\b/gi;
            const dangerousChars = /['"`;\\]/;
            
            if (sqlKeywords.test(input) || dangerousChars.test(input)) {
                throw new Error('Input contains potentially dangerous content');
            }
    }
    
    return input.trim();
}

// การใช้งาน
try {
    const safeUsername = validateInput(req.body.username, 'username', 50);
    const safePassword = validateInput(req.body.password, 'password', 100);
    
    // ใช้ prepared statement
    const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
    db.query(query, [safeUsername, safePassword], callback);
    
} catch (error) {
    res.status(400).json({ error: error.message });
}
```

### 3. Error Handling ที่ปลอดภัย

**ปัญหาเดิม:**
```javascript
// ❌ เปิดเผยรายละเอียด error
db.query(query, (err, result) => {
    if (err) {
        res.status(500).json({ error: err.message }); // อันตราย!
    }
});
```

**วิธีแก้ไข:**
```javascript
// ✅ Generic error message
db.query(query, (err, result) => {
    if (err) {
        // Log รายละเอียดสำหรับ developer
        console.error('Database error:', err);
        
        // ส่ง generic message ให้ client
        res.status(500).json({ 
            error: 'An error occurred while processing your request',
            code: 'DB_ERROR'
        });
    }
});
```

### 4. การใช้ ORM (Object-Relational Mapping)

**ตัวอย่างการใช้ Sequelize:**
```javascript
// ✅ ORM ป้องกัน SQL injection โดยอัตโนมัติ
const { User } = require('./models');

// การค้นหาที่ปลอดภัย
const user = await User.findOne({
    where: {
        username: req.body.username,
        password: req.body.password
    }
});

// การค้นหาแบบ complex
const users = await User.findAll({
    where: {
        [Op.or]: [
            { username: { [Op.like]: `%${searchTerm}%` } },
            { email: { [Op.like]: `%${searchTerm}%` } }
        ]
    },
    limit: 10
});
```

## แบบฝึกหัดสำหรับนักศึกษา

### Exercise 1: ปรับปรุง Login Function
```javascript
// โค้ดที่มีช่องโหว่ - ให้นักศึกษาแก้ไข
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    // TODO: เพิ่ม input validation
    
    // TODO: เปลี่ยนจาก string concatenation เป็น prepared statement
    const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
    
    db.query(query, (err, result) => {
        if (err) {
            // TODO: ปรับปรุง error handling
            res.status(500).json({ error: err.message });
        } else if (result.length > 0) {
            res.json({ success: true, user: result[0] });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    });
});
```

**คำสั่งให้นักศึกษา:**
1. เพิ่ม input validation function
2. เปลี่ยนเป็น prepared statement
3. ปรับปรุง error handling
4. ทดสอบด้วย SQL injection payloads
5. อธิบายเหตุผลในแต่ละการปรับปรุง

### Exercise 2: สร้าง Search Function ที่ปลอดภัย
```javascript
// สร้าง search function ที่ป้องกัน SQL injection
app.get('/search', (req, res) => {
    // TODO: นักศึกษาเขียนโค้ดที่ปลอดภัย
    // ข้อกำหนด:
    // 1. รับ query parameter 'q'
    // 2. ค้นหาใน products table
    // 3. ป้องกัน SQL injection
    // 4. จำกัดผลลัพธ์ไม่เกิน 50 รายการ
    // 5. ส่งกลับเฉพาะ id, name, price
});
```

### Exercise 3: Input Validation Testing
ให้นักศึกษาสร้าง test cases สำหรับ validation function:

```javascript
// ให้นักศึกษาเติม test cases เพิ่มเติม
const testCases = [
    // Valid inputs
    { input: 'admin', type: 'username', expected: 'pass' },
    { input: 'user123', type: 'username', expected: 'pass' },
    
    // Invalid inputs
    { input: "admin'; --", type: 'username', expected: 'fail' },
    { input: '', type: 'username', expected: 'fail' },
    
    // TODO: เพิ่ม test cases อื่นๆ
];

// ทดสอบและบันทึกผล
testCases.forEach(test => {
    // นักศึกษาเขียนโค้ดทดสอบ
});
```

## คำถามวิเคราะห์สำหรับนักศึกษา

1. **เปรียบเทียบวิธีการป้องกัน:**
   - Prepared statement vs Input validation - อันไหนสำคัญกว่า? ทำไม?
   - ควรใช้ทั้งสองวิธีหรือเลือกอันใดอันหนึ่ง?

2. **กรณีพิเศษ:**
   - ถ้าต้องการใช้ dynamic SQL (เช่น dynamic ORDER BY) จะทำอย่างไร?
   - ORM ป้องกัน SQL injection ได้ 100% หรือไม่?

3. **Performance impact:**
   - Prepared statement มีผลต่อประสิทธิภาพอย่างไร?
   - Input validation ควรทำฝั่ง client หรือ server?

4. **Real-world scenarios:**
   - ในโปรเจค capstone ของนักศึกษา มีจุดไหนที่เสี่ยงต่อ SQL injection?
   - จะตรวจสอบว่าโค้ดปลอดภัยจาก SQL injection ได้อย่างไร?

## เฉลยแบบฝึกหัด

### Exercise 1 Solution:
```javascript
app.post('/login', [
    // Input validation middleware
    body('username').trim().isLength({min: 1, max: 50}).matches(/^[a-zA-Z0-9_]+$/),
    body('password').isLength({min: 1, max: 100})
], async (req, res) => {
    try {
        // ตรวจสอบ validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                error: 'Invalid input format',
                details: errors.array()
            });
        }

        const { username, password } = req.body;
        
        // ใช้ prepared statement
        const query = 'SELECT id, username, email, role FROM users WHERE username = ? AND password = ?';
        
        db.query(query, [username, password], (err, result) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ 
                    error: 'An error occurred during login' 
                });
            }
            
            if (result.length > 0) {
                res.json({ 
                    success: true, 
                    user: result[0] 
                });
            } else {
                res.status(401).json({ 
                    error: 'Invalid credentials' 
                });
            }
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            error: 'Login failed' 
        });
    }
});
```

**การปรับปรุงที่สำคัญ:**
1. **Input validation** - ตรวจสอบรูปแบบและความยาว
2. **Prepared statement** - แยก SQL กับ data
3. **Error handling** - ไม่เปิดเผยรายละเอียด
4. **Security headers** - จำกัดข้อมูลที่ส่งกลับ
</artifact>
</artifacts>

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