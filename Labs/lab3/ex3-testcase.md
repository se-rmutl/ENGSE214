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

## Experiment 3: Input Validation และ Authorization Test Cases

### 3.1 Input Validation Test Cases

<artifacts>
<artifact identifier="input_validation_test_cases" type="text/markdown" title="Input Validation Test Cases">
# Input Validation Test Cases

## Test Case Group 1: Data Type Validation

### TC301: Type Checking
**วัตถุประสงค์:** ทดสอบการตรวจสอบ data type

**Test Data:**
```javascript
const testInputs = [
    // Valid inputs
    { input: "admin", type: "string", expected: "pass" },
    { input: 123, type: "number", expected: "pass" },
    { input: true, type: "boolean", expected: "pass" },
    
    // Invalid inputs
    { input: null, type: "string", expected: "fail" },
    { input: undefined, type: "string", expected: "fail" },
    { input: [], type: "string", expected: "fail" },
    { input: {}, type: "string", expected: "fail" },
    { input: "123", type: "number", expected: "fail" }, // string number
];
```

### TC302: Length Validation
**Test Data:**
```javascript
const lengthTests = [
    // Username validation (3-20 chars)
    { input: "ab", field: "username", expected: "fail", reason: "too short" },
    { input: "abc", field: "username", expected: "pass" },
    { input: "a".repeat(20), field: "username", expected: "pass" },
    { input: "a".repeat(21), field: "username", expected: "fail", reason: "too long" },
    
    // Password validation (8-100 chars)
    { input: "1234567", field: "password", expected: "fail", reason: "too short" },
    { input: "12345678", field: "password", expected: "pass" },
    { input: "a".repeat(100), field: "password", expected: "pass" },
    { input: "a".repeat(101), field: "password", expected: "fail", reason: "too long" },
];
```

### TC303: Pattern Validation
**Test Data:**
```javascript
const patternTests = [
    // Email validation
    { input: "user@example.com", pattern: "email", expected: "pass" },
    { input: "user+tag@example.co.uk", pattern: "email", expected: "pass" },
    { input: "invalid-email", pattern: "email", expected: "fail" },
    { input: "user@", pattern: "email", expected: "fail" },
    { input: "@example.com", pattern: "email", expected: "fail" },
    
    // Username pattern (alphanumeric + underscore)
    { input: "user123", pattern: "username", expected: "pass" },
    { input: "user_name", pattern: "username", expected: "pass" },
    { input: "user-name", pattern: "username", expected: "fail" },
    { input: "user@name", pattern: "username", expected: "fail" },
    { input: "user name", pattern: "username", expected: "fail" },
    
    // Phone number
    { input: "0812345678", pattern: "phone", expected: "pass" },
    { input: "+66812345678", pattern: "phone", expected: "pass" },
    { input: "081-234-5678", pattern: "phone", expected: "pass" },
    { input: "abc123", pattern: "phone", expected: "fail" },
];
```

## Test Case Group 2: Security Validation

### TC304: SQL Injection Prevention
**Test Payloads:**
```javascript
const sqlInjectionTests = [
    // Basic injection attempts
    { input: "admin'; --", expected: "block", reason: "SQL comment" },
    { input: "' OR '1'='1", expected: "block", reason: "Boolean injection" },
    { input: "' UNION SELECT", expected: "block", reason: "Union injection" },
    { input: "'; DROP TABLE", expected: "block", reason: "Destructive command" },
    
    // Advanced injection attempts  
    { input: "admin' AND LENGTH(password)>5; --", expected: "block", reason: "Blind injection" },
    { input: "1'; WAITFOR DELAY '00:00:05'; --", expected: "block", reason: "Time-based injection" },
    { input: "admin' OR ASCII(SUBSTRING(password,1,1))>64; --", expected: "block", reason: "ASCII-based extraction" },
    
    // Valid inputs that should pass
    { input: "john_doe", expected: "pass", reason: "Valid username" },
    { input: "user@company.com", expected: "pass", reason: "Valid email" },
];
```

### TC305: XSS Prevention
**Test Payloads:**
```javascript
const xssTests = [
    // Script tags
    { input: "<script>alert('xss')</script>", expected: "block" },
    { input: "<Script>alert('xss')</Script>", expected: "block" },
    { input: "<scr<script>ipt>alert('xss')</script>", expected: "block" },
    
    // Event handlers
    { input: "<img src=x onerror=alert('xss')>", expected: "block" },
    { input: "<div onmouseover=alert('xss')>", expected: "block" },
    { input: "<input onfocus=alert('xss') autofocus>", expected: "block" },
    
    // JavaScript protocols
    { input: "javascript:alert('xss')", expected: "block" },
    { input: "vbscript:alert('xss')", expected: "block" },
    { input: "data:text/html,<script>alert('xss')</script>", expected: "block" },
    
    // Encoded attempts
    { input: "%3Cscript%3Ealert('xss')%3C/script%3E", expected: "block" },
    { input: "&lt;script&gt;alert('xss')&lt;/script&gt;", expected: "pass", reason: "Already encoded" },
];
```

### TC306: Path Traversal Prevention
**Test Payloads:**
```javascript
const pathTraversalTests = [
    // Basic traversal
    { input: "../../../etc/passwd", expected: "block" },
    { input: "..\\..\\..\\windows\\system32", expected: "block" },
    { input: "/etc/passwd", expected: "block" },
    
    // Encoded traversal
    { input: "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", expected: "block" },
    { input: "..%252f..%252f..%252fetc%252fpasswd", expected: "block" },
    
    // Valid file names
    { input: "document.pdf", expected: "pass" },
    { input: "image_2024.jpg", expected: "pass" },
    { input: "report-final.docx", expected: "pass" },
];
```

## Test Case Group 3: Business Logic Validation

### TC307: Range Validation
**Test Data:**
```javascript
const rangeTests = [
    // Age validation (13-120)
    { input: 12, field: "age", expected: "fail", reason: "Below minimum" },
    { input: 13, field: "age", expected: "pass" },
    { input: 25, field: "age", expected: "pass" },
    { input: 120, field: "age", expected: "pass" },
    { input: 121, field: "age", expected: "fail", reason: "Above maximum" },
    
    // Price validation (0.01-1000000)
    { input: 0, field: "price", expected: "fail", reason: "Below minimum" },
    { input: 0.01, field: "price", expected: "pass" },
    { input: 999999.99, field: "price", expected: "pass" },
    { input: 1000001, field: "price", expected: "fail", reason: "Above maximum" },
    
    // Quantity validation (1-999)
    { input: 0, field: "quantity", expected: "fail" },
    { input: 1, field: "quantity", expected: "pass" },
    { input: 999, field: "quantity", expected: "pass" },
    { input: 1000, field: "quantity", expected: "fail" },
];
```

### TC308: Date Validation
**Test Data:**
```javascript
const dateTests = [
    // Valid dates
    { input: "2024-01-01", format: "YYYY-MM-DD", expected: "pass" },
    { input: "01/01/2024", format: "MM/DD/YYYY", expected: "pass" },
    
    // Invalid dates
    { input: "2024-13-01", format: "YYYY-MM-DD", expected: "fail", reason: "Invalid month" },
    { input: "2024-02-30", format: "YYYY-MM-DD", expected: "fail", reason: "Invalid day" },
    { input: "not-a-date", format: "YYYY-MM-DD", expected: "fail", reason: "Invalid format" },
    
    // Business logic dates
    { input: "1900-01-01", field: "birthdate", expected: "fail", reason: "Too old" },
    { input: "2025-01-01", field: "birthdate", expected: "fail", reason: "Future date" },
    { input: "2024-12-31", field: "event_date", expected: "pass", reason: "Valid future date" },
];
```

## นักศึกษาลองทำ

### Exercise 1: Custom Validator Builder
```javascript
// ให้นักศึกษาสร้าง validation system
class ValidatorBuilder {
    constructor() {
        this.rules = [];
    }
    
    // TODO: เพิ่ม method สำหรับ validation rules
    isRequired() {
        // TODO: implement required validation
        return this;
    }
    
    isString() {
        // TODO: implement string type validation
        return this;
    }
    
    minLength(min) {
        // TODO: implement minimum length validation
        return this;
    }
    
    maxLength(max) {
        // TODO: implement maximum length validation
        return this;
    }
    
    matches(pattern) {
        // TODO: implement pattern matching
        return this;
    }
    
    isEmail() {
        // TODO: implement email validation
        return this;
    }
    
    custom(validator) {
        // TODO: implement custom validation function
        return this;
    }
    
    validate(input) {
        // TODO: run all validation rules
        const errors = [];
        
        // TODO: iterate through rules and collect errors
        
        return {
            isValid: errors.length === 0,
            errors: errors
        };
    }
}

// การใช้งาน
const usernameValidator = new ValidatorBuilder()
    .isRequired()
    .isString()
    .minLength(3)
    .maxLength(20)
    .matches(/^[a-zA-Z0-9_]+$/)
    .custom(input => {
        const reservedNames = ['admin', 'root', 'system'];
        if (reservedNames.includes(input.toLowerCase())) {
            throw new Error('Username is reserved');
        }
    });

// TODO: ทดสอบกับ test cases
const testCases = [
    'admin',      // should fail (reserved)
    'ab',         // should fail (too short)
    'user@name',  // should fail (invalid chars)
    'user_name',  // should pass
];
```

### Exercise 2: Input Sanitization
```javascript
// ให้นักศึกษาสร้าง sanitizer
class InputSanitizer {
    // TODO: implement sanitization methods
    
    sanitizeString(input) {
        // TODO: 
        // 1. Trim whitespace
        // 2. Remove null bytes
        // 3. Normalize unicode
        // 4. Remove control characters
    }
    
    sanitizeHTML(input) {
        // TODO:
        // 1. Remove script tags
        // 2. Remove event handlers
        // 3. Encode HTML entities
        // 4. Remove dangerous protocols
    }
    
    sanitizeSQL(input) {
        // TODO:
        // 1. Escape single quotes
        // 2. Remove SQL keywords
        // 3. Remove comments
    }
    
    sanitizeFilename(input) {
        // TODO:
        // 1. Remove path traversal
        // 2. Remove special characters
        // 3. Limit length
        // 4. Check file extension
    }
    
    sanitizeURL(input) {
        // TODO:
        // 1. Validate protocol
        // 2. Encode dangerous characters
        // 3. Remove malicious parameters
    }
}

// Test cases สำหรับนักศึกษา
const sanitizerTests = [
    {
        input: '  <script>alert("xss")</script>  ',
        method: 'sanitizeHTML',
        expectedOutput: '&lt;script&gt;alert("xss")&lt;/script&gt;'
    },
    {
        input: '../../../etc/passwd',
        method: 'sanitizeFilename',
        expectedOutput: 'etc_passwd'
    },
    // TODO: เพิ่ม test cases อื่นๆ
];
```

### Exercise 3: Real-time Validation
```javascript
// ให้นักศึกษาสร้าง real-time validation สำหรับ form
class RealTimeValidator {
    constructor(formElement) {
        this.form = formElement;
        this.validators = new Map();
        this.setupEventListeners();
    }
    
    addFieldValidator(fieldName, validator) {
        // TODO: เพิ่ม validator สำหรับ field
        this.validators.set(fieldName, validator);
    }
    
    setupEventListeners() {
        // TODO: setup event listeners สำหรับ input events
        this.form.addEventListener('input', this.handleInput.bind(this));
        this.form.addEventListener('blur', this.handleBlur.bind(this), true);
        this.form.addEventListener('submit', this.handleSubmit.bind(this));
    }
    
    handleInput(event) {
        // TODO: validate เมื่อ user พิมพ์
    }
    
    handleBlur(event) {
        // TODO: validate เมื่อ user ออกจาก field
    }
    
    handleSubmit(event) {
        // TODO: validate ทั้ง form ก่อน submit
    }
    
    showFieldError(fieldName, message) {
        // TODO: แสดง error message
    }
    
    clearFieldError(fieldName) {
        // TODO: ล้าง error message
    }
    
    validateField(fieldName, value) {
        // TODO: validate field เดี่ยว
    }
    
    validateForm() {
        // TODO: validate ทั้ง form
    }
}

// การใช้งาน
const form = document.getElementById('registrationForm');
const validator = new RealTimeValidator(form);

// TODO: เพิ่ม validators สำหรับแต่ละ field
validator.addFieldValidator('username', usernameValidator);
validator.addFieldValidator('email', emailValidator);
validator.addFieldValidator('password', passwordValidator);
```

## คำถามวิเคราะห์

1. **Client-side vs Server-side Validation:**
   - ความแตกต่างและความจำเป็นของแต่ละแบบ
   - ทำไมต้องทำทั้งสองฝั่ง?

2. **Performance Impact:**
   - Real-time validation มีผลต่อ UX อย่างไร?
   - ควร validate ทุก keystroke หรือเมื่อออกจาก field?

3. **Security vs Usability:**
   - Validation ที่เข้มงวดเกินไปส่งผลต่อ user experience อย่างไร?
   - จะสมดุลระหว่างความปลอดภัยและความสะดวกได้อย่างไร?

4. **Error Handling:**
   - ควรแสดง error message อย่างไรให้ user เข้าใจและไม่เปิดเผยข้อมูลระบบ?
   - การ log validation errors มีประโยชน์อย่างไร?
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