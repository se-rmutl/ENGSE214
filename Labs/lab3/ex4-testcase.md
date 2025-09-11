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

## Experiment 4: Password Security Test Cases

### 4.1 Password Strength Test Cases

<artifacts>
<artifact identifier="password_security_test_cases" type="text/markdown" title="Password Security Test Cases">
# Password Security Test Cases

## Test Case Group 1: Password Strength Assessment

### TC401: Basic Password Strength
**วัตถุประสงค์:** ทดสอบการประเมินความแข็งแรงของรหัสผ่าน

**Test Data:**
```javascript
const passwordStrengthTests = [
    // Very Weak (0-1 points)
    { password: "123", expected: "very_weak", score: 0, reasons: ["Too short", "Only numbers"] },
    { password: "abc", expected: "very_weak", score: 0, reasons: ["Too short", "Only lowercase"] },
    { password: "password", expected: "very_weak", score: 1, reasons: ["Common password", "Only lowercase"] },
    
    // Weak (2 points)
    { password: "password1", expected: "weak", score: 2, reasons: ["Common pattern", "No uppercase"] },
    { password: "12345678", expected: "weak", score: 1, reasons: ["Only numbers", "Sequential"] },
    { password: "abcdefgh", expected: "weak", score: 1, reasons: ["Only lowercase", "Sequential"] },
    
    // Fair (3 points)
    { password: "Password1", expected: "fair", score: 3, reasons: ["Good length", "Mixed case", "Has numbers"] },
    { password: "mypass123", expected: "fair", score: 3, reasons: ["Good length", "Mixed characters"] },
    
    // Good (4 points)
    { password: "MyPassword1", expected: "good", score: 4, reasons: ["Good length", "Mixed case", "Numbers"] },
    { password: "Hello2024", expected: "good", score: 4, reasons: ["Good complexity"] },
    
    // Strong (5+ points)
    { password: "MySecure#Pass2024", expected: "strong", score: 6, reasons: ["Excellent length", "All character types"] },
    { password: "Tr0ub4dor&3", expected: "strong", score: 6, reasons: ["Complex pattern", "Special characters"] },
    { password: "C0rr3ct-H0rs3-B@tt3ry-St@pl3", expected: "strong", score: 6, reasons: ["Very long", "Complex"] }
];
```

### TC402: Common Password Detection
**วัตถุประสงค์:** ทดสอบการตรวจจับรหัสผ่านที่ใช้กันทั่วไป

**Test Data:**
```javascript
const commonPasswordTests = [
    // Top common passwords (ควรถูกปฏิเสธ)
    { password: "123456", expected: "reject", reason: "Most common password" },
    { password: "password", expected: "reject", reason: "Second most common" },
    { password: "123456789", expected: "reject", reason: "Sequential numbers" },
    { password: "qwerty", expected: "reject", reason: "Keyboard pattern" },
    { password: "abc123", expected: "reject", reason: "Simple pattern" },
    { password: "admin", expected: "reject", reason: "Default admin password" },
    { password: "welcome", expected: "reject", reason: "Common word" },
    { password: "monkey", expected: "reject", reason: "Dictionary word" },
    
    // Variations of common passwords (ควรถูกปฏิเสธ)
    { password: "Password1", expected: "reject", reason: "Common pattern with variation" },
    { password: "123456!", expected: "reject", reason: "Common password + symbol" },
    { password: "Qwerty123", expected: "reject", reason: "Keyboard pattern variation" },
    
    // Acceptable passwords
    { password: "MyUniqueP@ss2024", expected: "accept", reason: "Unique combination" },
    { password: "Coffee#Morning7", expected: "accept", reason: "Personal but complex" }
];
```

### TC403: Dictionary Attack Resistance
**วัตถุประสงค์:** ทดสอบการป้องกัน dictionary attacks

**Test Data:**
```javascript
const dictionaryTests = [
    // Simple dictionary words
    { password: "computer", expected: "weak", reason: "Dictionary word" },
    { password: "elephant", expected: "weak", reason: "Dictionary word" },
    { password: "sunshine", expected: "weak", reason: "Dictionary word" },
    
    // Dictionary words with numbers
    { password: "computer1", expected: "fair", reason: "Dictionary + number" },
    { password: "elephant123", expected: "fair", reason: "Dictionary + numbers" },
    
    // Dictionary words with substitutions
    { password: "c0mputer", expected: "fair", reason: "Leet speak substitution" },
    { password: "3l3ph@nt", expected: "good", reason: "Multiple substitutions" },
    
    // Multiple dictionary words
    { password: "computer-elephant", expected: "good", reason: "Multiple words" },
    { password: "Coffee#Morning", expected: "good", reason: "Two words + symbol" },
    
    // Non-dictionary combinations
    { password: "Xy7#mPq9$", expected: "strong", reason: "Random characters" },
    { password: "BlueSky#2024*Moon", expected: "strong", reason: "Creative combination" }
];
```

### TC404: Brute Force Resistance
**วัตถุประสงค์:** ประเมินการต้านทานการโจมตีแบบ brute force

**Test Data:**
```javascript
const bruteForceTests = [
    // Time estimates for cracking (approximate)
    { password: "abc", charset: "lowercase", timeEstimate: "< 1 second" },
    { password: "Abc", charset: "mixed_case", timeEstimate: "< 1 minute" },
    { password: "Abc1", charset: "alphanumeric", timeEstimate: "< 1 hour" },
    { password: "Abc1!", charset: "full", timeEstimate: "~ 1 day" },
    { password: "MyPass1!", charset: "full", timeEstimate: "~ 3 years" },
    { password: "MySecure#Pass2024", charset: "full", timeEstimate: "> 1000 years" },
    
    // Character set analysis
    { password: "hello", charset_size: 26, combinations: "26^5" },
    { password: "Hello", charset_size: 52, combinations: "52^5" },
    { password: "Hello1", charset_size: 62, combinations: "62^6" },
    { password: "Hello1!", charset_size: 94, combinations: "94^7" }
];
```

## Test Case Group 2: Password Storage Security

### TC405: Hashing Method Comparison
**วัตถุประสงค์:** เปรียบเทียบวิธีการ hash รหัสผ่าน

**Test Data:**
```javascript
const hashingTests = [
    {
        password: "mypassword123",
        methods: {
            plaintext: {
                stored: "mypassword123",
                security_level: "none",
                crack_time: "instant",
                risk: "critical"
            },
            md5: {
                stored: "482c811da5d5b4bc6d497ffa98491e38",
                security_level: "very_low",
                crack_time: "seconds",
                risk: "high",
                vulnerabilities: ["Rainbow tables", "Fast computation"]
            },
            sha1: {
                stored: "943a702d06f34599aee1f8da8ef9f7296031d699",
                security_level: "low",
                crack_time: "minutes",
                risk: "high",
                vulnerabilities: ["Rainbow tables", "Collision attacks"]
            },
            sha256: {
                stored: "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",
                security_level: "medium",
                crack_time: "hours",
                risk: "medium",
                vulnerabilities: ["Rainbow tables", "GPU attacks"]
            },
            sha256_salted: {
                stored: "salt:ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",
                security_level: "good",
                crack_time: "days",
                risk: "low",
                benefits: ["Prevents rainbow tables", "Unique per password"]
            },
            bcrypt: {
                stored: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewReZtSmbnBz5xz.",
                security_level: "high",
                crack_time: "years",
                risk: "very_low",
                benefits: ["Adaptive cost", "Built-in salt", "Slow by design"]
            }
        }
    }
];
```

### TC406: Salt Implementation
**วัตถุประสงค์:** ทดสอบการใช้งาน salt

**Test Data:**
```javascript
const saltTests = [
    // ไม่มี salt - รหัสผ่านเดียวกันได้ hash เดียวกัน
    {
        password: "password123",
        method: "sha256_no_salt",
        hash1: "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",
        hash2: "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",
        same_hash: true,
        vulnerability: "Rainbow table attack possible"
    },
    
    // มี salt - รหัสผ่านเดียวกันได้ hash ต่างกัน
    {
        password: "password123",
        method: "sha256_with_salt",
        hash1: "a1b2c3:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        hash2: "d4e5f6:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        same_hash: false,
        benefit: "Prevents rainbow table attacks"
    },
    
    // Salt length testing
    { salt_length: 8, security: "minimum", recommendation: "Use longer salt" },
    { salt_length: 16, security: "good", recommendation: "Recommended minimum" },
    { salt_length: 32, security: "excellent", recommendation: "Ideal length" },
    { salt_length: 64, security: "overkill", recommendation: "Unnecessary but harmless" }
];
```

### TC407: bcrypt Cost Factor Testing
**วัตถุประสงค์:** ทดสอบ cost factor ของ bcrypt

**Test Data:**
```javascript
const bcryptCostTests = [
    // Different cost factors
    { cost: 4, iterations: 16, time_ms: 1, security: "too_low", year_appropriate: "1999" },
    { cost: 8, iterations: 256, time_ms: 15, security: "low", year_appropriate: "2005" },
    { cost: 10, iterations: 1024, time_ms: 60, security: "acceptable", year_appropriate: "2010" },
    { cost: 12, iterations: 4096, time_ms: 250, security: "good", year_appropriate: "2024" },
    { cost: 14, iterations: 16384, time_ms: 1000, security: "high", year_appropriate: "2030" },
    { cost: 16, iterations: 65536, time_ms: 4000, security: "very_high", year_appropriate: "2040" }
];
```

## นักศึกษาลองทำ

### Exercise 1: Password Strength Calculator
```javascript
// ให้นักศึกษาสร้าง password strength calculator
class PasswordStrengthCalculator {
    constructor() {
        this.commonPasswords = [
            // TODO: เพิ่ม list ของ common passwords
            "123456", "password", "123456789", "qwerty", "abc123"
        ];
        
        this.patterns = {
            // TODO: เพิ่ม regex patterns สำหรับตรวจสอบ
            lowercase: /[a-z]/,
            uppercase: /[A-Z]/,
            numbers: /[0-9]/,
            symbols: /[!@#$%^&*(),.?":{}|<>]/,
            sequential: /012|123|234|345|456|567|678|789|890|abc|bcd|cde|def/i,
            repeated: /(.)\1{2,}/,
            keyboard: /qwerty|asdf|zxcv|qwertyuiop/i
        };
    }
    
    calculateStrength(password) {
        let score = 0;
        const feedback = [];
        
        // TODO: นักศึกษาเขียน logic การคำนวณ
        
        // 1. ตรวจสอบความยาว
        if (password.length >= 8) {
            score += 1;
        } else {
            feedback.push("Use at least 8 characters");
        }
        
        // TODO: เพิ่มการตรวจสอบอื่นๆ
        // 2. ตรวจสอบ character types
        // 3. ตรวจสอบ common passwords
        // 4. ตรวจสอบ patterns
        // 5. คำนวณ entropy
        
        return {
            score: score,
            maxScore: 6,
            strength: this.getStrengthLabel(score),
            feedback: feedback,
            entropy: this.calculateEntropy(password),
            crackTime: this.estimateCrackTime(password)
        };
    }
    
    getStrengthLabel(score) {
        // TODO: แปลง score เป็น label
        const labels = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong"];
        return labels[Math.min(score, labels.length - 1)];
    }
    
    calculateEntropy(password) {
        // TODO: คำนวณ entropy ของรหัสผ่าน
        // Entropy = log2(charset_size^password_length)
    }
    
    estimateCrackTime(password) {
        // TODO: ประเมินเวลาที่ใช้ในการ crack
        // พิจารณาจาก entropy และ hash rate
    }
    
    isCommonPassword(password) {
        // TODO: ตรวจสอบว่าเป็น common password หรือไม่
    }
    
    detectPatterns(password) {
        // TODO: ตรวจจับ patterns ต่างๆ
    }
}

// Test cases สำหรับนักศึกษา
const testPasswords = [
    "123",
    "password",
    "Password1",
    "MySecure#Pass2024",
    "Tr0ub4dor&3"
];

// TODO: ทดสอบแต่ละรหัสผ่านและบันทึกผล
```

### Exercise 2: Hash Comparison Tool
```javascript
// ให้นักศึกษาสร้างเครื่องมือเปรียบเทียบ hash methods
class HashComparison {
    constructor() {
        this.hashMethods = ['md5', 'sha1', 'sha256', 'sha256_salted', 'bcrypt'];
    }
    
    async compareAllMethods(password) {
        const results = {};
        
        for (const method of this.hashMethods) {
            const startTime = Date.now();
            const hash = await this.hashPassword(password, method);
            const endTime = Date.now();
            
            results[method] = {
                hash: hash,
                time_ms: endTime - startTime,
                security_level: this.getSecurityLevel(method),
                crack_resistance: this.getCrackResistance(method)
            };
        }
        
        return results;
    }
    
    async hashPassword(password, method) {
        switch (method) {
            case 'md5':
                // TODO: implement MD5 hashing
                break;
            case 'sha1':
                // TODO: implement SHA1 hashing
                break;
            case 'sha256':
                // TODO: implement SHA256 hashing
                break;
            case 'sha256_salted':
                // TODO: implement SHA256 with salt
                break;
            case 'bcrypt':
                // TODO: implement bcrypt hashing
                break;
        }
    }
    
    getSecurityLevel(method) {
        // TODO: กำหนดระดับความปลอดภัยของแต่ละ method
    }
    
    getCrackResistance(method) {
        // TODO: ประเมินการต้านทานการ crack
    }
    
    demonstrateRainbowTableAttack() {
        // TODO: แสดงตัวอย่างการโจมตีด้วย rainbow table
        const commonPasswords = ["password", "123456", "qwerty"];
        
        // สร้าง rainbow table สำหรับ common passwords
        const rainbowTable = {};
        
        // TODO: สร้าง hash สำหรับ common passwords
        // TODO: แสดงว่าสามารถ reverse lookup ได้อย่างไร
    }
}

// การใช้งาน
const comparison = new HashComparison();

// TODO: เปรียบเทียบ methods ต่างๆ
const testPassword = "mypassword123";
comparison.compareAllMethods(testPassword).then(results => {
    // TODO: แสดงผลการเปรียบเทียบ
});
```

### Exercise 3: Password Policy Validator
```javascript
// ให้นักศึกษาสร้าง password policy validator
class PasswordPolicy {
    constructor(policyConfig = {}) {
        this.config = {
            minLength: policyConfig.minLength || 8,
            maxLength: policyConfig.maxLength || 128,
            requireUppercase: policyConfig.requireUppercase || true,
            requireLowercase: policyConfig.requireLowercase || true,
            requireNumbers: policyConfig.requireNumbers || true,
            requireSymbols: policyConfig.requireSymbols || true,
            forbidCommon: policyConfig.forbidCommon || true,
            forbidPersonalInfo: policyConfig.forbidPersonalInfo || true,
            maxRepeatedChars: policyConfig.maxRepeatedChars || 2,
            preventDictionary: policyConfig.preventDictionary || true,
            minUniqueChars: policyConfig.minUniqueChars || 6
        };
    }
    
    validatePassword(password, userInfo = {}) {
        const violations = [];
        
        // TODO: นักศึกษาเขียน validation logic
        
        // 1. ความยาว
        if (password.length < this.config.minLength) {
            violations.push(`Password must be at least ${this.config.minLength} characters`);
        }
        
        // TODO: เพิ่ม validations อื่นๆ
        // 2. Character requirements
        // 3. Common password check
        // 4. Personal information check
        // 5. Dictionary check
        // 6. Pattern analysis
        
        return {
            isValid: violations.length === 0,
            violations: violations,
            strength: this.calculateCompliance(password)
        };
    }
    
    calculateCompliance(password) {
        // TODO: คำนวณระดับการปฏิบัติตาม policy
    }
    
    generateSuggestions(password) {
        // TODO: สร้างคำแนะนำปรับปรุงรหัสผ่าน
    }
    
    // Different policy presets
    static getPolicyPreset(type) {
        const presets = {
            basic: {
                minLength: 6,
                requireUppercase: false,
                requireSymbols: false
            },
            standard: {
                minLength: 8,
                requireUppercase: true,
                requireNumbers: true,
                requireSymbols: false
            },
            strong: {
                minLength: 12,
                requireUppercase: true,
                requireLowercase: true,
                requireNumbers: true,
                requireSymbols: true,
                forbidCommon: true
            },
            enterprise: {
                minLength: 14,
                requireUppercase: true,
                requireLowercase: true,
                requireNumbers: true,
                requireSymbols: true,
                forbidCommon: true,
                forbidPersonalInfo: true,
                preventDictionary: true
            }
        };
        
        return presets[type] || presets.standard;
    }
}

// การทดสอบ policies ต่างๆ
const testCases = [
    {
        password: "password",
        userInfo: { name: "John", email: "john@example.com" },
        policies: ["basic", "standard", "strong", "enterprise"]
    },
    {
        password: "MySecure#Pass2024",
        userInfo: { name: "Jane", email: "jane@company.com" },
        policies: ["basic", "standard", "strong", "enterprise"]
    }
];

// TODO: ทดสอบแต่ละ policy และบันทึกผล
```

## คำถามวิเคราะห์

1. **Password Complexity vs Usability:**
   - ความซับซ้อนของรหัสผ่านกับความสะดวกในการใช้งาน
   - ผู้ใช้มักเลือกรหัสผ่านที่จำง่ายแต่ไม่ปลอดภัย จะแก้ไขอย่างไร?

2. **Hash Method Selection:**
   - ในปี 2024 ควรใช้ hash method ใด? เพราะอะไร?
   - bcrypt vs Argon2 vs scrypt แตกต่างกันอย่างไร?

3. **Password Manager Impact:**
   - Password managers เปลี่ยนแปลงแนวทางการสร้างรหัสผ่านอย่างไร?
   - ผลกระทบต่อ password policies ขององค์กร

4. **Future of Authentication:**
   - Passkeys และ WebAuthn จะทดแทนรหัสผ่านได้หรือไม่?
   - Multi-factor authentication มีความสำคัญอย่างไร?
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