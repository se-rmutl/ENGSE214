## Experiment 5: HTTP vs HTTPS Security Test Cases และ Implementation Guide

### 5.1 Protocol Security Test Cases

<artifacts>
<artifact identifier="http_https_complete_test_cases" type="text/markdown" title="HTTP vs HTTPS Complete Test Cases">
# HTTP vs HTTPS Security Test Cases

## Test Case Group 1: Data Transmission Security

### TC501: Plain Text vs Encrypted Data Transmission
**วัตถุประสงค์:** เปรียบเทียบการส่งข้อมูลผ่าน HTTP และ HTTPS

**Setup Environment:**
```javascript
// HTTP Server (ไม่เข้ารหัส)
const express = require('express');
const http = require('http');
const https = require('https');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(express.static('public'));

// Endpoint สำหรับทดสอบ
app.post('/sensitive-data', (req, res) => {
    const { creditCard, ssn, password } = req.body;
    
    console.log('--- SENSITIVE DATA RECEIVED ---');
    console.log('Credit Card:', creditCard);
    console.log('SSN:', ssn);
    console.log('Password:', password);
    console.log('Protocol:', req.secure ? 'HTTPS' : 'HTTP');
    console.log('Encrypted:', req.secure ? 'Yes' : 'No');
    
    res.json({
        received: true,
        protocol: req.secure ? 'HTTPS' : 'HTTP',
        secure: req.secure
    });
});

// HTTP Server
const httpServer = http.createServer(app);
httpServer.listen(3080, () => {
    console.log('HTTP Server (INSECURE) running on port 3080');
});

// HTTPS Server
const httpsOptions = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem')
};
const httpsServer = https.createServer(httpsOptions, app);
httpsServer.listen(3443, () => {
    console.log('HTTPS Server (SECURE) running on port 3443');
});
```

**Test Data:**
```javascript
const transmissionTests = [
    {
        testId: "TC501-1",
        protocol: "HTTP",
        url: "http://localhost:3080/sensitive-data",
        data: {
            creditCard: "4532-1234-5678-9012",
            ssn: "123-45-6789",
            password: "MySecretPassword123"
        },
        expected: {
            transmission: "plain_text",
            sniffable: true,
            mitm_vulnerable: true,
            data_visible: true,
            security_level: "none"
        }
    },
    {
        testId: "TC501-2",
        protocol: "HTTPS",
        url: "https://localhost:3443/sensitive-data",
        data: {
            creditCard: "4532-1234-5678-9012",
            ssn: "123-45-6789",
            password: "MySecretPassword123"
        },
        expected: {
            transmission: "encrypted",
            sniffable: false,
            mitm_vulnerable: false,
            data_visible: false,
            security_level: "high"
        }
    }
];
```

### TC502: Network Packet Analysis Simulation
**วัตถุประสงค์:** จำลองการดู network packets

**HTTP Packet Structure:**
```
GET /login?username=admin&password=secret HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Cookie: session=abc123xyz
Authorization: Basic YWRtaW46c2VjcmV0

POST /api/payment HTTP/1.1
Host: shop.com
Content-Type: application/json
Content-Length: 89

{
  "cardNumber": "4532123456789012",
  "cvv": "123",
  "amount": 1500.00
}
```

**HTTPS Packet Structure:**
```
TLS Record Layer: Handshake Protocol
    Handshake Type: Client Hello (1)
    TLS Version: TLS 1.3 (0x0304)

TLS Record Layer: Application Data Protocol
    Content Type: Application Data (23)
    Version: TLS 1.3 (0x0304)
    Length: 1024
    Encrypted Application Data: [ENCRYPTED CONTENT]
```

**Network Analysis Test:**
```javascript
const packetAnalysisTests = [
    {
        testId: "TC502-1",
        scenario: "HTTP Login Request",
        packet_content: "GET /login?username=admin&password=secret123 HTTP/1.1",
        attacker_can_see: {
            credentials: true,
            session_tokens: true,
            personal_data: true,
            api_keys: true,
            cookies: true
        },
        risk_level: "critical"
    },
    {
        testId: "TC502-2", 
        scenario: "HTTPS Login Request",
        packet_content: "[ENCRYPTED DATA - 2048 bytes]",
        attacker_can_see: {
            credentials: false,
            session_tokens: false,
            personal_data: false,
            api_keys: false,
            cookies: false,
            metadata_only: true
        },
        risk_level: "low"
    }
];
```

### TC503: Man-in-the-Middle Attack Simulation
**วัตถุประสงค์:** จำลองการโจมตี MITM

**Attack Simulation Code:**
```javascript
class MITMSimulator {
    constructor() {
        this.interceptedData = [];
        this.attackSuccess = false;
    }
    
    // จำลองการดักจับ HTTP traffic
    interceptHTTPTraffic(request) {
        console.log('🚨 MITM ATTACK: HTTP Traffic Intercepted!');
        
        const intercepted = {
            timestamp: new Date(),
            method: request.method,
            url: request.url,
            headers: request.headers,
            body: request.body,
            protocol: 'HTTP'
        };
        
        // ดึงข้อมูลสำคัญ
        const sensitiveData = this.extractSensitiveData(intercepted);
        
        this.interceptedData.push({
            ...intercepted,
            sensitive_data_found: sensitiveData,
            attack_success: true
        });
        
        console.log('💥 Stolen Data:', sensitiveData);
        return intercepted;
    }
    
    // จำลองการพยายามดักจับ HTTPS traffic
    interceptHTTPSTraffic(request) {
        console.log('🔒 MITM ATTACK: HTTPS Traffic Detected');
        
        const intercepted = {
            timestamp: new Date(),
            encrypted_data: '[ENCRYPTED - UNREADABLE]',
            packet_size: 2048,
            destination: request.destination,
            protocol: 'HTTPS'
        };
        
        this.interceptedData.push({
            ...intercepted,
            attack_success: false,
            reason: 'Data encrypted with TLS'
        });
        
        console.log('❌ Attack Failed: Cannot decrypt TLS traffic');
        return intercepted;
    }
    
    extractSensitiveData(request) {
        const sensitive = {};
        
        // ตรวจหาข้อมูลสำคัญ
        const content = JSON.stringify(request);
        
        // Credit cards
        const ccPattern = /\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}/g;
        const creditCards = content.match(ccPattern);
        if (creditCards) sensitive.credit_cards = creditCards;
        
        // Passwords
        const passwordPattern = /"password":\s*"([^"]+)"/gi;
        const passwords = [...content.matchAll(passwordPattern)].map(m => m[1]);
        if (passwords.length) sensitive.passwords = passwords;
        
        // Email addresses
        const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
        const emails = content.match(emailPattern);
        if (emails) sensitive.emails = emails;
        
        // API Keys
        const apiKeyPattern = /[Aa][Pp][Ii][-_]?[Kk][Ee][Yy][-_:]?\s*["']?([a-zA-Z0-9_-]{20,})/g;
        const apiKeys = [...content.matchAll(apiKeyPattern)].map(m => m[1]);
        if (apiKeys.length) sensitive.api_keys = apiKeys;
        
        return sensitive;
    }
    
    generateAttackReport() {
        const httpAttacks = this.interceptedData.filter(d => d.protocol === 'HTTP');
        const httpsAttacks = this.interceptedData.filter(d => d.protocol === 'HTTPS');
        
        return {
            total_attempts: this.interceptedData.length,
            successful_attacks: httpAttacks.filter(a => a.attack_success).length,
            failed_attacks: httpsAttacks.length,
            stolen_data_types: this.categorizeStoredData(),
            recommendation: this.generateRecommendation()
        };
    }
    
    categorizeStoredData() {
        const categories = {};
        
        this.interceptedData.forEach(data => {
            if (data.sensitive_data_found) {
                Object.keys(data.sensitive_data_found).forEach(type => {
                    categories[type] = (categories[type] || 0) + 1;
                });
            }
        });
        
        return categories;
    }
    
    generateRecommendation() {
        const recommendations = [];
        
        if (this.interceptedData.some(d => d.protocol === 'HTTP' && d.attack_success)) {
            recommendations.push("CRITICAL: Migrate all traffic to HTTPS immediately");
            recommendations.push("HTTP traffic is completely visible to attackers");
        }
        
        if (this.interceptedData.some(d => d.protocol === 'HTTPS')) {
            recommendations.push("GOOD: HTTPS traffic is protected from interception");
        }
        
        return recommendations;
    }
}
```

**Attack Scenarios:**
```javascript
const mitmScenarios = [
    {
        testId: "TC503-1",
        scenario: "Public WiFi HTTP Attack",
        setup: "Attacker controls router in coffee shop",
        target: "HTTP banking site",
        attack_vector: "ARP spoofing + packet sniffing",
        success_probability: "100%",
        data_at_risk: [
            "Login credentials",
            "Account numbers", 
            "Transaction details",
            "Session cookies"
        ],
        impact: "Complete account compromise"
    },
    {
        testId: "TC503-2",
        scenario: "Public WiFi HTTPS Protection",
        setup: "Same attacker, same network",
        target: "HTTPS banking site",
        attack_vector: "Packet sniffing",
        success_probability: "0%",
        data_at_risk: [
            "Connection metadata only"
        ],
        impact: "No sensitive data compromised"
    },
    {
        testId: "TC503-3",
        scenario: "DNS Hijacking HTTP",
        setup: "Attacker controls DNS server",
        target: "HTTP e-commerce site",
        attack_vector: "DNS spoofing to malicious server",
        success_probability: "95%",
        data_at_risk: [
            "Credit card details",
            "Personal information",
            "Shopping history"
        ],
        impact: "Financial fraud"
    },
    {
        testId: "TC503-4",
        scenario: "DNS Hijacking HTTPS",
        setup: "Same DNS attack",
        target: "HTTPS e-commerce site", 
        attack_vector: "DNS spoofing",
        success_probability: "5%",
        data_at_risk: [],
        impact: "Browser shows certificate warning, user protected"
    }
];
```

## Test Case Group 2: Certificate and TLS Security

### TC504: SSL Certificate Validation
**วัตถุประสงค์:** ทดสอบการตรวจสอบ SSL certificates

**Certificate Test Implementation:**
```javascript
class CertificateValidator {
    constructor() {
        this.validationResults = [];
    }
    
    async validateCertificate(hostname, port = 443) {
        try {
            const cert = await this.getCertificateInfo(hostname, port);
            const validation = this.performValidation(cert, hostname);
            
            this.validationResults.push({
                hostname,
                port,
                certificate: cert,
                validation: validation,
                timestamp: new Date()
            });
            
            return validation;
        } catch (error) {
            return {
                valid: false,
                error: error.message,
                security_risk: "high"
            };
        }
    }
    
    performValidation(cert, expectedHostname) {
        const validation = {
            valid: true,
            issues: [],
            warnings: [],
            security_score: 100
        };
        
        // 1. วันหมดอายุ
        if (new Date(cert.valid_to) < new Date()) {
            validation.valid = false;
            validation.issues.push("Certificate has expired");
            validation.security_score -= 50;
        } else if (new Date(cert.valid_to) < new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)) {
            validation.warnings.push("Certificate expires within 30 days");
            validation.security_score -= 10;
        }
        
        // 2. Subject Alternative Name
        if (!this.checkHostnameMatch(cert, expectedHostname)) {
            validation.valid = false;
            validation.issues.push("Hostname does not match certificate");
            validation.security_score -= 40;
        }
        
        // 3. Certificate Authority
        if (!this.isTrustedCA(cert.issuer)) {
            validation.valid = false;
            validation.issues.push("Certificate issued by untrusted CA");
            validation.security_score -= 30;
        }
        
        // 4. Key strength
        if (cert.bits < 2048) {
            validation.warnings.push("Key strength below 2048 bits");
            validation.security_score -= 20;
        }
        
        // 5. Signature algorithm
        if (this.isWeakSignatureAlgorithm(cert.signatureAlgorithm)) {
            validation.issues.push("Weak signature algorithm");
            validation.security_score -= 25;
        }
        
        return validation;
    }
    
    checkHostnameMatch(cert, hostname) {
        // ตรวจสอบ Subject Alternative Names
        if (cert.subjectaltname) {
            const sans = cert.subjectaltname.split(', ').map(san => 
                san.replace('DNS:', '').toLowerCase()
            );
            
            return sans.some(san => {
                if (san.startsWith('*.')) {
                    // Wildcard certificate
                    const domain = san.substring(2);
                    return hostname.endsWith('.' + domain) || hostname === domain;
                }
                return san === hostname.toLowerCase();
            });
        }
        
        // ตรวจสอบ Common Name
        return cert.subject.CN === hostname;
    }
    
    isTrustedCA(issuer) {
        const trustedCAs = [
            'Let\'s Encrypt',
            'DigiCert',
            'Comodo',
            'GlobalSign',
            'GeoTrust',
            'Symantec',
            'VeriSign'
        ];
        
        return trustedCAs.some(ca => issuer.includes(ca));
    }
    
    isWeakSignatureAlgorithm(algorithm) {
        const weakAlgorithms = [
            'md5WithRSAEncryption',
            'sha1WithRSAEncryption'
        ];
        
        return weakAlgorithms.includes(algorithm);
    }
    
    async getCertificateInfo(hostname, port) {
        // จำลองการดึงข้อมูล certificate
        // ในการใช้งานจริงจะใช้ tls.connect()
        return {
            subject: { CN: hostname },
            issuer: 'Let\'s Encrypt Authority X3',
            valid_from: '2024-01-01T00:00:00.000Z',
            valid_to: '2024-12-31T23:59:59.000Z',
            subjectaltname: `DNS:${hostname}, DNS:www.${hostname}`,
            bits: 2048,
            signatureAlgorithm: 'sha256WithRSAEncryption'
        };
    }
}
```

**Certificate Test Cases:**
```javascript
const certificateTests = [
    {
        testId: "TC504-1",
        description: "Valid CA-signed certificate",
        hostname: "github.com",
        expected: {
            valid: true,
            trusted: true,
            issues: [],
            security_score: 95
        }
    },
    {
        testId: "TC504-2", 
        description: "Self-signed certificate",
        hostname: "self-signed.badssl.com",
        expected: {
            valid: false,
            trusted: false,
            issues: ["Certificate issued by untrusted CA"],
            security_score: 70
        }
    },
    {
        testId: "TC504-3",
        description: "Expired certificate",
        hostname: "expired.badssl.com",
        expected: {
            valid: false,
            trusted: false,
            issues: ["Certificate has expired"],
            security_score: 50
        }
    },
    {
        testId: "TC504-4",
        description: "Wrong hostname certificate",
        hostname: "wrong.host.badssl.com",
        expected: {
            valid: false,
            trusted: false,
            issues: ["Hostname does not match certificate"],
            security_score: 60
        }
    }
];
```

### TC505: TLS Version and Cipher Suite Testing
**วัตถุประสงค์:** ทดสอบ TLS versions และ cipher suites

**TLS Testing Implementation:**
```javascript
class TLSSecurityTester {
    constructor() {
        this.supportedVersions = [];
        this.supportedCiphers = [];
        this.securityScore = 0;
    }
    
    async testTLSConfiguration(hostname, port = 443) {
        const results = {
            hostname: hostname,
            port: port,
            timestamp: new Date(),
            tls_versions: await this.testTLSVersions(hostname, port),
            cipher_suites: await this.testCipherSuites(hostname, port),
            security_assessment: {}
        };
        
        results.security_assessment = this.assessSecurity(results);
        return results;
    }
    
    async testTLSVersions(hostname, port) {
        const versions = [
            { name: 'SSLv3', secure: false, year: 1996 },
            { name: 'TLSv1.0', secure: false, year: 1999 },
            { name: 'TLSv1.1', secure: false, year: 2006 },
            { name: 'TLSv1.2', secure: true, year: 2008 },
            { name: 'TLSv1.3', secure: true, year: 2018 }
        ];
        
        const results = [];
        
        for (const version of versions) {
            const isSupported = await this.checkTLSVersion(hostname, port, version.name);
            results.push({
                version: version.name,
                supported: isSupported,
                secure: version.secure,
                year: version.year,
                recommendation: this.getTLSRecommendation(version)
            });
        }
        
        return results;
    }
    
    async testCipherSuites(hostname, port) {
        // จำลองการทดสอบ cipher suites
        const commonCiphers = [
            {
                name: 'TLS_AES_256_GCM_SHA384',
                security_level: 'excellent',
                tls_version: '1.3',
                pfs: true,
                aead: true
            },
            {
                name: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                security_level: 'good',
                tls_version: '1.2',
                pfs: true,
                aead: true
            },
            {
                name: 'TLS_RSA_WITH_AES_128_CBC_SHA',
                security_level: 'weak',
                tls_version: '1.0+',
                pfs: false,
                aead: false
            },
            {
                name: 'TLS_RSA_WITH_RC4_128_MD5',
                security_level: 'insecure',
                tls_version: '1.0+',
                pfs: false,
                aead: false
            }
        ];
        
        // จำลองการตรวจสอบ
        const supportedCiphers = commonCiphers.filter(cipher => 
            Math.random() > (cipher.security_level === 'insecure' ? 0.8 : 0.3)
        );
        
        return supportedCiphers.map(cipher => ({
            ...cipher,
            recommendation: this.getCipherRecommendation(cipher)
        }));
    }
    
    assessSecurity(results) {
        let score = 0;
        let maxScore = 100;
        const issues = [];
        const recommendations = [];
        
        // TLS Version Assessment
        const tlsVersions = results.tls_versions;
        const hasSecureTLS = tlsVersions.some(v => v.supported && v.secure);
        const hasInsecureTLS = tlsVersions.some(v => v.supported && !v.secure);
        
        if (hasSecureTLS) {
            score += 40;
        } else {
            issues.push("No secure TLS versions supported");
        }
        
        if (hasInsecureTLS) {
            score -= 20;
            issues.push("Insecure TLS versions still enabled");
            recommendations.push("Disable TLS 1.0, 1.1 and SSLv3");
        }
        
        // Cipher Suite Assessment
        const ciphers = results.cipher_suites;
        const excellentCiphers = ciphers.filter(c => c.security_level === 'excellent');
        const insecureCiphers = ciphers.filter(c => c.security_level === 'insecure');
        
        if (excellentCiphers.length > 0) {
            score += 30;
        }
        
        if (insecureCiphers.length > 0) {
            score -= 30;
            issues.push("Insecure cipher suites enabled");
            recommendations.push("Remove weak cipher suites");
        }
        
        // Perfect Forward Secrecy
        const pfsCiphers = ciphers.filter(c => c.pfs);
        if (pfsCiphers.length > 0) {
            score += 20;
        } else {
            issues.push("No Perfect Forward Secrecy support");
            recommendations.push("Enable ECDHE cipher suites");
        }
        
        // AEAD Support
        const aeadCiphers = ciphers.filter(c => c.aead);
        if (aeadCiphers.length > 0) {
            score += 10;
        } else {
            recommendations.push("Enable AEAD cipher suites for better security");
        }
        
        return {
            score: Math.max(0, Math.min(100, score)),
            grade: this.scoreToGrade(score),
            issues: issues,
            recommendations: recommendations
        };
    }
    
    scoreToGrade(score) {
        if (score >= 90) return 'A+';
        if (score >= 80) return 'A';
        if (score >= 70) return 'B';
        if (score >= 60) return 'C';
        if (score >= 50) return 'D';
        return 'F';
    }
    
    getTLSRecommendation(version) {
        switch (version.name) {
            case 'SSLv3':
            case 'TLSv1.0':
            case 'TLSv1.1':
                return 'DISABLE - Insecure and deprecated';
            case 'TLSv1.2':
                return 'ACCEPTABLE - Minimum recommended version';
            case 'TLSv1.3':
                return 'RECOMMENDED - Latest and most secure';
            default:
                return 'UNKNOWN';
        }
    }
    
    getCipherRecommendation(cipher) {
        switch (cipher.security_level) {
            case 'excellent':
                return 'RECOMMENDED - Modern and secure';
            case 'good':
                return 'ACCEPTABLE - Good security';
            case 'weak':
                return 'AVOID - Consider disabling';
            case 'insecure':
                return 'DISABLE - Security risk';
            default:
                return 'REVIEW NEEDED';
        }
    }
    
    // Helper methods (จำลอง)
    async checkTLSVersion(hostname, port, version) {
        // ในการใช้งานจริงจะใช้ tls.connect() กับ version ที่ระบุ
        const insecureVersions = ['SSLv3', 'TLSv1.0', 'TLSv1.1'];
        return Math.random() > (insecureVersions.includes(version) ? 0.7 : 0.2);
    }
}
```

## นักศึกษาลองทำ

### Exercise 1: HTTP vs HTTPS Comparison Tool
```javascript
// ให้นักศึกษาสร้างเครื่องมือเปรียบเทียบ HTTP และ HTTPS
class HTTPSComparisonTool {
    constructor() {
        this.testResults = [];
        this.securityAnalysis = {};
    }
    
    async runComparisonTest(testData) {
        const results = {
            testId: testData.testId,
            timestamp: new Date(),
            http_test: await this.testHTTP(testData.http_endpoint, testData.payload),
            https_test: await this.testHTTPS(testData.https_endpoint, testData.payload),
            comparison: {}
        };
        
        results.comparison = this.compareResults(results.http_test, results.https_test);
        this.testResults.push(results);
        
        return results;
    }
    
    async testHTTP(endpoint, payload) {
        // TODO: นักศึกษาเขียนการทดสอบ HTTP
        const startTime = Date.now();
        
        try {
            // จำลองการส่งข้อมูลผ่าน HTTP
            const response = await this.sendRequest('HTTP', endpoint, payload);
            const endTime = Date.now();
            
            return {
                success: true,
                response_time: endTime - startTime,
                protocol: 'HTTP',
                encrypted: false,
                data_visible: true,
                security_level: 'none',
                vulnerability_score: 100, // สูงสุด = อันตรายสุด
                response: response
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message,
                protocol: 'HTTP'
            };
        }
    }
    
    async testHTTPS(endpoint, payload) {
        // TODO: นักศึกษาเขียนการทดสอบ HTTPS
        const startTime = Date.now();
        
        try {
            const response = await this.sendRequest('HTTPS', endpoint, payload);
            const endTime = Date.now();
            
            return {
                success: true,
                response_time: endTime - startTime,
                protocol: 'HTTPS',
                encrypted: true,
                data_visible: false,
                security_level: 'high',
                vulnerability_score: 10, // ต่ำ = ปลอดภัย
                tls_version: response.tls_version || 'TLS 1.3',
                cipher_suite: response.cipher_suite || 'TLS_AES_256_GCM_SHA384',
                response: response
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message,
                protocol: 'HTTPS'
            };
        }
    }
    
    compareResults(httpResult, httpsResult) {
        // TODO: นักศึกษาเขียนการเปรียบเทียบ
        const comparison = {
            security_difference: httpsResult.vulnerability_score - httpResult.vulnerability_score,
            performance_difference: httpsResult.response_time - httpResult.response_time,
            encryption_benefit: httpsResult.encrypted && !httpResult.encrypted,
            recommendation: ''
        };
        
        // สร้างคำแนะนำ
        if (comparison.security_difference < -50) {
            comparison.recommendation = 'CRITICAL: Migrate to HTTPS immediately for security';
        } else if (comparison.performance_difference < 100) {
            comparison.recommendation = 'RECOMMENDED: HTTPS provides security with minimal performance impact';
        }
        
        return comparison;
    }
    
    async sendRequest(protocol, endpoint, payload) {
        // TODO: จำลองการส่ง request
        // ในการทดสอบจริงจะใช้ fetch() หรือ axios
        
        const simulatedResponse = {
            status: 200,
            data: { received: true },
            protocol: protocol,
            tls_version: protocol === 'HTTPS' ? 'TLS 1.3' : undefined,
            cipher_suite: protocol === 'HTTPS' ? 'TLS_AES_256_GCM_SHA384' : undefined
        };
        
        // จำลอง network delay
        await new Promise(resolve => setTimeout(resolve, Math.random() * 100));
        
        return simulatedResponse;
    }
    
    generateSecurityReport() {
        // TODO: นักศึกษาสร้างรายงานความปลอดภัย
        const report = {
            total_tests: this.testResults.length,
            http_vulnerabilities: 0,
            https_protections: 0,
            security_improvements: [],
            recommendations: []
        };
        
        this.testResults.forEach(result => {
            if (result.http_test.success && result.http_test.vulnerability_score > 50) {
                report.http_vulnerabilities++;
            }
            
            if (result.https_test.success && result.https_test.vulnerability_score < 30) {
                report.https_protections++;
            }
        });
        
        // สร้างคำแนะนำ
        if (report.http_vulnerabilities > 0) {
            report.recommendations.push('Disable HTTP for sensitive operations');
            report.recommendations.push('Implement HTTPS redirects');
            report.recommendations.push('Use HSTS headers to force HTTPS');
        }
        
        return report;
    }

    async runAllTests() {
        const testScenarios = [
            {
                testId: 'COMP-001',
                description: 'Login credentials transmission',
                http_endpoint: 'http://localhost:3080/login',
                https_endpoint: 'https://localhost:3443/login',
                payload: { username: 'admin', password: 'secret123' }
            },
            {
                testId: 'COMP-002', 
                description: 'Credit card payment',
                http_endpoint: 'http://localhost:3080/payment',
                https_endpoint: 'https://localhost:3443/payment',
                payload: {
                    cardNumber: '4532-1234-5678-9012',
                    cvv: '123',
                    amount: 299.99
                }
            },
            {
                testId: 'COMP-003',
                description: 'Personal data update',
                http_endpoint: 'http://localhost:3080/profile',
                https_endpoint: 'https://localhost:3443/profile', 
                payload: {
                    ssn: '123-45-6789',
                    address: '123 Main St',
                    phone: '555-1234'
                }
            }
        ];
        
        for (const scenario of testScenarios) {
            const result = await this.runComparisonTest(scenario);
            console.log(`Test ${scenario.testId} completed:`, result.comparison);
        }
        
        return this.generateSecurityReport();
    }
}

// การใช้งาน
const comparisonTool = new HTTPSComparisonTool();

// TODO: นักศึกษารันการทดสอบและวิเคราะห์ผล
comparisonTool.runAllTests().then(report => {
    console.log('Security Analysis Report:', report);
});
```

### Exercise 2: Network Security Analyzer
```javascript
// ให้นักศึกษาสร้างเครื่องมือวิเคราะห์ความปลอดภัยของ network
class NetworkSecurityAnalyzer {
    constructor() {
        this.trafficLog = [];
        this.securityEvents = [];
        this.threats = [];
    }
    
    // จำลองการ monitor network traffic
    monitorTraffic(connection) {
        const traffic = {
            timestamp: new Date(),
            source: connection.source,
            destination: connection.destination,
            protocol: connection.protocol,
            port: connection.port,
            data_size: connection.data_size,
            encrypted: connection.protocol === 'HTTPS'
        };
        
        this.trafficLog.push(traffic);
        this.analyzeTrafficSecurity(traffic);
        
        return traffic;
    }
    
    analyzeTrafficSecurity(traffic) {
        // TODO: นักศึกษาเขียนการวิเคราะห์
        const analysis = {
            traffic_id: traffic.timestamp.getTime(),
            security_level: this.calculateSecurityLevel(traffic),
            vulnerabilities: this.detectVulnerabilities(traffic),
            recommendations: []
        };
        
        // ตรวจสอบการเข้ารหัส
        if (!traffic.encrypted) {
            analysis.vulnerabilities.push({
                type: 'unencrypted_transmission',
                severity: 'high',
                description: 'Data transmitted without encryption'
            });
            analysis.recommendations.push('Use HTTPS for all sensitive data');
        }
        
        // ตรวจสอบ port ที่อันตราย
        const dangerousPorts = [21, 23, 53, 80, 110, 143];
        if (dangerousPorts.includes(traffic.port)) {
            analysis.vulnerabilities.push({
                type: 'insecure_port',
                severity: 'medium',
                description: `Using potentially insecure port ${traffic.port}`
            });
        }
        
        this.securityEvents.push(analysis);
        return analysis;
    }
    
    calculateSecurityLevel(traffic) {
        let score = 0;
        
        // Protocol security
        if (traffic.protocol === 'HTTPS') score += 40;
        else if (traffic.protocol === 'HTTP') score -= 30;
        
        // Port security
        const securePorts = [443, 993, 995];
        if (securePorts.includes(traffic.port)) score += 20;
        
        // Data size (larger transfers need more protection)
        if (traffic.data_size > 1000000 && !traffic.encrypted) score -= 20;
        
        score = Math.max(0, Math.min(100, score + 50)); // Normalize to 0-100
        
        if (score >= 80) return 'high';
        if (score >= 60) return 'medium';  
        if (score >= 40) return 'low';
        return 'critical';
    }
    
    detectVulnerabilities(traffic) {
        const vulnerabilities = [];
        
        // TODO: นักศึกษาเพิ่มการตรวจจับ vulnerabilities
        
        // 1. Plain text protocols
        const plainTextProtocols = ['HTTP', 'FTP', 'TELNET', 'SMTP'];
        if (plainTextProtocols.includes(traffic.protocol)) {
            vulnerabilities.push({
                type: 'plain_text_protocol',
                severity: 'high',
                description: `${traffic.protocol} transmits data in plain text`
            });
        }
        
        // 2. Suspicious data patterns
        if (traffic.data_size > 0) {
            // จำลองการตรวจสอบ payload patterns
            vulnerabilities.push(...this.analyzePayloadPatterns(traffic));
        }
        
        return vulnerabilities;
    }
    
    analyzePayloadPatterns(traffic) {
        const patterns = [];
        
        // TODO: นักศึกษาสร้างการตรวจจับ patterns อันตราย
        // ในการใช้งานจริงจะ inspect actual packet content
        
        // จำลอง pattern detection
        if (traffic.protocol === 'HTTP' && traffic.port === 80) {
            patterns.push({
                type: 'potential_credential_leak',
                severity: 'critical',
                description: 'HTTP traffic may contain exposed credentials'
            });
        }
        
        return patterns;
    }
    
    generateThreatAssessment() {
        // TODO: นักศึกษาสร้างการประเมินภัยคุกคาม
        const assessment = {
            timestamp: new Date(),
            total_connections: this.trafficLog.length,
            encrypted_connections: this.trafficLog.filter(t => t.encrypted).length,
            unencrypted_connections: this.trafficLog.filter(t => !t.encrypted).length,
            security_distribution: {},
            high_risk_connections: [],
            recommendations: []
        };
        
        // Security level distribution
        const levels = ['critical', 'low', 'medium', 'high'];
        levels.forEach(level => {
            assessment.security_distribution[level] = this.securityEvents.filter(
                e => e.security_level === level
            ).length;
        });
        
        // High risk connections
        assessment.high_risk_connections = this.securityEvents
            .filter(e => e.security_level === 'critical')
            .map(e => ({
                traffic_id: e.traffic_id,
                vulnerabilities: e.vulnerabilities.length,
                primary_threat: e.vulnerabilities[0]?.type || 'unknown'
            }));
        
        // Generate recommendations
        if (assessment.unencrypted_connections > 0) {
            assessment.recommendations.push({
                priority: 'high',
                action: 'Encrypt all network communications',
                description: `${assessment.unencrypted_connections} unencrypted connections detected`
            });
        }
        
        return assessment;
    }
    
    simulateNetworkAttack(attackType) {
        // TODO: นักศึกษาจำลองการโจมตี
        const attacks = {
            'packet_sniffing': this.simulatePacketSniffing(),
            'mitm': this.simulateMITMAttack(),
            'dns_poisoning': this.simulateDNSPoisoning()
        };
        
        return attacks[attackType] || { error: 'Unknown attack type' };
    }
    
    simulatePacketSniffing() {
        // จำลอง packet sniffing attack
        const vulnerableConnections = this.trafficLog.filter(t => !t.encrypted);
        
        return {
            attack_type: 'packet_sniffing',
            success: vulnerableConnections.length > 0,
            captured_data: vulnerableConnections.map(conn => ({
                source: conn.source,
                destination: conn.destination,
                data_visible: true,
                risk: 'All transmitted data compromised'
            })),
            mitigation: 'Use HTTPS/TLS encryption for all communications'
        };
    }
    
    simulateMITMAttack() {
        // จำลอง Man-in-the-Middle attack
        const httpConnections = this.trafficLog.filter(t => t.protocol === 'HTTP');
        
        return {
            attack_type: 'man_in_the_middle',
            success: httpConnections.length > 0,
            compromised_connections: httpConnections.length,
            impact: 'Attacker can intercept and modify all HTTP traffic',
            mitigation: 'Implement HTTPS with certificate validation'
        };
    }
    
    simulateDNSPoisoning() {
        // จำลอง DNS poisoning attack
        return {
            attack_type: 'dns_poisoning',
            success: true,
            impact: 'Users redirected to malicious servers',
            affected_protocols: ['HTTP'],
            mitigation: 'Use HTTPS to detect certificate mismatches'
        };
    }
}

// Test scenarios
const analyzer = new NetworkSecurityAnalyzer();

// จำลอง network traffic
const testConnections = [
    { source: 'user_pc', destination: 'bank.com', protocol: 'HTTPS', port: 443, data_size: 2048 },
    { source: 'user_pc', destination: 'social.com', protocol: 'HTTP', port: 80, data_size: 5120 },
    { source: 'user_pc', destination: 'email.com', protocol: 'HTTP', port: 80, data_size: 1024 },
    { source: 'user_pc', destination: 'secure-shop.com', protocol: 'HTTPS', port: 443, data_size: 3072 }
];

// TODO: นักศึกษา monitor traffic และวิเคราะห์
testConnections.forEach(conn => {
    analyzer.monitorTraffic(conn);
});

// TODO: สร้างรายงานและทดสอบการโจมตี
const assessment = analyzer.generateThreatAssessment();
const sniffingAttack = analyzer.simulateNetworkAttack('packet_sniffing');
console.log('Threat Assessment:', assessment);
console.log('Packet Sniffing Attack:', sniffingAttack);
```

### Exercise 3: HTTPS Implementation Checker
```javascript
// ให้นักศึกษาสร้างเครื่องมือตรวจสอบการ implement HTTPS
class HTTPSImplementationChecker {
    constructor() {
        this.checkResults = [];
        this.bestPractices = [
            'force_https_redirect',
            'hsts_header',
            'secure_cookies',
            'csp_header',
            'tls_version',
            'cipher_suites',
            'certificate_validity'
        ];
    }
    
    async checkImplementation(domain) {
        const results = {
            domain: domain,
            timestamp: new Date(),
            checks: {},
            overall_score: 0,
            grade: 'F',
            recommendations: []
        };
        
        // รันการตรวจสอบแต่ละข้อ
        for (const check of this.bestPractices) {
            try {
                results.checks[check] = await this.runCheck(check, domain);
            } catch (error) {
                results.checks[check] = {
                    passed: false,
                    error: error.message,
                    score: 0
                };
            }
        }
        
        // คำนวณคะแนนรวม
        results.overall_score = this.calculateOverallScore(results.checks);
        results.grade = this.scoreToGrade(results.overall_score);
        results.recommendations = this.generateRecommendations(results.checks);
        
        this.checkResults.push(results);
        return results;
    }
    
    async runCheck(checkType, domain) {
        switch (checkType) {
            case 'force_https_redirect':
                return await this.checkHTTPSRedirect(domain);
            case 'hsts_header':
                return await this.checkHSTSHeader(domain);
            case 'secure_cookies':
                return await this.checkSecureCookies(domain);
            case 'csp_header':
                return await this.checkCSPHeader(domain);
            case 'tls_version':
                return await this.checkTLSVersion(domain);
            case 'cipher_suites':
                return await this.checkCipherSuites(domain);
            case 'certificate_validity':
                return await this.checkCertificateValidity(domain);
            default:
                throw new Error(`Unknown check type: ${checkType}`);
        }
    }
    
    async checkHTTPSRedirect(domain) {
        // TODO: นักศึกษาเขียนการตรวจสอบ HTTPS redirect
        try {
            // จำลองการตรวจสอบ HTTP -> HTTPS redirect
            const httpResponse = await this.makeRequest(`http://${domain}`);
            
            const hasRedirect = httpResponse.status === 301 || httpResponse.status === 302;
            const redirectsToHTTPS = httpResponse.location && httpResponse.location.startsWith('https://');
            
            return {
                passed: hasRedirect && redirectsToHTTPS,
                score: (hasRedirect && redirectsToHTTPS) ? 100 : 0,
                details: {
                    status_code: httpResponse.status,
                    location: httpResponse.location,
                    redirect_type: hasRedirect ? 'permanent' : 'none'
                },
                description: 'HTTP requests are redirected to HTTPS'
            };
        } catch (error) {
            return {
                passed: false,
                score: 0,
                error: error.message
            };
        }
    }
    
    async checkHSTSHeader(domain) {
        // TODO: นักศึกษาตรวจสอบ HSTS header
        try {
            const response = await this.makeRequest(`https://${domain}`);
            const hstsHeader = response.headers['strict-transport-security'];
            
            if (!hstsHeader) {
                return {
                    passed: false,
                    score: 0,
                    description: 'HSTS header not present'
                };
            }
            
            // วิเคราะห์ HSTS header
            const analysis = this.analyzeHSTSHeader(hstsHeader);
            
            return {
                passed: analysis.score > 50,
                score: analysis.score,
                details: analysis.details,
                description: 'HTTP Strict Transport Security configuration'
            };
            
        } catch (error) {
            return {
                passed: false,
                score: 0,
                error: error.message
            };
        }
    }
    
    analyzeHSTSHeader(headerValue) {
        let score = 10; // Base score for having the header
        const details = { value: headerValue };
        
        // Check max-age
        const maxAgeMatch = headerValue.match(/max-age=(\d+)/);
        if (maxAgeMatch) {
            const maxAge = parseInt(maxAgeMatch[1]);
            details.max_age = maxAge;
            
            if (maxAge >= 31536000) { // 1 year
                score += 40;
                details.max_age_assessment = 'excellent';
            } else if (maxAge >= 2592000) { // 1 month
                score += 25;
                details.max_age_assessment = 'good';
            } else {
                score += 10;
                details.max_age_assessment = 'too_short';
            }
        }
        
        // Check includeSubDomains
        if (headerValue.includes('includeSubDomains')) {
            score += 25;
            details.include_subdomains = true;
        }
        
        // Check preload
        if (headerValue.includes('preload')) {
            score += 25;
            details.preload = true;
        }
        
        return { score, details };
    }
    
    async checkSecureCookies(domain) {
        // TODO: ตรวจสอบ secure cookie attributes
        try {
            const response = await this.makeRequest(`https://${domain}/login`);
            const cookies = this.parseCookies(response.headers['set-cookie'] || []);
            
            let secureCount = 0;
            let httpOnlyCount = 0;
            let sameSiteCount = 0;
            
            cookies.forEach(cookie => {
                if (cookie.secure) secureCount++;
                if (cookie.httpOnly) httpOnlyCount++;
                if (cookie.sameSite) sameSiteCount++;
            });
            
            const totalCookies = cookies.length;
            const score = totalCookies > 0 ? 
                ((secureCount + httpOnlyCount + sameSiteCount) / (totalCookies * 3)) * 100 : 100;
            
            return {
                passed: score > 70,
                score: Math.round(score),
                details: {
                    total_cookies: totalCookies,
                    secure_cookies: secureCount,
                    httponly_cookies: httpOnlyCount,
                    samesite_cookies: sameSiteCount
                },
                description: 'Cookie security attributes'
            };
            
        } catch (error) {
            return {
                passed: false,
                score: 0,
                error: error.message
            };
        }
    }
    
    async checkCSPHeader(domain) {
        // TODO: ตรวจสอบ Content Security Policy
        try {
            const response = await this.makeRequest(`https://${domain}`);
            const cspHeader = response.headers['content-security-policy'];
            
            if (!cspHeader) {
                return {
                    passed: false,
                    score: 0,
                    description: 'CSP header not present'
                };
            }
            
            const analysis = this.analyzeCSPHeader(cspHeader);
            
            return {
                passed: analysis.score > 50,
                score: analysis.score,
                details: analysis.details,
                description: 'Content Security Policy configuration'
            };
            
        } catch (error) {
            return {
                passed: false,
                score: 0,
                error: error.message
            };
        }
    }
    
    analyzeCSPHeader(cspHeader) {
        let score = 20; // Base score for having CSP
        const details = { directives: {} };
        
        // Parse CSP directives
        const directives = cspHeader.split(';').map(d => d.trim());
        
        directives.forEach(directive => {
            const [name, ...values] = directive.split(/\s+/);
            details.directives[name] = values;
            
            // Score based on directive
            switch (name) {
                case 'default-src':
                    score += 15;
                    break;
                case 'script-src':
                    score += 20;
                    if (values.includes("'unsafe-inline'")) score -= 10;
                    if (values.includes("'unsafe-eval'")) score -= 15;
                    break;
                case 'object-src':
                    score += 10;
                    break;
                case 'frame-ancestors':
                    score += 10;
                    break;
            }
        });
        
        return { score: Math.min(100, score), details };
    }
    
    calculateOverallScore(checks) {
        const weights = {
            'force_https_redirect': 15,
            'hsts_header': 15,
            'secure_cookies': 10,
            'csp_header': 10,
            'tls_version': 20,
            'cipher_suites': 15,
            'certificate_validity': 15
        };
        
        let totalScore = 0;
        let totalWeight = 0;
        
        Object.entries(checks).forEach(([checkName, result]) => {
            const weight = weights[checkName] || 10;
            totalScore += (result.score || 0) * weight / 100;
            totalWeight += weight;
        });
        
        return Math.round((totalScore / totalWeight) * 100);
    }
    
    scoreToGrade(score) {
        if (score >= 95) return 'A+';
        if (score >= 90) return 'A';
        if (score >= 80) return 'B';
        if (score >= 70) return 'C';
        if (score >= 60) return 'D';
        return 'F';
    }
    
    generateRecommendations(checks) {
        const recommendations = [];
        
        Object.entries(checks).forEach(([checkName, result]) => {
            if (!result.passed) {
                switch (checkName) {
                    case 'force_https_redirect':
                        recommendations.push({
                            priority: 'high',
                            issue: 'Missing HTTPS redirect',
                            action: 'Configure server to redirect HTTP to HTTPS'
                        });
                        break;
                    case 'hsts_header':
                        recommendations.push({
                            priority: 'high',
                            issue: 'Missing HSTS header',
                            action: 'Add Strict-Transport-Security header'
                        });
                        break;
                    // TODO: เพิ่ม recommendations อื่นๆ
                }
            }
        });
        
        return recommendations;
    }
    
    // Helper methods
    async makeRequest(url) {
        // TODO: จำลองการส่ง HTTP request
        // ในการใช้งานจริงจะใช้ fetch() หรือ axios
        
        const isHTTPS = url.startsWith('https://');
        const domain = url.replace(/https?:\/\//, '').split('/')[0];
        
        return {
            status: url.startsWith('http://') ? 301 : 200,
            location: url.startsWith('http://') ? `https://${domain}` : undefined,
            headers: {
                'strict-transport-security': isHTTPS ? 'max-age=31536000; includeSubDomains' : undefined,
                'content-security-policy': isHTTPS ? "default-src 'self'; script-src 'self'" : undefined,
                'set-cookie': isHTTPS ? ['sessionid=abc123; Secure; HttpOnly; SameSite=Strict'] : []
            }
        };
    }
    
    parseCookies(cookieHeaders) {
        return cookieHeaders.map(header => {
            const parts = header.split(';').map(p => p.trim());
            const [name, value] = parts[0].split('=');
            
            return {
                name,
                value,
                secure: parts.some(p => p.toLowerCase() === 'secure'),
                httpOnly: parts.some(p => p.toLowerCase() === 'httponly'),
                sameSite: parts.find(p => p.toLowerCase().startsWith('samesite'))
            };
        });
    }
}

// การใช้งาน
const checker = new HTTPSImplementationChecker();

// TODO: นักศึกษาทดสอบเว็บไซต์ต่างๆ
const testDomains = [
    'github.com',
    'google.com', 
    'example.com'
];

// TODO: รันการตรวจสอบและสร้างรายงาน
testDomains.forEach(async domain => {
    const results = await checker.checkImplementation(domain);
    console.log(`${domain} Security Assessment:`, results);
});
```

## คำถามวิเคราะห์สำหรับนักศึกษา

1. **Performance vs Security Trade-offs:**
   - HTTPS มี overhead เท่าไหร่เมื่อเทียบกับ HTTP?
   - ในกรณีไหนที่ performance penalty ของ HTTPS เป็นปัญหา?
   - HTTP/2 และ HTTP/3 ช่วยลด overhead ของ HTTPS ได้อย่างไร?

2. **Certificate Management Challenges:**
   - การจัดการ SSL certificates ในองค์กรขนาดใหญ่มีความท้าทายอะไรบ้าง?
   - Let's Encrypt vs Commercial CA มีข้อดีเสียอย่างไร?
   - Certificate pinning มีประโยชน์และข้อเสียอย่างไร?

3. **HTTPS Implementation Best Practices:**
   - ทำไมต้องใช้ HSTS header?
   - การตั้งค่า secure cookies มีความสำคัญอย่างไร?
   - CSP header ช่วยเสริมความปลอดภัยของ HTTPS ได้อย่างไร?

4. **Real-world Attack Scenarios:**
   - ในสภาพแวดล้อมไหนที่ HTTP ยังคงเสี่ยงต่อการโจมตี?
   - การใช้ public WiFi กับ HTTP มีความเสี่ยงอย่างไร?
   - Captive portals สามารถเป็นช่องทางโจมตี HTTPS ได้หรือไม่?

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