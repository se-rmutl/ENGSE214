# Week 6: Cryptography Basics
## ENGSE214 – ความมั่นคงปลอดภัยทางไซเบอร์เบื้องต้น (Introduction to Cyber Security)

**เวลาการสอน:** 2-3 ชั่วโมง (รวม Demo และ Lab)  
**CLO ที่เกี่ยวข้อง:** CLO1, CLO3

---

## 📚 ทบทวนเนื้อหาสัปดาห์ที่ผ่านมา

### Week 5: Network Security & Basic Packet Filtering

เราได้เรียนรู้เกี่ยวกับ:

```
┌────────────────────────────────────────────────────────┐
│  ✓ Network Security Fundamentals                       │
│  ✓ Firewall, IDS/IPS Concepts                          │
│  ✓ Packet Filtering & Wireshark Analysis               │
│  ✓ DMZ Architecture & Network Segmentation             │
└────────────────────────────────────────────────────────┘
```

**Key Takeaway จาก Week 5:**
- Firewall ช่วยควบคุมการเข้า-ออกของ network traffic
- IDS/IPS ช่วยตรวจจับและป้องกันการโจมตี
- การแบ่งส่วนเครือข่าย (Network Segmentation) ช่วยลดความเสี่ยง
- **สัปดาห์นี้:** เราจะเรียนรู้วิธี "เข้ารหัสข้อมูล" เพื่อปกป้องข้อมูลระหว่างการส่งผ่าน network!

---

## 🎯 วัตถุประสงค์การเรียนรู้ (Learning Objectives)

เมื่อจบ Week 6 นักศึกษาจะสามารถ:
1. อธิบายหลักการพื้นฐานของการเข้ารหัสข้อมูลได้
2. เปรียบเทียบความแตกต่างระหว่าง Symmetric และ Asymmetric Encryption
3. เข้าใจหลักการทำงานของ Digital Signature และ PKI
4. ประยุกต์ใช้ Hash Function และ Message Authentication
5. สาธิตการใช้งาน OpenSSL และตรวจสอบ SSL/TLS Certificate

---

## 💭 คำถามชวนคิด

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🤔 "ทำไมเราต้อง 'เข้ารหัส' ข้อมูล?                           ║
║      แค่ใช้ Firewall ป้องกันไม่พอหรือ?"                         ║
║                                                           ║
║   คำตอบ: Firewall ปกป้องเฉพาะ 'ทางเข้า' เท่านั้น!              ║
║                                                           ║
║   ส่วนการเข้ารหัส (Encryption) ปกป้อง...                      ║
║   1. ข้อมูลขณะส่งผ่าน Network (Data in Transit)               ║
║   2. ข้อมูลที่เก็บในฐานข้อมูล (Data at Rest)                     ║
║   3. ความเป็นส่วนตัวของผู้ใช้                                   ║
║   4. ตัวตนของผู้ส่ง (Authentication)                          ║
║                                                           ║
║   💡 แม้ว่า Hacker จะดักข้อมูลได้                               ║
║      แต่ก็อ่านไม่ออกหาก "เข้ารหัส" อย่างถูกวิธี!                    ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
```

---

## 🔐 Part 1: หลักการพื้นฐานการเข้ารหัสข้อมูล (Cryptography Fundamentals)

### 1.1 Cryptography คือ อะไร?

**Cryptography (วิทยาการเข้ารหัส)** คือศาสตร์และศิลป์ของการปกป้องข้อมูลด้วยการแปลงข้อมูลให้อ่านไม่ออก (unintelligible) สำหรับคนที่ไม่มีสิทธิ์เข้าถึง

```
┌──────────────────────────────────────────────────────────────────────┐
│              Cryptography Workflow                                   │
│                                                                      │
│  Plaintext  ──[Encryption]──> Ciphertext ──[Decryption]──> Plaintext │
│  "HELLO"         (ใช้ Key)     "X@#$%"      (ใช้ Key)       "HELLO".   │
│                                                                      │
│  ข้อมูลจริง        เข้ารหัส      ข้อมูลรหัส    ถอดรหัส       ข้อมูลจริง           │
└──────────────────────────────────────────────────────────────────────┘
```

### 1.2 คำศัพท์พื้นฐาน

```
╔════════════════════════════════════════════════════════╗
║  📖 CRYPTOGRAPHY GLOSSARY                              ║
╠════════════════════════════════════════════════════════╣
║                                                        ║
║  🔹 Plaintext (ข้อความต้นฉบับ)                            ║
║     - ข้อมูลที่ยังไม่ได้เข้ารหัส อ่านได้ชัดเจน                     ║
║     - ตัวอย่าง: "My password is 12345"                   ║
║                                                        ║
║  🔹 Ciphertext (ข้อความรหัส)                             ║
║     - ข้อมูลหลังเข้ารหัสแล้ว อ่านไม่ออก                        ║
║     - ตัวอย่าง: "4f8b2e9d1a3c..."                        ║
║                                                        ║
║  🔹 Encryption (การเข้ารหัส)                             ║
║     - กระบวนการแปลง Plaintext → Ciphertext             ║
║                                                        ║
║  🔹 Decryption (การถอดรหัส)                             ║
║     - กระบวนการแปลง Ciphertext → Plaintext             ║
║                                                        ║
║  🔹 Key (กุญแจ/คีย์)                                      ║
║     - ตัวเลขหรือข้อความพิเศษที่ใช้เข้า/ถอดรหัส                  ║
║     - เหมือนกุญแจที่เปิด-ปิดล็อค                              ║
║                                                        ║
║  🔹 Algorithm (อัลกอริทึม)                                ║
║     - ขั้นตอนหรือสูตรคำนวณที่ใช้เข้ารหัส                        ║
║     - ตัวอย่าง: AES, RSA, SHA-256                        ║
║                                                        ║
╚════════════════════════════════════════════════════════╝
```

### 1.3 เป้าหมายของ Cryptography (CIA Triad Revisited)

```
         การเข้ารหัสช่วยปกป้อง CIA Triad
         
    ┌──────────────────────────────────────┐
    │   C : Confidentiality (ความลับ)       │ ← Encryption
    │   I : Integrity (ความถูกต้อง)          │ ← Hash, MAC
    │   A : Authentication (ยืนยันตัวตน)      │ ← Digital Signature
    └──────────────────────────────────────┘
```

**นอกจาก CIA แล้วยังมี:**
- **Non-repudiation** (ปฏิเสธไม่ได้): ผู้ส่งไม่สามารถปฏิเสธว่าไม่ได้ส่งข้อความ
- **Availability** (พร้อมใช้งาน): ระบบเข้ารหัส/ถอดรหัสต้องทำงานได้รวดเร็ว

---

## 🔑 Part 2: Symmetric vs Asymmetric Encryption

### 2.1 Symmetric Encryption (การเข้ารหัสแบบสมมาตร)

**หลักการ:** ใช้ **กุญแจเดียวกัน (Same Key)** ทั้งเข้ารหัสและถอดรหัส

```
┌──────────────────────────────────────────────────────────────┐
│            SYMMETRIC ENCRYPTION                              │
│                                                              │
│   Alice                                      Bob             │
│   ┌─────┐                                  ┌─────┐           │
│   │     │                                  │     │           │
│   │  A  │───┐                          ┌───│  B  │           │
│   │     │   │                          │   │     │           │
│   └─────┘   │                          │   └─────┘           │
│             │                          │                     │
│        ┌────▼────┐                ┌────▼────┐                │
│        │  KEY 🔑 │                │  KEY 🔑 │                │
│        │  Same!  │                │  Same!  │                │
│        └────┬────┘                └────┬────┘                │
│             │                          │                     │
│       Encrypt with Key           Decrypt with Key            │
│             │                          │                     │
│        Plaintext ──────────> Ciphertext ──────────> Plaintext│
│        "HELLO"                "@#$%^"                "HELLO" │
│                                                              │
│  🔐 ปัญหา: ต้องแบ่งปัน Key อย่างปลอดภัย!                           │
└──────────────────────────────────────────────────────────────┘
```

**ข้อดี:**
- ⚡ **เร็วมาก** – เหมาะกับข้อมูลขนาดใหญ่
- 💻 ใช้ทรัพยากรคอมพิวเตอร์น้อย
- 🎯 เหมาะกับ: การเข้ารหัสไฟล์, Database, Disk Encryption

**ข้อเสีย:**
- 🔑 ต้องแบ่งปัน Key อย่างปลอดภัย (Key Distribution Problem)
- 👥 ถ้ามีผู้ใช้ n คน ต้องมี n(n-1)/2 Keys!

**ตัวอย่าง Algorithm:**
- **AES (Advanced Encryption Standard)** – มาตรฐานปัจจุบัน ใช้ key 128/192/256 bits
- **DES (Data Encryption Standard)** – เก่า ไม่แนะนำใช้แล้ว (56-bit key อ่อนแอ)
- **3DES (Triple DES)** – DES 3 รอบ
- **ChaCha20** – เร็ว ใช้ใน mobile apps

### 2.2 Asymmetric Encryption (การเข้ารหัสแบบอสมมาตร)

**หลักการ:** ใช้ **กุญแจคู่ (Key Pair)** 
- **Public Key (กุญแจสาธารณะ)** – แจกให้ทุกคนได้
- **Private Key (กุญแจส่วนตัว)** – เก็บไว้เอง ห้ามบอกใคร!

```
┌──────────────────────────────────────────────────────────────┐
│            ASYMMETRIC ENCRYPTION                             │
│                                                              │
│   Alice                                      Bob             │
│   ┌─────┐                                  ┌─────┐          │
│   │     │  "ส่งข้อความลับให้ Bob"              │     │          │
│   │  A  │                                  │  B  │          │
│   │     │                                  │     │          │
│   └─────┘                                  └─────┘          │
│      │                                        │              │
│      │ 1. Bob ส่ง Public Key ให้ Alice          │              │
│      │ ◄────────────────────────────────────  │              │
│      │         🔓 Public Key (Bob)            │              │
│      │                                        │              │
│      │                                    ┌───────┐          │
│      │                                    │🔐 Private│       │
│      │                                    │  (Bob)  │       │
│      │                                    └───────┘          │
│      │                                        │              │
│      │ 2. Alice encrypt ด้วย Bob's Public Key  │              │
│   Plaintext ─────[Encrypt]────> Ciphertext    │              │
│   "HELLO"     (Bob's Public🔓)    "@#$%^"     │              │
│      │                                │       │              │
│      │ 3. ส่ง Ciphertext ไปหา Bob      │       │              │
│      │ ──────────────────────────────>│       │              │
│      │                                │       │              │
│      │ 4. Bob decrypt ด้วย Private Key (เขาเท่านั้น!)      │
│      │                    Ciphertext ─────[Decrypt]────> Plaintext
│      │                      "@#$%^"   (Bob's Private🔐)  "HELLO"
│                                                              │
│  ✓ Alice encrypt ด้วย Bob's Public Key 🔓                  │
│  ✓ เฉพาะ Bob ถอดรหัสได้ด้วย Private Key 🔐 ของตัวเอง       │
│  ✓ ไม่ต้องแบ่งปัน Key แบบ Symmetric!                        │
└──────────────────────────────────────────────────────────────┘
```

**ข้อดี:**
- 🔑 **ไม่ต้องแบ่งปัน Private Key** – แก้ปัญหา Key Distribution
- 🌐 เหมาะกับการสื่อสารผ่าน Internet
- ✍️ สามารถทำ Digital Signature ได้

**ข้อเสีย:**
- 🐌 **ช้ากว่า Symmetric มาก** (100-1000 เท่า)
- 💻 ใช้ทรัพยากรเยอะ
- 📦 ไม่เหมาะกับข้อมูลขนาดใหญ่

**ตัวอย่าง Algorithm:**
- **RSA (Rivest-Shamir-Adleman)** – ยอดนิยมที่สุด ใช้ 2048/4096-bit keys
- **ECC (Elliptic Curve Cryptography)** – ปลอดภัยเท่า RSA แต่ใช้ key สั้นกว่า
- **Diffie-Hellman** – ใช้แลก key ระหว่างกัน
- **DSA/ECDSA** – สำหรับ Digital Signature

### 2.3 การใช้งานในโลกจริง: Hybrid Encryption

**ปัญหา:**
- Symmetric เร็วแต่มีปัญหา Key Distribution
- Asymmetric แก้ปัญหา Key Distribution แต่ช้ามาก

**วิธีแก้:** ใช้ทั้งสองแบบร่วมกัน! (Hybrid Encryption)

```
┌──────────────────────────────────────────────────────────────┐
│         🎯 HYBRID ENCRYPTION (SSL/TLS ใช้วิธีนี้!)            │
│                                                              │
│  Step 1: ใช้ Asymmetric เพื่อแลก Session Key                 │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ Alice สร้าง Random Session Key (Symmetric)          │    │
│  │ แล้ว Encrypt Session Key ด้วย Bob's Public Key     │    │
│  │ ส่งไปให้ Bob → Bob ถอดรหัสด้วย Private Key ของตัวเอง │    │
│  └─────────────────────────────────────────────────────┘    │
│           │                                                  │
│           ▼                                                  │
│  Step 2: ใช้ Symmetric เพื่อเข้ารหัสข้อมูลจริง               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ Alice & Bob ต่างคนต่างมี Session Key เดียวกันแล้ว   │    │
│  │ → ใช้ Session Key (Symmetric) เข้ารหัสข้อมูลต่อไป    │    │
│  │   (เร็วมาก! เหมาะกับข้อมูลเยอะ)                       │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  💡 ได้ทั้งความเร็ว (Symmetric) และความปลอดภัย (Asymmetric)! │
│  💡 HTTPS (SSL/TLS) ใช้วิธีนี้ทุกครั้งที่คุณท่อง website!    │
└──────────────────────────────────────────────────────────────┘
```

### 2.4 เปรียบเทียบ Symmetric vs Asymmetric

| **ลักษณะ**          | **Symmetric** ⚡                    | **Asymmetric** 🔐               |
|---------------------|-----------------------------------|--------------------------------|
| **จำนวน Key**       | 1 Key (ใช้ร่วมกัน)                 | 2 Keys (Public + Private)      |
| **ความเร็ว**        | เร็วมาก 🚀                          | ช้า 🐌                          |
| **Key Distribution**| ยาก 😰 (ต้องแบ่งปัน Key ปลอดภัย)   | ง่าย 😊 (แจก Public Key ได้)    |
| **ขนาดข้อมูล**      | เหมาะกับข้อมูลใหญ่                  | เหมาะกับข้อมูลเล็ก               |
| **Use Cases**       | File/Disk Encryption, Bulk Data  | Key Exchange, Digital Signature|
| **ตัวอย่าง**        | AES, ChaCha20                     | RSA, ECC                       |

---

## ✍️ Part 3: Digital Signature & PKI (Public Key Infrastructure)

### 3.1 Digital Signature คืออะไร?

**Digital Signature (ลายเซ็นดิจิทัล)** เหมือนการเซ็นเอกสารในโลกดิจิทัล แต่ปลอมแปลงไม่ได้!

```
┌──────────────────────────────────────────────────────────────┐
│              🖊️  DIGITAL SIGNATURE WORKFLOW                   │
│                                                              │
│  Step 1: Alice ส่งข้อความพร้อมลายเซ็น                         │
│  ┌──────────────────────────────────────────────────┐        │
│  │ 1. Alice สร้าง Hash จากข้อความ                   │        │
│  │    Message ──[Hash Function]──> Hash Value       │        │
│  │    "Transfer $100"            "a3f5..."          │        │
│  │                                                  │        │
│  │ 2. Encrypt Hash ด้วย Private Key ของ Alice      │        │
│  │    Hash ──[Encrypt with Alice's Private🔐]──> Signature
│  │                                               "x7y2..."   │
│  │                                                  │        │
│  │ 3. ส่งทั้งข้อความและลายเซ็นไปหา Bob               │        │
│  │    Message + Digital Signature                   │        │
│  └──────────────────────────────────────────────────┘        │
│           │                                                  │
│           │ ส่งผ่าน Internet                                 │
│           ▼                                                  │
│  Step 2: Bob ตรวจสอบลายเซ็น                                  │
│  ┌──────────────────────────────────────────────────┐        │
│  │ 1. Bob Decrypt Signature ด้วย Alice's Public Key│        │
│  │    Signature ──[Decrypt with Alice's Public🔓]──> Hash A
│  │                                                  │        │
│  │ 2. Bob สร้าง Hash จากข้อความที่ได้รับ            │        │
│  │    Message ──[Hash Function]──> Hash B           │        │
│  │                                                  │        │
│  │ 3. เปรียบเทียบ Hash A == Hash B ?                │        │
│  │    ✓ เหมือนกัน → ถูกต้อง! Alice ส่งแน่นอน         │        │
│  │    ✗ ไม่เหมือน → ข้อความถูกแก้ไขระหว่างทาง!       │        │
│  └──────────────────────────────────────────────────┘        │
│                                                              │
│  💡 Digital Signature พิสูจน์ได้ 2 อย่าง:                     │
│     1. Authentication: Alice เป็นคนส่งจริง ๆ                │
│     2. Integrity: ข้อความไม่ถูกแก้ไข                          │
│     3. Non-repudiation: Alice ปฏิเสธไม่ได้ว่าไม่ได้ส่ง       │
└──────────────────────────────────────────────────────────────┘
```

### 3.2 PKI (Public Key Infrastructure)

**PKI** คือระบบที่จัดการ Digital Certificates และ Public Keys ในองค์กร

```
╔═══════════════════════════════════════════════════════════╗
║               PKI ARCHITECTURE                            ║
╠═══════════════════════════════════════════════════════════╣
║                                                           ║
║                 ┌─────────────────┐                       ║
║                 │   Root CA       │ ← ตัวออก Certificate สูงสุด
║                 │  (Trusted)      │                       ║
║                 └────────┬────────┘                       ║
║                          │                                ║
║           ┌──────────────┼──────────────┐                 ║
║           │              │              │                 ║
║      ┌────▼────┐    ┌────▼────┐    ┌────▼────┐           ║
║      │Intermediate│ │Intermediate│ │Intermediate│        ║
║      │    CA      │ │    CA      │ │    CA      │        ║
║      └────┬────┘    └────┬────┘    └────┬────┘           ║
║           │              │              │                 ║
║    ┌──────┼──────┐      │       ┌──────┼──────┐          ║
║    │      │      │      │       │      │      │          ║
║ ┌──▼──┐┌──▼──┐┌──▼──┐┌──▼──┐ ┌──▼──┐┌──▼──┐┌──▼──┐       ║
║ │Cert ││Cert ││Cert ││Cert │ │Cert ││Cert ││Cert │       ║
║ │User1││User2││Web  ││Email│ │App  ││API  ││VPN  │       ║
║ └─────┘└─────┘└─────┘└─────┘ └─────┘└─────┘└─────┘       ║
║                                                           ║
║  📜 Certificate = Public Key + Identity + CA Signature   ║
╚═══════════════════════════════════════════════════════════╝
```

**องค์ประกอบของ PKI:**

1. **Certificate Authority (CA)** – ผู้ออก Certificate (เช่น DigiCert, Let's Encrypt)
2. **Registration Authority (RA)** – ตรวจสอบตัวตนก่อนออก Certificate
3. **Digital Certificate** – เอกสารดิจิทัลที่บอกว่า Public Key นี้เป็นของใคร
4. **Certificate Revocation List (CRL)** – รายชื่อ Certificate ที่ถูกยกเลิก

### 3.3 Digital Certificate

**Certificate** ประกอบด้วย:

```
┌─────────────────────────────────────────────────────────┐
│        📜 X.509 DIGITAL CERTIFICATE                     │
├─────────────────────────────────────────────────────────┤
│  Version: v3                                            │
│  Serial Number: 04:7f:a7:b2:c1:3e:9d:8f                │
│                                                         │
│  Issuer (ผู้ออก):                                       │
│    CN = DigiCert Global Root CA                        │
│    O  = DigiCert Inc                                   │
│    C  = US                                             │
│                                                         │
│  Subject (เจ้าของ):                                     │
│    CN = www.example.com                                │
│    O  = Example Corp                                   │
│    L  = Bangkok, C = TH                                │
│                                                         │
│  Validity Period (ระยะเวลาใช้งาน):                       │
│    Not Before: 2024-01-01 00:00:00                     │
│    Not After : 2026-01-01 23:59:59                     │
│                                                         │
│  Subject Public Key Info:                              │
│    Algorithm: RSA 2048-bit                             │
│    Public Key: 30:82:01:0a:02:82:01:01:00:d4:...      │
│                                                         │
│  X509v3 Extensions:                                    │
│    Subject Alternative Name:                           │
│      DNS:www.example.com, DNS:example.com             │
│    Key Usage: Digital Signature, Key Encipherment     │
│    Extended Key Usage: TLS Web Server Authentication   │
│                                                         │
│  Signature Algorithm: sha256WithRSAEncryption          │
│  Signature: 4a:7c:2f:8b:...                            │
│             (ลายเซ็นของ CA)                             │
└─────────────────────────────────────────────────────────┘
```

**สิ่งที่ Certificate การันตี:**
1. Public Key นี้เป็นของ www.example.com จริง ๆ
2. CA ได้ตรวจสอบตัวตนของ example.com แล้ว
3. สามารถใช้ Public Key นี้เข้ารหัสข้อมูลส่งไปหา example.com ได้อย่างปลอดภัย

---

## #️⃣ Part 4: Hash Function & Message Authentication

### 4.1 Hash Function คืออะไร?

**Hash Function** คือฟังก์ชันที่แปลงข้อมูลขนาดใดก็ตามให้เป็น **Fixed-Size Output** (Hash Value)

```
┌──────────────────────────────────────────────────────────────┐
│                 🔢 HASH FUNCTION                              │
│                                                              │
│  Input (ขนาดต่างกัน)  ──[Hash]──>  Output (ขนาดเท่ากัน)       │
│                                                              │
│  "Hello"              ──[SHA-256]──>  2cf24db...  (64 hex)  │
│  "Hello World"        ──[SHA-256]──>  a591a6d...  (64 hex)  │
│  [10 GB File]         ──[SHA-256]──>  7f83b1c...  (64 hex)  │
│                                            ↑                 │
│                                   ขนาดเท่ากันเสมอ!            │
│                                                              │
│  💡 คุณสมบัติสำคัญ:                                           │
│  1. One-way: หา Input จาก Output ไม่ได้                      │
│  2. Deterministic: Input เดิมได้ Output เดิมเสมอ             │
│  3. Avalanche Effect: แก้ Input นิดเดียว Output เปลี่ยนเยอะ  │
│  4. Collision Resistant: หา Input 2 ตัวที่ได้ Output เดียวกันยาก
└──────────────────────────────────────────────────────────────┘
```

**ตัวอย่าง: แก้ตัวอักษรเดียว Output เปลี่ยนทั้งหมด!**

```
Input: "Hello"
SHA-256: 185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969

Input: "hello"  (เปลี่ยนแค่ตัวพิมพ์เล็ก)
SHA-256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
         ↑
         เปลี่ยนแทบทั้งหมด!
```

### 4.2 Hash Algorithms

```
╔════════════════════════════════════════════════════════════╗
║         POPULAR HASH ALGORITHMS                            ║
╠════════════════════════════════════════════════════════════╣
║                                                            ║
║  ✗ MD5 (Message Digest 5)                                 ║
║    - Output: 128 bits (32 hex characters)                 ║
║    - Status: BROKEN! อย่าใช้แล้ว                           ║
║    - เหตุผล: พบวิธี Collision ได้ง่าย                       ║
║                                                            ║
║  ⚠️ SHA-1 (Secure Hash Algorithm 1)                       ║
║    - Output: 160 bits (40 hex characters)                 ║
║    - Status: DEPRECATED ไม่แนะนำให้ใช้แล้ว                 ║
║    - เหตุผล: Google พบวิธี Collision ได้ (2017)            ║
║                                                            ║
║  ✓ SHA-2 Family (แนะนำ!)                                  ║
║    - SHA-256: 256 bits (64 hex) ← ยอดนิยม                ║
║    - SHA-384: 384 bits (96 hex)                           ║
║    - SHA-512: 512 bits (128 hex)                          ║
║    - Status: SECURE ใช้ได้                                 ║
║                                                            ║
║  ✓ SHA-3 (Keccak)                                         ║
║    - มาตรฐานใหม่ (2015)                                    ║
║    - ใช้อัลกอริทึมต่างจาก SHA-2                             ║
║    - Status: SECURE                                        ║
║                                                            ║
║  ✓ BLAKE2/BLAKE3                                          ║
║    - เร็วกว่า SHA-2                                         ║
║    - ใช้ใน Crypto Currencies                              ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
```

### 4.3 การใช้งาน Hash Function

```
┌──────────────────────────────────────────────────────────┐
│           USE CASES OF HASH FUNCTIONS                    │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  1. 🔐 Password Storage (เก็บรหัสผ่าน)                   │
│     ไม่เก็บ password แบบ plaintext แต่เก็บ hash!          │
│     User: "mypassword123"                                │
│           ↓ [SHA-256 + Salt]                             │
│     DB: "9f86d081884c7d659a2feaa0c55ad015a..."          │
│                                                          │
│  2. ✓ File Integrity Check (ตรวจสอบไฟล์ไม่เปลี่ยน)       │
│     ก่อนโหลด: Hash = abc123...                            │
│     หลังโหลด: Hash = abc123... ← เหมือนกัน = ไม่มีการแก้ไข │
│                                                          │
│  3. 📜 Digital Signature                                 │
│     Sign Hash แทนที่จะ sign ข้อความทั้งหมด (เร็วกว่า)     │
│                                                          │
│  4. 🔗 Blockchain                                        │
│     Bitcoin/Ethereum ใช้ SHA-256 ใน Mining               │
│                                                          │
│  5. 🆔 Data Deduplication                                │
│     ตรวจสอบไฟล์ซ้ำด้วยการเปรียบเทียบ Hash                 │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### 4.4 Message Authentication Code (MAC)

**MAC** คือ Hash พิเศษที่ใช้ **Key** ร่วมด้วย เพื่อพิสูจน์ว่าข้อความมาจากคนที่รู้ Key

```
┌──────────────────────────────────────────────────────────────┐
│              HMAC (Hash-based MAC)                           │
│                                                              │
│  Sender (Alice)                         Receiver (Bob)       │
│  ┌──────────────┐                      ┌──────────────┐     │
│  │ Message +    │                      │ Message +    │     │
│  │ Shared Key   │                      │ Shared Key   │     │
│  └──────┬───────┘                      └──────┬───────┘     │
│         │                                     │              │
│         ▼                                     ▼              │
│  [HMAC-SHA256]                         [HMAC-SHA256]        │
│         │                                     │              │
│         ▼                                     ▼              │
│   MAC Value ──────────> send ──────────> MAC Value'         │
│   "7f3a..."                                "7f3a..."        │
│                                                              │
│                    Compare MAC == MAC' ?                     │
│                    ✓ เหมือน → Message ถูกต้อง + มาจากคนที่รู้ Key
│                    ✗ ต่าง → Message ถูกแก้ หรือ ไม่มี Key    │
│                                                              │
│  💡 HMAC ให้ทั้ง Integrity + Authentication!                 │
└──────────────────────────────────────────────────────────────┘
```

**ความแตกต่างระหว่าง Hash กับ MAC:**

| **ลักษณะ**        | **Hash**                  | **MAC (HMAC)**              |
|-------------------|---------------------------|-----------------------------|
| **Input**         | Message only              | Message + Secret Key        |
| **Output**        | Hash Value                | MAC Value                   |
| **Purpose**       | Integrity                 | Integrity + Authentication  |
| **ใครสร้างได้**    | ใครก็ได้ที่มี Message      | เฉพาะคนที่มี Key เท่านั้น    |

---

## 🎬 Part 5: Demonstrations & Hands-on Activities

### 5.1 Alice-Bob-Eve Scenario (Infographic)

```
┌──────────────────────────────────────────────────────────────────────┐
│                  🎭 ALICE, BOB, AND EVE                              │
│                                                                      │
│                                                                      │
│   Alice 👩     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━→      Bob 👨        │
│  (Sender)        ส่งข้อความ "Hello Bob!"               (Receiver)    │
│                                                                      │
│                              ↑                                       │
│                              │                                       │
│                              │                                       │
│                         Eve 😈 🕵️                                     │
│                     (Eavesdropper)                                   │
│                    พยายามดักฟังและแก้ไขข้อความ!                        │
│                                                                      │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Scenario 1: ❌ ไม่มีการเข้ารหัส (No Encryption)                     │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━                   │
│                                                                      │
│   Alice  ─────["Hello Bob!"]────────> Eve ─────["Hello Bob!"]────> Bob
│                   Plaintext               👁️ อ่านได้!                 │
│                                                                      │
│   ✗ Eve อ่านข้อความได้ (Confidentiality ถูกทำลาย)                     │
│   ✗ Eve แก้ไขเป็น "Send $1000 to Eve" (Integrity ถูกทำลาย)          │
│   ✗ Bob คิดว่า Alice ส่งมาจริง (Authentication ไม่มี)                │
│                                                                      │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Scenario 2: ✓ มี Symmetric Encryption                              │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━                   │
│                                                                      │
│   Alice  ─────["@#$%^&*"]────────> Eve ─────["@#$%^&*"]────> Bob   │
│         (Encrypt ด้วย Shared Key)      ❓ อ่านไม่ออก!                │
│                                                  (Decrypt ด้วย Key)  │
│                                                     ↓                │
│                                               "Hello Bob!"           │
│                                                                      │
│   ✓ Eve อ่านไม่ออก (Confidentiality ปลอดภัย)                          │
│   ⚠️ แต่ยังมีปัญหา: Alice-Bob ต้องแบ่งปัน Key ก่อน (Key Distribution)│
│                                                                      │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Scenario 3: ✓ Asymmetric + Digital Signature                       │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━                   │
│                                                                      │
│  Step 1: Bob แจก Public Key ให้ทุกคน (รวม Alice)                     │
│   Bob ────[Public Key 🔓]────> Alice                                │
│                                                                      │
│  Step 2: Alice encrypt ด้วย Bob's Public Key + Sign ด้วย Private Key│
│   Alice  ─────[Ciphertext + Signature]────> Eve ───> Bob           │
│                                              ❓         ↓             │
│                                         อ่านไม่ออก  [Decrypt +      │
│                                                      Verify]         │
│                                                        ↓             │
│                                                  "Hello Bob!" ✓      │
│                                                                      │
│   ✓ Confidentiality: เฉพาะ Bob ถอดรหัสได้                             │
│   ✓ Authentication: ตรวจสอบ Signature ได้ว่า Alice ส่งจริง            │
│   ✓ Integrity: ข้อความไม่ถูกแก้ไข                                     │
│   ✓ Non-repudiation: Alice ปฏิเสธไม่ได้                              │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### 5.2 Demo 1: การเข้ารหัสด้วย OpenSSL

#### Demo 1.1: Symmetric Encryption (AES-256-CBC)

**สร้างไฟล์ข้อความ:**
```bash
echo "This is a secret message from Alice to Bob!" > message.txt
```

**เข้ารหัสด้วย AES-256:**
```bash
# Encrypt
openssl enc -aes-256-cbc -salt -in message.txt -out message.enc -k "MySecretPassword"

# ดูไฟล์ที่เข้ารหัสแล้ว (อ่านไม่ออก)
hexdump -C message.enc | head
```

**ถอดรหัส:**
```bash
# Decrypt
openssl enc -aes-256-cbc -d -in message.enc -out decrypted.txt -k "MySecretPassword"

# ตรวจสอบ
cat decrypted.txt
```

**ทดลอง:**
- ลองใช้ password ผิด → ถอดรหัสไม่ได้
- ลองแก้ไข message.enc → Error เมื่อถอดรหัส

#### Demo 1.2: Hash Function

**สร้าง Hash จากไฟล์:**
```bash
# SHA-256
echo -n "Hello World" | openssl dgst -sha256
# Output: 64ec88ca00b268e5ba1a35678a1b5316d212f4f366b2477232534a8aeca37f3c

# เปลี่ยนตัวอักษรเดียว
echo -n "hello World" | openssl dgst -sha256
# Output: 03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340
#          ↑ เปลี่ยนแทบทั้งหมด!
```

**ตรวจสอบ File Integrity:**
```bash
# สร้างไฟล์
echo "Important Document" > document.txt

# เก็บ Hash ไว้
openssl dgst -sha256 document.txt > document.txt.sha256

# ส่งไฟล์ทั้งสองให้เพื่อน...

# ตรวจสอบว่าไฟล์ไม่เปลี่ยน
openssl dgst -sha256 document.txt
# เปรียบเทียบกับ document.txt.sha256
```

#### Demo 1.3: Asymmetric Encryption (RSA)

**สร้าง Key Pair:**
```bash
# สร้าง Private Key
openssl genrsa -out private_key.pem 2048

# สร้าง Public Key จาก Private Key
openssl rsa -in private_key.pem -pubout -out public_key.pem

# ดู Private Key
cat private_key.pem

# ดู Public Key (แจกให้คนอื่นได้)
cat public_key.pem
```

**Encrypt ด้วย Public Key:**
```bash
echo "Secret message for Bob" > plain.txt

# Alice encrypt ด้วย Bob's Public Key
openssl rsautl -encrypt -inkey public_key.pem -pubin -in plain.txt -out encrypted.bin

# ดูไฟล์ที่เข้ารหัส (binary)
hexdump -C encrypted.bin
```

**Decrypt ด้วย Private Key:**
```bash
# Bob decrypt ด้วย Private Key ของตัวเอง
openssl rsautl -decrypt -inkey private_key.pem -in encrypted.bin -out decrypted.txt

cat decrypted.txt
```

**ทดลอง:**
- ลอง decrypt ด้วย Public Key → ไม่ได้!
- ลอง decrypt โดยไม่มี Private Key → ไม่ได้!

#### Demo 1.4: Digital Signature

**สร้าง Signature:**
```bash
echo "I agree to transfer $100" > contract.txt

# Alice sign ด้วย Private Key
openssl dgst -sha256 -sign private_key.pem -out contract.sig contract.txt

# ส่ง contract.txt + contract.sig ไปให้ Bob
```

**ตรวจสอบ Signature:**
```bash
# Bob verify ด้วย Alice's Public Key
openssl dgst -sha256 -verify public_key.pem -signature contract.sig contract.txt

# Output: Verified OK ✓
```

**ทดลอง:**
```bash
# แก้ไข contract.txt
echo "I agree to transfer $1000" > contract.txt

# Verify อีกครั้ง
openssl dgst -sha256 -verify public_key.pem -signature contract.sig contract.txt

# Output: Verification Failure ✗ (ถูกแก้ไข!)
```

### 5.3 Demo 2: ตรวจสอบ SSL/TLS Certificate

#### วิธีที่ 1: ผ่าน Browser (Chrome/Firefox)

```
┌──────────────────────────────────────────────────────────────┐
│      🌐 ตรวจสอบ Certificate ผ่าน Browser                     │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Step 1: เปิดเว็บ HTTPS (เช่น https://www.google.com)        │
│                                                              │
│  Step 2: คลิกที่ไอคอนกุญแจ 🔒 ข้าง URL                        │
│                                                              │
│  Step 3: เลือก "Certificate" / "รายละเอียดใบรับรอง"           │
│                                                              │
│  Step 4: ตรวจสอบข้อมูล:                                       │
│     ✓ Issued to: www.google.com                             │
│     ✓ Issued by: GTS CA 1C3 (Google Trust Services)        │
│     ✓ Valid from: 2024-10-21                                │
│     ✓ Expires on: 2025-01-13                                │
│     ✓ Public Key: RSA 2048-bit                              │
│     ✓ Signature Algorithm: SHA-256 with RSA                 │
│                                                              │
│  💡 Certificate บอกว่า:                                       │
│     1. Website นี้เป็น google.com จริง (Authentication)     │
│     2. CA (Google Trust Services) การันตีว่าตรวจสอบแล้ว       │
│     3. สามารถ Encrypt ข้อมูลได้ปลอดภัย (Confidentiality)     │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

#### วิธีที่ 2: ใช้ OpenSSL Command Line

```bash
# ดู Certificate จาก Website
openssl s_client -connect www.google.com:443 -showcerts

# ดูเฉพาะวันหมดอายุ
echo | openssl s_client -connect www.google.com:443 2>/dev/null | openssl x509 -noout -dates

# ดูใครออก Certificate
echo | openssl s_client -connect www.google.com:443 2>/dev/null | openssl x509 -noout -issuer

# ดูเจ้าของ Certificate
echo | openssl s_client -connect www.google.com:443 2>/dev/null | openssl x509 -noout -subject

# ดู Public Key Algorithm
echo | openssl s_client -connect www.google.com:443 2>/dev/null | openssl x509 -noout -text | grep "Public Key"
```

**ตัวอย่าง Output:**
```
subject=CN = www.google.com
issuer=C = US, O = Google Trust Services LLC, CN = GTS CA 1C3
notBefore=Oct 21 08:21:43 2024 GMT
notAfter=Jan 13 08:21:42 2025 GMT
Public-Key: (256 bit)
```

#### วิธีที่ 3: ตรวจสอบ Certificate Chain

```bash
# ดู Certificate Chain ทั้งหมด
openssl s_client -connect www.google.com:443 -showcerts 2>/dev/null | grep -A 50 "BEGIN CERTIFICATE"
```

**Certificate Chain:**
```
Root CA (Google Root CA)
    ↓
Intermediate CA (GTS CA 1C3)
    ↓
End-Entity Certificate (www.google.com)
```

### 5.4 Demo 3: เครื่องมือออนไลน์

**เครื่องมือที่แนะนำ:**

1. **CyberChef** (https://gchq.github.io/CyberChef/)
   - เข้ารหัส/ถอดรหัสแบบ Visual
   - รองรับ AES, RSA, Base64, Hash ฯลฯ
   - ไม่ต้อง install

2. **SSL Labs** (https://www.ssllabs.com/ssltest/)
   - ตรวจสอบ SSL/TLS Configuration ของเว็บไซต์
   - วิเคราะห์ความปลอดภัยของ Certificate

3. **Hash Generator** (https://emn178.github.io/online-tools/)
   - สร้าง Hash จากข้อความ
   - รองรับ MD5, SHA-1, SHA-256, SHA-512

---

## 🎮 Part 6: In-class Activity – Cipher Puzzle

### Activity 1: Caesar Cipher (Substitution Cipher)

**โจทย์:**

```
┌──────────────────────────────────────────────────────────────┐
│           🔐 CAESAR CIPHER CHALLENGE                         │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ข้อความที่เข้ารหัส:                                          │
│  "KHOOR ZRUOG"                                              │
│                                                              │
│  คำใบ้: ใช้ Caesar Cipher โดย Shift ไป 3 ตำแหน่ง             │
│                                                              │
│  คำถาม: ข้อความจริงคืออะไร?                                   │
│                                                              │
│  วิธีถอดรหัส:                                                 │
│  A B C D E F G H I J K L M N O P Q R S T U V W X Y Z        │
│  ↓ ↓ ↓ (shift กลับ 3 ตำแหน่ง)                                │
│  X Y Z A B C D E F G H I J K L M N O P Q R S T U V W        │
│                                                              │
│  K → H                                                       │
│  H → E                                                       │
│  O → L                                                       │
│  O → L                                                       │
│  R → O                                                       │
│  ...                                                         │
│                                                              │
│  คำตอบ: "HELLO WORLD"                                        │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

**Caesar Cipher Table:**
```
Original: A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
Shift +3: D E F G H I J K L M N O P Q R S T U V W X Y Z A B C
```

### Activity 2: Substitution Cipher (ซับซ้อนขึ้น)

**โจทย์:**

```
┌──────────────────────────────────────────────────────────────┐
│       🔐 SUBSTITUTION CIPHER CHALLENGE (HARDER)              │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ข้อความที่เข้ารหัส:                                          │
│  "ITSXJXHX JO NXJCXH FOHSHX"                                │
│                                                              │
│  คำใบ้:                                                       │
│  - นี่คือประโยคเกี่ยวกับ Cybersecurity                         │
│  - มีคำว่า "SECURITY" ซ่อนอยู่                                │
│                                                              │
│  เทคนิค: Frequency Analysis                                  │
│  - ภาษาอังกฤษใช้ E, T, A, O บ่อยที่สุด                        │
│  - ดูว่าตัวไหนซ้ำบ่อย แล้วลองแทนด้วย E, T, A, O              │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

**คำตอบ:**
```
Substitution Key:
I→T, T→E, S→S, X→C, J→U, H→R, N→I, F→S, O→Y

Decrypted: "TECHOLOGY IS CYBER SUSURE"
→ แก้ไขเป็น "TECHNOLOGY IS CYBER SECURE"
```

### Activity 3: Modern Cipher – เข้ารหัส/ถอดรหัสด้วย Python

**Code:**
```python
from cryptography.fernet import Fernet

# สร้าง Key
key = Fernet.generate_key()
print(f"Key: {key.decode()}")

# สร้าง Cipher Suite
cipher_suite = Fernet(key)

# Encrypt
plaintext = b"This is a secret message!"
ciphertext = cipher_suite.encrypt(plaintext)
print(f"Ciphertext: {ciphertext}")

# Decrypt
decrypted = cipher_suite.decrypt(ciphertext)
print(f"Decrypted: {decrypted.decode()}")
```

**Challenge:**
1. ให้นักศึกษาเข้ารหัสข้อความของตัวเอง
2. แลก Ciphertext + Key กับเพื่อน
3. ลองถอดรหัสของเพื่อน
4. ทดลองถอดรหัสโดยไม่มี Key → ไม่ได้!

---

## 📊 Part 7: Cryptography in Real World

### 7.1 Use Cases ที่พบเห็นในชีวิตประจำวัน

```
╔════════════════════════════════════════════════════════════════╗
║        🌍 CRYPTOGRAPHY IN THE REAL WORLD                      ║
╠════════════════════════════════════════════════════════════════╣
║                                                                ║
║  1. 🌐 HTTPS / SSL/TLS (Website Security)                     ║
║     ├─ ใช้ Hybrid Encryption (RSA + AES)                      ║
║     ├─ Certificate จาก CA (DigiCert, Let's Encrypt)          ║
║     └─ ทุกครั้งที่เห็น 🔒 คุณกำลังใช้ Cryptography!           ║
║                                                                ║
║  2. 💬 Messaging Apps (WhatsApp, Signal, Line)                ║
║     ├─ End-to-End Encryption (E2EE)                           ║
║     ├─ เฉพาะผู้ส่ง-ผู้รับอ่านได้ แม้แต่ Server ก็อ่านไม่ได้      ║
║     └─ ใช้ Signal Protocol (Double Ratchet Algorithm)         ║
║                                                                ║
║  3. 💳 Credit Cards & Online Payments                         ║
║     ├─ PCI DSS Compliance (เข้ารหัสข้อมูลบัตร)                 ║
║     ├─ Tokenization (แทนเลขบัตรด้วย Token)                    ║
║     └─ 3D Secure (OTP ผ่าน SMS)                              ║
║                                                                ║
║  4. 🔐 Password Managers (1Password, LastPass)                ║
║     ├─ Master Password → Decrypt Vault                        ║
║     ├─ ใช้ AES-256 Encryption                                 ║
║     └─ Password ถูกเข้ารหัสก่อนส่งไป Server                     ║
║                                                                ║
║  5. 💰 Cryptocurrency (Bitcoin, Ethereum)                     ║
║     ├─ Blockchain ใช้ SHA-256 Hashing                         ║
║     ├─ Digital Signature ยืนยัน Transaction                   ║
║     └─ Public/Private Key เป็นที่อยู่ Wallet                  ║
║                                                                ║
║  6. 🔑 SSH & VPN                                              ║
║     ├─ SSH: Remote Login ที่ปลอดภัย (RSA/ED25519)            ║
║     ├─ VPN: Encrypt ทั้ง Network Traffic                      ║
║     └─ ใช้ IPsec, OpenVPN, WireGuard                          ║
║                                                                ║
║  7. 📧 Email Encryption                                        ║
║     ├─ PGP/GPG: Encrypt Email Content                         ║
║     ├─ S/MIME: Certificate-based Email Encryption            ║
║     └─ TLS: Encrypt การส่งระหว่าง Mail Servers                ║
║                                                                ║
║  8. 💾 Full Disk Encryption                                    ║
║     ├─ Windows: BitLocker                                     ║
║     ├─ macOS: FileVault                                       ║
║     └─ Linux: LUKS (Linux Unified Key Setup)                  ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
```

### 7.2 Case Study: WhatsApp End-to-End Encryption

```
┌─────────────────────────────────────────────────────────────────┐
│        📱 WHATSAPP E2EE (END-TO-END ENCRYPTION)                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Alice's Phone    WhatsApp Server    Bob's Phone               │
│  ┌───────────┐    ┌───────────┐    ┌───────────┐              │
│  │           │    │           │    │           │              │
│  │  Message  │    │           │    │           │              │
│  │  "Hello"  │    │           │    │           │              │
│  │           │    │           │    │           │              │
│  │    ↓      │    │           │    │           │              │
│  │ [Encrypt] │    │           │    │           │              │
│  │ (Bob's PK)│    │           │    │           │              │
│  │    ↓      │    │           │    │           │              │
│  │ "@#$%^"   │────>│ "@#$%^"  │───>│ "@#$%^"   │              │
│  │           │    │ (Forward) │    │    ↓      │              │
│  │           │    │ (Can't    │    │ [Decrypt] │              │
│  │           │    │  Read!)   │    │ (Bob's SK)│              │
│  │           │    │           │    │    ↓      │              │
│  │           │    │           │    │  "Hello"  │              │
│  │           │    │           │    │           │              │
│  └───────────┘    └───────────┘    └───────────┘              │
│                                                                 │
│  💡 Key Points:                                                 │
│  1. Message เข้ารหัสที่อุปกรณ์ Alice (Client-side)               │
│  2. Server ส่งต่อเฉพาะ Ciphertext (อ่านไม่ได้)                  │
│  3. เฉพาะ Bob ถอดรหัสได้ที่อุปกรณ์ของเขา                         │
│  4. แม้ WhatsApp Server ก็อ่านไม่ได้!                            │
│  5. Government ขอ Decrypt → WhatsApp ก็ทำไม่ได้ (ไม่มี Key)    │
│                                                                 │
│  🔐 Encryption Used: Signal Protocol                           │
│     - X3DH (Extended Triple Diffie-Hellman)                    │
│     - Double Ratchet Algorithm                                 │
│     - AES-256 + HMAC-SHA256                                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 7.3 Case Study: HTTPS - How it Works

```
┌──────────────────────────────────────────────────────────────────┐
│              🔒 HTTPS / TLS HANDSHAKE                            │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Browser                                       Web Server        │
│  ┌──────────┐                                 ┌──────────┐      │
│  │          │  1. ClientHello                 │          │      │
│  │          │  (Supported Ciphers)            │          │      │
│  │          │ ──────────────────────────────> │          │      │
│  │          │                                 │          │      │
│  │          │  2. ServerHello                 │          │      │
│  │          │  + Certificate (Public Key)     │          │      │
│  │          │ <────────────────────────────── │          │      │
│  │          │                                 │          │      │
│  │ Verify   │                                 │          │      │
│  │ Cert ✓   │                                 │          │      │
│  │          │                                 │          │      │
│  │          │  3. Generate Session Key        │          │      │
│  │ Session  │  Encrypt with Server's Public   │          │      │
│  │ Key 🔑   │ ──────────────────────────────> │          │      │
│  │          │                                 │ Decrypt  │      │
│  │          │                                 │ Session  │      │
│  │          │                                 │ Key 🔑   │      │
│  │          │                                 │          │      │
│  │   ทั้งสองฝ่ายมี Session Key เหมือนกันแล้ว!   │          │      │
│  │          │                                 │          │      │
│  │          │  4. Encrypted Data (AES-256)    │          │      │
│  │ Encrypt  │ ──────────────────────────────> │ Decrypt  │      │
│  │ with SK  │                                 │ with SK  │      │
│  │          │ <────────────────────────────── │          │      │
│  │ Decrypt  │  5. Encrypted Response          │ Encrypt  │      │
│  │ with SK  │                                 │ with SK  │      │
│  │          │                                 │          │      │
│  └──────────┘                                 └──────────┘      │
│                                                                  │
│  🎯 Hybrid Encryption in Action:                                │
│  Step 1-3: Asymmetric (RSA) สำหรับแลก Session Key               │
│  Step 4-5: Symmetric (AES) สำหรับเข้ารหัสข้อมูลจริง              │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## ⚠️ Part 8: Common Mistakes & Best Practices

### 8.1 ข้อผิดพลาดที่พบบ่อย

```
╔════════════════════════════════════════════════════════════╗
║          ❌ COMMON CRYPTOGRAPHY MISTAKES                  ║
╠════════════════════════════════════════════════════════════╣
║                                                            ║
║  1. ❌ ใช้อัลกอริทึมที่อ่อนแอหรือเก่า                       ║
║     - MD5, SHA-1, DES → อย่าใช้แล้ว!                       ║
║     ✓ ใช้ SHA-256, SHA-3, AES-256 แทน                     ║
║                                                            ║
║  2. ❌ Hard-code Keys ในโค้ด                               ║
║     String key = "MySecretKey123";  ← อันตราย!            ║
║     ✓ เก็บ Keys ใน Environment Variables หรือ Key Vault  ║
║                                                            ║
║  3. ❌ ใช้ Key สั้นเกินไป                                  ║
║     - RSA 512-bit, AES 64-bit → แคร็กง่าย!                ║
║     ✓ RSA อย่างน้อย 2048-bit, AES อย่างน้อย 128-bit      ║
║                                                            ║
║  4. ❌ ไม่ใช้ Salt กับ Password Hashing                    ║
║     hash = sha256(password)  ← Rainbow Table Attack ได้!  ║
║     ✓ ใช้ bcrypt, scrypt, Argon2 (มี Salt อัตโนมัติ)      ║
║                                                            ║
║  5. ❌ Reuse IV (Initialization Vector)                    ║
║     - ใช้ IV เดิมซ้ำ ๆ → เดา Pattern ได้                   ║
║     ✓ สร้าง IV ใหม่ทุกครั้ง (Random)                       ║
║                                                            ║
║  6. ❌ ECB Mode (Electronic Codebook)                      ║
║     - Pattern ซ้ำ → เห็น Pattern ของภาพได้                ║
║     ✓ ใช้ CBC, GCM Mode แทน                                ║
║                                                            ║
║  7. ❌ Ignore Certificate Errors                           ║
║     curl_setopt(CURLOPT_SSL_VERIFYPEER, false); ← อันตราย!║
║     ✓ ตรวจสอบ Certificate ทุกครั้ง                          ║
║                                                            ║
║  8. ❌ Roll Your Own Crypto                                ║
║     - สร้างอัลกอริทึมเข้ารหัสเอง → มักมีช่องโหว่            ║
║     ✓ ใช้ Library ที่ผ่านการทดสอบแล้ว (OpenSSL, libsodium)║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
```

### 8.2 Best Practices

```
╔════════════════════════════════════════════════════════════╗
║          ✅ CRYPTOGRAPHY BEST PRACTICES                   ║
╠════════════════════════════════════════════════════════════╣
║                                                            ║
║  1. ✓ ใช้ Standard และ Proven Algorithms                  ║
║     - AES-256-GCM, RSA-2048/4096, SHA-256, Argon2        ║
║                                                            ║
║  2. ✓ Keep Keys Secure                                    ║
║     - เก็บใน Hardware Security Module (HSM)               ║
║     - เก็บใน Key Management Service (KMS)                 ║
║     - อย่า Hard-code, อย่า Commit ลง Git!                 ║
║                                                            ║
║  3. ✓ Rotate Keys Regularly                                ║
║     - เปลี่ยน Keys เป็นประจำ (ทุก 90 วัน)                  ║
║     - มี Key Rotation Policy                              ║
║                                                            ║
║  4. ✓ Use Strong Random Number Generator                   ║
║     - ใช้ /dev/urandom (Linux) หรือ CryptGenRandom (Win) ║
║     - อย่าใช้ rand(), random() → ไม่ Cryptographically Secure
║                                                            ║
║  5. ✓ Implement Perfect Forward Secrecy (PFS)             ║
║     - แม้ Private Key รั่วในอนาคต ข้อมูลเก่ายังปลอดภัย      ║
║     - ใช้ Ephemeral Keys (Key ที่ใช้ครั้งเดียวแล้วทิ้ง)      ║
║                                                            ║
║  6. ✓ Regular Security Audits                              ║
║     - ตรวจสอบ Crypto Implementation โดย Expert            ║
║     - Penetration Testing                                  ║
║                                                            ║
║  7. ✓ Plan for Crypto Agility                              ║
║     - เตรียมพร้อมเปลี่ยนอัลกอริทึมเมื่ออ่อนแอ                ║
║     - ไม่ควร Hardwire Algorithm ตายตัว                     ║
║                                                            ║
║  8. ✓ Educate Developers                                   ║
║     - Training เรื่อง Secure Coding                        ║
║     - Code Review สำหรับ Crypto Code                       ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
```

### 8.3 Password Hashing – ตัวอย่างที่ถูกต้อง

```python
# ❌ ผิด: Hash ธรรมดาไม่ปลอดภัย
import hashlib
password = "mypassword123"
hash = hashlib.sha256(password.encode()).hexdigest()
# ปัญหา: Rainbow Table Attack ได้!

# ✓ ถูก: ใช้ bcrypt (มี Salt อัตโนมัติ)
import bcrypt

# Hash password
password = b"mypassword123"
salt = bcrypt.gensalt(rounds=12)  # rounds càng สูงยิ่งปลอดภัย (แต่ช้าขึ้น)
hashed = bcrypt.hashpw(password, salt)
print(f"Hashed: {hashed}")

# ตรวจสอบ password
if bcrypt.checkpw(password, hashed):
    print("Password correct!")
else:
    print("Password incorrect!")
```

---

## 🔮 Part 9: Future of Cryptography

### 9.1 Quantum Computing Threat

```
┌──────────────────────────────────────────────────────────────┐
│         ⚛️  QUANTUM COMPUTING VS CURRENT CRYPTO               │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ปัญหา: Quantum Computer สามารถทำลาย Crypto ปัจจุบันได้!     │
│                                                              │
│  🔓 Vulnerable (อ่อนแอต่อ Quantum):                          │
│     ❌ RSA → Shor's Algorithm แคร็กได้                        │
│     ❌ ECC → แคร็กได้เช่นกัน                                  │
│     ❌ Diffie-Hellman → แคร็กได้                              │
│                                                              │
│  🔒 Still Safe (ปลอดภัยจาก Quantum):                         │
│     ✓ AES-256 → ยังปลอดภัย (ใช้ AES-256 แทน AES-128)         │
│     ✓ SHA-256/SHA-3 → ปลอดภัย                                │
│                                                              │
│  💡 Post-Quantum Cryptography (PQC):                         │
│     - NIST กำลังมาตรฐาน Algorithm ใหม่ที่ปลอดภัยจาก Quantum  │
│     - CRYSTALS-Kyber (Key Exchange)                          │
│     - CRYSTALS-Dilithium (Digital Signature)                 │
│     - SPHINCS+ (Hash-based Signature)                        │
│                                                              │
│  📅 Timeline:                                                │
│     2024-2030: Post-Quantum Standards                        │
│     2030+: Quantum Computers อาจมีจริง                       │
│     → ต้องเริ่มเตรียมตัวตั้งแต่ตอนนี้!                          │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 9.2 Homomorphic Encryption

**Homomorphic Encryption** = เข้ารหัสแล้วยังคำนวณได้!

```
┌──────────────────────────────────────────────────────────────┐
│        🎩 HOMOMORPHIC ENCRYPTION                             │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ปกติ:                                                        │
│  Encrypt(5) + Encrypt(3) = ???                               │
│  → ต้อง Decrypt ก่อนถึงบวกได้                                 │
│                                                              │
│  Homomorphic Encryption:                                     │
│  Encrypt(5) + Encrypt(3) = Encrypt(8)                        │
│  → คำนวณใน Ciphertext ได้เลย!                                │
│                                                              │
│  Use Cases:                                                  │
│  1. Cloud Computing – คำนวณข้อมูลที่เข้ารหัสโดยไม่ต้องถอดรหัส   │
│  2. Privacy-Preserving Machine Learning                      │
│  3. Secure Multi-Party Computation                           │
│                                                              │
│  ปัญหา: ยังช้ามาก (100-1000 เท่าของ Crypto ปกติ)             │
│  Future: กำลังพัฒนาให้เร็วขึ้น                                 │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## 📝 Part 10: สรุปบทเรียน

### 10.1 Key Takeaways

```
╔═══════════════════════════════════════════════════════════════╗
║              📚 WEEK 6 SUMMARY                                ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  🔐 1. Cryptography Basics                                    ║
║     ✓ Plaintext → [Encrypt] → Ciphertext → [Decrypt] → Plaintext
║     ✓ Key คือส่วนสำคัญที่สุด                                   ║
║                                                               ║
║  🔑 2. Symmetric vs Asymmetric                                ║
║     ✓ Symmetric: เร็ว, 1 Key, Key Distribution ยาก            ║
║     ✓ Asymmetric: ช้า, 2 Keys, แก้ปัญหา Key Distribution      ║
║     ✓ Hybrid: ใช้ทั้งสองแบบร่วมกัน (เช่น SSL/TLS)             ║
║                                                               ║
║  ✍️ 3. Digital Signature & PKI                                ║
║     ✓ Signature พิสูจน์ Authentication + Integrity            ║
║     ✓ Certificate การันตีว่า Public Key เป็นของใคร            ║
║     ✓ CA ออก Certificate หลังตรวจสอบตัวตนแล้ว                  ║
║                                                               ║
║  #️⃣ 4. Hash Function                                          ║
║     ✓ One-way Function (หา Input จาก Output ไม่ได้)           ║
║     ✓ ใช้ตรวจสอบ Integrity, เก็บ Password, Digital Signature  ║
║     ✓ SHA-256 แนะนำ, MD5/SHA-1 อย่าใช้                        ║
║                                                               ║
║  🌐 5. Real-World Applications                                ║
║     ✓ HTTPS, WhatsApp E2EE, Bitcoin, Password Manager        ║
║     ✓ Cryptography อยู่ทุกที่ในชีวิตดิจิทัล!                   ║
║                                                               ║
║  ⚠️ 6. Best Practices                                         ║
║     ✓ ใช้ Standard Algorithms, Keep Keys Secure              ║
║     ✓ Rotate Keys, Security Audit, Educate Developers        ║
║     ✓ อย่า Roll Your Own Crypto!                              ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
```

### 10.2 Comparison Table

| **เปรียบเทียบ**     | **Symmetric** | **Asymmetric** | **Hash** | **MAC** |
|---------------------|---------------|----------------|----------|---------|
| **Input**           | Message + Key | Message + Key  | Message  | Message + Key |
| **Output**          | Ciphertext    | Ciphertext     | Hash Value | MAC Value |
| **Reversible?**     | ✓ (ถอดรหัสได้)  | ✓ (ถอดรหัสได้)   | ✗ (One-way) | ✗ (One-way) |
| **Purpose**         | Confidentiality | Confidentiality | Integrity | Integrity + Auth |
| **Speed**           | เร็วมาก ⚡      | ช้า 🐌          | เร็วมาก ⚡ | เร็วมาก ⚡ |
| **Key Management**  | ยาก 😰         | ง่าย 😊         | ไม่มี Key | ต้องแบ่งปัน Key |

---

## 🔜 Part 11: Preview – สัปดาห์หน้าเรียนอะไร?

### Week 7: Web Application Security & OWASP Overview

```
┌──────────────────────────────────────────────────────────────┐
│        🌐 NEXT WEEK: WEB SECURITY                            │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  สัปดาห์หน้าเราจะเรียนรู้:                                     │
│                                                              │
│  1. 🎯 OWASP Top 10 (ช่องโหว่ Web ที่พบบ่อยที่สุด)             │
│     - SQL Injection                                          │
│     - Cross-Site Scripting (XSS)                             │
│     - Broken Authentication                                  │
│     - Security Misconfiguration                              │
│                                                              │
│  2. 💉 SQL Injection                                         │
│     - วิธีการโจมตี                                             │
│     - การป้องกันด้วย Parameterized Query                      │
│     - Lab: ทดลองโจมตี DVWA / Juice Shop                       │
│                                                              │
│  3. 🎭 Cross-Site Scripting (XSS)                            │
│     - Reflected XSS, Stored XSS, DOM XSS                    │
│     - การป้องกันด้วย Input Validation & Output Encoding      │
│                                                              │
│  4. ✍️ Secure Coding Practices                               │
│     - Input Validation                                       │
│     - Output Encoding                                        │
│     - Principle of Least Privilege                           │
│                                                              │
│  💡 Cryptography ที่เรียนไปสัปดาห์นี้จะถูกใช้ใน:               │
│     - HTTPS (SSL/TLS) สำหรับ Web Security                    │
│     - Password Hashing (bcrypt, Argon2)                      │
│     - Session Token Encryption                               │
│     - JWT (JSON Web Token) Signing                           │
│                                                              │
│  🔗 Connection:                                              │
│  Week 6 (Crypto) + Week 7 (Web Security)                    │
│  = Secure Web Application! 🎯                                │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

**สิ่งที่ควรเตรียม:**
1. ติดตั้ง DVWA (Damn Vulnerable Web Application) ใน VM
2. ทบทวน HTML, JavaScript พื้นฐาน
3. ลองเล่น Burp Suite / OWASP ZAP

---

## 📊 Assessment สำหรับ Week 6

### Quiz 3: Concepts Cryptography พื้นฐาน

**รูปแบบ:** Online Quiz (10 คะแนน)  
**เวลา:** 15 นาที

**ตัวอย่างข้อสอบ:**

1. Symmetric Encryption ใช้กุญแจกี่ตัวในการเข้ารหัสและถอดรหัส?
   - a) 0 ตัว
   - b) 1 ตัว ✓
   - c) 2 ตัว
   - d) 3 ตัว

2. อัลกอริทึมใดเป็น Asymmetric Encryption?
   - a) AES
   - b) DES
   - c) RSA ✓
   - d) ChaCha20

3. Hash Function มีคุณสมบัติใด?
   - a) สามารถหา Input จาก Output ได้
   - b) Input เดิมได้ Output เดิมเสมอ ✓
   - c) Output มีขนาดต่างกันตาม Input
   - d) ถูกทั้ง a และ b

4. Digital Signature ใช้ Key ใดในการสร้างลายเซ็น?
   - a) Public Key
   - b) Private Key ✓
   - c) Session Key
   - d) Shared Key

5. SSL/TLS Certificate ออกโดยใคร?
   - a) ผู้ใช้งานเอง
   - b) Web Browser
   - c) Certificate Authority (CA) ✓
   - d) Web Server

### Participation: Cipher Puzzle (10 คะแนน)

**การให้คะแนน:**
- ถอดรหัส Caesar Cipher ได้: 3 คะแนน
- ถอดรหัส Substitution Cipher ได้: 4 คะแนน
- เข้าร่วมกิจกรรม Group Discussion: 3 คะแนน

---

## 📚 แหล่งข้อมูลเพิ่มเติม

### 📖 หนังสือแนะนำ
1. **"Cryptography and Network Security" – William Stallings**
2. **"Applied Cryptography" – Bruce Schneier**
3. **"The Code Book" – Simon Singh** (อ่านง่าย เหมาะกับมือใหม่)

### 🌐 Websites & Online Resources
1. **Khan Academy – Cryptography** (https://www.khanacademy.org/computing/computer-science/cryptography)
2. **Coursera – Cryptography I** by Dan Boneh (Stanford)
3. **Cryptopals Challenges** (https://cryptopals.com/) – เรียนรู้ผ่านโจทย์
4. **OWASP Cryptographic Storage Cheat Sheet**

### 🎥 Videos
1. **"The Mathematics of Cryptography"** – YouTube (Computerphile)
2. **"How Does HTTPS Work?"** – YouTube
3. **"Encryption and HUGE numbers"** – 3Blue1Brown

### 🛠️ Tools & Libraries
1. **OpenSSL** – Command-line Crypto Tool
2. **CyberChef** – Web-based Crypto Tool
3. **hashcat** – Password Cracking Tool (เรียนรู้ความแข็งแรงของ Password)
4. **Libsodium** – Modern Crypto Library

---

## 🎓 การเชื่อมโยง CLO

**Week 6 สนับสนุน CLO:**

- **CLO1 – Fundamental Concepts:** อธิบายหลักการ Cryptography พื้นฐาน (Symmetric, Asymmetric, Hash)
- **CLO3 – Protection Techniques:** ประยุกต์ใช้ OpenSSL เข้ารหัส/ถอดรหัส ตรวจสอบ Certificate

---

## 🎯 Challenge Questions (สำหรับนักศึกษาที่สนใจลึก)

1. **ทำไม AES ใช้ Key Size 128/192/256 bits แต่ SHA-256 ให้ Output 256 bits?**
   - คำตอบ: Key Size ≠ Hash Output Size มีวัตถุประสงค์ต่างกัน

2. **ถ้า Hash Function เป็น One-way แล้วทำไม Rainbow Table ถึงแคร็กได้?**
   - คำตอบ: Rainbow Table Pre-compute Hash ของ Password ทั่วไป แก้ด้วย Salt

3. **ทำไม WhatsApp ใช้ E2EE แล้ว Government ยังขอให้ Decrypt ข้อความได้ไหม?**
   - คำตอบ: ทำไม่ได้เพราะ WhatsApp ไม่มี Key (Key อยู่ที่ Device ของผู้ใช้)

4. **Bitcoin ใช้ SHA-256 แต่ถ้า Quantum Computer แคร็ก SHA-256 ได้ จะเกิดอะไรขึ้น?**
   - คำตอบ: SHA-256 ยังปลอดภัยจาก Quantum แต่ ECDSA ที่ Bitcoin ใช้มีปัญหา → ต้องเปลี่ยนเป็น Post-Quantum Signature

---

## 🎬 สรุปสุดท้าย

```
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║           🎉 ยินดีด้วย! คุณผ่าน Week 6 แล้ว!                 ║
║                                                               ║
║     ตอนนี้คุณรู้แล้วว่า:                                       ║
║     ✓ Cryptography คืออะไรและทำไมสำคัญ                        ║
║     ✓ Symmetric vs Asymmetric Encryption                     ║
║     ✓ Digital Signature & PKI ทำงานอย่างไร                   ║
║     ✓ Hash Function และ MAC คืออะไร                          ║
║     ✓ Crypto ถูกใช้งานในชีวิตจริงอย่างไร                       ║
║                                                               ║
║     💪 คุณสามารถ:                                             ║
║     ✓ ใช้ OpenSSL เข้ารหัส/ถอดรหัสข้อมูล                        ║
║     ✓ ตรวจสอบ SSL/TLS Certificate ของเว็บไซต์                  ║
║     ✓ ถอดรหัส Caesar Cipher และ Substitution Cipher         ║
║     ✓ เข้าใจว่า HTTPS, WhatsApp E2EE ทำงานอย่างไร              ║
║                                                               ║
║     🚀 สัปดาห์หน้า: Web Application Security!                ║
║        เตรียมเรียนรู้ช่องโหว่ Web และวิธีป้องกัน!               ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
```

---

**จบ Week 6: Cryptography Basics** 🔐

