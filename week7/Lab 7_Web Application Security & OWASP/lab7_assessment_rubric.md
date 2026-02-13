# Lab 7 Assessment Rubric
## Web Application Security - Vulnerable Blog System

**Total Points: 10**  
**Student Name:** ________________  
**Student ID:** ________________  
**Submission Date:** ________________

---

## 📊 Grading Breakdown

### Part 1: SQL Injection Testing & Exploitation (2 คะแนน)

#### 1.1 Login Bypass (1 คะแนน)

| Criteria | Excellent (1.0) | Good (0.7) | Fair (0.5) | Poor (0-0.3) |
|----------|----------------|-----------|-----------|--------------|
| **Payload Effectiveness** | ใช้ payload ที่ bypass ได้สำเร็จและอธิบายได้ชัดเจน | ใช้ payload ได้แต่อธิบายไม่ชัดเจน | ใช้ payload ได้บางส่วน | ไม่สามารถ bypass ได้ |
| **Documentation** | มี screenshot, query ที่ execute, และคำอธิบายครบถ้วน | มี screenshot แต่คำอธิบายไม่ครบ | มี screenshot แต่ไม่มีคำอธิบาย | ไม่มี documentation |
| **Understanding** | อธิบายทำไม payload ทำงานได้และผลกระทบ | อธิบายได้บางส่วน | อธิบายไม่ชัดเจน | ไม่เข้าใจ |

**Score: _____ / 1.0**

**Comments:**
```




```

---

#### 1.2 Search Feature SQL Injection (1 คะแนน)

| Criteria | Excellent (1.0) | Good (0.7) | Fair (0.5) | Poor (0-0.3) |
|----------|----------------|-----------|-----------|--------------|
| **Data Extraction** | ดึงข้อมูล users table ได้สำเร็จและแสดง technique | ดึงข้อมูลได้บางส่วน | พยายามแต่ไม่สำเร็จ | ไม่สามารถทำได้ |
| **UNION Query** | ใช้ UNION SELECT ถูกต้องและหาจำนวน column ได้ | ใช้ UNION ได้แต่ไม่ถูกต้อง | ไม่เข้าใจ UNION | ไม่ได้ลอง |
| **Impact Analysis** | อธิบายผลกระทบและความเสี่ยงชัดเจน | อธิบายได้บางส่วน | อธิบายคลุมเครือ | ไม่มีการวิเคราะห์ |

**Score: _____ / 1.0**

**Comments:**
```




```

---

### Part 2: Cross-Site Scripting (XSS) Testing (2 คะแนน)

#### 2.1 Stored XSS in Comments (1 คะแนน)

| Criteria | Excellent (1.0) | Good (0.7) | Fair (0.5) | Poor (0-0.3) |
|----------|----------------|-----------|-----------|--------------|
| **Payload Execution** | JavaScript execute สำเร็จและแสดงหลายตัวอย่าง | Execute สำเร็จ 1 payload | พยายามแต่ไม่สำเร็จ | ไม่ได้ลอง |
| **Impact Demonstration** | แสดง impact เช่น cookie stealing, phishing | แสดง basic alert เท่านั้น | ไม่แสดง impact | - |
| **Documentation** | มี screenshot ชัดเจนและอธิบายครบ | มี screenshot แต่ไม่ครบ | มี screenshot น้อย | ไม่มี screenshot |

**Score: _____ / 1.0**

**Comments:**
```




```

---

#### 2.2 Reflected XSS in Search (1 คะแนน)

| Criteria | Excellent (1.0) | Good (0.7) | Fair (0.5) | Poor (0-0.3) |
|----------|----------------|-----------|-----------|--------------|
| **XSS Detection** | พบและ exploit reflected XSS ได้ | พบแต่ exploit ไม่สำเร็จ | พยายามแต่ไม่พบ | ไม่ได้ลอง |
| **Stored vs Reflected** | อธิบายความแตกต่างชัดเจน | อธิบายได้บางส่วน | สับสนระหว่าง 2 แบบ | ไม่เข้าใจความแตกต่าง |
| **Attack Scenario** | อธิบาย attack scenario ในโลกจริง | อธิบายได้แต่ไม่ชัดเจน | ไม่มี scenario | - |

**Score: _____ / 1.0**

**Comments:**
```




```

---

### Part 3: Fixing SQL Injection (2 คะแนน)

| Criteria | Excellent (2.0) | Good (1.5) | Fair (1.0) | Poor (0-0.5) |
|----------|----------------|-----------|-----------|--------------|
| **Parameterized Query** | ใช้ parameterized query ถูกต้องทุกจุด | ใช้ถูกต้องแต่ไม่ครบทุกจุด | ใช้แต่ผิดวิธี | ไม่ได้แก้ไข |
| **Code Quality** | Code สะอาด มี comment อธิบาย | Code ใช้ได้แต่ไม่มี comment | Code ยุ่งและไม่มี comment | Code ใช้ไม่ได้ |
| **Testing** | ทดสอบว่า payload เดิมไม่ทำงานแล้ว | ทดสอบบางส่วน | ไม่ได้ทดสอบ | - |
| **Explanation** | อธิบายว่าแก้อย่างไรและทำไม | อธิบายได้แต่ไม่ละเอียด | อธิบายคลุมเครือ | ไม่มีคำอธิบาย |

**Score: _____ / 2.0**

**Comments:**
```




```

---

### Part 4: Fixing XSS (2 คะแนน)

| Criteria | Excellent (2.0) | Good (1.5) | Fair (1.0) | Poor (0-0.5) |
|----------|----------------|-----------|-----------|--------------|
| **Output Encoding** | ใช้ escapeHtml() หรือ textContent ถูกต้องครบ | ใช้ถูกแต่ไม่ครบทุกจุด | ใช้แต่วิธีไม่ถูก | ไม่ได้แก้ไข |
| **Both XSS Types** | แก้ทั้ง Stored และ Reflected XSS | แก้แค่อย่างใดอย่างหนึ่ง | แก้ไม่ครบ | ไม่ได้แก้ |
| **Testing** | ทดสอบว่า payload เดิมไม่ทำงานแล้ว | ทดสอบบางส่วน | ไม่ได้ทดสอบ | - |
| **Security Headers (Bonus)** | เพิ่ม CSP และ security headers | เพิ่มบางส่วน | ไม่ได้เพิ่ม | - |

**Score: _____ / 2.0**

**Comments:**
```




```

---

### Part 5: Report Quality (2 คะแนน)

#### 5.1 Structure & Completeness (1 คะแนน)

| Criteria | Excellent (1.0) | Good (0.7) | Fair (0.5) | Poor (0-0.3) |
|----------|----------------|-----------|-----------|--------------|
| **Report Structure** | มี structure ชัดเจนตาม template | มี structure แต่ไม่สมบูรณ์ | Structure ไม่ชัดเจน | ไม่มี structure |
| **Completeness** | ครบทุกส่วนที่กำหนด | ครบแต่ไม่ละเอียด | ขาดหลายส่วน | ขาดส่วนสำคัญ |
| **Screenshots** | มี screenshot ครบและชัดเจน | มีแต่ไม่ครบ | มีน้อยมาก | ไม่มี screenshot |

**Score: _____ / 1.0**

---

#### 5.2 Code Comparison & Explanation (1 คะแนน)

| Criteria | Excellent (1.0) | Good (0.7) | Fair (0.5) | Poor (0-0.3) |
|----------|----------------|-----------|-----------|--------------|
| **Before/After Code** | มี code comparison ชัดเจนทุกจุด | มีแต่ไม่ครบ | มีแต่ไม่ชัดเจน | ไม่มี comparison |
| **Explanation Quality** | อธิบายชัดเจนและเข้าใจง่าย | อธิบายได้แต่ไม่ชัดเจน | อธิบายคลุมเครือ | ไม่มีคำอธิบาย |
| **Recommendations** | มี recommendations ที่ดีและนำไปใช้ได้ | มีแต่ไม่ชัดเจน | มีแต่ไม่เกี่ยวข้อง | ไม่มี |
| **Professional Writing** | เขียนเป็นมืออาชีพและอ่านง่าย | เขียนดีแต่มี typo บ้าง | เขียนไม่ชัดเจน | เขียนยุ่งมาก |

**Score: _____ / 1.0**

**Comments:**
```




```

---

## 🎁 Bonus Points (Maximum +5 คะแนน)

### Bonus 1: Broken Access Control Fix (+2 คะแนน)

| Criteria | Points |
|----------|--------|
| แก้ไข user profile access control ถูกต้อง | +1.0 |
| ทดสอบและ document ครบถ้วน | +0.5 |
| อธิบายชัดเจนและมี code quality ดี | +0.5 |

**Bonus Score: _____ / 2.0**

---

### Bonus 2: Content Security Policy (+1 คะแนน)

| Criteria | Points |
|----------|--------|
| Implement CSP headers ถูกต้อง | +0.5 |
| Test และอธิบายว่า CSP ทำงานอย่างไร | +0.5 |

**Bonus Score: _____ / 1.0**

---

### Bonus 3: Password Hashing (+2 คะแนน)

| Criteria | Points |
|----------|--------|
| Implement bcrypt สำหรับ password hashing | +1.0 |
| Migration script สำหรับ existing users | +0.5 |
| Documentation และ testing | +0.5 |

**Bonus Score: _____ / 2.0**

---

### Additional Bonus: Extra Findings

| Finding | Points | Awarded |
|---------|--------|---------|
| พบช่องโหว่อื่นที่ไม่ได้ระบุในโจทย์ | +1.0 | _____ |
| Automated testing script | +1.0 | _____ |
| Defense technique research & presentation | +1.0 | _____ |

**Extra Bonus Score: _____ / 3.0**

---

## 📊 Summary

| Section | Points | Score |
|---------|--------|-------|
| SQL Injection Testing | 2.0 | _____ |
| XSS Testing | 2.0 | _____ |
| SQL Injection Fix | 2.0 | _____ |
| XSS Fix | 2.0 | _____ |
| Report Quality | 2.0 | _____ |
| **Subtotal (Required)** | **10.0** | **_____** |
| Bonus Points | +5.0 | _____ |
| **Total Score** | **15.0** | **_____** |

**Final Score (capped at 10): _____**

---

## 💬 Overall Feedback

### Strengths:
```




```

### Areas for Improvement:
```




```

### Specific Comments:
```




```

---

## ⚠️ Academic Integrity Check

- [ ] Code appears to be student's own work
- [ ] Report is written in student's own words
- [ ] Proper understanding demonstrated
- [ ] No evidence of plagiarism

**If plagiarism detected:**
- [ ] Minor similarity (warning) - deduct 20%
- [ ] Significant copying (serious) - deduct 50%
- [ ] Complete plagiarism - 0 points + report to department

---

## ✅ Grading Completed By

**Instructor/TA:** ________________  
**Date:** ________________  
**Signature:** ________________

---

## 📝 Notes for Graders

### Common Mistakes to Watch For:

1. **SQL Injection:**
   - ใช้ string concatenation แทน parameterized query
   - ใช้ escape() แต่ไม่ครบทุก special character
   - แก้เฉพาะ login แต่ลืม search

2. **XSS:**
   - ใช้ blacklist approach (ไม่ปลอดภัย)
   - Encode แค่บางจุด ไม่ครบทั้งหมด
   - ไม่เข้าใจความแตกต่าง stored vs reflected

3. **Report:**
   - ไม่มี screenshot
   - Copy-paste code โดยไม่อธิบาย
   - ไม่มี before/after comparison

### Grading Tips:

- อ่าน code ทั้งหมดก่อนให้คะแนน
- ลอง run code เพื่อตรวจสอบว่าทำงาน
- ให้คะแนนตาม rubric อย่างเคร่งครัด
- เขียน feedback ที่เป็นประโยชน์
- ถ้า code ดีมาก พิจารณาให้ bonus

---

## 🎯 Grade Distribution Guidelines

**Expected Distribution:**

- A (8.5-10): 20-30% - Outstanding work, ทำครบและเข้าใจลึก
- B (7.0-8.4): 40-50% - Good work, ทำครบแต่อาจมีจุดบกพร่องเล็กน้อย
- C (5.5-6.9): 20-30% - Satisfactory, ทำได้แต่ยังขาดความเข้าใจ
- D (4.0-5.4): 5-10% - Poor, ทำไม่ครบหรือไม่เข้าใจ
- F (0-3.9): <5% - Fail, ไม่ส่งหรือทำผิดหมด

---

**End of Rubric**
