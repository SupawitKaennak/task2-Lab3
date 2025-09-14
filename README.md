# LAB3: เอกสารคู่มือการทดสอบความปลอดภัยเว็บแอปพลิเคชัน
## Security Testing Guide & Report Template

**Team:** กลุ่ม5

**1. ชื่อ-สกุล:** นายศุภวิชญ์ แก่นนาค 
**รหัสนักศึกษา:** 66543210031-1 

**2. ชื่อ-สกุล:** นางสาวชวัลลักษณ์  ไพบูลย์ชมพู
**รหัสนักศึกษา:** 66543210009-7

**3. ชื่อ-สกุล:** นางสาวบุญศิริ เจริญพร 
**รหัสนักศึกษา:** 66543210050-1 



**วันที่ทดสอบ:** 19 ส.ค. 2568
 
**เวลาที่ใช้:** 3 วัน

---

## การเตรียมความพร้อม (Pre-Testing Checklist)

### ✅ ตรวจสอบระบบ
- [✅] ติดตั้ง Node.js และ SQL Server เรียบร้อย
- [✅] สร้างฐานข้อมูลและ import ข้อมูลทดสอบแล้ว
- [✅] Vulnerable Server (port 3000) ทำงานได้
- [✅] Secure Server (port 3001) ทำงานได้
- [✅] Frontend files เปิดได้ในเบราว์เซอร์
- [✅] เครื่องมือทดสอบ (Browser Developer Tools) พร้อมใช้
<img width="1053" height="244" alt="{3F1D77FD-79B3-4A24-B61B-11D63DEAC771}" src="https://github.com/user-attachments/assets/64db83c3-255e-4202-af04-d73398a143d5" />
<img width="952" height="482" alt="{B723266D-B58D-4893-9AF9-14B2DFB64078}" src="https://github.com/user-attachments/assets/1a60e5f0-5a72-45a5-adad-735e20ae8d28" />
<img width="1324" height="901" alt="{3B6A4E1E-4E7B-4593-8432-09BF9A04439A}" src="https://github.com/user-attachments/assets/3c7592a2-23b2-4255-816d-cfca667ed7e0" />
<img width="1516" height="760" alt="{C79CBA4B-953F-4CD0-8700-2909D01F308D}" src="https://github.com/user-attachments/assets/4b442241-332f-4fba-883f-d036e25fd18f" />
<img width="479" height="275" alt="{F3797D19-E0BF-4100-8C8B-4CBA164A4657}" src="https://github.com/user-attachments/assets/3fc22ead-7fa1-461b-baba-0f5765fc4f43" />
<img width="736" height="76" alt="{9B65DF2C-4AB3-47B2-82D1-15244FBF2E4D}" src="https://github.com/user-attachments/assets/817ac814-4f54-4ba1-a590-14c4f5093009" />
<img width="999" height="1074" alt="{047CF803-D35D-4825-9348-60BDD9E37997}" src="https://github.com/user-attachments/assets/94063b97-260d-4e67-a79f-5f9f8b45e2cb" />



### 📋 ข้อมูลระบบ
| รายการ | Vulnerable Version | Secure Version |
|--------|-------------------|----------------|
| Backend URL | http://localhost:3000 | http://localhost:3001 |
| Frontend URL | index.html | secure.html |
| Database | SecurityLab | SecurityLab |

---

## Part 1: การทดสอบ Vulnerable Version

### Test Case 1.1: SQL Injection - Login Bypass

**วัตถุประสงค์:** ทดสอบการ bypass login ด้วย SQL Injection

**ขั้นตอนการทดสอบ:**
1. เปิด `index.html` (Vulnerable Version)
2. ไปยังส่วน Login
3. กรอกข้อมูลดังนี้:
   - Username: `admin'; --`
   - Password: `anything`
4. กดปุ่ม Login

**บันทึกผลการทดสอบ:**

| ผลลัพธ์ที่คาดหวัง | ผลลัพธ์จริง | สำเร็จ/ล้มเหลว |
|------------------|------------|----------------|
| Login สำเร็จโดยไม่ตรวจสอบรหัสผ่าน | สามารถ login ได้จริงๆ | ⚪ สำเร็จ |

**Screenshot หลักฐาน:** (<img width="732" height="84" alt="{FBA80C7F-D426-49E5-9906-AA637415885C}" src="https://github.com/user-attachments/assets/c3d113a8-f434-45f0-a70b-877633630194" />
<img width="588" height="491" alt="{C8EA5E63-93E6-4BF2-8195-7113239FD62C}" src="https://github.com/user-attachments/assets/37cdc051-35c4-47d0-b9bc-20865c6f1981" />
)

**วิเคราะห์และความคิดเห็น:**
```
sql SELECT * FROM Users WHERE username='admin'; --' AND password='1'
`--` คือ comment ใน SQL ทำให้ทุกอย่างหลังมันถูกละเลย
ดังนั้น query จะกลายเป็นแค่ `SELECT * FROM Users WHERE username='admin';` ไม่สนใจ password เลย
```

---

### Test Case 1.2: SQL Injection - Data Extraction

**วัตถุประสงค์:** ทดสอบการดึงข้อมูลผู้ใช้ด้วย UNION attack

**ขั้นตอนการทดสอบ:**
1. ไปยังส่วน Product Search
2. กรอกข้อมูล: `' UNION SELECT id,username,password FROM Users; --`
3. กดปุ่ม Search

**บันทึกผลการทดสอบ:**

| ผลลัพธ์ที่คาดหวัง | ผลลัพธ์จริง | สำเร็จ/ล้มเหลว |
|------------------|------------|----------------|
| แสดงข้อมูลผู้ใช้และรหัสผ่าน | ไม่มีข้อมูลแสดงออกมา |⚪ ล้มเหลว |

**ข้อมูลที่ได้รับ:**
<img width="1030" height="181" alt="{A3F012E4-5534-4AE7-B430-B4BE07F5C539}" src="https://github.com/user-attachments/assets/6ef12361-801f-45b1-a0f2-8e57a2d277eb" />

<img width="803" height="135" alt="{654C4B86-8927-48C0-8030-6D6A834F2B7D}" src="https://github.com/user-attachments/assets/d9903d2f-8899-491f-adcd-cc6f7525b721" />

<img width="1002" height="181" alt="{71186AA9-2650-4190-A0DA-F75DBDCC01DE}" src="https://github.com/user-attachments/assets/ca851656-f1d7-487a-8564-eb94782973b0" />

<img width="1028" height="172" alt="{54181EDD-7CED-4351-ABAD-E442C1155F45}" src="https://github.com/user-attachments/assets/5cc1ab98-6fae-4ca6-92ff-cddb596ad7ce" />

**วิเคราะห์และความคิดเห็น:**
```
ไม่แน่ใจว่าเป้นที่อะไรครับ แต่ไม่สามารถ ดูข้อม฿ลได้

```

---

### Test Case 1.3: Cross-Site Scripting (XSS)

**วัตถุประสงค์:** ทดสอบการแทรก JavaScript code ผ่าน comment

**ขั้นตอนการทดสอบ:**
1. Login ด้วย user ปกติ (john/password)
2. ไปยังส่วน Comments
3. กรอก comment: `<script>alert('XSS Attack!');</script>`
4. Submit comment

**บันทึกผลการทดสอบ:**

| ผลลัพธ์ที่คาดหวัง | ผลลัพธ์จริง | สำเร็จ/ล้มเหลว |
|------------------|------------|----------------|
| JavaScript execute และแสดง alert | | ⚪ ล้มเหลว |

**ทดสอบ XSS เพิ่มเติม:**

**Test 1.3.1:** Cookie Stealing Simulation
- Payload: `<script>alert('Cookie: ' + document.cookie);</script>`
- ผลลัพธ์: ไม่มีอะไรเกิดขึ้น
- <img width="993" height="898" alt="{96250989-3820-4567-A2FF-806784EBB84A}" src="https://github.com/user-attachments/assets/46b28fe1-bed6-4d52-b2bc-2b6185a77b88" />


**Test 1.3.2:** DOM Manipulation
- Payload: `<img src=x onerror=alert('XSS via IMG tag')>`
- ผลลัพธ์: ไม่มีอะไรเกิดขึ้น
- <img width="973" height="886" alt="{8E9451C5-8125-4322-92FA-2E731E12B19C}" src="https://github.com/user-attachments/assets/91204a03-31f2-4e70-8f68-227d410393ce" />


**วิเคราะห์และความคิดเห็น:**
```
โค้ดนี้ใช้ <script> หรือ <img onerror=...> แล้ว "ไม่เกิด alert"
   อาจเป็นเพราะ เบราว์เซอร์หรือ framework มีการกรองอัตโนมัติ (เช่น Chrome มีบางส่วน)
ส่วนแสดงผล comment ใน script.js มีการ escape หรือ sanitize ข้อมูลก่อนแสดงผล
หรืออาจยังไม่ได้แสดง comment ที่โพสต์ใหม่ทันที
```

---

### Test Case 1.4: Insecure Direct Object Reference (IDOR)

**วัตถุประสงค์:** ทดสอบการเข้าถึงข้อมูลผู้ใช้อื่นโดยไม่ได้รับอนุญาต

**ขั้นตอนการทดสอบ:**
1. Login ด้วย john/password
2. ไปยังส่วน User Profile
3. ลองเปลี่ยน User ID เป็น 1, 2, 3
4. สังเกตข้อมูลที่ได้รับ

**บันทึกผลการทดสอบ:**

| User ID | ข้อมูลที่แสดง | สามารถเข้าถึงได้ |
|---------|---------------|------------------|
| 1 |<img width="227" height="147" alt="{52E79B82-5880-42A8-BE5D-2F727E0039C3}" src="https://github.com/user-attachments/assets/6847895f-42b2-407f-be42-f104909b91a4" />
 | ⚪ ใช่ |
| 2 |<img width="218" height="162" alt="{DFB2547A-1264-4AE1-AFDB-0EED82EDE9DC}" src="https://github.com/user-attachments/assets/416a28ec-0208-44ad-873e-fbd33d5a82a8" />
 | ⚪ ใช่ |
| 3 |<img width="211" height="153" alt="{30DD13A6-FE4D-4063-9219-408ED4134355}" src="https://github.com/user-attachments/assets/89394cd8-d897-4e66-adcf-091150cd4d76" />
 | ⚪ ใช่ |

<img width="969" height="835" alt="{69FF6FC0-E035-4ABF-9550-875C391D17E8}" src="https://github.com/user-attachments/assets/06ec314f-1543-464e-9186-a9ef94cac161" />
<img width="978" height="667" alt="{F4A5B785-10C7-4BB6-8A40-89B3A7D66D51}" src="https://github.com/user-attachments/assets/c7c979f4-563c-4709-a5cd-71cab66f0d96" />


**วิเคราะห์และความคิดเห็น:**
```
วิเคราะห์ปัญหา IDOR:
- ข้อมูลอะไรบ้างที่เข้าถึงได้
- ความเสี่ยงด้านความเป็นส่วนตัว
- วิธีการที่ผู้โจมตีอาจใช้ช่องโหว่นี้
```

---

## Part 2: การทดสอบ Secure Version

### Test Case 2.1: SQL Injection Protection

**วัตถุประสงค์:** ทดสอบการป้องกัน SQL Injection

**ขั้นตอนการทดสอบ:**
1. เปิด `secure.html` (Secure Version)
2. ทดสอบ payloads เดียวกันกับ vulnerable version

**บันทึกผลการทดสอบ:**

| Payload | ผลลัพธ์ | การป้องกัน |
|---------|---------|------------|
| `admin'; --` | | ⚪ ถูกบล็อก ⚪ ผ่านได้ |
| `' UNION SELECT * FROM Users; --` | | ⚪ ถูกบล็อก ⚪ ผ่านได้ |
| `'; DROP TABLE Products; --` | | ⚪ ถูกบล็อก ⚪ ผ่านได้ |

**วิธีการป้องกันที่สังเกตได้:**
- [ ] Input validation
- [ ] Prepared statements
- [ ] Error message ที่ไม่เปิดเผยรายละเอียด
- [ ] อื่นๆ: ________________

**วิเคราะห์และความคิดเห็น:**
```
เปรียบเทียบกับ vulnerable version:
- ความแตกต่างในการตอบสนอง
- วิธีการป้องกันที่มีประสิทธิภาพ
- ข้อเสนอแนะสำหรับการพัฒนา
```

---

### Test Case 2.2: XSS Protection

**วัตถุประสงค์:** ทดสอบการป้องกัน Cross-Site Scripting

**ขั้นตอนการทดสอบ:**
1. Login ในระบบ secure version
2. ทดสอบ XSS payloads ในช่อง comment

**บันทึกผลการทดสอบ:**

| Payload | ผลลัพธ์ที่แสดง | Script Execute หรือไม่ |
|---------|----------------|----------------------|
| `<script>alert('XSS')</script>` | | ⚪ ใช่ ⚪ ไม่ |
| `<img src=x onerror=alert('XSS')>` | | ⚪ ใช่ ⚪ ไม่ |
| `<svg onload=alert('XSS')>` | | ⚪ ใช่ ⚪ ไม่ |

**วิธีการป้องกันที่สังเกตได้:**
- [ ] HTML encoding
- [ ] Input sanitization
- [ ] Content validation
- [ ] CSP (Content Security Policy)
- [ ] อื่นๆ: ________________

**วิเคราะห์และความคิดเห็น:**
```
การป้องกัน XSS ที่มีประสิทธิภาพ:
- วิธีการ encoding ที่ใช้
- ผลต่างจาก vulnerable version
- ความปลอดภัยของผู้ใช้งาน
```

---

### Test Case 2.3: IDOR Protection

**วัตถุประสงค์:** ทดสอบการป้องกัน Insecure Direct Object Reference

**ขั้นตอนการทดสอบ:**
1. Login ด้วย user ปกติ
2. ทดสอบการเข้าถึง profile ของผู้ใช้อื่น
3. ทดสอบด้วย admin account (ถ้ามี)

**บันทึกผลการทดสอบ:**

| User Account | Target User ID | สามารถเข้าถึงได้ | Error Message |
|--------------|----------------|-------------------|---------------|
| john (user) | 1 | ⚪ ใช่ ⚪ ไม่ | |
| john (user) | 3 | ⚪ ใช่ ⚪ ไม่ | |
| admin | 2 | ⚪ ใช่ ⚪ ไม่ | |

**วิธีการป้องกันที่สังเกตได้:**
- [ ] JWT token validation
- [ ] Authorization checks
- [ ] Role-based access control
- [ ] อื่นๆ: ________________

**วิเคราะห์และความคิดเห็น:**
```
ประสิทธิภาพของการป้องกัน IDOR:
- ความแตกต่างระหว่าง user และ admin
- ความเหมาะสมของ error messages
- ระดับความปลอดภัยที่ได้รับ
```

---

## Part 3: การทดสอบความปลอดภัยเพิ่มเติม

### Test Case 3.1: Rate Limiting

**วัตถุประสงค์:** ทดสอบการจำกัดจำนวน request

**ขั้นตอนการทดสอบ:**
1. ใช้ Security Testing Dashboard ใน secure version
2. กดปุ่ม "Run Rate Limit Test"
3. สังเกตผลลัพธ์

**บันทึกผลการทดสอบ:**

| Attempt | Response Status | Rate Limited |
|---------|-----------------|--------------|
| 1 | | ⚪ ใช่ ⚪ ไม่ |
| 2 | | ⚪ ใช่ ⚪ ไม่ |
| 3 | | ⚪ ใช่ ⚪ ไม่ |
| 4 | | ⚪ ใช่ ⚪ ไม่ |
| 5 | | ⚪ ใช่ ⚪ ไม่ |
| 6 | | ⚪ ใช่ ⚪ ไม่ |

**จำนวน attempts ก่อนถูกบล็อก:** ___________

**วิเคราะห์และความคิดเห็น:**
```
ประสิทธิภาพของ Rate Limiting:
- ความเหมาะสมของจำนวนที่จำกัด
- ผลกระทบต่อ user experience
- การป้องกัน brute force attacks
```

---

### Test Case 3.2: Authentication & Authorization

**วัตถุประสงค์:** ทดสอบระบบยืนยันตัวตนและการให้สิทธิ์

**ขั้นตอนการทดสอบ:**
1. ทดสอบการเข้าถึงหน้าต่างๆ โดยไม่ login
2. ทดสอบการใช้ invalid JWT token
3. ทดสอบการ expire ของ token

**บันทึกผลการทดสอบ:**

| การทดสอบ | URL/Action | ผลลัพธ์ | HTTP Status |
|----------|------------|---------|-------------|
| No token | /comments POST | | |
| Invalid token | /user/1 GET | | |
| Expired token | /admin/users | | |

**วิเคราะห์และความคิดเห็น:**
```
ความแข็งแกร่งของระบบ authentication:
- การจัดการ token ที่หมดอายุ
- Error messages ที่เหมาะสม
- ความปลอดภัยของ session management
```

---

## Part 4: การเปรียบเทียบและวิเคราะห์

### Security Features Comparison

**เปรียบเทียบฟีเจอร์ความปลอดภัย:**

| ฟีเจอร์ | Vulnerable Version | Secure Version | ผลกระทบต่อความปลอดภัย |
|---------|-------------------|----------------|------------------------|
| SQL Injection Protection | ⚪ มี ⚪ ไม่มี | ⚪ มี ⚪ ไม่มี | |
| XSS Protection | ⚪ มี ⚪ ไม่มี | ⚪ มี ⚪ ไม่มี | |
| IDOR Protection | ⚪ มี ⚪ ไม่มี | ⚪ มี ⚪ ไม่มี | |
| Rate Limiting | ⚪ มี ⚪ ไม่มี | ⚪ มี ⚪ ไม่มี | |
| Input Validation | ⚪ มี ⚪ ไม่มี | ⚪ มี ⚪ ไม่มี | |
| Error Handling | ⚪ ปลอดภัย ⚪ ไม่ปลอดภัย | ⚪ ปลอดภัย ⚪ ไม่ปลอดภัย | |
| Authentication | ⚪ มี ⚪ ไม่มี | ⚪ มี ⚪ ไม่มี | |

---

## Part 5: การวิเคราะห์และข้อเสนอแนะ

### 5.1 ช่องโหว่ที่พบและผลกระทบ

**ช่องโหว่ความรุนแรงสูง:**
```
1. _________________________________
   - ผลกระทบ: 
   - ความเสี่ยง: 

2. _________________________________
   - ผลกระทบ: 
   - ความเสี่ยง: 
```

**ช่องโหว่ความรุนแรงปานกลาง:**
```
1. _________________________________
   - ผลกระทบ: 
   - ความเสี่ยง: 

2. _________________________________
   - ผลกระทบ: 
   - ความเสี่ยง: 
```

### 5.2 วิธีการป้องกันที่มีประสิทธิภาพ

**วิธีการป้องกันที่ดีที่สุด (Top 3):**
```
1. _________________________________
   เหตุผล: 

2. _________________________________
   เหตุผล: 

3. _________________________________
   เหตุผล: 
```

### 5.3 ข้อเสนอแนะสำหรับการพัฒนา

**สำหรับ Developer:**
```
1. _________________________________

2. _________________________________

3. _________________________________
```

**สำหรับ Security Team:**
```
1. _________________________________

2. _________________________________

3. _________________________________
```

**สำหรับ Management:**
```
1. _________________________________

2. _________________________________

3. _________________________________
```

---

## Part 6: สรุปและบทเรียน

### 6.1 สิ่งที่เรียนรู้

**ด้านเทคนิค:**
```
- _________________________________
- _________________________________
- _________________________________
```

**ด้านกระบวนการ:**
```
- _________________________________
- _________________________________
- _________________________________
```

**ด้าน Business Impact:**
```
- _________________________________
- _________________________________
- _________________________________
```

### 6.2 ความท้าทายที่พบ

**ในการทดสอบ:**
```
1. _________________________________
   แก้ไขโดย: 

2. _________________________________
   แก้ไขโดย: 
```

**ในการเข้าใจ:**
```
1. _________________________________

2. _________________________________
```

### 6.3 การประยุกต์ใช้ในอนาคต

**ในการพัฒนาโปรเจค:**
```
1. _________________________________

2. _________________________________

3. _________________________________
```

**ในการทำงาน:**
```
1. _________________________________

2. _________________________________

3. _________________________________
```

---

## คะแนนการประเมินตนเอง

| หัวข้อ | คะแนนเต็ม | คะแนนที่ได้ | หมายเหตุ |
|--------|-----------|------------|----------|
| การทดสอบ Vulnerable Version | 25 | | |
| การทดสอบ Secure Version | 25 | | |
| การวิเคราะห์และเปรียบเทียบ | 20 | | |
| การเขียนรายงาน | 15 | | |
| ความคิดสร้างสรรค์ | 15 | | |
| **รวม** | **100** | | |

### ความคิดเห็นเพิ่มเติม
```
เขียนความคิดเห็นส่วนตัวเกี่ยวกับแลปนี้:
- สิ่งที่ชอบที่สุด
- สิ่งที่ยากที่สุด  
- ข้อเสนอแนะการปรับปรุง
- การนำไปใช้ในชีวิตจริง
```

---

## ภาคผนวก

### A. Screenshots หลักฐาน
*(แนบ screenshots ของการทดสอบแต่ละขั้นตอน)*

### B. Code Snippets ที่สำคัญ
*(แนบโค้ดส่วนที่สำคัญที่พบว่าเป็นช่องโหว่หรือการป้องกัน)*

### C. เอกสารอ้างอิง
- OWASP Top 10: https://owasp.org/Top10/
- Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- Lab Materials: [ระบุแหล่งที่มา]

---

**การใช้งาน:** ให้นักศึกษากรอกข้อมูลในช่องว่างและเครื่องหมาย ⚪ ตลอดการทดสอบ พร้อมแนบหลักฐาน screenshots และวิเคราะห์ผลอย่างละเอียด
