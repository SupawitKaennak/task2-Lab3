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
ข้อมูลที่เข้าถึงได้:
   ผู้โจมตีสามารถดูข้อมูลส่วนตัวของผู้ใช้คนอื่น เช่น ID, username, email, password, role, วันที่สร้างบัญชี
ความเสี่ยงด้านความเป็นส่วนตัว:
   ข้อมูลสำคัญ (เช่น email, password) รั่วไหล อาจถูกนำไปใช้โจมตีหรือแอบอ้างตัวตน
วิธีการโจมตี:
   ผู้โจมตีเปลี่ยนค่า User ID ในช่อง input เพื่อดูข้อมูลของผู้ใช้คนอื่นโดยไม่ต้องมีสิทธิ์
```

---

## Part 2: การทดสอบ Secure Version
<img width="1079" height="340" alt="{95154EEA-1DE5-40E6-88FD-A0A067F021AA}" src="https://github.com/user-attachments/assets/80d78b7d-5829-4639-a29b-83722395b832" />

### Test Case 2.1: SQL Injection Protection

**วัตถุประสงค์:** ทดสอบการป้องกัน SQL Injection

<img width="999" height="241" alt="{8933E5BF-90E0-4F52-AF0A-A5CA511419CC}" src="https://github.com/user-attachments/assets/cb62a52f-f7e1-4453-9aa5-a8a23e68b2c2" />


**ขั้นตอนการทดสอบ:**
1. เปิด `secure.html` (Secure Version)
2. ทดสอบ payloads เดียวกันกับ vulnerable version

**บันทึกผลการทดสอบ:**

| Payload | ผลลัพธ์ | การป้องกัน |
|---------|---------|------------|
| `admin'; --` |<img width="948" height="461" alt="{DF7B3292-1BBE-4D41-8B21-5DA41E4F986F}" src="https://github.com/user-attachments/assets/a3112416-592b-4b03-9321-210b21f1ec64" />
 | ⚪ ถูกบล็อก |
| `' UNION SELECT * FROM Users; --` |<img width="561" height="186" alt="{7023CC3A-07F9-4443-89CA-BC0E19541D77}" src="https://github.com/user-attachments/assets/c682947f-bef7-438b-80e6-5bf4107319df" />
 | ⚪ ถูกบล็อก |
| `'; DROP TABLE Products; --` |<img width="566" height="176" alt="{099BA6F5-6C9C-48C7-A3B1-8DBB4A66319B}" src="https://github.com/user-attachments/assets/cc548ae1-66bf-4afe-8c8d-1b6f50b63234" />
 | ⚪ ถูกบล็อก |

**วิธีการป้องกันที่สังเกตได้:**
- [✅] Input validation
- [✅] Prepared statements
- [✅] Error message ที่ไม่เปิดเผยรายละเอียด
- [✅] อื่นๆ: Principle of Least Privilege (หลักการให้สิทธิ์น้อยที่สุด)

**วิเคราะห์และความคิดเห็น:**
```
เปรียบเทียบกับ vulnerable version:
- ไม่มีการ drop table จริงๆ
- ไม่แสดง error บอกให้ผู้ไม่ประสงค์ดี
- ใช้ ai เพิ่ม secure ให้กับโค้ดแล้วลองทดสอบดู
```

---

### Test Case 2.2: XSS Protection

**วัตถุประสงค์:** ทดสอบการป้องกัน Cross-Site Scripting

**ขั้นตอนการทดสอบ:**
1. Login ในระบบ secure version
2. ทดสอบ XSS payloads ในช่อง comment
<img width="995" height="940" alt="{B8BA48EC-8FC3-45B4-A9AF-314F33D078AF}" src="https://github.com/user-attachments/assets/6afb5d17-2cda-4e9f-933d-fe20a10b8126" />

**บันทึกผลการทดสอบ:**

| Payload | ผลลัพธ์ที่แสดง | Script Execute หรือไม่ |
|---------|----------------|----------------------|
| `<script>alert('XSS')</script>` |<img width="767" height="613" alt="{F687B435-0B99-4170-B1AC-39C69A86068A}" src="https://github.com/user-attachments/assets/8c371be3-6239-4de8-a1a8-9e7aaa185dca" />
 | ⚪ ไม่ |
| `<img src=x onerror=alert('XSS')>` |<img width="764" height="622" alt="{8FE25B0A-B611-413C-A45F-F0A10FBA0010}" src="https://github.com/user-attachments/assets/9c64cbec-5d1f-4c50-ab30-bc5aeae41b2f" />
 | ⚪ ไม่ |
| `<svg onload=alert('XSS')>` |<img width="746" height="601" alt="{C01160FC-B69D-44BD-B700-EE73D96DAD92}" src="https://github.com/user-attachments/assets/d18a6b23-2945-4d7a-9840-f13c60e516de" />
 | ⚪ ไม่ |
<img width="898" height="533" alt="{B95AD9F6-6B3A-4919-83DD-F4C9EEA4272E}" src="https://github.com/user-attachments/assets/a7162a67-d3b8-4d50-859c-62212ed485d2" />


**วิธีการป้องกันที่สังเกตได้:**
- [✅] HTML encoding
- [✅] Input sanitization
- [✅] Content validation
- [✅] CSP (Content Security Policy)
- [ ] อื่นๆ: ________________

**วิเคราะห์และความคิดเห็น:**
```
การป้องกัน XSS ที่มีประสิทธิภาพ:
- ในเวอร์ชันที่ปลอดภัย (secure-server.js) มีการใช้ฟังก์ชัน htmlEncode ซึ่งทำหน้าที่แปลงอักขระพิเศษทาง HTML ให้กลายเป็น "HTML Entities" ที่ปลอดภัยก่อนที่จะบันทึกลงฐานข้อมูล
- Vulnerable Version (server.js): รับข้อมูลความคิดเห็น (content) จากผู้ใช้แล้วบันทึกลงฐานข้อมูลโดยตรง ไม่มีการตรวจสอบหรือแปลงข้อมูลใดๆ หากผู้ใช้ส่งโค้ด <script>alert('XSS')</script> เข้ามา โค้ดนั้นจะถูกบันทึกตามตัวอักษร
Secure Version (secure-server.js): ก่อนบันทึกข้อมูล จะนำข้อมูลความคิดเห็นไปผ่านกระบวนการตรวจสอบ (Validation) และเข้ารหัส (Encoding) ก่อน โค้ด <script>... จะถูกแปลงเป็น &lt;script&gt;... แล้วจึงบันทึกลงฐานข้อมูล
- ใน Vulnerable Version: เบราว์เซอร์ของผู้ใช้จะรันสคริปต์อันตรายนั้นทันที ซึ่งอาจนำไปสู่การขโมยข้อมูลส่วนตัว, การดักจับ Session (Session Hijacking), หรือการเปลี่ยนเส้นทางไปยังเว็บไซต์หลอกลวง
ใน Secure Version: เบราว์เซอร์ของผู้ใช้จะเห็นข้อความ &lt;script&gt;...&lt;/script&gt; และแสดงผลเป็นตัวอักษรบนหน้าจอเท่านั้น สคริปต์จะไม่ถูกรัน ทำให้ผู้ใช้ปลอดภัยจากการโจมตีดังกล่าวโดยสิ้นเชิง
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
| john (user) | <img width="325" height="161" alt="{6046AEA3-C03B-493D-A61E-670F42C9CCE5}" src="https://github.com/user-attachments/assets/1c5a5a89-d5a6-490f-be8b-91fbb1be902a" />
 | ⚪ ใช่  |<img width="811" height="107" alt="{BA109E54-05FE-4EEB-A78A-C8D20783AC27}" src="https://github.com/user-attachments/assets/e86bcfcd-b503-45bc-852a-570303160a33" />
 |
| john (user) | <img width="325" height="161" alt="{6046AEA3-C03B-493D-A61E-670F42C9CCE5}" src="https://github.com/user-attachments/assets/0ec6006d-591f-4031-9960-a5fc00efab11" />
 | ⚪ ใช่  | <img width="815" height="108" alt="{9223F4E0-222D-4AAE-9347-5C33506C9DBD}" src="https://github.com/user-attachments/assets/b85af208-0130-4fdb-8fb8-d40d924a5257" />
|
| admin | <img width="228" height="78" alt="{5FBBD2B7-2FAC-44BA-9543-AD0D581FA35C}" src="https://github.com/user-attachments/assets/fd80eb17-e946-4692-8021-9cb07a0ec9ad" />
 | ⚪ ไม่ |<img width="352" height="40" alt="{A26A50DE-C44C-46A9-8F61-736E35B5A29C}" src="https://github.com/user-attachments/assets/3efb68e3-7264-4ef9-aec4-b11d578bd7a8" />
 |

**วิธีการป้องกันที่สังเกตได้:**
- [✅] JWT token validation
- [✅] Authorization checks
- [✅] Role-based access control
- [ ] อื่นๆ: ________________

**วิเคราะห์และความคิดเห็น:**
<img width="446" height="367" alt="{11FEDB6B-D5B5-4789-BDC3-7602770D3B09}" src="https://github.com/user-attachments/assets/d80323e4-507c-4a09-8041-5dc57ac3a79e" />

```
ประสิทธิภาพของการป้องกัน IDOR:
- User ทั่วไป: สามารถเข้าถึงได้เฉพาะข้อมูลโปรไฟล์ของ ตัวเอง เท่านั้น ระบบจะตรวจสอบว่า userId ที่ถูกส่งมาใน JWT token (ซึ่งเชื่อถือได้) ตรงกับ :id ใน URL ที่ร้องขอหรือไม่
Admin: สามารถเข้าถึงข้อมูลโปรไฟล์ของ ผู้ใช้ทุกคน ได้ ระบบมีการตรวจสอบ "Role" (บทบาท) จาก JWT token หากเป็น 'admin' จะได้รับอนุญาตให้ข้ามเงื่อนไขการตรวจสอบความเป็นเจ้าของข้อมูลได้ นี่คือการทำ Role-Based Access Control (RBAC) ที่ถูกต้อง
- เหมาะสมและปลอดภัย: เมื่อ User ทั่วไปพยายามเข้าถึงข้อมูลของคนอื่น ระบบจะตอบกลับด้วย 403 Forbidden (Access denied) ซึ่งเป็นการบอกอย่างชัดเจนว่า "คุณไม่มีสิทธิ์" โดยไม่เปิดเผยว่า User ID ที่ร้องขอนั้นมีอยู่จริงในระบบหรือไม่ ซึ่งช่วยป้องกันการคาดเดาข้อมูล (Enumeration Attack)
หาก User ID ที่ร้องขอไม่มีอยู่จริง ระบบจะตอบกลับด้วย 404 Not Found ซึ่งเป็นมาตรฐานและไม่เปิดเผยข้อมูลเกินจำเป็น
- สูงมาก: การป้องกันนี้มีประสิทธิภาพสูง เพราะใช้หลักการตรวจสอบสิทธิ์ (Authorization) ที่ถูกต้องและรัดกุมเสมอหลังจากยืนยันตัวตน (Authentication) แล้ว
ระบบไม่ได้เชื่อแค่ ID ที่ผู้ใช้ส่งมาใน URL แต่ใช้ข้อมูลที่เชื่อถือได้จาก JWT token (ทั้ง userId และ role) มาเป็นตัวตัดสินใจ ทำให้ผู้ใช้ไม่สามารถเข้าถึงข้อมูลที่ตนเองไม่มีสิทธิ์ได้อย่างเด็ดขาด
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
| 1 | Status 401 | ⚪ ใช่  |
| 2 | Status 401 | ⚪ ใช่  |
| 3 | 🚫 Rate limited | ⚪ ใช่ |
| 4 | 🚫 Rate limited | ⚪ ใช่ |
| 5 | 🚫 Rate limited | ⚪ ใช่ |
| 6 | 🚫 Rate limited | ⚪ ใช่ |
<img width="406" height="505" alt="{ACE72648-264B-49FA-817F-736C25A30843}" src="https://github.com/user-attachments/assets/862e740b-6965-4532-912f-76fabb1bd407" />

**จำนวน attempts ก่อนถูกบล็อก:** 4 จำนวน

**วิเคราะห์และความคิดเห็น:**
```
ประสิทธิภาพของ Rate Limiting:
- เหมาะสมมาก: การจำกัดการล็อกอินไว้ที่ 5 ครั้งต่อ 15 นาที เป็นค่าที่สมดุลอย่างยิ่ง
สำหรับผู้ใช้ทั่วไป: เพียงพอสำหรับกรณีที่พิมพ์รหัสผ่านผิดพลาดโดยไม่ได้ตั้งใจ
สำหรับผู้โจมตี: จำนวนนี้น้อยเกินไปที่จะทำการโจมตีแบบ Brute Force ได้อย่างมีประสิทธิภาพ ทำให้การเดาสุ่มรหัสผ่านช้าลงอย่างมาก
การจำกัด request ทั่วไปที่ 100 ครั้งต่อ 15 นาที ก็เป็นค่าพื้นฐานที่ดีในการป้องกันการโจมตีแบบ Denial-of-Service (DoS) ระดับเบื้องต้น โดยไม่กระทบการใช้งานปกติ
- น้อยมาก: ผู้ใช้ทั่วไปแทบจะไม่ได้รับผลกระทบเลย เพราะโอกาสที่จะล็อกอินผิดพลาดเกิน 5 ครั้งใน 15 นาทีนั้นมีน้อยมาก
ให้ข้อมูลที่ชัดเจน: เมื่อผู้ใช้ถูกจำกัดการเข้าถึง ระบบจะส่งข้อความ Too many login attempts... กลับไป ซึ่งช่วยให้ผู้ใช้เข้าใจสถานการณ์และไม่ต้องสับสนกับข้อผิดพลาดที่ไม่ทราบสาเหตุ
- มีประสิทธิภาพสูง: นี่คือแนวป้องกันด่านหน้าที่สำคัญที่สุดในการต่อต้านการโจมตีแบบ Brute Force
ทำให้การโจมตีไม่คุ้มค่า: การจำกัดจำนวนครั้งและกำหนดกรอบเวลา ทำให้ผู้โจมตีที่ใช้ IP เดียวกันไม่สามารถเดาสุ่มรหัสผ่านได้อย่างรวดเร็ว จากที่เคยทำได้หลายพันครั้งต่อนาที อาจจะเหลือเพียง 20 ครั้งต่อชั่วโมง ซึ่งทำให้การโจมตีแทบจะเป็นไปไม่ได้ในทางปฏิบัติ
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
| No token | /comments POST | <img width="1325" height="699" alt="{620C29F9-F090-4E6C-83AC-8DC9E51005F2}" src="https://github.com/user-attachments/assets/60d3beeb-a10a-425f-a95e-ea2e8081ddcb" />
 | <img width="949" height="206" alt="{F2B233A5-B6A8-4F63-859E-CE6C975751C0}" src="https://github.com/user-attachments/assets/b3293237-2ce6-475f-9455-f2d64cf16663" />
 |
| Invalid token | /user/1 GET | <img width="1295" height="697" alt="{AF11C456-7146-4671-BD4B-78CB7961D98C}" src="https://github.com/user-attachments/assets/34a14c14-ada8-4c3c-baf9-3f91bb03796c" />
 | <img width="401" height="143" alt="{207AF374-5B42-4D1B-AF46-54946DDFB274}" src="https://github.com/user-attachments/assets/99fd5814-9821-4d90-b541-5e053f79782b" />
 |
| Expired token | /admin/users | <img width="1282" height="700" alt="{F7EC18CC-E2B6-4803-AC16-8BF4EC502EB0}" src="https://github.com/user-attachments/assets/d71439ff-638f-42d7-90c8-77a1b607ae77" />
 | <img width="434" height="176" alt="{738B48FD-2285-4C96-B17C-2B665049A4CB}" src="https://github.com/user-attachments/assets/bcc17891-fc7e-4a3a-a55b-2924902a60d5" />
 |

**วิเคราะห์และความคิดเห็น:**
```
ความแข็งแกร่งของระบบ authentication:
- จัดการอย่างรัดกุม: เมื่อมีการสร้าง JWT (JSON Web Token) จะมีการกำหนดอายุการใช้งานไว้ที่ 1 ชั่วโมง (expiresIn: '1h')
ตรวจสอบทุกครั้ง: ในทุกๆ request ที่ต้องใช้สิทธิ์, middleware authenticateToken จะใช้ jwt.verify() เพื่อตรวจสอบ token ซึ่งฟังก์ชันนี้จะเช็ควันหมดอายุโดยอัตโนมัติ
เมื่อ Token หมดอายุ: หาก token หมดอายุแล้ว ระบบจะปฏิเสธการเข้าถึงทันทีและส่งสถานะ 403 Forbidden พร้อมข้อความ Invalid or expired token กลับไป ทำให้ token ที่หมดอายุแล้วไม่สามารถนำกลับมาใช้ได้อีก
- ป้องกันการคาดเดา: ในกรณีที่ล็อกอินไม่สำเร็จ (ไม่ว่าจะใส่ชื่อผู้ใช้หรือรหัสผ่านผิด) ระบบจะตอบกลับด้วยข้อความทั่วไปคือ Invalid credentials เสมอ วิธีนี้ช่วยป้องกันไม่ให้ผู้โจมตีทราบได้ว่า "ชื่อผู้ใช้" ที่กรอกมานั้นมีอยู่จริงในระบบหรือไม่ (Username Enumeration)
ไม่เปิดเผยข้อมูล: ข้อความแสดงข้อผิดพลาดที่ส่งกลับไปยังผู้ใช้จะไม่มีรายละเอียดทางเทคนิคของเซิร์ฟเวอร์หรือฐานข้อมูลหลุดออกไปเลย ซึ่งทำให้ผู้โจมตีคาดเดาโครงสร้างของระบบได้ยากขึ้น
- ใช้ JWT ที่ปลอดภัย: ระบบใช้ JWT ซึ่งเป็น Stateless Token หมายความว่าเซิร์ฟเวอร์ไม่จำเป็นต้องเก็บข้อมูล Session ของผู้ใช้ไว้ ทำให้ลดภาระและลดพื้นที่ในการโจมตี
มีการยืนยันความถูกต้อง (Signature): Token ทุกตัวจะถูก "เซ็น" ด้วย JWT_SECRET ทำให้เซิร์ฟเวอร์สามารถตรวจสอบได้ว่า token นั้นถูกสร้างโดยเซิร์ฟเวอร์จริงและไม่ถูกแก้ไขหรือปลอมแปลงระหว่างทาง
อายุสั้น: การกำหนดให้ token มีอายุแค่ 1 ชั่วโมง ช่วยจำกัดความเสียหายในกรณีที่ token หลุดออกไป ผู้โจมตีจะมีเวลาใช้งาน token นั้นได้ไม่นาน
```

---

## Part 4: การเปรียบเทียบและวิเคราะห์

### Security Features Comparison

**เปรียบเทียบฟีเจอร์ความปลอดภัย:**

| ฟีเจอร์ | Vulnerable Version | Secure Version | ผลกระทบต่อความปลอดภัย |
|---------|-------------------|----------------|------------------------|
| SQL Injection Protection | ⚪ ไม่มี | ⚪ มี  | ป้องกันผู้โจมตีจากการขโมย, แก้ไข, หรือลบข้อมูลในฐานข้อมูล (เช่น ข้อมูลผู้ใช้, รหัสผ่าน) |
| XSS Protection | ⚪ ไม่มี  | ⚪ มี  | ป้องกันการฝังสคริปต์อันตรายที่อาจขโมยข้อมูล Session หรือควบคุมบัญชีของผู้ใช้ |
| IDOR Protection | ⚪ ไม่มี  | ⚪ มี  | ป้องกันผู้ใช้จากการเข้าถึงหรือแก้ไขข้อมูลของผู้อื่นโดยการเดา ID ใน URL |
| Rate Limiting | ⚪ ไม่มี  | ⚪ มี  | 	ป้องกันการโจมตีแบบ Brute Force (เดาสุ่มรหัสผ่าน) และช่วยลดความเสี่ยงจาก DoS |
| Input Validation | ⚪ ไม่มี  | ⚪ มี  | เป็นด่านแรกในการกรองข้อมูลอันตราย, ลดโอกาสการโจมตีหลายรูปแบบ |
| Error Handling | ⚪ ไม่ปลอดภัย  | ⚪ ปลอดภัย  | ป้องกันการเปิดเผยข้อมูลทางเทคนิคของระบบ (Information Disclosure) ที่ช่วยให้แฮกเกอร์วางแผนโจมตีได้ง่ายขึ้น |
| Authentication | ⚪ ไม่มี  | ⚪ มี | ยืนยันตัวตนและจัดการ Session อย่างปลอดภัย (ด้วย JWT) เพื่อให้เฉพาะผู้มีสิทธิ์เข้าถึงข้อมูลได้ |

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
