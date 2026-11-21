# ติดตั้ง TENIX Exposure บน VM

คู่มือนี้ใช้กับ Linux (Ubuntu 22.04/24.04 หรือเทียบเท่า) ถ้า VM เป็น OS อื่นให้ปรับคำสั่งเอง

## 1. สิ่งที่ต้องมี

| อย่าง | เวอร์ชัน | หมายเหตุ |
|---|---|---|
| Node.js | **24 ขึ้นไป** | เซิร์ฟเวอร์รัน TypeScript ตรงๆ ไม่ต้อง build ฝั่ง server |
| PostgreSQL | 14 ขึ้นไป (ทดสอบกับ 16) | ฐานข้อมูลเดียว ตารางสร้างเองตอนเริ่ม |
| nginx (หรือ reverse proxy อื่น) + HTTPS | | **จำเป็น** cookie เซสชันตั้ง `Secure` เมื่อเป็น production |
| ออกเน็ตไป `api.<cloud>.crowdstrike.com` ที่พอร์ต 443 | | cloud ของคุณคือ us-2 (`api.us-2.crowdstrike.com`) |

เซิร์ฟเวอร์ฟังเฉพาะ `127.0.0.1` ที่พอร์ต `PORT` (ค่าเริ่มต้น 8787) ปรับได้ด้วย `TENIX_HOST` (เวอร์ชันเก่าฟังทุก interface) ให้ nginx เป็นทางเข้าเดียว ถ้าตั้ง `TENIX_HOST=0.0.0.0` ต้องมี firewall ปิดพอร์ตนี้จากภายนอก

## 2. แตกไฟล์และติดตั้ง

```bash
sudo mkdir -p /opt/tenix && sudo chown $USER /opt/tenix
unzip TENIX-Exposure-vm-package.zip -d /opt/tenix
cd /opt/tenix/TG-Exposure-Management-Production
(cd tenix-exposure/server && npm ci)
(cd tenix-exposure/web && npm ci && npm run build)   # ได้ web/dist ที่เซิร์ฟเวอร์ให้บริการเอง
```

โครงสร้างโฟลเดอร์ต้องคงไว้ (`.claude/`, `tenix-exposure/`, `cs_*.py` อยู่ระดับเดียวกัน) เพราะ Claude Code skills และ CLAUDE.md อ้างอิงตำแหน่งนี้

## 3. ฐานข้อมูล

```bash
sudo -u postgres createuser --pwprompt tenix
sudo -u postgres createdb -O tenix tenix_exposure
```

## 4. ตัวแปรสภาพแวดล้อม (ไฟล์ `/etc/tenix/tenix.env`, สิทธิ์ 600)

```
NODE_ENV=production
PORT=8787
TENIX_DATABASE_URL=postgres://tenix:<รหัสผ่าน>@localhost:5432/tenix_exposure   # บนเครื่อง .109 ใช้พอร์ต 5433 (container tenix-exposure-postgres) ไม่ใช่ 5432
TENIX_APP_URL=https://<ชื่อโดเมนของระบบ>
TENIX_SECRET_KEY=<openssl rand -base64 32>
TENIX_TRUST_PROXY=1
TENIX_SYNC_MINUTES=60
# ใช้เฉพาะตอนยังไม่มีผู้ใช้เลย แล้วลบออกหลังสร้างแอดมินคนแรก
TENIX_BOOTSTRAP_EMAIL=<อีเมลแอดมินคนแรก>
```

- `TENIX_SECRET_KEY` **ห้ามทำหาย** ใช้เข้ารหัส Falcon secret, รหัส SMTP และ TOTP ในฐานข้อมูล ถ้าเปลี่ยนหรือทำหาย ต้องกรอก Falcon secret/SMTP ใหม่และผู้ใช้ต้องตั้ง MFA ใหม่ เก็บสำเนาไว้ที่ปลอดภัย (password manager)
- **อย่าตั้ง** `TENIX_DEV_FALCON_URL_OK` บน production

## 5. รันเป็นบริการ (systemd)

`/etc/systemd/system/tenix-exposure.service`

```
[Unit]
Description=TENIX Exposure
After=network.target postgresql.service

[Service]
User=tenix
WorkingDirectory=/opt/tenix/TG-Exposure-Management-Production/tenix-exposure/server
EnvironmentFile=/etc/tenix/tenix.env
ExecStart=/usr/bin/node src/index.ts
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now tenix-exposure
journalctl -u tenix-exposure -f      # ดู log และ "ลิงก์สร้างแอดมินคนแรก" (ใช้ได้ครั้งเดียว 24 ชม.)
```

(ถ้า `node` ไม่ได้อยู่ที่ `/usr/bin/node` ให้แก้ `ExecStart` ตาม `which node`)

## 6. nginx + HTTPS (ตัวอย่าง)

```
server {
  listen 443 ssl;
  server_name <ชื่อโดเมนของระบบ>;
  # ssl_certificate / ssl_certificate_key (เช่นจาก certbot)
  client_max_body_size 2m;
  location / {
    proxy_pass http://127.0.0.1:8787;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
```

## 7. ตั้งค่าครั้งแรก

1. เปิดลิงก์แอดมินคนแรกจาก log → ตั้งรหัสผ่าน (คนนี้เป็น **Super Admin**) แล้วลบ `TENIX_BOOTSTRAP_EMAIL` ออกจากไฟล์ env
2. ใส่ Falcon: ทำบนหน้า **Integrations** หรือรันสคริปต์ในเทอร์มินัลโดยไม่ต้องพิมพ์ secret ในแชต
   ```bash
   cd tenix-exposure/server && set -a && . /etc/tenix/tenix.env && set +a && npm run falcon-setup
   ```
3. หน้า **Tenants** → สร้าง Tenant และผูก CID → Integrations → **Sync all** (ราว 2–3 นาทีต่อ CID ที่มีข้อมูลราว 120,000 รายการ)
4. หน้า **Team** → เชิญผู้ใช้ (ระบบ**ยังไม่ส่งอีเมลคำเชิญเอง** ใช้ปุ่มคัดลอกลิงก์ส่งให้ผู้ใช้) ตั้ง SMTP ได้ที่ Integrations → Email alerts เพื่อให้แจ้งเตือนอัตโนมัติ

## 8. ย้ายข้อมูลจากเครื่องเดิม (ถ้าต้องการ)

ถ้าอยากเริ่มใหม่ ข้ามหัวข้อนี้ไปได้ (sync ใหม่จาก Falcon ได้ทุกอย่างยกเว้นผู้ใช้/Tenant/การตั้งค่า)

บนเครื่องเดิม:
```bash
pg_dump -Fc tenix_exposure > tenix_exposure.dump
cat tenix-exposure/server/.data/dev-secret.key      # กุญแจเข้ารหัสของเครื่องเดิม (base64 32 ไบต์)
```
บน VM:
```bash
pg_restore -d tenix_exposure --no-owner --role=tenix tenix_exposure.dump
```
แล้วตั้ง `TENIX_SECRET_KEY` เป็น**ค่าในไฟล์ dev-secret.key เดิม** เพื่อให้ถอดรหัส Falcon secret/SMTP/MFA ที่เก็บไว้ได้ ส่งกุญแจนี้ทางช่องทางที่ปลอดภัย (ไม่ใส่ในแชตหรืออีเมลเปล่า) และ**ไม่ได้รวมอยู่ใน zip**

ถ้าฐานข้อมูลเดิมยังเป็นเวอร์ชันเก่ามาก ตอนสตาร์ทครั้งแรกระบบแปลงบทบาทผู้ใช้ให้เป็น Super Admin / Admin / System Operator อัตโนมัติ **แบบย้อนกลับไม่ได้** ให้สำรองก่อนเสมอ

## 9. สำรองข้อมูลและอัปเดต

```bash
# สำรองรายวัน (cron)
pg_dump -Fc tenix_exposure > /var/backups/tenix/tenix_$(date +%F).dump
# อัปเดตเวอร์ชัน: แตกไฟล์ใหม่ทับ (เก็บ env ไว้) แล้ว
(cd tenix-exposure/server && npm ci) && (cd tenix-exposure/web && npm ci && npm run build) && sudo systemctl restart tenix-exposure
```

## 10. ตรวจว่าใช้งานได้

```bash
curl -sI http://127.0.0.1:8787/ | head -1        # ต้องได้ HTTP/1.1 200
curl -s http://127.0.0.1:8787/api/auth/me          # ยังไม่ล็อกอิน ต้องได้ 401
cd tenix-exposure/server && npm test          # ต้องผ่านทุกข้อ ต้องตั้ง TENIX_TEST_DATABASE_URL ก่อน (ดูด้านล่าง) และสร้างฐาน tenix_test: createdb tenix_test
```

ทดสอบหน้าเว็บด้วย Playwright (ไม่บังคับ): `cd tenix-exposure/web && npx playwright install --with-deps chromium && npm run e2e` ใช้พอร์ต 8790–8792 และ schema ชั่วคราวใน `tenix_test` ไม่แตะฐานจริง

**ชุดทดสอบ (server `npm test` และ e2e) ต่อฐานผ่าน `TENIX_TEST_DATABASE_URL` ตัวแปรเดียว ไม่มีค่าเริ่มต้น** และปฏิเสธทุกค่าที่ไม่ใช่ `127.0.0.1`/`localhost` พอร์ต **5433** ฐาน `tenix_test` พอดี (ไม่อ่าน `TENIX_DATABASE_URL`) ตัวอย่างพอร์ต 5432 ด้านบนเป็นของ VM ทั่วไป บนเครื่อง .109 Postgres ของ Exposure คือ 5433 และ 5432 เป็นของระบบอื่น ห้ามแตะ ถ้า VM ใหม่ใช้ Postgres พอร์ต 5432 ต้องแก้ค่าที่ฟังก์ชันตรวจ (`server/test/test-db.ts` และ `web/e2e/test-db.ts`) ให้ตรงกันทั้งสองไฟล์

## ความปลอดภัยที่ต้องรู้
- ใส่ HTTPS ด้านหน้าเสมอ ปิดพอร์ต 8787 จากภายนอก
- ตัวนับล็อกอินผิด (rate limit) อยู่ใน memory ใช้ได้กับ 1 โปรเซสเท่านั้น อย่ารันหลาย instance
- ข้อมูลที่ Falcon คืนมาในบัญชีนี้ราว 92% เป็นสินทรัพย์ภายนอก (EASM) ที่ชื่อ/IP ดูเป็นข้อมูลจำลอง ดูหน้า Graph และตัวกรอง Source
