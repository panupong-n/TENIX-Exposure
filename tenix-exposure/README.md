# TENIX Exposure

ระบบดูช่องโหว่ (CrowdStrike Falcon Exposure Management) ที่ลูกค้าและทีม SOC ใช้ร่วมกัน ลูกค้าเห็นเฉพาะข้อมูลองค์กรตัวเอง

```
tenix-exposure/
├── web/      หน้าเว็บ (ปรับจาก TailAdmin React: React 19 + Vite + Tailwind 4) เมนูอยู่ด้านบน หน้าเว็บเป็นภาษาไทย
└── server/   API + ฐานข้อมูล PostgreSQL (Node 24 ขึ้นไป, ไลบรารี: pg, nodemailer)
```

โฟลเดอร์ `../TEMPLATE` คือ TailAdmin ต้นฉบับ ไม่ได้แก้

## ฐานข้อมูล (PostgreSQL)

```bash
createdb tenix_exposure        # ครั้งเดียว ตารางสร้างเองตอนเซิร์ฟเวอร์เริ่ม
```

เซิร์ฟเวอร์ต่อผ่าน `TENIX_DATABASE_URL` (**บังคับใน production**; นอก production ค่าเริ่มต้นคือ `postgres://localhost:5433/tenix_exposure`) เช่น `postgres://user:pass@host:5432/tenix_exposure`

## ใส่ค่า Falcon จริง (ไม่ต้องพิมพ์ key ในแชต)

```bash
cd server && npm install && npm run falcon-setup
```

สคริปต์ถามทีละข้อในเทอร์มินัล: เลือก Falcon cloud (ค่าเริ่มต้น **us-2**), Client ID, Client Secret (พิมพ์แล้วไม่แสดงบนจอ), ชื่อองค์กร และ CID แล้วเก็บลงฐานข้อมูล (secret เข้ารหัส) ทดสอบการเชื่อมต่อ และเสนอให้ซิงก์รอบแรกทันที ทำซ้ำได้เพื่อเพิ่ม CID อื่น ส่วนหน้าเว็บทำสิ่งเดียวกันได้ที่ Integrations (เลือก cloud ได้จากรายการ)

## อีเมลแจ้งเตือน

หน้า Integrations → **Email alerts** (เฉพาะ Super Admin): เพิ่มผู้ส่ง (SMTP, รหัสผ่านเข้ารหัส, ปุ่มส่งอีเมลทดสอบ), เพิ่มผู้รับ และติ๊กว่าใครรับแจ้งเตือนอะไร
ตอนนี้มี 2 ประเภท: `sync_failed` (ซิงก์ไม่ครบ/ล้มเหลว) และ `critical_new` (พบช่องโหว่ Critical ใหม่ต่างจากรอบก่อน รอบแรกไม่ส่ง) เพิ่มประเภทใหม่ที่ `EVENTS` ใน `server/src/mail.ts` แล้วเรียก `notify()`
ผู้รับที่ผูกกับองค์กรได้รับเฉพาะเรื่องขององค์กรนั้น ส่งแยกทีละคน (ไม่มี To รวม) ยังไม่ได้ส่งอีเมลคำเชิญ (ยังเป็นลิงก์)

## รันตอนพัฒนา

```bash
cd server && npm run mock-falcon     # Falcon จำลอง :8799 (client id mock-client / secret mock-secret)
cd server && TENIX_DEV_FALCON_URL_OK=1 TENIX_BOOTSTRAP_EMAIL=you@company.com npm run dev   # API :8787
cd web && npm install && npm run dev # หน้าเว็บ :5173 (proxy /api ไป :8787)
```

ครั้งแรกที่ยังไม่มีผู้ใช้ เซิร์ฟเวอร์จะพิมพ์ **ลิงก์สร้างแอดมินคนแรก** (ใช้ได้ครั้งเดียว 24 ชม.) ใน log
จากนั้น: Integrations → ใส่ Falcon → Tenants → สร้าง Tenant และผูก CID → ซิงก์ (Integrations → Sync all)

ทดสอบ: `cd server && npm test` (ต้องผ่านทุกข้อ ใช้ฐาน `tenix_test` สร้างเอง: `createdb tenix_test` และใช้ schema ชั่วคราวที่ลบทิ้งหลังจบ) · `cd web && npm run build && npm run lint`

**ข้อห้ามของชุดทดสอบ:** ทุกเทสต์ (server `npm test`, web `npm run e2e`) อ่านฐานจากตัวแปร **`TENIX_TEST_DATABASE_URL` ตัวเดียว** ไม่อ่าน `TENIX_DATABASE_URL` และไม่มีค่าเริ่มต้น (ไม่ตั้ง = ล้มพร้อมข้อความ) ฟังก์ชันตรวจ (`server/test/test-db.ts`, `web/e2e/test-db.ts`) ปฏิเสธทุกค่าที่ไม่ใช่ host `127.0.0.1`/`localhost` พอร์ต **5433** และชื่อฐาน `tenix_test` พอดี ตรวจก่อนต่อฐานและก่อนสร้าง/ลบ schema ใด ๆ ตัวอย่าง: `export TENIX_TEST_DATABASE_URL='postgres://user:***@127.0.0.1:5433/tenix_test'` บนเครื่อง .109 Postgres 5433 เป็นของ Exposure ส่วน 5432 เป็นของระบบอื่น ห้ามแตะ
ทดสอบหน้าเว็บด้วย Playwright: `cd web && npm run e2e` (ชุดทดสอบแยกต่างหาก: เว็บ :8790, Falcon จำลอง :8791, SMTP จำลอง :8792, schema `e2e_*` ในฐาน `tenix_test` ไม่แตะฐานจริง) รายละเอียดใน `web/e2e/README.md`

## ขึ้นระบบจริง

1. `cd web && npm run build` แล้วรัน `NODE_ENV=production node server/src/index.ts` (เซิร์ฟเวอร์ให้บริการไฟล์ใน `web/dist` ด้วย)
2. ตัวแปรที่ต้องตั้ง

| ตัวแปร | ความหมาย |
|---|---|
| `TENIX_SECRET_KEY` | **จำเป็น** คีย์ 32 ไบต์ฐาน base64 (`openssl rand -base64 32`) ใช้เข้ารหัส Falcon secret และ TOTP secret **ห้ามทำหาย** ไม่งั้นต้องกรอก Falcon secret ใหม่และผู้ใช้ต้องตั้ง MFA ใหม่ |
| `TENIX_APP_URL` | URL จริงของระบบ ใช้สร้างลิงก์เชิญ |
| `TENIX_DATABASE_URL` | **จำเป็นใน production** PostgreSQL connection string (ดูด้านบน) สำรองฐานข้อมูลด้วย `pg_dump` เป็นประจำ |
| `TENIX_BOOTSTRAP_EMAIL` | อีเมลแอดมินคนแรก (ใช้เฉพาะตอนยังไม่มีผู้ใช้) |
| `TENIX_SYNC_MINUTES` | ซิงก์ Falcon ทุกกี่นาที (ค่าเริ่มต้น 60, 0 = ปิด) |
| `TENIX_TRUST_PROXY=1` | ตั้งเมื่ออยู่หลัง reverse proxy เพื่ออ่าน IP จริงจาก `X-Forwarded-For` |
| `PORT` | ค่าเริ่มต้น 8787 |
| `TENIX_HOST` | ที่อยู่ที่เซิร์ฟเวอร์ฟัง ค่าเริ่มต้น `127.0.0.1` (เข้าได้ทาง reverse proxy เท่านั้น) ตั้งเป็น `0.0.0.0` เฉพาะเมื่อมีอย่างอื่นป้องกันพอร์ตอยู่ |

3. **ต้องใส่ HTTPS ด้านหน้า** (cookie เซสชันตั้ง `Secure` เมื่อเป็น production) อย่าตั้ง `TENIX_DEV_FALCON_URL_OK`

## บทบาทและสิทธิ์

ผู้ใช้มี 3 ประเภท **Super Admin**, **Admin**, **System Operator** โดย Admin และ System Operator ผูกกับ **Tenant** (องค์กรลูกค้า) ได้หนึ่งหรือหลาย Tenant และบทบาทแยกกันต่อ Tenant (คนเดียวเป็น Admin ของ Tenant หนึ่งและ Operator ของอีก Tenant ได้)

| ประเภท | ทำได้ |
|---|---|
| **Super Admin** | ทุกอย่าง: ตั้งค่า Falcon, สร้าง/แก้/ลบ Tenant และผูก CID, ตั้งค่าอีเมลแจ้งเตือน, เชิญ/ปิด/ลบผู้ใช้ทุกคน, กำหนดว่าผู้ใช้เห็น Tenant ไหน, ดูข้อมูลทุก Tenant (เลือกที่หัวหน้าเว็บ) ทุกการอ่านถูกบันทึก |
| **Admin** (ต่อ Tenant) | ดูข้อมูลของ Tenant ตัวเอง, **เชิญ ปิด เปิด ลบ** ผู้ใช้ของ Tenant ที่ตัวเองเป็น Admin, ตั้งว่าผู้ใช้เหล่านั้นเป็น Admin หรือ Operator, ดูบันทึกการใช้งานของ Tenant ตัวเอง |
| **System Operator** (ต่อ Tenant) | ดูข้อมูลของ Tenant ตัวเองเท่านั้น (ไม่เห็นหน้า Team, Audit, Tenants, Integrations และไม่เห็น CID) |

กฎที่ควรรู้:
- Tenant คือหน่วยแยกข้อมูล ผู้ใช้เห็นเฉพาะ Tenant ที่ถูกกำหนดให้ ถ้ามีหลาย Tenant จะมีตัวเลือกที่หัวหน้าเว็บ (มีเดียวไม่ต้องเลือก) การพยายามขอ Tenant อื่นได้ 404 เหมือนไม่มี และถูกบันทึกว่าถูกปฏิเสธ
- Admin ของ Tenant **ปิด/ลบ/รีเซ็ต** ผู้ใช้ที่สังกัด Tenant อื่นด้วยไม่ได้ (ทำได้เพียงแก้สิทธิ์ใน Tenant ของตัวเอง) และเชิญ Super Admin ไม่ได้ การสร้าง Super Admin ทำโดย Super Admin เท่านั้น
- ระบบไม่ยอมให้ปิด/ลบ/ลดสิทธิ์ Super Admin ที่ใช้งานอยู่คนสุดท้าย การเปลี่ยนประเภทผู้ใช้ทำให้ต้องล็อกอินใหม่
- ลบ Tenant ต้องพิมพ์ชื่อ Tenant ยืนยัน และจะลบข้อมูลช่องโหว่ สถานะ CID สแนปช็อต และประวัติซิงก์ของ Tenant นั้น
- เซิร์ฟเวอร์เป็นผู้ตัดสินสิทธิ์ทั้งหมด (Tenant → CID มาจากฐานข้อมูล ไม่เชื่อค่าจาก client)

**อัปเกรดจากเวอร์ชันเก่า:** ตอนเซิร์ฟเวอร์เริ่มครั้งแรก ระบบแปลงบทบาทเดิมให้อัตโนมัติ **แบบย้อนกลับไม่ได้** ให้สำรองก่อน `pg_dump tenix_exposure > backup.sql`

| บทบาทเดิม | เป็นบทบาทใหม่ |
|---|---|
| `soc_admin` | Super Admin |
| `customer_admin` | Admin ของ Tenant ตัวเอง |
| `customer_user` | System Operator ของ Tenant ตัวเอง |
| `soc_analyst` | System Operator ของ**ทุก** Tenant ที่มีอยู่ตอนแปลง (ไม่ใช่ Super Admin) |

หลังอัปเกรดควรซิงก์ใหม่ (Integrations → Sync all) เพื่อให้ได้ข้อมูล Falcon EASM, คำอธิบาย CVE และข้อมูลซอฟต์แวร์ที่เพิ่มเข้ามา

## ที่ควรรู้

- **คำเชิญ/รีเซ็ตรหัสผ่านเป็นลิงก์** ใช้ได้ครั้งเดียว หมดอายุ 7 วัน ระบบ**ยังไม่ส่งอีเมลให้เอง** (ตั้ง SMTP แล้วแต่ยังใช้กับการแจ้งเตือนเท่านั้น) มีปุ่มคัดลอกลิงก์และเปิดในแอปอีเมล
- **MFA (TOTP) ไม่บังคับ** ผู้ใช้เปิดเองที่หน้า Account; ผู้ดูแลรีเซ็ต MFA ให้ผู้ที่ทำเครื่องหาย (ยังไม่มี recovery code)
- การดึงข้อมูล Falcon: ขอทีละ 5,000 รายการ (ถ้า Falcon ปฏิเสธขนาดนี้ด้วย HTTP 400 จะลดเป็น 1,000 เองและบันทึกหมายเหตุไว้) เพดานความปลอดภัย 400,000 รายการต่อ CID ถ้าชนเพดานจะขึ้น "ไม่ครบ" ปรับขนาดหน้าที่ `hooks.pageSizes` และเพดานที่ `MAX_FINDINGS` ใน `server/src/falcon.ts`
- ระหว่างซิงก์ หน้า Integrations แสดงความคืบหน้า (อ่านแล้ว X จาก Y, หน้าที่เท่าไร, ขั้นตอนค้นหาชื่อเครื่อง/วิธีแก้) และคอลัมน์ Detail แยก "ข้อมูลที่ขาด" (สีเหลือง ทำให้สถานะไม่ครบ) ออกจาก "หมายเหตุ" (เช่น ข้ามกี่รายการเพราะไม่มี CVE/ไม่มี device ID พร้อมตัวอย่าง ไม่ทำให้สถานะไม่ครบ)
- ผลซิงก์ที่ไม่ครบ (`partial`/`failed`) จะแสดงแบนเนอร์เตือนเสมอ และ**ไม่ทับ**ข้อมูลที่ครบล่าสุด
- หน้าที่ปิดไว้ (ไม่ลบ): ดู `web/src/disabled-routes.tsx` และ `web/src/components/layout/app-layout/sidebar/disabled-data.tsx` วิธีเปิดกลับอยู่ในคอมเมนต์หัวไฟล์
- ธีม: โหมดสว่างอย่างเดียว ปิดโหมดมืดไว้ (ไม่ลบโค้ด) ไม่มีปุ่มสลับธีมและไม่สนใจค่าที่เคยบันทึกหรือค่าของระบบ เปิดกลับโดยแก้ `LIGHT_ONLY` ใน `web/src/contexts/theme-context.tsx` และใส่ปุ่มกลับ
- ภาษา: หน้าเว็บเป็น**ภาษาไทยแบบตายตัว** (ไม่มีปุ่มสลับภาษา และไม่ดูภาษาของเบราว์เซอร์) ข้อมูลจาก CrowdStrike คงตามเดิม (ระดับความรุนแรง สถานะ exploit CVE/KEV/CVSS ชื่อเครื่อง ชื่อซอฟต์แวร์) วันที่ใช้ชื่อเดือนไทยและปี ค.ศ. ข้อความภาษาอังกฤษยังอยู่เป็นต้นฉบับอ้างอิงและใช้กับชุดทดสอบ e2e (`VITE_LOCALE=en`) เพิ่มข้อความใหม่ที่ `web/scripts/messages-th-*.json` และ `messages-en*.json` แล้วรัน `node scripts/merge-messages.mjs` `npm run lint` ตรวจว่าทุกข้อความที่ใช้งานมีภาษาไทยครบ
- กด CVE หรืออุปกรณ์ที่ไหนก็ได้ จะเปิด Drawer ในหน้าเดิม (URL `?cve=` / `?device=`) เปิด Drawer ซ้อนกันได้และมีปุ่ม Back กลับ Drawer ก่อนหน้า ข้อมูลเวอร์ชันซอฟต์แวร์ที่ติดตั้งใน CVE Drawer ดึงสดจาก Falcon ตอนเปิด (ไม่เก็บในฐานข้อมูล)
- หน้า **Software** (Falcon Discover): แอปพลิเคชัน แพ็กเกจ ส่วนขยายเบราว์เซอร์/IDE โมเดล AI และ MCP ที่พบบนเครื่อง จัดกลุ่มตาม ประเภท+ผู้พัฒนา+ชื่อ แสดงจำนวนเครื่อง/เวอร์ชัน กดเปิด Drawer ดูเวอร์ชันที่ติดตั้งและรายชื่อเครื่อง ดึงตอนซิงก์พร้อมข้อมูลช่องโหว่ (ต้องมีสิทธิ์ Falcon Discover: Read ถ้าไม่มีจะขึ้นสถานะ failed เฉพาะหน้านี้ ไม่กระทบข้อมูลช่องโหว่) รายการที่ Falcon ไม่มีชื่อจะถูกข้ามและบันทึกจำนวนไว้ ทดสอบกับ CID จริงแบบอ่านอย่างเดียว: 32,815 รายการ อ่านครบใน ~60 วินาที
- ข้อความ UI ใหม่แก้ที่ `web/scripts/messages-en.json` แล้วรัน `node scripts/merge-messages.mjs`
- ฟอนต์โหลดจาก Google Fonts (Outfit + Noto Sans Thai) ถ้าต้องการไม่พึ่งภายนอกให้โฮสต์เอง
- ข้อจำกัด: ตัวนับล็อกอินผิด (rate limit) อยู่ใน memory ใช้ได้กับ 1 โปรเซส ถ้ารันหลาย instance ต้องย้ายลงฐานข้อมูล
- ข้อมูลเดโมเดิมใน SQLite (`.data/*.db`) ไม่ถูกย้ายมา Postgres

## Executive overview and the preview stack
- **Executive** (`/executive`, `web/src/pages/main/executive`, API `GET /api/exposure/executive`): one screen for management. Totals, CISA KEV, internet-facing findings ("internet-facing" = found by Falcon EASM, or a sensor device Falcon marks as internet exposed), age of Critical and High findings, trend and the most exposed assets. It reads only the data that is already synced, through `tenantScope()`, and never returns CIDs to customers. The change over time needs two different days of snapshots and stays empty until then.
- **Preview** (`server/scripts/preview-stack.ts`): a separate copy of the app on port 8795 with the mock Falcon on 8796, its own schema `preview_demo` in the **test** database (`TENIX_TEST_DATABASE_URL`, port 5433), served from `~/tenix-preview/dist`. Build the web into that folder with `cd web && npx vite build --outDir ~/tenix-preview/dist --emptyOutDir`, then `node server/scripts/preview-stack.ts` (restart) or `... stop`. The history, ages and CISA KEV flags in the preview are synthetic. It never touches the real database or `web/dist`.

## Organizations: CrowdStrike and LINE per organization

- **Create an organization, then connect it** (Settings > Organizations): each organization has its own CrowdStrike connection(s): cloud (Base URL), Client ID, Client Secret and CID (`server/src/connections.ts`). The secret is stored sealed and never returned. "Test" logs in and reads one finding of the CID, so a wrong secret, a missing *Spotlight vulnerabilities: Read* scope and a CID the API client cannot see are told apart. A CID is read with its own connection; a CID that has none is read with the old shared login (Integrations), and "adopt" copies that login onto the organization. Removing a connection needs the CID typed and also removes the data read for it.
- **LINE is per organization** (`line_chats`): an organization can have any number of *news sources* (chats whose messages are read for THAT organization only) and any number of *destination groups* (each receives that organization's answers, never another's). The SOC keeps its own sources (news checked against every organization) and destinations (summaries) under Settings > LINE bot. A chat belongs to one organization (or the SOC) per role. News posted in an organization's own source chat is answered to its destinations (or in that chat when it has none). Older settings (one chat list, one answer chat, `tenants.line_chat`) are moved into `line_chats` once at first start.

## E-mail

Every mail (invitation, password reset, sync alert, new-critical alert, test) is built by `server/src/mailkit.ts` in ONE look taken from TENIX DeepSpace's Portal mails: 600 px card, dark header with the wordmark, a status rail, chips, a facts panel, one solid button (with an Outlook fallback), a footer that says why it was sent, a plain-text twin, a dark-mode palette. Templates are fixed: callers pass values and every value is escaped. Invitations and reset links are e-mailed only when the request says `sendEmail: true` and a sender exists; the link is always returned too (`emailed`: sent / no_sender / failed / not_asked).

## Near-real-time CVE feed, CISA KEV and urgent items

Customers see, on one page, what a CVE is, whether it is known to be exploited, which of their devices have it and how fresh that answer is. Three facts are kept apart on purpose: **announced** (CVE Program), **in CISA KEV** (public: it says nothing about this organization being attacked), **found by Falcon in the organization** (its own findings). The wording is "near real time" (about 10 minutes behind the CVE Program), never "real time".

- **CVE List V5** (`server/src/feeds.ts`, official `CVEProject/cvelistV5`): `cves/deltaLog.json` lists, newest first, what changed in every ~7 minute publishing run; each changed record is one file. A run reads only the start of the log (HTTP Range, widening 64 KB > 512 KB > 4 MB > whole file, about 30 days) back to the stored checkpoint, fetches the changed records (6 at a time, at most 500 per run, the rest next run) and moves the checkpoint **only after every record of an entry is saved**. A re-run changes nothing; an older copy never overwrites a newer one; REJECTED is stored as such; fields the record lacks (e.g. CVSS) stay empty and the page says so. If the source is down, the data stays and the last successful time stays visible. First run: only the last `initialDays` (default 2) are read; a CVE named in a LINE message or opened on a page that is not in the registry is fetched on demand, and one the CVE Program has not published yet shows "waiting for the CVE Program" and is filled in by a later run.
- **CISA KEV** (`cisagov/kev-data`): the whole list (about 1,800 entries) is read with `If-None-Match`. The first import is a baseline (nothing is "new"); an empty or broken answer never replaces the list.
- **Intervals** (setup page, Integrations > CVE feed, super admin; or `PUT /api/integrations/feeds`): CVE List every **10 minutes** (5-1440), KEV every **60** (15-1440), initial window 2 days. A one-minute tick checks what is due, so a change needs no restart and a restart does not reset the schedule. The Falcon sync interval (`TENIX_SYNC_MINUTES`, default 60) is separate. **Run now:** the same tab, or `POST /api/integrations/feeds/run`.
- **Impact states** per organization and CVE: found / waiting for a result / partly checked / cannot check / not found in the latest Falcon data. "Not found" is said only when every CID's latest read is complete **and** newer than the CVE's announcement; the time shown is the Falcon sync time, labelled as such.
- **Urgent items** (`alerts`): one per organization and CVE and reason, enforced by the primary key, so repeated syncs and restarts make no second one. Reason 1: the organization has the CVE for the first time (after a complete read). Reason 2: the CVE enters KEV while it is still open there. The first read of a CID and the first start of the feature only record a baseline, so existing findings do not flood. Shown on the overview page; no outbound channel yet.
- **Public search** (`GET /api/public/cves`) lists announced CVEs for everyone and never counts or names anything of an organization.
- **Isolation:** the registry and KEV are public and shared; everything about devices goes through `tenantScope()`. News items are never shown to customers, so a link from one customer's LINE group cannot reach another.
- **What is verified:** parsing, the Range window, checkpoint, retries, KEV and urgent items, isolation, and a full case (LINE first, official record, Falcon devices, KEV) with fixtures in `server/test/feeds.test.ts` and `api.test.ts`. The two real sources were also read once (1,786 KEV entries, 90 real CVE records, a second KEV request answered `304`). **Not yet verified:** a long unattended run against the real feed on the production VM, and the impact states against the real Falcon tenants.

## LINE news bot
People send a news link, text or a picture to the bot in LINE. The bot finds the CVE ids, matches them with the synced findings of every organization, and answers in the same chat with the organizations and device names that are affected. Code: `server/src/line.ts`; setup page: Integrations > LINE bot (super admin).
- **Flow:** `POST /api/line/webhook` (signature `X-Line-Signature` = base64 HMAC-SHA256 of the raw body with the channel secret, checked before anything is parsed or stored) > dedupe by `webhookEventId` > store (`news_items`, `news_cves`) > open links > read pictures > CVE ids > match > answer.
- **Setup:** create a Messaging API channel in LINE Developers and copy the channel secret and the channel access token into the LINE tab (stored encrypted). The webhook has two ways to reach this app:
  1. *Direct:* set the Webhook URL shown on the tab in LINE Developers and turn on Use webhook (public HTTPS; the proxy in front must forward that path).
  2. *Shared channel (the webhook of this channel belongs to another system):* that system forwards every request to `POST <this app>/api/line/webhook` **unchanged**: the exact raw body and the `X-Line-Signature` header (the signature is computed over those bytes with the same channel secret), fire and forget with a short timeout so it never delays its own answer to LINE. On the same machine use `http://127.0.0.1:8787/api/line/webhook`; from elsewhere use the public HTTPS URL. This app answers 200 at once and works in the background.
  3. *Front door (this app owns the LINE webhook, another system must still receive everything):* set the **forward URL** on the tab (https only). Every request with a valid signature is sent on byte for byte with the same `X-Line-Signature`, so the other system verifies it itself and needs no change. This app answers LINE first and forwards in the background: 5 s timeout, 2 retries (1 s, 3 s) on a connection failure or 5xx, none on 4xx; the tab shows the last result. LINE redelivery is off for that channel, so a delivery that still fails is lost; a bad channel secret here means 401 and nothing is forwarded either, so press Verify in LINE Developers and test the other system right after switching, and switch back to its URL if anything is wrong. The retry queue is in memory (a restart in those few seconds loses that delivery).
- **Answers are per organization (Flex messages):** every message the bot sends is a Flex card (white card, coloured strip and pill by severity, big device count, device names in a grey panel; the SOC summary and the short notices use the same style), and every organization gets its own message with only its own devices, every device name listed (no "and N more"; long lists are split over bubbles and messages within LINE's limits). Set the organization's **LINE group** (Tenants > menu > LINE group; the ID comes from typing `id` in the group, one group per organization): the message goes there and starts "องค์กรของคุณ", and the organization also gets "องค์กรของคุณไม่พบเครื่องที่เกี่ยวข้อง" when nothing matches. An organization without a group is only reported, under its name, when it has matching devices, in the SOC chat (the chat that receives answers). The SOC chat also gets one text summary (which organizations have devices, who was sent to, who failed). Each push counts against the LINE message quota of the channel.
- **Two chat lists on the LINE tab:** "Chats that may send news" (whose messages the bot reads) and "Chat that receives the answers" (where every answer is pushed; empty = back to the chat the news came from). When the answer goes to another chat it starts with a line saying what news it is about. The answer group must be an internal SOC group, not a customer's and not one that another system already uses; the bot must be a member.
- **Silent by design:** the bot answers only in allowed chats (the answer names organizations and devices) and only to links, CVE ids and pictures there; ordinary conversation is ignored, and a picture with no CVE gets no answer (it is kept as evidence). Outside allowed chats it says nothing at all, except that the single word `/chatid` makes it reply with the chat's ID, which you add to "Allowed chats". Answers are always sent with the push API and never with a reply token, because a reply token works once and the system that owns the webhook may need it. Push messages count against the channel's monthly message quota.
- **Links:** only http/https on ports 80/443, no credentials in the URL, DNS is resolved by us and every address is checked (loopback, private, link-local, CGNAT, multicast, metadata, IPv6 and IPv4-mapped are refused), the connection goes to the address that was checked, redirects are followed by hand (5 at most, each hop checked again), 8 s, 2 MB, text only. A link that cannot be opened is reported as "could not check", never as "no CVE".
- **Pictures:** read with the local `tesseract` (English and Thai, `apt install tesseract-ocr tesseract-ocr-tha`; the picture never leaves the machine). Digits that OCR confuses (`O`/`0`, `l`/`1`) are repaired, impossible years are refused, and the answer says the CVE came from a picture so a person checks it against the original. Without `tesseract` the answer says it could not read the picture.
- **Matching:** uses the findings already synced. "No device" is only said for an organization whose data is complete; otherwise the answer says it cannot conclude. Software-only news with no CVE id is not matched (software is not linked to CVEs yet).
- **Not done:** a page in the portal that lists the news (the last 20 appear on the LINE tab); a customer-facing bot (it would need a per-chat organization mapping).

## การซิงก์ Falcon (Falcon sync design)
ออกแบบให้ "ครบและตรงความจริง" แม้ CID ที่มีช่องโหว่หลายสิบล้านแถว (`server/src/falcon.ts`, `rollup.ts`, `retention.ts`; ทดสอบที่ `server/test/falcon-sync.test.ts`, `rollup.test.ts`)
- **ตัวเลขจริงจาก Falcon ทุกรอบ:** เรียก `limit=1` แล้วอ่าน `pagination.total` (ทั้งหมด, แยก severity, KEV `cve.is_cisa_kev:true`, ExPRT, exploited, และ slice) เก็บใน `cid_counts` ใช้กับหน้า Overview และ `snapshots` ตัวเลขนับทุก severity เสมอ
- **เก็บทุกแถว (ทุก severity ทุกองค์กร) สองเฟส:** A = slice "แก้ก่อน" `status:['open','reopen']+cid:'X'+(cve.severity:'CRITICAL',cve.is_cisa_kev:true,cve.exploit_status:['60','70','80','90'],cve.exprt_rating:'CRITICAL')` (วงเล็บและจุลภาค = OR) เพื่อให้ใช้งานได้เร็ว, B = backfill ที่เหลือทั้งหมด สถานะเป็น `partial` ("เก็บ X จาก Y") จนเฟส B จบ แล้วเป็น `complete` เฟส A ยังเดินต่อระหว่างเฟส B เพื่อให้ slice สดเสมอ
- **Watermark:** อ่านทีละหน้าเรียง `updated_timestamp|asc` ด้วย `updated_timestamp:>'<watermark>'` เขียนแบบ UPSERT ทีละหน้า แล้วบันทึก watermark (`cid_cursor`) หลังทุกหน้า เดินต่อได้หลังถูกตัด/รีสตาร์ท (ข้อผิดพลาด, หมดเวลา `TENIX_FINDINGS_BUDGET_MINUTES` ค่าเริ่มต้น 20 นาทีต่อ CID ต่อรอบ, cursor หาย) ไม่เก็บทุกแถวไว้ในหน่วยความจำ
- **ตารางเวลา:** แต่ละรอบทำ CID ที่เสร็จแล้วก่อน (incremental ไม่กี่วินาที) แล้วตามด้วย CID ที่ยังไม่เสร็จ (ไม่เกินงบเวลา) ถ้ายังมี CID ที่ backfill ไม่จบจะเริ่มรอบถัดไปทันทีโดยไม่รอ tick รายชั่วโมง (ล็อกเดียว `syncState.running`) หลังรีสตาร์ท 15 วินาทีจะเดินต่อเอง
- **ปิดแล้ว:** ดึง `status:'closed'+closed_timestamp:>…` (ทุกแถว) ลบแถวที่เก็บไว้และเขียน `finding_closed` ด้วยเวลาปิดของ Falcon (เก็บรายแถว 35 วัน) ทำก่อนอ่านการเปลี่ยนแปลง reconcile ทุก 7 วัน หรือเมื่อจำนวนที่เก็บกับของ Falcon เบี่ยงเกิน 1% จะเดินใหม่ทุกแถวแล้วลบแถวที่ไม่เห็น (เฉพาะเมื่อเห็นอย่างน้อย 95% ของที่ Falcon นับ)
- **สถานะ (`cid_status.state`):** `complete` / `partial` / `failed` + `cid_status.reason` (`invalid_credentials | cid_not_authorized | missing_scope | unreachable | error`) รอบที่ล้มเหลวไม่ลบข้อมูลเดิม `recordImpact` เป็น baseline จนเฟส B จบ, `critical_new` แจ้งเฉพาะ CRITICAL ใหม่หลังเฟส A
- **ตารางสรุป (rollup) ต่อ CID:** `roll_cve`, `roll_host`, `roll_sev`, `roll_age` สร้างใหม่หลังรอบที่ข้อมูลเปลี่ยน ทุกหน้าลูกค้า (Overview, รายการช่องโหว่/เครื่อง, กราฟ) อ่านจากตารางเหล่านี้แทนการ GROUP BY หลายสิบล้านแถว; หน้ารายละเอียด CVE/เครื่องอ่านจากแถวผ่านดัชนี `(cid, cve_id)` / `(cid, aid)` `findings` เป็น view ของ `findings_t` (ข้อความ remediation เก็บครั้งเดียวใน `rem_sets`)
- **เลือก severity ที่เก็บต่อองค์กร (`tenant_settings`, `GET/PUT /api/tenants/:id/retention`):** ค่าเริ่มต้นเก็บทั้ง 5 ระดับ เอาติ๊กออก = หยุดเก็บทันที แต่ลบข้อมูลที่เก็บไว้หลังผ่าน 3 วัน (job ใน scheduler ลบเป็นก้อน + audit; ติ๊กกลับภายใน 3 วันยกเลิกการลบและดึงส่วนที่เปลี่ยนมาเติม; ติ๊กกลับหลังลบแล้ว = backfill ระดับนั้นใหม่จากต้น สถานะ `partial` จนกว่าจะครบ) ตัวเลข Falcon (`cid_counts`) นับทุก severity เสมอ ส่วน `coverage.scope`/`keptTotal` บอกขอบเขตที่เลือก
- **ยังไม่ทำ:** Software (Discover) ยังเป็นเพดาน 150,000 รายการและสถานะ partial (ตาราง hosts ครบทุกเครื่องทำแล้ว ดูหัวข้อ API v2 ด้านล่าง)

## รายการเฝ้าระวัง การตั้งค่าแจ้งเตือน ข่าว CVE และ EASM เพิ่มเติม (API v2 ฝั่ง B)
สัญญา API เต็มอยู่ที่ `api-v2-contract-B.md` (scratchpad) โค้ด: `server/src/watch.ts`, `notify.ts`, `news.ts`, `easm.ts` ทดสอบที่ `server/test/watch-notify-news.test.ts` ทุก endpoint ผ่าน `tenantScope()` (ขอ Tenant อื่น = 404) การเขียน/ลบด้วย `DELETE`/`PUT` ต้องส่ง `Content-Type: application/json` (ส่ง `{}` ได้)
- **`watch_hosts`** (PK tenant_id+aid, สูงสุด 200 เครื่อง ใช้ร่วมกันทั้ง Tenant): `GET /api/exposure/watchlist` (เครื่องที่เฝ้า + ระดับสูงสุด + P1 + รายการใหม่ 24 ชม. + KEV + รายการอัตโนมัติ: `kev_added`, `first_impact`, `critical_new`, `cve_news`), `PUT /api/exposure/watchlist/:aid` `{note}` (เพิ่ม/แก้โน้ต), `PUT /api/exposure/watchlist` `{aids:[]}` (เพิ่มหลายเครื่อง), `DELETE /api/exposure/watchlist/:aid` aid ที่ไม่ใช่ของ Tenant = 404 ทุกบทบาทของ Tenant (admin/operator) เขียนได้ บันทึก audit (`watch.add|note|remove`) `/api/exposure/urgent` ยังใช้ได้ตามเดิม
- **`notify_prefs`** (ต่อ Tenant): `GET/PUT /api/tenants/:id/notify` (ดู: สมาชิก Tenant, แก้: Admin ของ Tenant หรือ Super Admin) ระดับที่ส่ง, ส่ง P1 (KEV/exploited) เสมอ, โหมดรายชื่อเครื่อง `all | watched | top` (N เริ่มต้น 10), จำนวนชื่อสูงสุดต่อข้อความ, เปิด/ปิด, อนุญาตให้ลูกค้าเห็น "อาจกระทบ" และชื่อเครื่องในหน้าข่าว `POST .../notify/preview` ดูตัวอย่างข้อความ Flex, `POST .../notify/test` ส่งข้อความทดสอบ **ไม่มีแถว = พฤติกรรมเดิมทุกอย่าง** ตัวกรองอยู่ใน `line.ts` (`deliver`) เฉพาะข้อความที่ส่งเข้ากลุ่มของ Tenant ไม่กระทบแชต SOC จำนวนเครื่องจริงแสดงเสมอ ยังไม่มีโหมดสรุปรายวัน
- **`news_match`** (Tenant+CVE หนึ่งแถว): สถานะ `exact` (พบใน finding) | `possible` (ชื่อซอฟต์แวร์ที่ติดตั้งตรงกับผลิตภัณฑ์ใน CVE record ภายใน 14 วัน ลูกค้าเห็นเมื่อเปิด `newsPossible`) | `wait` | `not_affected` คำนวณใหม่หลังซิงก์ทุก CID, หลังรอบ CVE feed/KEV และหลังบอทวิเคราะห์ข่าว แจ้งซ้ำเฉพาะเมื่อเปลี่ยนสาระสำคัญ (เพิ่งเป็น exact หรือจำนวนเครื่อง ≥ 2 เท่า / +10) ข่าวที่มาจากแชตของ Tenant อื่นไม่ถูกนำมาจับคู่ `GET /api/exposure/news`, `GET /api/exposure/news/:cve`, `GET /api/exposure/news-soc` (Super Admin เท่านั้น) ลูกค้าเห็นจำนวนเครื่อง ชื่อเครื่องเมื่อเปิด `newsHostNames`
- **EASM เพิ่มเติม**: ซิงก์เก็บตำแหน่ง ASN เส้นทางที่ Falcon ค้นพบ และทุก service (พอร์ต โปรโตคอล แอปพลิเคชัน ใบรับรอง TLS: ผู้ออก/หมดอายุ) ใน `external_assets` (คอลัมน์ใหม่) และ `external_services` ธง: ใบรับรองหมดอายุ, ใกล้หมดอายุ (30 วัน), พอร์ตเสี่ยง `21, 23, 25, 135, 139, 445, 3389` `GET /api/exposure/easm/assets` (กรอง type, perimeter, review, expiredCert, riskyPort; เรียง "รอตรวจทานและใหม่ก่อน"), `GET /api/exposure/easm/assets/:id` (Drawer), `GET /api/exposure/easm/services` (สรุป) ข้อมูลใหม่จะมีหลังซิงก์รอบถัดไป

## ระดับแจ้งเตือน (ระดับ CVE x ระดับเครื่อง) และการยกระดับเมื่อถูกโจมตี
โค้ด: `server/src/alertlevel.ts` (เมทริกซ์ ระดับเครื่อง หลักฐาน), `notify.ts` (`annotate`, `applyPrefs`), `line.ts` (การ์ด Flex), เว็บ `settings/notify-levels.tsx` ทดสอบ `server/test/alert-level.test.ts`
- **สองระดับแยกกันต่อคู่ (CVE, เครื่อง)**: ระดับ CVE = ความรุนแรงของ CVE (Falcon severity/CVSS; P1/P2/P3, KEV, ExPRT เป็นข้อเท็จจริงเพิ่มเติม) ระดับเครื่อง = Critical/High/Medium/Low/Unassigned ที่มา (ตามลำดับ): (a) ระดับที่ตั้งเองบนเครื่องในรายการเฝ้าระวัง (`watch_hosts.criticality`; เพิ่มเข้ารายการโดยไม่ระบุ = High; แถวเดิมก่อนอัปเกรด = ไม่ตั้ง) (b) `criticality` ของ Falcon ที่ซิงก์เก็บใน `hosts.criticality` แล้ว (c) ตารางชื่อกลุ่มเครื่อง (host group) → ระดับ ต่อ Tenant (`notify_group_levels`, ใช้ระดับสูงสุดถ้าอยู่หลายกลุ่ม) (d) Unassigned (นับเป็น Medium ในเมทริกซ์)
- **เมทริกซ์ 4x4** เก็บเป็น JSON ใน `notify_prefs.matrix_json` (NULL = ค่าเริ่มต้น) แก้ได้ทุกช่อง ตรวจรูปแบบที่ `parseMatrix`. กติกาเริ่มต้น: ถ้าเท่ากัน → ระดับนั้น; ถ้าระดับที่ต่ำกว่า >= High → ระดับที่สูงกว่า; ไม่เช่นนั้น → ต่ำกว่าระดับที่สูงกว่า 1 ขั้น (ต่ำสุด Low) (แถว = ระดับ CVE, คอลัมน์ = ระดับเครื่อง, ลำดับ Critical/High/Medium/Low)

  | CVE \ เครื่อง | Critical | High | Medium | Low |
  |---|---|---|---|---|
  | **Critical** | Critical | Critical | High | High |
  | **High** | Critical | High | Medium | Medium |
  | **Medium** | High | Medium | Medium | Low |
  | **Low** | High | Medium | Low | Low |

  คำถามผู้บริหาร: CVE Critical + เครื่องกลุ่ม Low = **High**; CVE Moderate(Medium) + เครื่องกลุ่ม Critical = **High**
- **ยกระดับเป็น Critical** เมื่อมีหลักฐานว่าเครื่องนั้นถูกโจมตีจริง: ค่าเริ่มต้น = มี alert ของ Falcon บน aid นั้นในช่วง N วัน (ค่าเริ่มต้น 7, 1 ถึง 30) หลักฐานที่อ่อนกว่า (KEV / exploit_status >= 60 ของ CVE นั้น) แสดงเป็นป้ายและยกระดับเฉพาะเมื่อเปิดสวิตช์ `escKev` (ค่าเริ่มต้นปิด) ทุกครั้งที่ยกระดับ บอกเหตุผลในข้อความ (ชนิดหลักฐาน, alert id, จำนวนวัน) และบันทึก audit `notify.escalate`; แคชผลต่อเครื่อง 30 นาที (`attack_evidence`), ไม่เกิน 30 เครื่องที่ยังไม่มีแคชต่อข้อความ, เว้น 150 ms ต่อการเรียก (rate limit ของ Falcon ราว 6000/นาที), GET อย่างเดียว (`GET /alerts/queries/alerts/v2` อยู่ใน allowlist) ถ้า Falcon ตอบ 403 (API client ไม่มีสิทธิ์) จะจำไว้ 1 ชม. ไม่ยกระดับ ไม่ error และหน้าตั้งค่าแสดง "ไม่มีสิทธิ์ตรวจหลักฐาน"
- **ตัวกรองเดิม** (ระดับที่ส่ง, รายชื่อเครื่อง all/watched/top N) กรองตามระดับแจ้งเตือนต่อเครื่องเมื่อเปิด `matrixOn`; **แถวเดิมและ Tenant ที่ยังไม่มีแถว `matrixOn=false`** = กรองตามระดับ CVE เหมือนเดิมทุกประการ (การ์ดแสดงชิป ระดับ CVE / ระดับเครื่อง เพิ่มเท่านั้น ไม่มีระดับแจ้งเตือนและไม่มีการยกระดับ) ผู้ดูแลเปิดสวิตช์ในการตั้งค่าเมื่อพร้อม
- **การ์ด LINE**: ชิป "ระดับ CVE: X" และ "ระดับเครื่อง: Y" แยกกัน แล้ว "ระดับแจ้งเตือน: Z" บรรทัด "ยกระดับ: พบการโจมตีบนเครื่องนี้" (พร้อม alert id) ระดับเครื่องในแต่ละแถวเครื่อง และ altText มีระดับแจ้งเตือน สีคงที่ (Critical แดง, High ส้ม, Medium เหลือง, Low เขียว, อื่นๆ น้ำเงิน) ระดับของการ์ด = สูงสุดของทุกเครื่องในการ์ด
### ผลสำรวจ Falcon (อ่านอย่างเดียว ทดสอบกับ API จริงของลูกค้ารายหนึ่ง, GET เท่านั้น, 2026-11-21)
- **ระดับความสำคัญของเครื่อง (asset criticality)**: Devices API (`/devices/combined/devices/v1`, `/devices/entities/devices/v2`) มีฟิลด์ `criticality` (ค่าที่พบ `unassigned`; กรองด้วย `criticality:'Critical'` ได้ ซึ่งคืนเครื่อง) ใช้สิทธิ์ Hosts: Read ที่ Tenant มีอยู่แล้ว และระบบซิงก์เก็บใน `hosts.criticality` อยู่แล้ว จึงไม่มีการเรียก API เพิ่ม; `/exposure-management/queries/assets/v1` และ `entities/assets/v1` ตอบ **404** บน cloud นี้ (ยังไม่ยืนยันว่ามีที่ cloud/โมดูลอื่นหรือไม่ จึงไม่ใช้)
- **Alerts API**: `GET /alerts/queries/alerts/v2` ตอบ 200 ด้วยสิทธิ์ที่มีอยู่ ตัวกรอง `device.device_id:'<aid>'` ใช้ได้ (aid ที่มี alert คืน total ตามจริง, aid ปลอมคืน 0; `aid:'..'` ไม่ใช่ฟิลด์ที่ใช้ได้ และฟิลด์ที่ไม่มีจริงถูกเมินโดยไม่ error จึงต้องทดสอบด้วยข้อมูลจริง) `created_timestamp:>'ISO'` และ `sort=created_timestamp|desc` ใช้ได้ คืนเฉพาะ id (composite id, ไม่มีเวลา) `GET /alerts/entities/alerts/v2` ตอบ 405 รายละเอียด alert ต้องใช้ POST จึง**ไม่ใช้** (นอก allowlist แบบอ่านอย่างเดียว) ดังนั้นเหตุผลที่แสดงคือ alert id ล่าสุด + จำนวนวัน ไม่มีเวลาของ alert; Tenant ที่ API client ไม่มีสิทธิ์ **Alerts: Read** จะได้ 403 → ไม่ยกระดับ ให้เพิ่มสิทธิ์นี้ที่ Falcon (API clients and keys)

## API v2: เครื่อง (hosts), ระดับ P1/P2/P3, วิธีแก้ (fix), กราฟ

สัญญา API ฉบับเต็มสำหรับหน้าเว็บอยู่ที่ `api-v2-contract-A.md` (ทุก endpoint เป็นการเพิ่ม ไม่แก้ของเดิม) โค้ด: `server/src/hosts.ts`, `rollup.ts`, `overview.ts`, `lists2.ts`, `graph2.ts` ทดสอบ: `server/test/v2.test.ts`, `rollup2.test.ts`
- **ตาราง `hosts`** (จาก `GET /devices/combined/devices/v1` ทุกชั่วโมงหลังซิงก์ findings, ชื่อกลุ่มจาก `host-groups` 1 ครั้ง): เป็นแหล่งความจริงของ "มีกี่เครื่อง" รวมเครื่องที่ไม่มี finding และไม่นับสินทรัพย์ EASM; `last_seen` คือเวลาเช็คอินจริง (stale 7/30 วัน คำนวณตอนอ่าน); ทำเครื่องหมายเครื่องซ้ำ (hostname/serial/MAC เดียวกัน) และ "แฝดเก่า" (หยุดรายงานก่อนตัวใหม่อย่างน้อย 1 วัน); อ่านไม่สำเร็จ/ไม่ครบจะไม่ทับของเดิม; สถานะอยู่ใน `hosts_sync`
- **ระดับ (tier)** คำนวณตอนสร้าง rollup (ไม่เก็บบนแถว 17 ล้าน เพราะรายการ KEV เปลี่ยนเอง): P1 = อยู่ใน KEV หรือ exploit status >= 60 หรือ (CRITICAL และ ExPRT CRITICAL); P2 = ไม่ใช่ P1 และ (CRITICAL หรือ ExPRT HIGH/CRITICAL หรือ exploit status 30); P3 = ที่เหลือ finding ที่ถูก suppress (`suppressed`) และสถานะ `expired`/`closed` ไม่อยู่ในตัวเลขใด ๆ (`expired` ถูกดึงด้วยฟีด `status:'expired'+updated_timestamp` แล้วปฏิบัติเหมือน closed) finding ของ EASM (provider EASM) ไม่นับเป็นเครื่อง/CVE/tier ใน v2
- **rollup ใหม่ต่อ CID** (สร้างใน `refreshRollups`, สลับในทรานแซกชันเดียว): `roll_fix` (วิธีแก้ = `rem_set`), `roll_fix_host`, `roll_fix_cve`, `roll_prod_host` (คู่ที่อยู่เบื้องหลัง), `roll_fix_dim`, `roll_prod_dim` (เซลล์กราฟต่อกลุ่มเครื่อง/OS/ไซต์ นับเครื่องแบบ distinct), `roll_dim`, `roll_p1_prod`/`roll_soft` (P1/KEV CVE ต่อซอฟต์แวร์ ผูกด้วยชื่อผลิตภัณฑ์) และคอลัมน์ tier ใน `roll_cve`/`roll_host` ขอบเขตของ fix/กราฟคือ P1+P2 (คู่ P3 จะเป็นหลายล้านแถว) ตารางพักชั่วคราว `stg_*` สร้างบนเซิร์ฟเวอร์แล้วลบทิ้งทุกครั้ง
- **`hist_day`**: หนึ่งแถวต่อ CID ต่อวัน (UTC) เขียนหลังทุก rollup/ซิงก์/ซิงก์ hosts (P1/P2/P3 ที่เก็บ, เครื่องที่มี P1, จำนวนเครื่อง, ตัวเลข Falcon exact ของตอนนั้น) ใช้กับกราฟแนวโน้มและ portfolio
- **ตัวเลข Falcon exact เฉพาะ sensor:** รอบซิงก์เพิ่มนับ `s_*` (sensor เท่านั้น ไม่รวม EASM) และ `s_kx`, `s_c`, `s_kxc`, `s_p12` ซึ่งให้ P1 = kx + c - kxc, P1+P2 = p12 (OR แบนไม่ต้องซ้อน AND/OR) นับไม่สำเร็จ = หน้าแสดง "อย่างน้อย" ไม่ทำให้สถานะเป็น partial
- **Endpoint:** `/api/exposure/v2/summary|trend|fixes|fixes/:id|hosts|hosts/:aid|vulnerabilities|vulnerabilities/:cve` + `.csv` ของ fixes/hosts/vulnerabilities/software, `/api/exposure/portfolio` (เฉพาะ Super Admin), `/api/exposure/graph?lens=fix|matrix|focus`, `/graph/list`, `/graph/search`, `/graph/meta` ทุกตัวผ่าน `tenantScope()` และมีเทสต์แยกองค์กร; CSV สตรีม, จำกัด 200,000 แถว, กัน formula injection (ข้อความที่ขึ้นต้นด้วย `= + - @` จะถูกนำหน้าด้วย `'`) และบันทึก audit
- **ข้อจำกัดที่ควรรู้:** (1) ยอดรวม P1/P2/P3 จาก Falcon ยังนับ finding sensor ที่ถูก suppress (หน้าแสดงจำนวนใน `tiers.suppressedIncluded`) (2) ผูกซอฟต์แวร์กับ CVE ด้วยชื่อผลิตภัณฑ์ (heuristic) (3) ตัวกรอง FQL แบบซ้อนไม่ได้ทดสอบกับ Falcon จริง ใช้เฉพาะรูปแบบ `a+(b,c)` ที่เคยใช้ได้ (4) KEV ใน tier เป็นค่า ณ rollup รอบล่าสุด

## แบรนด์ ลิงก์ Spotlight และแหล่งข่าวของตัวเอง

- ชื่อระบบ/Flex ใช้ "10CYBER" (ทีมภายใต้ TENFORWARD) โลโก้ทีมอยู่ที่ `/brand/team.png`; หน้าระบบแสดง "10CYBER × TENFORWARD"
- ปุ่ม "เปิดใน Falcon" ใช้ลิงก์ Spotlight ตามคลาวด์ของการเชื่อมต่อแต่ละองค์กร (`falconLink(cve, baseUrl)` ใน `server/src/falcon.ts`) ไม่มีการตั้ง console URL เอง
- แหล่งข่าวและกลุ่มแจ้งเตือนแยกรายองค์กร (หลายแหล่ง/หลายกลุ่มต่อ Tenant) แต่ละแชต LINE มีเจ้าของได้หนึ่งองค์กรเท่านั้น
