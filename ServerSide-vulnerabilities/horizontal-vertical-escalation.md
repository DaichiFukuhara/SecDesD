# Main
Horizontal escalation is a method to access other user accounts belonging in same level authority.
Vertical escalation is a method to access other user accounts belonging in different level authority.

# Solution
## Horizontal escalation
Check the articles and find an article writtern by Carlos.
Access the Carlos's page, and copy his GUID.
Then, login as wiener and change the URL's ID to Carlos's GUID.

## Vertical escalation
Login as wiener and change the URL's ID to administrator.
Then, you can find password so open the Devtools and check the password in the JavaScript file.
After that, login as administrator using the password you found.

---

# Review: corrections, extra information and recent cases

## 1. Corrections to my notes

### (1) Definitions: horizontal is right, vertical needs fixing
- **Horizontal privilege escalation** = accessing **another user's data or functions at the same privilege level**. ✅ My definition is right.
  Example: user wiener reads user carlos's account page.
- **Vertical privilege escalation** = getting access to **functions or data of a higher privilege level** (e.g. normal user → admin).
  ❌ It is not "accessing other user accounts at a different level". It does **not** need another user's account at all.
  Example: changing `Admin=false` to `true` in a cookie (`Cookie-admin.md`), or opening an unprotected `/admin` page (`access-admin.md`).
- The second lab in my notes is actually a **horizontal → vertical** escalation (PortSwigger calls it "horizontal to vertical privilege escalation"):
  1. **Horizontal step**: use the IDOR to open **another user's** account page (`id=administrator`).
  2. That user happens to be an **admin**, and their page leaks their password.
  3. **Vertical result**: log in as administrator → admin functions.

| | Horizontal | Vertical |
|---|---|---|
| Target | Same-level user (another normal user) | Higher role (admin) |
| What you gain | Other people's data | More power (admin functions) |
| Typical bug | IDOR: `?id=123` → `?id=124` | Missing role check, role in cookie/parameter, unprotected admin page |
| Lab | "User ID controlled by request parameter, with unpredictable user IDs" | "User role controlled by request parameter", "Unprotected admin functionality" |

### (2) Horizontal escalation lab: small fixes
Lab: **"User ID controlled by request parameter, with unpredictable user IDs"**.
- Carlos's **GUID** (a long random ID like `c8a3e7f2-…`) is not on "Carlos's page". It is in the **author link of a blog post written by carlos**: `/blogs?userId=<GUID>`.
- Steps:
  1. Log in as `wiener:peter`.
  2. Open a blog post by carlos → click/inspect the author name → copy the `userId` GUID.
  3. Go to `/my-account?id=<carlos's GUID>` → carlos's account page is shown.
  4. Copy carlos's **API key** and submit it to solve the lab.
- Lesson: **a GUID is hard to guess, but it is not an access control.** If the GUID leaks anywhere (blog posts, comments, emails, API responses), the attacker can use it. The real bug is that the server **doesn't check that the logged-in user owns that ID**.

### (3) Vertical (horizontal → vertical) lab: the password is in HTML, not in a JavaScript file
Lab: **"User ID controlled by request parameter with password disclosure"**.
- Change `/my-account?id=wiener` → `/my-account?id=administrator`.
- The page has a "change password" form whose input is **pre-filled with the current password**:
  ```html
  <input required type="password" name="password" value="s3cr3tAdminPw"/>
  ```
- The browser shows `••••••`, but the password is in the **HTML source** (`value` attribute). Find it with **View Page Source** or DevTools → **Elements** — not in a JavaScript file. (Burp Suite's response view also shows it.)
- Then log in as `administrator` with that password → `/admin` → **delete carlos** to solve the lab.
- Two bugs here:
  1. **IDOR**: the server shows any user's account page based on `id`.
  2. **Sensitive data exposure**: the server sends the current password to the browser at all. (It also means passwords are stored so they can be read back — they should be **hashed**, so even the server can't show them.)

## 2. IDOR (Insecure Direct Object Reference) — the main cause of horizontal escalation
- **IDOR** = the app uses an ID from the user (`id`, `userId`, `orderId`, `invoice=…`) to fetch an object, **without checking that the user is allowed to access it**.
- OWASP API Security Top 10 calls this **BOLA** (Broken Object Level Authorization) — **#1** risk for APIs. CWE-639.
- Places where IDs appear: URL path (`/users/123`), query (`?id=123`), JSON body (`{"id":123}`), cookies, hidden fields, file names (`/download/invoice_123.pdf`).
- Sequential IDs (1, 2, 3…) make it easy to **enumerate** everyone. Random IDs (UUID/GUID) make guessing hard, **but don't fix the bug**.
- Other PortSwigger variants:
  - **Data leakage in redirect**: the server redirects you to login, but the redirect **response body** still contains carlos's data (visible in Burp).
  - **Insecure direct object references**: chat transcripts saved as `1.txt`, `2.txt` → change the number → read others' transcripts (one contains a password).

## 3. Correct measures
1. **Check ownership on every request**: "does the logged-in user own (or have permission for) this object?"
   ```python
   # Bad: trusts the id from the URL
   account = db.get_account(request.args["id"])

   # Good: use the session, or check ownership
   account = db.get_account(session.user_id)              # /my-account needs no id at all
   # or
   account = db.get_account(request.args["id"])
   if account.owner_id != session.user_id and not session.is_admin:
       abort(403)
   ```
2. For "my own" pages, **don't take the user ID from the request at all** — take it from the **server-side session**.
3. Put the check in **one central place** (data access layer / policy) so it's not forgotten on some endpoints.
4. Use **random IDs (UUIDv4)** as an extra layer against enumeration — not as the main protection.
5. **Never send secrets back to the browser** (current password, full card number, API keys of other users). Store passwords **hashed** (bcrypt/Argon2).
6. Return **the same response** (403/404) for "doesn't exist" and "not yours", and watch logs for one user requesting many different IDs (enumeration).
7. Write tests: user A requests user B's objects → must get 403/404.

## 4. Real cases

### Background (older, well-known)
| Year | Case | What happened |
|---|---|---|
| 2019 | **First American Financial** (US) | Changing the **document number in a URL** showed other customers' documents → about **885 million** records (bank numbers, SSNs, tax records) exposed. |
| 2022 | **Optus** (Australia) | An unauthenticated API with **sequential customer IDs** was enumerated → ~9.8 million customers' data. |
| 2025 | **McDonald's McHire** (Paradox.ai) | Weak admin password + **IDOR on applicant IDs** → chat data of up to ~64 million job applicants reachable. |

### 2026 cases (searched and checked, Nov 2026)
| Date (2026) | Case | What happened | Source checked |
|---|---|---|---|
| Apr 15 (detected) | **France Titres / ANTS** (French agency for ID cards, passports, driving licences) | IDOR in the portal's **API**: changing request parameters returned **other citizens' records** (names, emails, birth date/place, addresses, phone numbers). Attacker claims 18–19 million records; the agency has **not** given an official number. Agency disclosed it on Apr 20–22 and notified CNIL, ANSSI and the prosecutor; it says uploaded documents (ID scans) were not taken. | Rescana analysis (secondary) |
| May–Jun | **iFood** (Brazil, food delivery) | Attackers allegedly used a **stolen police account** on iFood's **law-enforcement request portal**, then abused an **IDOR** by changing user parameters for ~3 months → names, emails, CPF numbers, phones, addresses, delivery history. iFood confirmed **~1.2 million** users; attackers claim 43.8 million. | BeyondMachines |
| Oct 14 (disclosed) | **ServiceNext** (CVE-2026-79957) | `POST /api/Usuario/GetUsuarios` with `{"ID": n}`: the server checked the token was **valid**, but not that it **belonged to that ID**. IDs were sequential → any logged-in user could list **every account**, including the **password in cleartext**. Same pattern as the "password disclosure" lab: **horizontal IDOR → read passwords → log in as anyone (including privileged users) = vertical**. Fixed by the vendor in Aug 2026. | Black Lantern Security write-up |
| 2026 | **Flowise** (AI workflow tool, CVE-2026-30823, CVSS 8.8) | IDOR in **SSO configuration** handling: a low-privileged user could change **other users' authentication settings** → possible account takeover. | CodeAnt AI database (details limited) |

Lessons:
- IDOR is still one of the most common causes of **large data breaches** in 2026 (ANTS, iFood) — usually in **APIs**, not visible pages.
- iFood: even a portal only for **trusted users** (police) needs per-object checks — one stolen account was enough.
- ServiceNext: exactly the lab — **"valid login" ≠ "allowed to see this object"**, and storing passwords in cleartext turned a horizontal bug into a vertical one.

## 5. One-line summary
Horizontal = **same level, other people's data** (usually IDOR). Vertical = **higher level, more power** (admin).
Horizontal can become vertical when the victim is an admin. Fix = **check ownership/role on the server for every object and every request**, take "my" ID from the session, and never send passwords to the browser.
