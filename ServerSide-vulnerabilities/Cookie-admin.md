# Main
Cookie is used for　keeping states.
The login authentication is contained by Cookies.

# Solution
Login as wiener, the password is peter.
Check application>storage>Cookies.
You find the admin is false, so change it.
And accessing /admin, you can reach the admin-panel.

---

# Review: corrections, extra information and recent cases

## 1. Corrections to my notes

### (1) "Cookie is used for keeping states" → ✅ correct, with more detail
- **HTTP is stateless**: each request is independent, and the server does not remember the previous one. Cookies are the most common way to keep **state** (login, cart, language…) across requests.
- How it works:
  ```
  (server → browser)  Set-Cookie: session=8f2a9c...; HttpOnly; Secure; SameSite=Lax
  (browser → server)  Cookie: session=8f2a9c...        ← sent automatically on every request to that site
  ```
- A cookie is **stored in the user's browser**, so **the user has full control over it**: they can read, edit, delete or invent cookies (DevTools, Burp Suite, curl).

### (2) "The login authentication is contained by cookies" → half right
- What a cookie *should* contain after login is a **session ID**: a long **random** value that means nothing by itself (like a cloakroom ticket number).
- The **real data** (who the user is, their role) is kept **on the server**, in a session store (memory / Redis / DB), and looked up with that ID.
- In this lab, the server put the **role itself** in the cookie: `Admin=false`. The server then **trusted whatever value the browser sent back**. That is the vulnerability.
- Rule: **anything the client sends can be changed by the attacker** — cookies, hidden form fields, URL parameters, headers, JSON body. Never use them to decide authorization unless they are **signed/encrypted and verified on the server**.
- Same lesson as `hardcode.md`: the decision "is this user admin?" must be made by the **server**, from **server-side data**.

### (3) Solution: steps are right; small additions
- PortSwigger lab name: **"User role controlled by request parameter"**.
- Steps:
  1. Log in as `wiener:peter`.
  2. DevTools → **Application** → **Storage** → **Cookies** → find `Admin=false` → change to `true`. (Or intercept the request in **Burp Suite** and change `Cookie: Admin=false` to `Admin=true`.)
  3. Open `/admin` → admin panel is shown.
  4. Delete the user **carlos** to solve the lab.
- Note: the server must accept the changed cookie on **every** request (also the "delete" request), so with Burp you need to change it each time, or edit it once in the browser.

## 2. Cookie attributes — what they protect, and what they don't
| Attribute | Protects against | Does NOT protect against |
|---|---|---|
| `HttpOnly` | JavaScript (e.g. XSS) **reading** the cookie | The user editing it in DevTools / Burp |
| `Secure` | Sending the cookie over plain HTTP (sniffing) | Tampering |
| `SameSite=Lax/Strict` | Cookie sent in cross-site requests (CSRF) | Tampering |
| `Domain` / `Path` | Cookie sent to other subdomains / paths | Tampering |
| `Expires` / `Max-Age` | Cookie living forever | Tampering |

➡ **No cookie attribute stops the user from changing their own cookie.** Only server-side checks (or a server-side signature check) do.

## 3. Ways sites store "who is logged in" — safe vs unsafe
| Method | Example | Safe? |
|---|---|---|
| Plain value | `Admin=true`, `role=admin`, `user=carlos` | ❌ Anyone can edit |
| Encoded (Base64, hex) | `role=YWRtaW4=` (= "admin") | ❌ Encoding is **not** encryption — just decode, edit, encode |
| Random session ID + server-side session | `session=8f2a9c…` (128-bit random) → server looks up user/role | ✅ Recommended |
| **Signed** cookie (HMAC) | Flask `session`, Express `cookie-signature`, Rails signed cookies | ✅ if the **secret key is strong and secret**. (Flask session data is signed, **not encrypted** — readable, don't put secrets in it) |
| JWT | `eyJhbGciOi...` | ✅ only if the signature is **verified**, algorithm fixed (reject `alg: none`), and the key is strong |

Common mistakes with signed cookies / JWT:
- **Default or hardcoded secret key** (e.g. `SECRET_KEY = "change_me"` from the docs / Docker image) → attacker signs their own `{"role": "admin"}` cookie. Tools: `flask-unsign`, `jwt_tool`.
- **Weak random** for the key or session ID (e.g. `Math.random()`, timestamps) → predictable.
- Not verifying the signature at all, or falling back to an unsigned format on error.

## 4. Other cookie/session attacks (related)
| Attack | Idea |
|---|---|
| **Session hijacking** | Steal someone's session cookie (XSS, malware, sniffing) and use it → logged in as them, **even with MFA** |
| **Session fixation** | Attacker sets the victim's session ID before login; if the server keeps the same ID after login, attacker knows it. Fix: **issue a new session ID after login** |
| **Predictable session IDs** | Sequential / time-based IDs → guess others' sessions |
| **Cookie forging** | Weak / leaked signing key → create a valid cookie for any user |
| **Missing logout / expiry** | Session stays valid forever on the server |

## 5. Correct measures
1. Store only a **random session ID** in the cookie; keep user ID and **role on the server**.
2. On every request, the server reads the role from the **server-side session / database** and checks it.
3. If you must store data in the cookie, **sign (HMAC) or encrypt** it with a **strong, unique, secret key** (≥ 256-bit random), and **verify** it every time. Never use default keys from documentation or Docker images.
4. Use a cryptographically secure random generator for keys and IDs (`secrets` in Python, `crypto.randomBytes` in Node.js) — not `Math.random()`.
5. **Regenerate the session ID after login** and after privilege changes; **invalidate on logout**; set an expiry.
6. Set `HttpOnly`, `Secure`, `SameSite` (against theft / CSRF).
7. Against stolen cookies: short session lifetime, re-authentication for sensitive actions, and newer **device-bound sessions** (Chrome's **DBSC**, Device Bound Session Credentials, ties the session to a key on the device so a copied cookie doesn't work elsewhere).

## 6. Real cases

### Background (older, well-known)
| Year | Case | What happened |
|---|---|---|
| 2023 | **Apache Superset** (CVE-2023-27524) | Many installs kept the **default `SECRET_KEY`** from the docs → attackers could **forge a signed session cookie as admin**. Thousands of internet-facing servers were affected. |
| 2023 | **Citrix Bleed** (CVE-2023-4966) | A memory leak in Citrix NetScaler leaked **session tokens** → attackers hijacked logged-in sessions and **bypassed MFA**. Used in ransomware attacks (e.g. Boeing). |

### 2026 cases (searched, Nov 2026)
| Date (2026) | Case | What happened | Checked? |
|---|---|---|---|
| Apr 15 | **WordPress "Login as User" plugin** (CVE-2026-5617, CVSS 8.8), ≤ 1.0.3 | **Almost exactly this lab.** The "Return to Admin" function trusted a **client-controlled cookie** `oclaup_original_admin` to decide which user to log in as. A normal **Subscriber** could set it to an admin's user ID → became **administrator**. | ✅ Tenable CVE page |
| Sep–Oct | **Rejetto HFS** (CVE-2026-61500, CVSS 9.8), 3.0.0–3.2.0, fixed in 3.2.1 | The cookie-**signing key** was made with `Math.random()` (not secure). From 6 unauthenticated requests the attacker recovers the random generator's state → rebuilds the key → signs a cookie `{username: "admin"}` → admin → runs server code as **root**. Found by Horizon3.ai; the article says exploitation in the wild started **Oct 1**. | ✅ Technical write-up (dev.to); in-the-wild claim not independently confirmed |
| 2026 | **Kimai** (time-tracking app, CVE-2026-52824) | Official Docker image had a **default `APP_SECRET`** (`change_this_to_something_unique`) → attackers could **forge cookies** and take over admin accounts. | ⚠ Search summary only; page could not be opened |
| Nov | **Xen Orchestra** (VSA-2026-062) | A crafted **cookie** made the parser return an empty object `{}`, and the token lookup then returned the **first token** in the database (often admin) → admin access without login; vendor said it was **actively exploited**. | ⚠ News summary only; article could not be opened |
| 2025–2026 | **Infostealer malware stealing session cookies** | Malware (Lumma, RedLine, Vidar…) copies browser cookies; attackers import them and are logged in **without password or MFA**. SpyCloud reported **8.6 billion stolen cookies in 2025**. | ⚠ Vendor reports / news summaries |

Lessons:
- CVE-2026-5617 shows this exact lab bug still ships in real plugins in 2026: **server trusts a cookie value to decide the user/role**.
- HFS and Kimai show the next level: even **signed** cookies fail if the key is **weak, default or predictable**.
- Infostealers show the opposite side: even a perfect cookie design fails if the cookie is **stolen** → short lifetimes, device-bound sessions, re-authentication.

## 7. One-line summary
Cookies are stored in the user's browser, so **the user can change them**. Putting `Admin=false` in a cookie and trusting it = anyone can become admin.
Fix = **random session ID in the cookie + role kept and checked on the server**; if data must be in the cookie, **sign it with a strong secret and verify it**.
