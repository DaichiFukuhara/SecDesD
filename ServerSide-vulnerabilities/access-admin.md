# Main
If a website doesn't check the user's authority, attackers can access the admin functionality.
This is called Vertical previllege Escalation.

# Interpretation
I think this vulnerability is usually occured.
A personal developer can spend a few money for his website, and can't split public and private server.
Especially, a website developed by AI may not check these security issues.

# Measures
Split servers like public and private server.
Check the authority.

# Solution
1. Check https://insecure-website/admin
This isn't founded.
2. Check https://insecure-website/robots.txt
I find the endpoint "/administrator-panel" but I don't know why this is screened and what is robots.txt.
3. Access https://insecure-website/administrator-panel and delete the user "Carlos".

---

# Review: corrections, extra information and recent cases

## 1. Corrections to my notes

### (1) Main: the idea is right, but the words can be more exact
- **Authentication** = "Who are you?" (login)
- **Authorization** = "Are you allowed to do this?" (permission / role check)
- "Check the user's authority" → the correct term is an **authorization check** (or **access control**).
- **Vertical privilege escalation** = a normal user (or someone not logged in) uses functions meant for a **higher role** (admin). ✅ correct.
- Compare: **horizontal privilege escalation** = a user accesses **another user's** data at the same level (e.g. change `?id=123` to `?id=124`; this is called IDOR).
- In this lab we were **not even logged in**, and the admin page had **no check at all**. PortSwigger calls this "unprotected functionality".
- Spelling: previllege → **privilege**, occured → **occurred**, founded → **found**.

### (2) Interpretation: "a personal developer can't split public and private servers"
Partly right, but the main cause is not money or server count.
- The real root cause is that **the server does not check authorization on each request**.
  Even with one cheap server, a few lines of code (a role check) fix this lab.
- Big companies with a lot of money also make this mistake (see the cases in section 4: Cisco, Atlassian, Palo Alto).
- Hiding the admin panel from the internet is still a good **extra layer**, and it can be cheap:
  - Bind the admin app to `localhost` only and use an SSH tunnel
  - IP allowlist, VPN, or a free zero-trust proxy (e.g. Cloudflare Access)
  - Separate subdomain with its own login + MFA
- "Website developed by AI may not check these issues" → a fair concern. AI-generated code often **hides the admin button in the UI** but forgets the **server-side check**. Always test by requesting the admin URL directly while logged out or as a normal user.

### (3) Measures: "Split servers" is not the main fix
Splitting servers = **defense in depth** (helps, but not enough alone).
The main fix = **server-side authorization check on every admin request** (see section 3).

### (4) Solution step 1: "/admin is not found" does not mean it is safe
A 404 only means the path is different. Attackers find hidden paths by:
- Reading `robots.txt`, `sitemap.xml`
- Reading the site's JavaScript (the next lab hides the admin URL in JS code)
- Guessing with wordlists: tools like `ffuf`, `gobuster`, Burp Intruder (`/admin`, `/administrator`, `/admin-panel`, `/manage`, `/console` …)

### (5) Solution step 2: What is robots.txt and why was the path there?
- `robots.txt` is a **public text file at the site root** that tells **search engine crawlers** (Googlebot etc.) which paths **not to crawl** (Robots Exclusion Protocol, RFC 9309).
- Example:
  ```
  User-agent: *
  Disallow: /administrator-panel
  ```
- The developer added the admin path so it **would not appear in Google search results**.
- But robots.txt is **readable by anyone** and is only a **request**, not a lock. Bad bots ignore it.
  So writing a secret path there **tells attackers where the admin panel is**. This is "information disclosure".
- Lesson: **never put secret paths in robots.txt**, and never rely on a hidden URL as protection ("security through obscurity").

## 2. Other variants of this vulnerability (PortSwigger labs)
| Variant | What is wrong | Attack |
|---|---|---|
| Unprotected admin page (this lab) | No check at all | Find URL → open it |
| Unpredictable URL leaked | Admin URL hidden in JavaScript | Read page source / JS |
| Role in a cookie | Server trusts `Cookie: Admin=false` | Change to `Admin=true` |
| Role in user profile | Server lets user update `roleid` | Send `"roleid": 2` in the update request (mass assignment) |
| URL-based check bypass | Front proxy blocks `/admin`, but app trusts `X-Original-URL` header | `GET /` + `X-Original-URL: /admin` |
| Method-based check bypass | Check only on `POST` | Send the same action with `GET` |
| Multi-step process | Check on step 1 & 2, not on step 3 | Send step 3 request directly |
| Referer-based check | Server trusts `Referer: /admin` | Add the header yourself |

Common point: **the server trusts something the user can control, or checks only some of the requests.**

## 3. Correct measures
1. **Deny by default.** Every endpoint is blocked unless a rule allows it.
2. **Check authorization on the server, for every request** — not only on the menu/button. Hiding the button in HTML/JS is not security.
3. **Use one central mechanism** (middleware / decorator / framework feature), so no endpoint is forgotten.
   ```python
   # Flask example
   from functools import wraps
   from flask import abort, session

   def admin_required(f):
       @wraps(f)
       def wrapper(*args, **kwargs):
           user = get_current_user(session)   # read role from server-side session/DB
           if user is None or user.role != "admin":
               abort(403)
           return f(*args, **kwargs)
       return wrapper

   @app.route("/administrator-panel/delete")
   @admin_required
   def delete_user():
       ...
   ```
4. **Take the role from server-side data** (session / database), never from a cookie value, hidden field, or request body that the user can edit.
5. **Don't rely on secret URLs or robots.txt.**
6. **Extra layers:** admin panel only from VPN / IP allowlist / separate host, MFA for admins, log and alert on admin actions.
7. **Test it:** automated tests that call each admin endpoint as (a) not logged in and (b) normal user, and expect `403`.

## 4. Recent real cases
Broken Access Control is **#1 in the OWASP Top 10 (2021, and still #1 in the 2025 edition)**. Many recent big incidents are "anyone could reach the admin function".

| Year | Case | What happened |
|---|---|---|
| 2022 | **Optus** (Australian telecom) | An API endpoint returned customer data **without any authentication**. ~9.8 million customers' personal data leaked. |
| 2023 | **Cisco IOS XE** (CVE-2023-20198, CVSS 10) | Web admin UI let an **unauthenticated** attacker create a **level-15 (highest) admin account**. Tens of thousands of devices were compromised. |
| 2023 | **Atlassian Confluence** (CVE-2023-22515, CVSS 10) | Attackers could re-run the **setup process** and create a new **admin account** without logging in. Exploited by state-backed attackers. |
| 2024 | **ConnectWise ScreenConnect** (CVE-2024-1709, CVSS 10) | Adding an extra `/` to the setup wizard URL (`/SetupWizard.aspx/`) skipped the check, so attackers could **create an admin user**. Used for ransomware. |
| 2024 | **Palo Alto PAN-OS** (CVE-2024-0012 + CVE-2024-9474) | Authentication bypass on the **management web interface** → admin rights → root. Mainly affected devices whose admin UI was **open to the internet**. |
| 2025 | **Fortinet FortiOS / FortiProxy** (CVE-2024-55591) | Crafted requests to the admin interface's websocket gave **super-admin** rights without login. |
| 2025 | **McDonald's "McHire"** (Paradox.ai hiring platform) | A test **admin login used the password `123456`** and also had an IDOR → access to data of up to ~64 million job applicants. |

Lessons from these cases:
- Even security vendors (Cisco, Palo Alto, Fortinet) make this mistake → it is **not only a small-developer problem**.
- Many were made much worse because the **admin interface was reachable from the internet** → so "splitting public / private" (my idea) is a **valuable extra layer**, together with server-side checks.
- Setup / install / test pages are often forgotten → remove or protect them after deployment.

(Cases above are up to 2025 and written from memory. 2026 cases below were searched and checked in Nov 2026.)

### 4-2. 2026 cases (searched)
All of these are "attacker gets admin / management access **without a valid login**", and all were **actually exploited** (CISA put them in the KEV = Known Exploited Vulnerabilities catalog, or the vendor/hosting company confirmed attacks).

| Date (2026) | Case | What happened | Checked with |
|---|---|---|---|
| Jan 27 (KEV) | **Fortinet FortiCloud SSO** (CVE-2026-24858) — FortiOS, FortiManager, FortiAnalyzer, FortiProxy, FortiWeb | If FortiCloud SSO was on, an attacker with **their own** FortiCloud account + device could log in to **other customers' devices**. Attackers then changed firewall settings, **created new accounts**, and gave them VPN access. Fortinet had to turn off FortiCloud SSO globally for a day. | CISA alert |
| Apr 28–29 | **cPanel & WHM** (CVE-2026-41940, CVSS 9.8) — the control panel used by many web hosting companies | **CRLF injection** (`\r\n`) in a Basic-Auth header was written into the session file without sanitizing, so the attacker could add a line like `user=root` to their own session → **WHM admin (root) access without a password**. About **1.5 million** cPanel servers were visible on the internet; a hosting company reported active exploitation, and some reports say it was used as a zero-day from Feb 2026. | Rapid7 analysis |
| May 29 (KEV) | **Palo Alto PAN-OS** (CVE-2026-0257) | "Authentication bypass" on the firewall OS, exploited in the wild. (CISA gives only the title; details not confirmed.) | CISA alert |
| May (KEV) | **Cisco Catalyst SD-WAN Controller** (CVE-2026-20182, reported CVSS 10) | Reported as admin access without login, used by a threat group Cisco Talos tracks as UAT-8616. ⚠ Only seen in a news summary; the article could not be opened to confirm. | News summary only |
| Aug 3 (KEV) | **N-able N-central** (CVE-2026-18577) — remote management tool used by IT service companies | "Authentication bypass using an **alternate path or channel**" (CWE-288) = the login is checked on the normal path, but another path to the same function has no check. Exploited in the wild. | CISA alert |
| Sep 16 (KEV) | **Cisco ISE / ISE-PIC** (CVE-2026-76460, CVSS 10.0) — Cisco's network access control server | A crafted request to an **API endpoint** skipped the login of the **web management interface**; Cisco warns it can lead to commands as **root**. No workaround, only patch. | Bitsight analysis |
| Oct (KEV) | **Cisco Catalyst SD-WAN Manager** (CVE-2026-76504, reported CVSS 9.8) | Reported: a crafted HTTP request gives API access **as the admin user**. ⚠ Only seen in a news summary; not confirmed. | News summary only |

What these 2026 cases teach (link to this lab):
- **"Alternate path"** (N-able, Cisco ISE API) = the same idea as this lab: the admin *page* had a login, but **another route to the same function** didn't. → Put the check on the **function / every endpoint**, not on one entry page.
- **cPanel**: the server **trusted data the user could influence** (the session file) to decide "who is admin". → Never let user input decide the role.
- **Fortinet**: the check was "is this a valid FortiCloud user?" (authentication) but **not** "does this user own this device?" (authorization). → Authentication ≠ authorization.
- Almost all are **management interfaces reachable from the internet** → keep admin panels on a private network / VPN.

## 5. robots.txt in detail

### 5-1. What it is
- A plain text file that a website puts at **the root of the host**: `https://example.com/robots.txt`.
- It tells **crawlers** (programs that automatically visit pages: Googlebot, Bingbot, AI crawlers…) **which URLs they should not visit**.
- Standard name: **Robots Exclusion Protocol (REP)**. Created in 1994, made an official internet standard as **RFC 9309** in 2022.
- Only valid for that exact host + protocol + port. `blog.example.com` needs its own `robots.txt`. A file at `/images/robots.txt` is ignored.
- Anyone can read it — just open it in a browser or run `curl https://example.com/robots.txt`.

### 5-2. Why websites use it
- Stop search engines from crawling pages that are useless in search results (search pages, carts, login pages, duplicate pages).
- Reduce server load from bots.
- Tell crawlers where the sitemap is.
- Recently: **opt out of AI training crawlers** (e.g. `GPTBot`, `ClaudeBot`, `CCBot`, `Google-Extended`).

### 5-3. Syntax
```
# Comment
User-agent: *              # rules for all crawlers
Disallow: /search          # don't crawl URLs starting with /search
Disallow: /*.pdf$          # * = any characters, $ = end of URL
Allow: /search/help        # exception inside a disallowed area

User-agent: GPTBot         # rules only for this crawler
Disallow: /                # block the whole site

Sitemap: https://example.com/sitemap.xml
```
| Directive | Meaning |
|---|---|
| `User-agent` | Which crawler the following rules are for (`*` = all) |
| `Disallow` | Path prefix the crawler should not fetch (`Disallow:` empty = allow all) |
| `Allow` | Exception; when rules conflict, the **longest (most specific) match wins** |
| `Sitemap` | Location of the sitemap (not part of RFC 9309, but widely supported) |
| `Crawl-delay` | Wait time between requests — **not standard**, Google ignores it |

Behaviour details (RFC 9309 / Google):
- `robots.txt` returns **404** → crawler assumes **everything is allowed**.
- Returns **5xx** (server error) → crawler should assume **everything is disallowed** for a while.
- Path matching is **case-sensitive** (`/Admin` ≠ `/admin`).
- Google reads only the first **500 KiB**.

### 5-4. What robots.txt does NOT do (important!)
1. **It is not access control.** It is a polite request. Good crawlers follow it; attackers' tools and bad bots simply ignore it. The page is still fully accessible.
2. **It does not reliably hide a page from Google.** If another site links to a disallowed URL, Google can still show the **URL** in results (without content). To keep a page out of search results, use
   `<meta name="robots" content="noindex">` or the HTTP header `X-Robots-Tag: noindex` — and **don't** block it in robots.txt, otherwise the crawler can't see the `noindex`.
3. **It does not protect private data.** For that you need authentication + authorization.

### 5-5. Why it matters for security (this lab)
- Because it is public and lists "places we don't want visited", it is a **map for attackers**. It is one of the **first things checked in reconnaissance** (manually, and automatically by tools like Burp Suite, Nikto, gobuster).
- Typical leaks found in real robots.txt files: `/admin`, `/administrator-panel`, `/backup`, `/old`, `/staging`, `/api/internal`, `/phpmyadmin`.
- In this lab: the developer wrote `Disallow: /administrator-panel` to keep it out of Google → the attacker read robots.txt → found the panel → it had no authorization check → deleted Carlos.
- Similar recon files to check: `/sitemap.xml`, `/.well-known/security.txt` (RFC 9116, contact info for reporting bugs — harmless), `/crossdomain.xml`, JavaScript files.

### 5-6. Correct way to use it
- Put only **non-sensitive** paths in it (things you're happy for everyone to know about).
- Protect secret areas with **login + role check**, not with robots.txt. If you also want them out of search results, add `noindex` — not a robots.txt line.
- If you must block a sensitive area from crawling, use a **generic prefix** that doesn't reveal the purpose — but this still isn't security.

## 6. One-line summary
Vertical privilege escalation = **the server lets a lower-role user use admin functions because it does not check authorization**.
Hidden URLs and robots.txt are not protection. Fix = **deny by default + server-side role check on every request**, plus keep the admin panel off the public internet.
