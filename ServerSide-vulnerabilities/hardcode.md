# Main
Hardcode is directly typing at source code.
In some website, there is security incident checking authority in frontend by hard-coding.

# Solution
Check the index, Sources.
And you find the admin URL because the website check the admin authority in frontend layer.

# Cases
It's seen in 東ラブ, that is a matching app.
In 東ラブ, the login ids and passwords were checked in app layer, and users could find them.

# Measures
Manage the login date in database, not do it by hardcoding.
And do not check the authority in client side. Check it in server side.
Because every users, even attackers, can see the client side's source code.

---

# Review: corrections, extra information and recent cases

## 1. Corrections to my notes

### (1) Main: what "hardcoding" is
- **Hardcoding** = writing a value (password, API key, URL, user role, IP address…) **directly in the source code**, instead of reading it from a config file, environment variable, or database.
- Hardcoding is not always a vulnerability (e.g. `MAX_ITEMS = 100` is fine). It becomes dangerous when:
  1. the value is a **secret** (password, API key, private key), or
  2. the code runs on the **client** (browser JavaScript, mobile app), where **everyone can read it**, or
  3. a **security decision** (is this user admin?) is made in that client code.
- Related weakness IDs: **CWE-798** (hard-coded credentials), **CWE-602** (client-side enforcement of server-side security), **CWE-615 / CWE-200** (information disclosure in source code / comments).

### (2) This lab mixes two problems — separate them
PortSwigger lab: *"Unprotected admin functionality with unpredictable URL"*. The page source has JavaScript like:

```js
var isAdmin = false;
if (isAdmin) {
    var topLinksTag = document.getElementsByClassName("top-links")[0];
    var adminPanelTag = document.createElement('a');
    adminPanelTag.setAttribute('href', '/admin-xxxxxx');   // admin URL hardcoded here
    adminPanelTag.innerText = 'Admin panel';
    topLinksTag.append(adminPanelTag);
}
```

- Problem A — **information disclosure**: the "secret" admin URL is hardcoded in JavaScript that is sent to **every** visitor (even when `isAdmin` is false, the code is still downloaded).
- Problem B — **the real bug**: the server does **not check authorization** on `/admin-xxxxxx`. `isAdmin` in the browser only decides whether to *show a link*; it does not protect anything. The attacker can change it to `true` in DevTools or just type the URL.
- So "the website checks admin authority in the frontend" is close, but more exactly: **the website only hides the link in the frontend, and has no check at all on the server.**
- A random, hard-to-guess URL is **security through obscurity** — it fails as soon as the URL leaks (JS, robots.txt, browser history, logs, Referer header, screenshots).

### (3) Solution: how to find it
- "Check the index, Sources" → right-click → **View Page Source** (`Ctrl+U` / `Cmd+Option+U`), or DevTools → **Sources** tab (all JS files), or search all files with `Ctrl+Shift+F` in DevTools.
- Good words to search for: `admin`, `isAdmin`, `role`, `href`, `api`, `key`, `token`, `secret`, `password`.
- Also look at JS **source maps** (`.js.map`) — they can contain the original, readable source code with comments.

### (4) Cases: "東ラブ"
- I searched but **could not find any report about an app called "東ラブ"**. ⚠ Please check the name again.
- A similar, well-reported case is **UTopia (東大生限定マッチングアプリ, April 2026)** — see section 4. But in UTopia, the reported problems were **missing server-side checks, a database key in frontend code, and client-side-only validation**. Reports do **not** say that login IDs/passwords were hardcoded in the app.
- If 東ラブ is a different case, add the source (news URL) here.

### (5) Measures: mostly right, with small fixes
- "Manage the login **date** in database" → **login data**. And more exactly:
  - **User passwords**: store in the database as **hashes** (bcrypt / Argon2), never in code, never in plain text.
  - **App secrets** (DB password, API keys): put in **environment variables** or a **secret manager** (AWS Secrets Manager, GCP Secret Manager, Vault) on the **server**.
- ⚠ Environment variables in **frontend** builds are **still public**. Anything named `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*` is copied into the JS bundle that every visitor downloads.
- ⚠ Mobile apps are also client side: an APK/IPA can be decompiled (jadx, apktool) and strings read. Obfuscation only slows attackers down.
- "Do not check authority in client side, check in server side" → ✅ correct. The client may *hide* buttons for usability, but the **server must decide**.

## 2. Things attackers find in client-side code
| What | Example | Impact |
|---|---|---|
| Hidden admin URLs / endpoints | `/admin-8f3k2`, `/api/internal/users` | Find functions to attack |
| Client-side role checks | `if (user.role === "admin")` | Bypass by editing JS / requests |
| API keys / tokens | AWS keys, Stripe secret key, GitHub tokens, Slack webhooks | Use the company's account, read data, spend money |
| Database keys with full rights | Supabase `service_role`, Firebase admin keys | Read/write the whole database |
| Hardcoded passwords | `if (pw === "admin123")` | Log in as admin |
| Developer comments | `// TODO remove test account test/test` | Extra info for attackers |

## 3. Correct measures
1. **Never put secrets in client code** (browser JS, mobile apps). Assume everything sent to the client is public.
2. **Every authorization decision on the server**, for every request (see `access-admin.md` section 3).
3. **Secrets on the server** in environment variables / a secret manager, not in source code or Git.
4. **Database "public" keys must be paired with server-side rules** — e.g. Supabase anon key + **Row Level Security (RLS)**, Firebase **Security Rules**. Never ship an admin/`service_role` key.
5. **Restrict API keys** that must be public (e.g. Google Maps key restricted to your domain/app and to one API).
6. **Secret scanning** before and after commit: `gitleaks`, `trufflehog`, GitHub secret scanning / push protection.
7. **If a secret leaks: rotate (revoke and re-issue) it immediately.** Deleting it from the code is not enough — it stays in Git history, caches and attackers' copies.
8. **Remove debug code, comments, test accounts and source maps** from production builds.

## 4. Real cases

### Background (older, well-known)
| Year | Case | What happened |
|---|---|---|
| 2016 | **Uber** | Developers left **AWS keys** in a GitHub repository. Attackers used them to download data of **57 million** users and drivers. |
| 2022 | **Toyota T-Connect** | An **access key to a customer database** was in source code published on GitHub for about **5 years** → about **296,000** customer email addresses possibly exposed. |

### 2026 cases (searched and checked, Nov 2026)
| Date (2026) | Case | What happened | Source checked |
|---|---|---|---|
| Feb 17 | **Intruder research: secrets in JavaScript bundles** | Scanned **5 million** web apps → **42,000+ exposed tokens of 334 types** in frontend JS. Included **688 GitHub/GitLab tokens** (one gave access to all private repos of a company, including AWS/SSH secrets in CI/CD), and hundreds of active Slack/Zapier webhooks. Shows how common "secrets in the frontend" is. (Note: vendor research, sponsored article.) | BleepingComputer |
| Feb 18 (KEV) | **Dell RecoverPoint for Virtual Machines** (CVE-2026-22769) | "Use of **hard-coded credentials**" — exploited in the wild. | CISA alert |
| Apr | **UTopia** (東大生限定マッチングアプリ) | Reported by engineers on X (not confirmed by the operator): all users' **name, university email, face photo** readable as JSON **without login**; **My Number card images** reportedly in public storage; the "UTokyo email only" check and the "ID verified" status were **client-side only** (users could fake them); a Supabase **`service_role` key** reportedly in frontend JS with RLS not set. Site went into "maintenance" on Apr 21; no official explanation found as of late May. Operator not named. | note / coki / technophere articles |
| Jul 29 (KEV) | **Cisco Secure Firewall Management Center** (CVE-2026-20316) | "Use of **hard-coded password**" in the firewall management server — exploited in the wild. | CISA alert |
| Nov | **Cisco Expressway** (CVE-2026-76466) | **Hard-coded credentials** + weak client-certificate check → **unauthenticated commands as root** on clustered Expressway-C/E. Security firm F6 reported attackers (using an AI assistant) got root, moved through the network and searched GitLab repos for more credentials. CISA gave US agencies only **3 days** to fix. | BleepingComputer |

Lessons:
- Hardcoded secrets are found **fast and automatically** — attackers (and now AI tools) scan public JS, apps and GitHub.
- UTopia is exactly this lab's lesson in a real Japanese service: **client-side checks + secret key in frontend + no server-side authorization**.
- Even big vendors (Cisco, Dell) still ship hardcoded passwords in products.

## 5. One-line summary
Hardcoding = writing values directly in code. **Anything in client-side code is public**, so hardcoded admin URLs, keys and role checks in the frontend help attackers.
Fix = **secrets only on the server (env vars / secret manager), authorization checks only on the server, rotate any leaked key**.
