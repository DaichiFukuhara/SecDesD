# Main-point
Path-traversal is an attack to change the path.

# Example
loadImage?image=picture.png
This endpoint means GET method.
GET https://__sample__.net/picture.png
The attackers change this to https://__sample__.net/../../../etc/passwd.
Then, the password file is displayed on attacker's screen.

# Interpretation
I think this is legacy attack way, so most of websites　take measures.
Because it is easy to do it.
For example, encrypting the sentences before access the point.
Or, don't give the access　authority for user. I don't know how to do this.

# Solution
"loadImage?image="picutre.png" →  ”loadImage?image="../../../etc/passwd"
Directly entering in URL is uncorrect, because "../" is deleted by browse's system.

---

# Review: corrections and extra information

## 1. Corrections to my notes

### (1) Main-point: "an attack to change the path"
More exactly: **path traversal (directory traversal, CWE-22) lets an attacker read (sometimes write) files on the server that they should not access.**
It happens when the server takes user input (e.g. a filename) and joins it into a **file system path** without checking it.
`../` means "go up one directory", so the attacker can climb out of the intended folder.

### (2) Example: the attacker changes the *parameter*, not the URL path
The request is not `GET https://__sample__.net/picture.png`.
It is:

```
GET /loadImage?image=picture.png HTTP/1.1
Host: __sample__.net
```

On the server, the code does something like:

```
base = "/var/www/images/"
open(base + request.args["image"])   # -> /var/www/images/picture.png
```

The attacker changes the **query parameter value**:

```
GET /loadImage?image=../../../etc/passwd
```

Server path: `/var/www/images/../../../etc/passwd` → resolved to `/etc/passwd`.

Changing the URL itself (`https://__sample__.net/../../../etc/passwd`) usually does **not** work,
because the browser and web server normalize `/../` in the URL path before anything else.
The bug is in the application code that builds a file path from user input.

- "This endpoint means GET method" → The query string (`?image=...`) can be used with any method. Here it is GET, but the same bug can exist in POST bodies, cookies, headers, etc.

### (3) `/etc/passwd` is not exactly "the password file"
- `/etc/passwd` = list of user accounts (name, UID, home dir, shell). Readable by everyone on Linux, so it is a safe file to **prove** the bug.
- Real password hashes are in `/etc/shadow`, which only root can read.
- Windows equivalent test file: `C:\Windows\win.ini` (and Windows also accepts `..\` as well as `../`).

### (4) "It is a legacy attack, most websites take measures" → Not true
It is old, but it is **still common and still serious**:
- It belongs to **OWASP Top 10 – A01: Broken Access Control**.
- Real recent CVEs:
  - CVE-2021-41773 / CVE-2021-42013 (Apache HTTP Server 2.4.49/2.4.50) – path traversal, led to RCE
  - CVE-2019-19781 (Citrix ADC) – path traversal → RCE, mass exploited
  - CVE-2018-13379 (Fortinet VPN) – read session files with passwords
  - "Zip Slip" (2018) – archive entries named `../../evil.sh` overwrite files when extracted
- Why still common: it is easy to *do*, but also easy to *accidentally create* (any feature that reads/writes files by name: image loader, file download, template name, language file, log viewer, upload, unzip).

### (5) "Encrypting the sentences before access" → Encryption is not the defense
Encrypting/hiding the parameter does not fix the root cause (untrusted input reaches a file API).
It is "security through obscurity". Correct defenses are below (section 4).

### (6) "Don't give access authority for user. I don't know how to do this."
This idea is good — it is the **principle of least privilege**. But "user" here should be the **web server process**, not the website visitor.
How to do it:
- Run the web app as a low-privilege OS user (e.g. `www-data`), never as `root`.
- Set file permissions so that user can only read the app folder (`chmod`, `chown`).
- Isolate the app: Docker container, chroot, read-only file system.
- Keep secrets (DB passwords, API keys) out of files the app can read when possible (use a secret manager / environment injection).
This is a **second layer** (limits damage). It does not remove the bug itself.

## 2. What attackers can do (impact)
- **Read** sensitive files:
  - App source code → find more bugs
  - Config files with credentials: `.env`, `config.php`, `web.config`, `application.properties`
  - SSH private keys: `/home/<user>/.ssh/id_rsa`
  - `/proc/self/environ` (environment variables, sometimes secrets)
- **Write** files (if the vulnerable feature saves files, e.g. upload or unzip):
  - Overwrite config or scripts, upload a web shell → **Remote Code Execution (RCE)**

## 3. Common bypass techniques (when the defense is weak)
These are why "just remove `../`" is not enough:

| Defense used by developer | Bypass |
|---|---|
| Blocks `../` but allows absolute paths | `image=/etc/passwd` |
| Removes `../` once (not recursive) | `image=....//....//....//etc/passwd` → after removal becomes `../../../etc/passwd` |
| Blocks `../` in raw text | URL encoding `%2e%2e%2f`, double encoding `%252e%252e%252f`, `..%c0%af` |
| Checks "path starts with `/var/www/images`" (before resolving) | `image=/var/www/images/../../../etc/passwd` |
| Checks "filename ends with `.png`" | Null byte (old languages/runtimes): `../../../etc/passwd%00.png` |
| Only blocks `/` | Windows: `..\..\..\Windows\win.ini` |

## 4. Correct defenses (best → backup)
1. **Don't pass user input to file system APIs at all.**
   Use an ID instead of a filename: `loadImage?id=42` → server looks up `42 → picture.png` in a database / map. (Indirect reference)
2. **Allowlist validation.**
   Allow only known filenames, or only safe characters (e.g. `^[a-zA-Z0-9_-]+\.png$`). Reject anything else (don't try to "clean" it).
3. **Canonicalize, then check the base directory.**
   Resolve the full real path first, then confirm it is still inside the allowed folder.

   ```python
   import os
   BASE = os.path.realpath("/var/www/images")
   target = os.path.realpath(os.path.join(BASE, user_input))
   if os.path.commonpath([BASE, target]) != BASE:
       abort(403)
   ```

   (Java: `getCanonicalPath()` + `startsWith`; Node.js: `path.resolve()` + check prefix with a trailing separator.)
   Note: `os.path.join(BASE, "/etc/passwd")` returns `/etc/passwd`, which is why checking *after* resolving matters.
4. **Least privilege / isolation** (section 1-(6)) — limits damage if 1–3 fail.
5. For archives (zip/tar): check every entry's resolved path before extracting (Zip Slip).

## 5. How to test (in a legal lab, e.g. PortSwigger Web Security Academy)
- Find parameters that look like filenames: `file=`, `image=`, `path=`, `template=`, `lang=`, `download=`.
- Try `../../../etc/passwd` (use many `../` — extra ones are ignored at `/`).
- If blocked, try the bypasses in section 3.
- Use Burp Suite to send requests, because an image endpoint shows the result as a broken image in the browser — view the raw response instead.

## 6. One-line summary
Path traversal = **untrusted input used as part of a file path** → attacker escapes the folder with `../` (or absolute path) → reads/writes server files.
Fix = **don't use user input as a path** (use IDs / allowlist), or **resolve then check the base directory**, plus **least privilege**. Encryption is not a fix.
