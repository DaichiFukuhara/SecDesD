# Main
Blute-force-attack means '乱暴な力による攻撃' in Japanese, so it is the most simple and easy way to crack website.
Prepare password's lists, and try them in order.

# Solution
Try to login with random username and passowrd like 'a' and 'a'.
Then, you can see the POST method in proxy tab in Burp Suite.
Select the username and send it to Intruder.
After that, in Intruder paster the username's list and start attacking.
As a result, you get responses which includes two responses, 'Invalid Username' or 'Incorrect Password'.
'Incorrect Password' means the username is right and password is wrong, so the username exists.
Then, like before try to crack the password's lists and username you found.
Eventually, you can get the '302' response. It means the combination of the username and the password is right.

---

# Review: corrections, extra information and recent cases

## 1. Corrections to my notes

### (1) "Blute-force" → "brute-force"

- The correct spelling is **brute-force attack**. In Japanese, the usual security term is **総当たり攻撃**; "乱暴な力による攻撃" is a literal translation.
- **Exhaustive brute force** tries every possible combination. Trying a prepared password list is more specifically a **dictionary attack**, often included under the broader term brute force.
- It is simple in concept, but success is not guaranteed: a long, unpredictable password and effective login protections can make guessing impractical.

Source: [PortSwigger: brute-forcing passwords](https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/authentication-mechanisms/brute-forcing-passwords).

### (2) The first stage is username enumeration

My notes describe two stages:

1. **Username enumeration**: discover which accounts exist from differences in failed-login responses.
2. **Password guessing**: keep a valid username fixed and try candidate passwords.

In this lab, `Invalid username` and `Incorrect password` reveal different states. The second message identifies an existing account even though the login failed. On other sites, differences can appear in response length, HTTP status or timing, even if the visible messages look identical.

Source: [PortSwigger: vulnerabilities in password-based login](https://portswigger.net/web-security/authentication/password-based).

### (3) "302 means the credentials are right" → a clue, not proof

**HTTP `302 Found` means a temporary redirect**, with the destination in the `Location` header. A site can redirect after success, failure, a lockout or an MFA challenge.
Inspect the destination and confirm that the resulting session can access the expected account page. A status code alone does not prove authentication succeeded.

Source: [MDN: 302 Found](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/302).

### (4) Small English corrections

- `passowrd` → `password`; `paster` → `paste`.
- `password's lists` → `password lists`; `username's list` → `username list`.
- "responses which includes two responses" → "responses containing one of two error messages".

## 2. Lab solution, with the missing details

The steps match PortSwigger's **[Username enumeration via different responses](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses)**. Use the candidate lists supplied by that lab.

1. Submit an invalid login with Burp running. In **Proxy → HTTP history**, find `POST /login` and send it to **Intruder**.
2. Choose **Sniper**. Set only the username value as a payload position (`username=§a§&password=a`), keeping the password fixed.
3. Load the username list as a **Simple list** and start. Sort by **Length**, then inspect the unusual response: `Incorrect password` identifies the valid username.
4. Clear the positions. Fix that username, mark only the password (`username=identified-user&password=§a§`), and replace the payloads with the password list.
5. Run again. The unusual `302` response suggests a successful guess in this lab.
6. Log in with that pair and **access the account page** to solve it.

## 3. Related attacks: what is different?

| Attack | What is tried | Key distinction |
|---|---|---|
| Exhaustive brute force | Every possible password combination | Search the full candidate space |
| Dictionary attack | Many likely passwords against an account | Use a wordlist instead of every combination |
| Password spraying | One or a few common passwords across many accounts | Spread guesses across accounts |
| Credential stuffing | Username/password pairs stolen from another service | Exploit password reuse |

Sources: [PortSwigger: password guessing](https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/authentication-mechanisms/brute-forcing-passwords), [OWASP: automated login attacks](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#protect-against-automated-attacks).

**Online vs offline:** this lab sends guesses to a live login endpoint. If password hashes are stolen, attackers can test guesses **offline**, where the site's rate limits and account lockouts do not apply. Salted, deliberately expensive password hashing (such as **Argon2id**) makes those offline guesses more costly; it does not replace online login protections.

Source: [OWASP: password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

## 4. Correct measures

1. **Use generic failures**, such as `Invalid username or password`. Keep failed-login status codes and processing behavior consistent too; avoid an obvious timing difference when a username does not exist.
2. **Throttle attempts on the server** with account-based limits and temporary delays or lockouts. Consider lockout abuse: an attacker must not be able to permanently lock out another user just by guessing.
3. **Add MFA** and enforce it on every supported login route. Protect recovery and MFA verification as well.
4. **Encourage long, unique passwords** and reject common or breached choices.

Source: [OWASP: authentication defenses](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).

5. **Combine account and network signals**: an IP-only limit is insufficient against distributed traffic. Monitor many accounts attacked from one source and one account attacked from many sources.
6. **Use CAPTCHA as an extra layer**, not the only control. Log suspicious authentication activity and alert on attack patterns; never log submitted passwords.

Source: [OWASP: credential stuffing prevention](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html).

## 5. Real cases

These illustrate related automated login attacks; they are not evidence that the services exposed the same username-enumeration bug as the lab.

| Date | Case | What happened | Source |
|---|---|---|---|
| Jan 2024 disclosure | **Microsoft / Midnight Blizzard** | A password spray compromised a legacy test-tenant account without MFA. The attackers then abused OAuth application access to reach corporate email. | [Microsoft incident analysis](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/) |
| Apr 2024 disclosure | **Roku** | Credential stuffing affected about 15,000 accounts, followed by a second incident involving approximately 576,000 additional accounts. Roku said the credentials came from outside its systems. | [Roku's disclosure](https://www.roku.com/blog/protecting-your-roku-account) |
| Jun 2026 observations | **Microsoft 365 password-spray campaign** | Huntress reported over **81 million attempts** and **78 account compromises** in two weeks. It linked successful access to missing or incorrectly scoped MFA policies on the ROPC authentication flow. This was a policy-enforcement gap, not proof that correctly enforced MFA was defeated. | [Huntress investigation recap](https://www.huntress.com/blog/twist-the-nozzle-on-password-spraying-a-tradecraft-tuesday-recap) |

## 6. One-line summary

This lab combines **username enumeration from different errors** with a **dictionary attack against the discovered account**. Defenses include consistent failures, server-side throttling, unique passwords and correctly enforced MFA; a `302` is only a clue until account access is confirmed.
