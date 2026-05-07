---
icon: lucide/notebook-pen
tags:
  - bug-bounty
  - reporting
  - triage
  - severity
description: A valid bug with a bad report pays less or gets rejected entirely — this section covers every component of a report that gets triaged, escalated, and paid.
---

# Reporting 

A valid bug with a bad report pays less or gets rejected entirely.   
Reporting is the product you are selling. The triager is the customer. Write for them, not for yourself.

---

<div class="grid cards" markdown>

-   :material-format-title:{ .lg .middle } __Report Structure__

    ---

    The non-negotiable seven-section template and how to fill every field.

    [:octicons-arrow-right-24: Report template](#report-template)

-   :material-gauge:{ .lg .middle } __Severity Calibration__

    ---

    CVSS is a starting point. Real-world impact determines what you actually get paid.

    [:octicons-arrow-right-24: Severity calibration](#severity-calibration)

-   :material-currency-usd:{ .lg .middle } __Getting Paid Faster__

    ---

    What triagers check in 30 seconds, and how to respond when they push back.

    [:octicons-arrow-right-24: Getting paid faster](#getting-paid-faster)

-   :material-scale-balance:{ .lg .middle } __Disclosure Etiquette__

    ---

    Platform SLAs, stalled report escalation, and how to write a public write-up correctly.

    [:octicons-arrow-right-24: Disclosure etiquette](#disclosure-etiquette)

</div>

## Decision Flow

```
Drafting a new report?
→ Follow the seven-section template in order. Never skip a section.

Writing the title?
→ [Vulnerability Class] in [Component] allows [Actor] to [Impact]. Under 120 characters.

Writing the impact statement?
→ Ask: one user or all users? PII? ATO? Financial? Regulatory? Then write to the worst realistic case.

Triager asks for reproduction help?
→ Add the raw HTTP request from Burp. Add exact account type. Offer a screen recording.

Triager downgrades severity?
→ Acknowledge → add context → show the full chain → propose a specific alternative severity. Once.

No triage response after 14 days?
→ One polite nudge on the report. Escalate to platform support at day 30.

Report closed as informational and you disagree?
→ Provide a concrete attack scenario with the specific action an attacker can take. One escalation attempt, then accept.

Considering public disclosure?
→ Confirm with the program first. Never include full exploit code or data that re-enables the attack before full patching.
```

---

## Report Template

Every report, every time — seven sections in this order:

```
1. Title
2. Severity (your assessment)
3. Summary (3 sentences)
4. Steps to Reproduce
5. Evidence (request/response, screenshot, video)
6. Impact Statement
7. Suggested Remediation
```

### Title

The title is the first thing a triager reads. It must answer three questions in one sentence: what is the vulnerability, where is it, and what can an attacker do?

```http title="title_formula"
[Vulnerability Class] in [Affected Component/Endpoint] allows [Actor] to [Impact]
```

=== "Good titles"

    ```
    IDOR in /api/invoices/{id} allows authenticated users to read any user's invoices
    Stored XSS in profile display name leads to admin account takeover
    SSRF in webhook URL parameter allows access to AWS EC2 metadata credentials
    JWT algorithm confusion enables privilege escalation to admin role
    Race condition in coupon redemption allows unlimited discount stacking
    ```

=== "Bad titles"

    ```
    "XSS vulnerability found"          → where? what impact?
    "Security issue in API"            → which class? which endpoint?
    "Broken access control"            → too vague for triage queue
    "Critical vulnerability"           → self-assigned severity in title
    "I found a bug"                    → rejected on sight
    ```

**Title calibration checklist:**

| Check | Pass condition |
|---|---|
| Vulnerability class | Named specifically, not "issue" or "problem" |
| Affected component | Exact endpoint or feature named |
| Impact | Stated in concrete terms |
| Length | Under 120 characters |
| Vague words | None: "issue", "problem", "bug" alone |

---

### Summary

Three sentences only. The summary tells a triager whether to keep reading.

```
Sentence 1: What the vulnerability is and where it exists
Sentence 2: What an attacker can do with it
Sentence 3: What conditions are required (authenticated? specific role?)
```

=== "IDOR example"

    ```
    The /api/invoices/{id} endpoint does not verify that the requesting user
    owns the invoice being requested. An authenticated attacker can enumerate
    invoice IDs to read billing details, payment amounts, and personal information
    belonging to any other user. This is exploitable by any registered user
    with a standard free account.
    ```

=== "SSRF example"

    ```
    The webhook delivery URL parameter is fetched server-side without
    validating that the destination is external. An attacker can use this
    to reach the AWS EC2 metadata endpoint at 169.254.169.254 and steal
    the instance's IAM role credentials. Exploitation requires an authenticated
    account with webhook creation access.
    ```

!!! warning "What not to write in the summary"
    Don't open with "I was testing the application and noticed...". Don't assign severity here — that's the severity field. Don't include reproduction steps or remediation. Three sentences: what, what attacker does, what conditions.

---

### Steps to Reproduce

Written for a developer with no security knowledge. If a developer follows these steps exactly, they reproduce the bug.

=== "IDOR"

    ```http title="idor_repro"
    1. Register two accounts: Account A (attacker) and Account B (victim).
    2. Log in as Account B. Create an invoice. Note the invoice ID in the URL:
       /dashboard/invoices/5523
    3. Log in as Account A.
    4. Send the following HTTP request:

       GET /api/invoices/5523 HTTP/1.1
       Host: target.com
       Authorization: Bearer <Account_A_token>
       Cookie: session=<Account_A_session>

    5. Observe: the response returns Account B's full invoice including
       billing address, amount, and payment method details.
    ```

=== "SQLi"

    ```http title="sqli_repro"
    1. Navigate to: https://target.com/search
    2. In the search field, enter: test' AND SLEEP(5)-- -
    3. Click Search.
    4. Observe: the response is delayed by approximately 5 seconds,
       confirming time-based blind SQL injection.
    5. Verify database version extraction:
       GET /search?q=test' AND IF(SUBSTRING(version(),1,1)='8',SLEEP(3),0)-- -
       [3-second delay confirms MySQL version 8.x]
    ```

**Steps quality checklist:**

| Check | Pass condition |
|---|---|
| Numbered and sequential | Yes |
| All inputs shown exactly | No paraphrasing |
| HTTP request included | Where relevant |
| Expected observation stated | At each critical step |
| Developer can follow without questions | Yes |
| Last step confirms the vulnerability | Not just approaches it |

---

### Evidence

Raw HTTP requests and responses are mandatory. Screenshots and video are additive.

**Always copy raw HTTP from Burp** — right-click → Copy as → Copy request. A screenshot of the request is not a substitute.

```http title="evidence_request_response"
Request:
POST /api/invoices/5523/delete HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGci...
Content-Type: application/json

{}

Response:
HTTP/1.1 200 OK
Content-Type: application/json

{"status": "deleted", "invoice_id": 5523}
```

**Minimum evidence by vulnerability type:**

| Type | Minimum | Ideal |
|---|---|---|
| IDOR | Request + response showing another user's data | Video showing full exploit from two accounts |
| XSS | Screenshot of `alert(document.domain)` firing | Video showing cookie exfiltration |
| SQLi | curl command + time delay measurement | sqlmap output showing DB version + one row |
| SSRF | interactsh callback screenshot | Response showing metadata content |
| Auth bypass | Request + response showing unauthorized access | Video walkthrough |
| RCE | DNS/HTTP OOB callback screenshot | Video showing command output |
| Race condition | Turbo Intruder screenshot showing multiple successes | Video showing financial impact |

**When to use video PoC:**

```
Use video when:
- Multiple steps are hard to follow in screenshots
- Race condition (timing is the evidence)
- DOM XSS (execution context matters)
- Complex chain (IDOR → password reset → ATO)

Guidelines:
- Screen record at 1080p minimum
- Show the full flow from start to finish
- Highlight the key moment (console, network tab, final outcome)
- Keep under 3 minutes — edit out the boring parts
- Host on: Loom, YouTube unlisted, or attach as file
```

---

### Impact Statement

The impact statement is the most underwritten section in most reports. This is what determines severity and bounty amount. Write it as if you are explaining to a CEO why this matters.

```
Impact = What the attacker gains + Who is affected + How many + Real-world consequence
```

=== "Weak"

    ```
    This vulnerability allows users to access other users' data.
    ```
    Result: Low/Medium, low bounty.

=== "Medium"

    ```
    An authenticated attacker can read any other user's invoice data by
    incrementing the invoice ID. This exposes billing details including
    name, address, and payment amount.
    ```
    Result: Expected severity.

=== "Strong"

    ```
    An authenticated attacker with a free account can enumerate all user
    invoices by incrementing the numeric invoice ID. Each response contains:
    full name, email address, physical address, and billing amount. With
    approximately 50,000 users and sequential IDs, a complete data dump of
    all user billing records is achievable in under 10 minutes using a simple
    script. This constitutes a mass PII breach potentially subject to GDPR
    notification requirements, with direct financial and reputational risk
    to the organization.
    ```
    Result: Elevated severity, higher bounty.

**Impact escalation questions:**

| Question | Why it matters |
|---|---|
| One victim or all users? | Scale multiplies severity |
| PII exposed? (name, email, address, DOB, SSN, payment) | Regulatory surface |
| Account takeover possible? | Moves to High/Critical |
| Financial manipulation? | Direct business damage |
| Admin access granted? | Privilege escalation path |
| GDPR/HIPAA/PCI-DSS concern? | Mandatory disclosure risk |
| Automated at scale? | Changes exploitability rating |

---

### Suggested Remediation

Always include remediation. It signals professionalism and often increases the bounty amount.

=== "IDOR"

    ```
    Implement server-side ownership verification before returning any resource.
    Verify that the authenticated user's ID matches the owner_id field of the
    requested resource before processing the request. Do not rely on
    client-supplied IDs as authorization controls.
    ```

=== "SQLi"

    ```
    Use parameterized queries or prepared statements for all database interactions.
    Avoid constructing SQL queries via string concatenation with user input.
    Consider a WAF as a secondary defense-in-depth measure — it does not
    replace parameterized queries.
    ```

=== "JWT"

    ```
    Explicitly specify the expected algorithm when verifying JWT signatures.
    Never accept the algorithm from the token header — hardcode the expected
    algorithm server-side. Use a well-tested JWT library rather than a
    custom implementation.
    ```

=== "SSRF"

    ```
    Implement a server-side allowlist of permitted webhook/URL destinations.
    Resolve the destination hostname server-side and verify it does not resolve
    to RFC 1918 private address ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16),
    the loopback address (127.0.0.1), or the link-local address (169.254.0.0/16).
    ```

---

## Severity Calibration

### CVSS vs. Real-World Impact

CVSS gives base scores but misses business context. Most programs use CVSS as a starting point, then adjust for actual impact. Always argue severity from real attacker capability.

| CVSS Says | Reality |
|---|---|
| Reflected XSS = 6.1 Medium | Reflected XSS stealing admin OAuth token on internal tool = High |
| IDOR (read-only) = 5.3 Medium | IDOR exposing SSNs of 100,000 users = Critical |
| Missing security header = 5.0 Medium | Missing security header = Informational in most programs |

### Severity Framework

**What actually gets each severity on most programs:**

=== "Critical (P1)"

    ```
    Remote code execution without authentication
    SQL injection with demonstrable data extraction
    Authentication bypass — admin access without credentials
    Account takeover without user interaction
    Mass PII/credential data dump (all users)
    AWS/GCP/Azure credential theft via SSRF
    Payment system manipulation (arbitrary charges/credits)
    Subdomain takeover with ATO potential via cookies
    ```

=== "High (P2)"

    ```
    Account takeover requiring minimal user interaction (click a link)
    Significant PII exposure (one user's full profile with sensitive data)
    Stored XSS in admin panel or high-privilege context
    Authentication bypass for regular user access
    SSRF with internal network access (not metadata)
    SQLi (blind, limited data retrieval)
    JWT forgery enabling admin access
    Broken OAuth leading to ATO
    Race condition with financial impact
    ```

=== "Medium (P3)"

    ```
    IDOR reading non-sensitive data of other users
    Reflected XSS (non-admin context)
    CSRF on sensitive action (password change, email change)
    Missing rate limit on authentication endpoint
    Path traversal reading non-sensitive files
    Subdomain takeover (no cookie scope)
    Open redirect chained with OAuth
    Information disclosure (stack traces, internal IPs)
    ```

=== "Low (P4)"

    ```
    Self-XSS (only affects attacker's own session)
    Open redirect (standalone, no chain)
    Missing security headers (CSP, HSTS, X-Frame-Options)
    Username/email enumeration without exploitation path
    Cookie without HttpOnly/Secure flags (standalone)
    Verbose error messages revealing framework/version
    SPF/DMARC misconfiguration (if email is in scope)
    ```

=== "Informational"

    ```
    Clickjacking on non-sensitive pages
    Missing rate limiting on non-auth endpoints
    SSL/TLS configuration issues (weak cipher suites)
    HTTP instead of HTTPS for non-sensitive content
    Tab nabbing via target="_blank"
    Software version disclosure without known CVEs
    Theoretical vulnerabilities without PoC
    ```

### Arguing Up

When the triager downgrades your report, use this structure: acknowledge → add context → show the full chain → propose a specific severity.

```http title="severity_dispute_example"
Triager: "Downgrading to P3. IDOR reads non-sensitive data."

Response:
"Thank you for the review. I'd like to note that this IDOR exposes the user's
registered email address. Combined with the password reset functionality at
/api/reset-password, which accepts an email parameter, this creates a viable
account takeover chain: IDOR reveals email → attacker triggers password reset
to that email. I've attached steps demonstrating the full chain. Would you
consider re-evaluating as P2 given this escalation path?"
```

**Evidence that supports severity escalation:**

| Evidence | Why it escalates severity |
|---|---|
| Chain to ATO | Read IDOR + password reset = full ATO |
| Mass exploitability | Affects all users, not just one |
| Regulatory impact | GDPR, HIPAA data class |
| Sensitive data class | PII, payment, medical vs. generic |
| Ease of exploitation | No special conditions, automatable |
| Prior art | Similar bugs paid higher on same platform |

!!! info "The MetaMask Precedent"
    A clickjacking vulnerability on MetaMask's transaction confirmation UI was awarded $120,000. CVSS would have rated it Medium/Low. The severity was driven by target application context (cryptocurrency wallet), specific user action (one click = irreversible fund transfer), and financial impact (up to the user's full wallet balance). Severity is always context-dependent — a "Low" on a banking app moving real money is not the same finding as on a blog.

---

## Getting Paid Faster

### What Triagers Check in 30 Seconds

Triagers process dozens of reports per day. Your report competes for attention. Reports that pass the 30-second scan get read fully. Reports that fail it get queued, deprioritized, or closed.

```
1. Title    — is this real and specific?
2. Severity — does the claimed severity match the title?
3. Summary  — is this clearly explained in 3 sentences?
4. Steps    — are they numbered and unambiguous?
5. Evidence — is there a screenshot or request/response?
```

**What kills reports immediately:**

| Mistake | Why it kills the report |
|---|---|
| Vague title | Triager can't route it |
| No severity justification | Forces them to do your analysis |
| Wall of text, no structure | Gets skipped, not read |
| Steps with unexplained prerequisites | Can't reproduce without clarification |
| No evidence | No PoC = no credibility |
| AI-generated text | Triagers recognize it in 2026 — signals low effort |

### Responding to Triage Questions

=== "Cannot reproduce"

    ```
    - Re-read your steps as if you've never seen the app before
    - Add: exact HTTP request from Burp, not a description of it
    - Add: exact account type needed (free? verified? specific permissions?)
    - Add: region or environment if relevant
    - Offer: "Happy to provide a screen recording if that would help"
    ```

=== "Duplicate"

    ```
    - Ask: "Could you share the duplicate report ID?"
    - If they won't: "Understood. May I ask approximately when the original
      was reported so I can track future disclosures?"
    - Do not argue unless you have clear evidence yours is different
    ```

=== "Not a vulnerability"

    ```
    - Ask for the specific reason
    - If you disagree, provide a concrete attack scenario:
      "To illustrate the impact: an attacker who exploits this can [specific action].
       Is there additional context that would help re-evaluate?"
    - One escalation attempt, then accept gracefully
    ```

=== "Out of scope"

    ```
    - Re-read the scope rules carefully before responding
    - If genuinely out of scope: accept it
    - If you believe it's in scope: quote the specific scope language and explain
      why the vulnerability falls within it
    ```

### Disputing Severity Professionally

```
1. Acknowledge their assessment without being defensive
2. Provide new information they may not have considered
3. Show the full attack chain, not just the isolated bug
4. Reference the impact on actual users of this specific application
5. Propose a specific alternative severity — don't just say "should be higher"
6. Accept the final decision gracefully — relationships matter long-term
```

!!! warning "What not to do"
    Don't send multiple back-and-forth messages repeating the same argument. Don't threaten public disclosure during the dispute window. Don't tag the company on social media while the dispute is open. Don't resubmit the same vulnerability with different framing.

---

## Disclosure Etiquette

### Platform SLAs

| Platform | Triage SLA | Payment SLA | Escalation Path |
|---|---|---|---|
| HackerOne | 1–7 days | 30–90 days after triage | @platform if >30 days no response |
| Bugcrowd | 1–7 days | 30–60 days | Bugcrowd support ticket |
| Intigriti | 3–10 days | 14–30 days | Intigriti support |
| YesWeHack | 3–10 days | 30–60 days | YesWeHack support |

**Status definitions:**

| Status | Meaning |
|---|---|
| Awaiting triage | In queue, not yet reviewed |
| Triaged | Reviewed and confirmed valid — payment coming |
| Resolved | Fixed (may not be paid yet) |
| Closed / Informational | Not accepted — ask for the reason |

### Escalating a Stalled Report

```bash title="escalation_timeline"
Day 14 (no response):
  One polite nudge on the report.
  "Hi, just following up on this report submitted 14 days ago.
   Happy to provide additional information or a screen recording if helpful."

Day 30 (still no response):
  Open platform support ticket.
  "Report #XXXX submitted on [date] has received no triage response in 30 days.
   Could you help escalate this to the program team?"

Day 60 (no resolution):
  Second platform support escalation.
  Most platforms take this seriously — they want to maintain program quality.
```

!!! danger "Never do this"
    Don't tweet at the company with vulnerability details. Don't open a GitHub issue in the target's repo. Don't post on Reddit or HackerOne Disclosure while under coordinated disclosure. Don't sell the vulnerability elsewhere while it's under active disclosure.

### Public Disclosure

Standard coordinated disclosure: report → vendor acknowledges and triages → vendor fixes → vendor approves disclosure or 90 days pass → public disclosure.

**When writing a public write-up:**

| Include | Exclude |
|---|---|
| Vulnerability class | Full exploit code |
| Affected feature | CVSS score that differs from their published one |
| Impact | Information that re-enables the attack before full patching |
| Thought process that led to discovery | Real user data seen during testing |
| Credit to the program for fixing promptly | |

!!! tip "Where to publish"
    Medium / InfoSecWriteups for maximum visibility. Publish after the CVE or fix is public, or the program explicitly approves. The thought process section is what gets you noticed — the technical steps alone are not the valuable part of a write-up.

---

## References

<div class="grid cards" markdown>

-   :simple-hackerone:{ .lg .middle } __HackerOne Resources__

    ---

    Writing good reports and browsing real disclosed examples for calibration.

    [:octicons-arrow-right-24: Report writing guide](https://docs.hackerone.com/hackers/submitting-reports.html) · [:octicons-arrow-right-24: Hacktivity](https://hackerone.com/hacktivity)

-   :simple-bugcrowd:{ .lg .middle } __Bugcrowd VRT__

    ---

    Bugcrowd's Vulnerability Rating Taxonomy — the severity framework most programs reference.

    [:octicons-arrow-right-24: VRT](https://bugcrowd.com/vulnerability-rating-taxonomy)

-   :material-calculator:{ .lg .middle } __CVSS Calculator__

    ---

    FIRST's CVSS v3.1 calculator and NVD scoring guide for base score reference.

    [:octicons-arrow-right-24: CVSS 3.1](https://www.first.org/cvss/calculator/3.1) · [:octicons-arrow-right-24: NVD guide](https://nvd.nist.gov/vuln-metrics/cvss)

-   :material-pen:{ .lg .middle } __Write-up Community__

    ---

    InfoSecWriteups on Medium — community write-ups for calibrating tone, structure, and impact framing.

    [:octicons-arrow-right-24: InfoSecWriteups](https://infosecwriteups.com)

</div>

---

??? note "Expand full checklist"

    ```
    BEFORE SUBMITTING
    □ Title: class + component + impact in one sentence (<120 chars)
    □ Severity: justified by real impact, not CVSS default
    □ Summary: 3 sentences — what, what attacker can do, what conditions
    □ Steps: numbered, exact inputs shown, reproducible by developer
    □ Evidence: raw HTTP request + response included
    □ Evidence: screenshot or video for visual confirmation
    □ Impact: who is affected, what data, what actions, at what scale
    □ Remediation: specific technical fix, not "fix the bug"
    □ Proofread: no typos, clear English, no AI-generated filler phrases

    SUBMISSION CHECKS
    □ Is this in scope? (re-read scope rules)
    □ Is it a duplicate? (search program's disclosed reports first)
    □ Is the severity honest? (over-inflation hurts credibility)
    □ Have you tested the reproduction steps one more time?

    AFTER SUBMISSION
    □ Check for triage response within 7 days
    □ Respond to triage questions within 48 hours
    □ Dispute severity once with full chain evidence, then accept
    □ Nudge if no response at day 14
    □ Escalate to platform support at day 30
    ```