---
icon: lucide/layers
tags:
  - bug-bounty
  - platforms
  - target-selection
  - reputation
description: The best hunter on the wrong program earns less than a mediocre hunter on the right one — platform selection, target timing, and reputation compounding are the meta-game that determines long-term income.
---

# Platform
Raw technical skill is not the ceiling on earnings — target selection is. A hunter who chases saturated programs, ignores new launches, and skips write-ups will earn a fraction of someone with less skill who plays the platform meta correctly. This section covers the decisions that determine return on time: which platforms to use, which programs to hunt, how to avoid duplicates, and how to build the reputation that unlocks private invites.

---

<div class="grid cards" markdown>

-   :material-compare:{ .lg .middle } __Platform Selection__

    ---

    Real differences between platforms, payout chains for Africa and Malawi, and the recommended start order for new hunters.

    [:octicons-arrow-right-24: Platform selection](#platform-selection)

-   :material-target:{ .lg .middle } __Target Selection__

    ---

    New program strategy, the program evaluation framework, depth vs. breadth, and finding the surfaces most hunters skip.

    [:octicons-arrow-right-24: Target selection](#target-selection)

-   :material-content-duplicate:{ .lg .middle } __Avoiding Duplicates__

    ---

    Where to hunt to minimise duplicate rates and a five-minute pre-submission check that pays for itself.

    [:octicons-arrow-right-24: Avoiding duplicates](#avoiding-duplicates)

-   :material-trophy:{ .lg .middle } __Reputation and Private Invites__

    ---

    The metrics that trigger invites, the write-up multiplier, community presence, and how to handle dry spells.

    [:octicons-arrow-right-24: Reputation and private invites](#reputation-and-private-invites)

</div>

## Decision Flow

```
Just starting out?
→ Create Bugcrowd + Payoneer first. Then YesWeHack + Wise. Add HackerOne after first valid bugs.

New program just launched?
→ Read scope (10 min) → run subdomain enum in background → manual browse main app →
  httpx + screenshots → test auth, IDOR, business logic → submit valid finding immediately.

Evaluating a program before committing time?
→ Check: launched recently? wide scope? P2 ≥ $500? response efficiency > 80%? low disclosed report count?
  If three or more red flags, skip it.

Deciding depth vs. breadth?
→ Breadth until 3–5 valid findings. Then: 1 deep target + 2–3 breadth targets at all times.

About to submit a finding?
→ Spend 5 minutes on duplicate check first: disclosed reports tab + HackerOne Hacktivity search.

Dry spell lasting more than 2 weeks?
→ Change one variable: target class, vulnerability class, or platform. Read 10 disclosed reports.
  Go back to PortSwigger labs for the class you're struggling with.

First interesting finding confirmed and paid?
→ Write it up on Medium / InfoSecWriteups after program approves disclosure.

Tracking private invite eligibility?
→ HackerOne: maintain Signal > 80%, aim for 5–10 valid Medium+ reports.
  Bugcrowd: build HackerScore to 30–40. One clean P2 outweighs ten sloppy P4s.
```

---

## Platform Selection

### Platform Comparison

| Platform | Best For | Competition | Payout Methods | Notes |
|---|---|---|---|---|
| Bugcrowd | Beginners, broad scope, VDPs | Medium | PayPal, Payoneer | Best Payoneer support. HackerScore drives invites. |
| HackerOne | Largest program selection, highest payouts | High | USDC, bank wire, PayPal | Most competitive publicly. Private programs are the prize. |
| Intigriti | EU programs, lower saturation | Low–Medium | SEPA via Wise, PayPal | Fresh EU company programs. Quality triagers. |
| YesWeHack | EU/global, least known | Low | Wise, Payoneer, EUR | Explicitly supports Wise. Least saturated of the four. |
| Open Bug Bounty | Practice only | Low | Voluntary / none | No reliable income. Use for skill building only. |
| Synack | Elite, invitation only | Low (curated) | Wire (US/EU) | Background check required. Skip until invited. |

**Recommended start order for a new hunter in 2026:**

```
1. Bugcrowd   — create account, configure Payoneer, start here
2. YesWeHack  — register, configure Wise, lower competition
3. Intigriti  — fresh EU programs, quality triage
4. HackerOne  — add after first valid bugs on the above
```

### Payout Logistics

!!! info "Africa / Malawi context"
    This section covers the practical payout chain for hunters in Malawi. The same chains apply across most of sub-Saharan Africa where direct bank wires are slow or unreliable.

```bash title="payout_chains"
Primary:   Bugcrowd → Payoneer → local bank or mobile money
Secondary: YesWeHack / Intigriti → Wise (IBAN) → local bank
Backup:    HackerOne → USDC crypto → exchange to local currency
```

**Setup sequence — do this before your first submission:**

```
1. Register Payoneer at payoneer.com (free, 3–5 business days to approve)
2. Register Wise at wise.com (free, IBAN account for EUR/USD)
3. Link both to your bug bounty platform profiles
4. Test with a small transfer once approved — don't wait for first payout
```

**Fee comparison:**

| Method | FX Fee | Notes |
|---|---|---|
| Payoneer | ~2% | Widely supported, slower |
| Wise | ~0.5–1% | Significantly cheaper for large amounts |
| USDC crypto | ~0.5–1% | Exchange fees vary by platform |

!!! warning "Tax — Malawi Revenue Authority"
    All foreign income is taxable as freelance/self-employment income. Set aside 25–30% from each payout before spending. Keep records: platform, payout date, amount, project description. Quarterly filing is recommended over annual for cash flow management.

---

## Target Selection

### The New Program Strategy

Being one of the first 50 hunters on a newly launched program is the single highest-leverage action in bug bounty. The low-hanging fruit hasn't been picked. The recon hasn't been done. The duplicate rate is near zero.

**How to be notified first:**

| Method | Where |
|---|---|
| BountyNotifier alerts | bountynotifier.com — push notification on new program launch |
| Platform new programs pages | bugcrowd.com/programs?sort_by=launched_at · hackerone.com/programs?order_field=launched_at |
| Twitter/X accounts | @Bugcrowd, @HackerOne, @intigriti, @yeswehack, @NahamSec, @jhaddix |

**Sprint order for the first 2 hours of a new program — this window matters most:**

```bash title="new_program_sprint"
Step 1: Read scope rules completely                   (~10 min)
Step 2: Subdomain enumeration                         (automated, run in background)
Step 3: Manual browse of main app while enum runs     (~20 min)
Step 4: httpx + screenshots of discovered subdomains  (automated)
Step 5: Test obvious surfaces manually — auth, IDOR, business logic
Step 6: Submit any valid finding immediately, even Low severity
Step 7: Continue deeper while recon pipeline completes
```

### Program Selection Framework

**Green flags — hunt here:**

```
□ Launched recently (< 6 months)
□ Wide scope (*.target.com, not just www.target.com)
□ Reasonable payout range (P2 ≥ $500, P1 ≥ $2,000)
□ Active response (recent triage activity visible in stats)
□ Response efficiency > 80%
□ Few disclosed reports (low saturation)
□ Technology stack you know well
□ Complex product (more attack surface)
```

**Red flags — avoid or de-prioritise:**

```
✗ Program has been public for 3+ years
✗ Narrow scope (only one subdomain in scope)
✗ No payout (VDP only) — unless for deliberate practice
✗ Response efficiency < 60% (reports go to die)
✗ Hundreds of disclosed reports (heavily saturated)
✗ "No bounties for Low/Medium" — high bar, lower ROI for beginners
```

### Depth vs. Breadth

=== "Breadth"

    ```
    Hunt many programs.

    Pros:
    - Higher chance of finding something while calibrating
    - Portfolio diversification across programs
    - Faster feedback loop on skill gaps

    Cons:
    - Never deep enough to find non-obvious bugs
    - Always finding what everyone else finds
    - High duplicate rate on obvious surfaces
    ```

=== "Depth"

    ```
    Master one or two programs.

    Pros:
    - Bugs that require deep application knowledge
    - Lower duplicate rate on non-obvious chains
    - Faster recon (you already know the surface)
    - Better reports from understanding business logic

    Cons:
    - Dry spells if that program has been picked clean
    ```

=== "Recommended balance"

    ```
    Beginners: start with breadth to find first bugs and calibrate skill.
    After 3–5 valid findings: shift to depth.
    Ongoing: 1 deep target + 2–3 breadth targets at all times.

    Sweet spot: depth on programs updated frequently.
    New features = new attack surface = new bugs even on mature programs.
    ```

### Reading Scope for Underexplored Surface

Most hunters test the obvious. The money is in what they skip.

| What everyone tests | What most skip |
|---|---|
| `www.target.com`, `/login`, `/api/v2/` | Mobile API endpoints listed in scope |
| Main auth flows | `partner.target.com`, `vendor.target.com` |
| User profile IDOR | API documentation portals (`/docs`, `/developer`) |
| Standard POST endpoints | Beta/preview features (`/beta`, `app.preview.target.com`) |
| — | Help/support center (often on separate platform with IDOR) |
| — | Integrations section (webhooks to third-party services) |
| — | Old subdomains listed in scope but not on main nav |

**How to read scope to find the underexplored surface:**

```
1. Read the full scope list — what's explicitly in scope?
2. Read the exclusions — what's explicitly out?
3. What's in scope but rarely mentioned in disclosed reports?
4. Are there scope expansions noted? ("Added mobile API 3 months ago")
5. Is there an "in the spirit of the program" clause? Use it.
```

---

## Avoiding Duplicates

### Smart Target and Surface Selection

The best duplicate avoidance is going where others aren't.

=== "New programs"

    ```
    Covered in the New Program Strategy section above.
    First 50 hunters = near-zero duplicate rate on standard surfaces.
    ```

=== "New features on old programs"

    ```
    - Follow the program's blog and changelog
    - When a new feature ships → test it within 48 hours
    - New code = new bugs the existing hunters haven't seen
    ```

=== "Underexplored surfaces"

    ```
    - Mobile API endpoints (web hunters skip mobile)
    - Partner/vendor portals
    - Legacy subdomains
    - GraphQL endpoints (many hunters don't test GraphQL)
    - AI features (still underexplored in 2026)
    - Non-English versions of the app (separate code paths)
    ```

=== "Second-order and chained bugs"

    ```
    - Less likely to be duplicates — they require connecting dots
    - A standalone IDOR + a standalone password reset = a chain that's unique
    - Less obvious classes: race conditions, business logic, SAML attacks
    ```

### Pre-Submission Duplicate Check

Five minutes before submitting saves thirty minutes writing a report that gets closed as duplicate.

```bash title="duplicate_check"
1. Check the program's disclosed reports:
   HackerOne: program page → Hacktivity tab → filter by program
   Bugcrowd:  program page → Hall of Fame / Disclosed tab
   Search for your vulnerability class + endpoint name

2. Search HackerOne's full disclosed report database:
   https://hackerone.com/hacktivity?type=public
   Query: "target.com IDOR" or "[endpoint name] XSS"

3. Check if the exact endpoint has been reported:
   If your bug is on /api/v1/users/{id} and there's a disclosed IDOR
   on that endpoint → likely duplicate.
   Unless: different parameter, different HTTP method, different auth context.
```

---

## Reputation and Private Invites

### What Triggers Private Invites

Private program invites are where the real earning is. The metrics that unlock them differ by platform.

=== "HackerOne"

    | Metric | Target |
    |---|---|
    | Signal (valid/invalid ratio) | > 80% |
    | Impact | Severity-weighted valid report count |
    | Reputation | Not penalised by N/A or duplicate flags |
    | Hall of Fame appearances | Each one = positive signal |
    | Approximate threshold | 5–10 valid Medium+ reports with good signal |

=== "Bugcrowd"

    | Metric | Target |
    |---|---|
    | HackerScore | > 30–40 (varies by program tier) |
    | Valid/invalid ratio | As high as possible |
    | Unique programs | Broad participation helps |
    | Approximate threshold | HackerScore > 30 with consistent valid findings |

=== "Intigriti / YesWeHack"

    | Metric | Target |
    |---|---|
    | Valid findings | 3–5 on the platform |
    | Triage feedback | Positive interactions matter |
    | Approximate threshold | Lower bar than HackerOne due to less competition |

!!! tip "Quality over volume"
    One clean P2 with a great report generates more invite signals than ten P4s with sloppy reports that accumulate N/A flags. The ratio matters more than the count.

### The Write-Up Multiplier

Public write-ups are the highest-leverage reputation action available to a hunter.

A write-up proves you understand the bug deeply, not just that you found it. It gets shared in security communities, attracts DMs from program teams, builds a portfolio for employment, and compounds into more invites over time.

**What makes a write-up worth sharing:**

| Element | What to include |
|---|---|
| Thought process | How did you notice this? What made you look here? |
| Failed attempts | What didn't work before you found the path? |
| The chain | How does this connect to other vulnerabilities? |
| Technical detail | What exactly is the vulnerable code doing? |
| The fix | What did the vendor do and why does it work? |

```bash title="writeup_format"
1. Title + one-sentence summary
2. Discovery story — the thought process, not just the steps
3. Technical breakdown — what the vulnerability is doing at code level
4. Remediation — what the fix was and why it works
```

!!! warning "What not to write"
    "I found IDOR on `/api/users/{id}`. I changed the ID. I got another user's data." — this is a report, not a write-up. The technical steps alone are not the valuable part. The discovery thought process is what gets shared and remembered.

Publish on Medium / InfoSecWriteups after the program approves disclosure. One detailed write-up per interesting finding beats five brief ones.

### Community Presence

| Community | Purpose | Where |
|---|---|---|
| Bugcrowd Discord (~20k members) | Program discussions, triage feedback, team hunting | discord.gg/bugcrowd |
| r/bugbounty | Program reviews, tool discussions, dry spell support | reddit.com/r/bugbounty |
| Twitter/X | Write-ups, tool tips, PoC demos, engagement | @NahamSec @jhaddix @STÖK @TomNomNom @corbenleo @vickieli7 |
| HackerOne Community Forum | Policy questions, platform updates | discourse.hackerone.com |

```
When to lurk:    First 3 months — absorb, learn, calibrate
When to post:    When you have something genuine — finding, technique, write-up
Don't post:      "I'm new, how do I start?" — read the resources first
Do post:         "Here's what I found when I tried X" — experience is valuable
```

### Dry Spell Management

Every hunter hits dry spells. The hunters who succeed treat them as data, not as verdicts on their ability.

**When stuck, change one variable:**

```bash title="dry_spell_response"
Target class:   If web apps aren't working → try mobile or API-only programs
Vuln class:     If you only test IDOR → try SSRF or business logic
Platform:       If HackerOne feels saturated → try Intigriti or YesWeHack
Study mode:     Read disclosed reports for the programs you're hunting.
                What are others finding? What's the pattern? What are you missing?
Labs:           Return to PortSwigger labs for the class you're struggling with
Write-up review: Read 10 write-ups about bugs you haven't found yet
```

**What dry spells usually are:**

| Cause | Fix |
|---|---|
| Wrong target (saturated) | Move to newer program or underexplored surface |
| Over-automating, under-thinking | Slow down, manual test for business logic |
| Skill gap in a specific class | PortSwigger labs for that class |
| Timing (program was quiet) | Wait or rotate targets — this passes |

---

## References

<div class="grid cards" markdown>

-   :material-bell-ring:{ .lg .middle } __New Program Alerts__

    ---

    BountyNotifier for real-time new program launch notifications.

    [:octicons-arrow-right-24: BountyNotifier](https://bountynotifier.com)

-   :simple-hackerone:{ .lg .middle } __Disclosed Reports__

    ---

    HackerOne Hacktivity for pre-submission duplicate checking and calibration.

    [:octicons-arrow-right-24: Hacktivity](https://hackerone.com/hacktivity)

-   :material-bank-transfer:{ .lg .middle } __Payout Infrastructure__

    ---

    Payoneer and Wise for receiving bounty payments outside traditional banking corridors.

    [:octicons-arrow-right-24: Payoneer](https://payoneer.com) · [:octicons-arrow-right-24: Wise](https://wise.com)

-   :material-pen:{ .lg .middle } __Write-Up Community__

    ---

    InfoSecWriteups on Medium for publishing disclosures and building community reputation.

    [:octicons-arrow-right-24: InfoSecWriteups](https://infosecwriteups.com)

</div>

---

??? note "Expand full checklist"

    ```
    SETUP (do once)
    □ Bugcrowd account created, Payoneer linked
    □ YesWeHack account created, Wise linked
    □ Intigriti account created
    □ HackerOne account created
    □ BountyNotifier (or equivalent) configured for new program alerts
    □ Twitter/X: following key hunters and platforms
    □ Bugcrowd Discord joined

    TARGET SELECTION (ongoing)
    □ New program alerts checked daily
    □ For each new program: read scope, assess green/red flags
    □ Current target portfolio: 1 deep + 2–3 breadth
    □ Deep target: tracking feature releases and changelog
    □ Pre-submission duplicate check: 5 minutes per finding

    REPUTATION BUILDING (ongoing)
    □ Valid/invalid ratio tracked — maintain > 80%
    □ First write-up published after first interesting finding
    □ Hall of Fame appearances tracked per platform
    □ Community engagement: respond, share, contribute
    □ Private invite metrics checked monthly (HackerOne Signal, Bugcrowd HackerScore)
    ```