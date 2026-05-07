---
icon: lucide/search
tags:
  - recon
  - bug-bounty
  - methodology
description: A field-tested recon workflow for web bug bounty hunters. Coverage over depth. Surface area first, exploitation second.
---

# Reconnaissance

Recon runs in parallel with exploitation. The hunter who finds the most bugs isn't the best at exploiting — they're the best at finding surface others missed.

**The goal:** Build a complete map of everything the target owns, runs, and exposes. Every subdomain. Every endpoint. Every JS file. Every parameter. Then hunt that map.

---

<div class="grid cards" markdown>

-   :octicons-search-16:{ .lg .middle } __1. Subdomain Enumeration__

    ---

    Passive, active, and permutation-based. Every source sees different data.

    [:octicons-arrow-right-24: Start here](#1-subdomain-enumeration)

-   :material-web:{ .lg .middle } __2. HTTP Surface Mapping__

    ---

    Probe what's alive. Fingerprint the stack. Screenshot everything.

    [:octicons-arrow-right-24: HTTP probing](#2-http-surface-mapping)

-   :material-language-javascript:{ .lg .middle } __3. JavaScript Analysis__

    ---

    The most underexploited recon surface in web bounty. Endpoints, secrets, auth logic.

    [:octicons-arrow-right-24: JS analysis](#3-javascript-analysis)

-   :octicons-mark-github-16:{ .lg .middle } __4. GitHub & Source Code__

    ---

    Companies commit secrets constantly. History is permanent.

    [:octicons-arrow-right-24: GitHub recon](#4-github--source-code-recon)

-   :material-folder-search:{ .lg .middle } __5. Directory & Parameter Fuzzing__

    ---

    Unlinked endpoints still respond. Fuzzing finds them.

    [:octicons-arrow-right-24: Fuzzing](#5-directory--parameter-fuzzing)

-   :material-link-variant-off:{ .lg .middle } __6. Subdomain Takeover__

    ---

    Dangling CNAMEs. High severity, fast to find, easy to prove.

    [:octicons-arrow-right-24: Takeover](#6-subdomain-takeover)

-   :simple-google:{ .lg .middle } __7. Dorking & OSINT__

    ---

    Search engines have indexed things the target never meant to expose.

    [:octicons-arrow-right-24: Dorking](#7-google--advanced-dorking)

-   :material-robot:{ .lg .middle } __8. Automation & Pipelines__

    ---

    First-mover advantage. Catch new surface before anyone else does.

    [:octicons-arrow-right-24: Pipelines](#8-recon-automation--pipelines)

</div>

---

## Decision Flow

Before touching any tool, answer these:

```
Target has < 50 subdomains?
→ Manual review first, then light tooling

Target has > 500 subdomains?
→ httpx + gowitness screenshot triage before any manual work

App is heavily JS-based (SPA, React, Angular)?
→ Prioritize JS analysis (section 3) early, parallel to subdomain work

Program has lots of repos on GitHub?
→ GitHub recon (section 4) before active scanning — high severity, low noise

Time-constrained session?
→ Passive enum → httpx → screenshot triage → fuzz one interesting target
```

---

## 1. Subdomain Enumeration

No single tool finds everything. Each queries different data sources. Run them all, merge, deduplicate. The subdomains that only appear in one source are often the most interesting.

### 1.1 Passive Enumeration

**When to use:** Always. Run this first on every target. No packets sent to the target — safe, fast, finds historical surface that active brute-force misses.

#### Passive Sources

| Source | What It Indexes | URL Pattern |
|---|---|---|
| **crt.sh** | Every SSL cert ever issued (CT logs) | `https://crt.sh/?q=%.target.com&output=json` |
| **CertSpotter** | CT log alternative, more stable API | `https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names` |
| **Shodan** | Internet-facing hosts with SSL metadata | `ssl.cert.subject.cn:"target.com"` |
| **Censys** | Internet-wide scan + cert search | `https://search.censys.io/search?resource=hosts&q=target.com` |
| **SecurityTrails** | Historical DNS + subdomain history | `https://securitytrails.com/domain/target.com/history/a` |
| **VirusTotal** | Aggregated passive DNS from 70+ feeds | `https://www.virustotal.com/gui/domain/target.com/relations` |
| **AlienVault OTX** | Threat intel passive DNS | `https://otx.alienvault.com/api/v1/indicators/domain/target.com/passive_dns` |
| **Wayback CDX API** | Archived URLs containing subdomains | `http://web.archive.org/cdx/search/cdx?url=*.target.com&output=text&fl=original&collapse=urlkey` |
| **RapidDNS** | Fast passive dataset | `https://rapiddns.io/subdomain/target.com` |
| **BufferOver** | Passive DNS dataset (used by Amass) | `https://dns.bufferover.run/dns?q=.target.com` |
| **URLScan.io** | Browser-based scans, sees JS-loaded subdomains | `https://urlscan.io/search/#page.domain:target.com` |
| **Chaos (ProjectDiscovery)** | Curated bounty program subdomain datasets | `https://chaos.projectdiscovery.io` |

```bash title="passive_enum.sh"
# Subfinder — hits multiple API sources simultaneously
# Configure APIs at ~/.config/subfinder/provider-config.yaml
subfinder -d target.com -all -silent -o subfinder_out.txt

# Assetfinder — quick, reliable
assetfinder --subs-only target.com > assetfinder_out.txt

# crt.sh — no signup, no API key
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
  jq -r '.[].name_value' | \
  sed 's/\*\.//g' | sort -u > crtsh_out.txt

# Also hit the nested wildcard pattern
curl -s "https://crt.sh/?q=%.%.target.com&output=json" | \
  jq -r '.[].name_value' | \
  sed 's/\*\.//g' | sort -u >> crtsh_out.txt

# Amass passive only (slower but thorough, hits sources others miss)
amass enum -passive -d target.com -o amass_passive.txt
```

```bash title="merge_and_dedup.sh"
cat subfinder_out.txt assetfinder_out.txt crtsh_out.txt amass_passive.txt | \
  sort -u | anew master_subdomains.txt
# anew appends only lines not already in the file
# and prints only the new ones — pipe to notification or further processing
```

!!! tip "API keys matter"
    Subfinder without API keys returns roughly 30% of what it returns with them. At minimum, set up free keys for SecurityTrails, Shodan, VirusTotal, and Censys. Takes 15 minutes and permanently improves every scan.

!!! warning "CT logs show historical surface"
    A subdomain in crt.sh that doesn't resolve isn't dead — it's a takeover candidate. Flag it and check section 6.

---

### 1.2 Active Brute-Force

**When to use:** After passive enumeration. Finds subdomains that have never been linked anywhere and won't appear in cert logs (especially behind wildcard certs).

The quality of your wordlist matters more than which tool you use.

```bash title="active_brute.sh"
# puredns — most reliable, handles wildcard filtering automatically
puredns bruteforce \
  /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
  target.com \
  -r /opt/resolvers/resolvers.txt \
  -o puredns_out.txt

# shuffledns — faster for huge wordlists
shuffledns -d target.com \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
  -r /opt/resolvers/resolvers.txt \
  -o shuffledns_out.txt
```

**Wordlist priority:**

| Priority | Wordlist | Notes |
|---|---|---|
| 1 | `jhaddix/all.txt` (~2M entries) | Best coverage for bounty work |
| 2 | `subdomains-top1million-110000.txt` | Faster, good hit rate |
| 3 | Target-specific | Build from known naming patterns (see 1.3) |

Get updated resolvers from [trickest/resolvers](https://github.com/trickest/resolvers) — don't use your ISP's resolver for brute-force.

!!! warning "Wildcard DNS"
    If `randomstring123456789.target.com` resolves — wildcards are set and every query will appear to resolve. `puredns` handles this automatically; `shuffledns` also detects it. Always test before running blind.

---

### 1.3 Permutation Scanning

**When to use:** After you have at least 20–30 known subdomains. Generates variants algorithmically — finds subdomains that wordlists miss and that passive sources never indexed.

If `api.target.com` exists, there's a good chance `api-dev`, `api-staging`, `api-v2`, and `api-internal` do too.

```bash title="permutations.sh"
# AlterX — generate and resolve permutations in one pipe
cat master_subdomains.txt | alterx -enrich | dnsx -silent -o alterx_resolved.txt

# More patterns:
cat master_subdomains.txt | alterx -enrich \
  -p '{{word}}-{{suffix}}' \
  -p '{{prefix}}-{{word}}' \
  -p '{{word}}{{number}}' | \
  dnsx -silent >> alterx_resolved.txt

# gotator — alternative, good for depth
gotator -sub master_subdomains.txt \
  -perm /opt/gotator/permutations.txt \
  -depth 1 -numbers 3 | \
  dnsx -silent >> permutation_resolved.txt
```

!!! tip "Run passive + active first"
    AlterX output quality scales with how many subdomains you feed into it. The more seeds, the better the patterns it generates. Permutate on the merged list, not individual tool output.

---

### 1.4 DNS Resolution & CNAME Extraction

**When to use:** After merging all sources. Validates what's alive at the DNS layer and extracts CNAMEs for takeover detection.

DNS resolution ≠ HTTP response. A resolved subdomain doesn't mean anything is listening on 80/443. That's what section 2 handles.

```bash title="dns_resolve.sh"
# Resolve everything — extract A records and CNAME chains
dnsx -l master_subdomains_raw.txt -silent -a -resp -o dns_resolved.txt
dnsx -l master_subdomains_raw.txt -silent -cname -o dns_cnames.txt

# Flag NXDOMAIN subdomains — immediate takeover candidates
dnsx -l master_subdomains_raw.txt -silent -rc NXDOMAIN -o nxdomain_subdomains.txt
```

**What to look for in DNS output:**

| Signal | Action |
|---|---|
| CNAME → third-party service | Takeover candidate — check section 6 |
| NXDOMAIN | Flag for takeover investigation |
| Resolves to private IP range (10.x, 192.168.x) | Possible internal infrastructure via split-horizon DNS |
| Wildcard resolution | Strip via puredns before continuing |

---

## 2. HTTP Surface Mapping

DNS tells you what exists. HTTP probing tells you what's running and what it looks like. This step transforms a list of subdomains into a prioritized attack surface.

### 2.1 Live Host Probing

**When to use:** After DNS resolution. This single step gives you status codes, page titles, tech stack, content length, and favicon hashes for every live host.

```bash title="httpx_probe.sh"
# Full metadata pass
httpx -l dns_resolved.txt \
  -silent \
  -status-code \
  -title \
  -tech-detect \
  -content-length \
  -web-server \
  -favicon \
  -follow-redirects \
  -timeout 10 \
  -o httpx_out.txt

# JSON output for scripting
httpx -l dns_resolved.txt -silent -json -o httpx_out.json

# Quick triage — only the interesting status codes
httpx -l dns_resolved.txt -silent -mc 200,401,403 -o interesting_hosts.txt
```

**Reading httpx output — triage priority:**

| Signal | Why It Matters |
|---|---|
| Status 200, title contains "Admin" / "Dashboard" / "Panel" | Exposed admin surface |
| Status 200, small content-length, generic title | Under-configured, default install |
| Status 403 | Something is behind auth — probe for bypass |
| Status 401 | Auth challenge — check for bypass methods |
| Tech: Jenkins, Grafana, Kibana, Portainer | Exposed internal tooling, often weak auth |
| Tech: Laravel, Django, Spring | Framework-specific attacks apply |
| Favicon hash match | Cross-reference on Shodan for related hosts |
| Redirect to login on main app | Register an account, hunt authenticated surface |

```bash title="favicon_shodan_lookup.sh"
# Get favicon hash from httpx output, look up on Shodan
# httpx outputs murmur hash — search: http.favicon.hash:<value>
grep "favicon" httpx_out.txt | grep -oE '\[-?[0-9]+\]' | tr -d '[]' | sort -u
```

!!! info "403 is not a wall"
    Status 403 means something is there. Before moving on, try: different HTTP method, trailing slash variations, path encoding (`%2f`), and `X-Original-URL` / `X-Forwarded-For: 127.0.0.1` headers. See section 5 for the full bypass checklist.

---

### 2.2 Port Scanning

**When to use:** After httpx. Admin panels and internal services frequently run on non-standard ports. This finds them.

Two-phase approach: broad sweep first, deep fingerprint second.

=== "Phase 1 — Naabu (broad)"

    ```bash title="naabu_sweep.sh"
    # Sweep common ports across all live hosts
    naabu -l dns_resolved.txt -top-ports 1000 -silent -o naabu_out.txt

    # High-value web ports specifically
    naabu -l dns_resolved.txt \
      -p 80,443,8080,8443,8888,8000,8001,9000,9001,3000,3001,5000,4443,7443,4848,9200,6379 \
      -silent -o naabu_webports.txt
    ```

=== "Phase 2 — Nmap (targeted)"

    ```bash title="nmap_fingerprint.sh"
    # Deep service fingerprint on interesting hosts only
    nmap -sV -sC -p 80,443,8080,8443,8000,9000 \
      --open -iL interesting_hosts.txt -oA nmap_detailed

    # Full port scan on a single high-value target
    nmap -p- -sV --open -T4 specific_target.target.com -oA nmap_full
    ```

**Ports worth investigating:**

| Port | Service | Why |
|---|---|---|
| 8080, 8443 | Alt HTTP/HTTPS | Dev or proxy interfaces |
| 8888 | Jupyter, dev servers | Often unauthenticated |
| 9000 | PHP-FPM, Portainer | Internal service exposure |
| 3000 | Node.js, Grafana | Dev apps |
| 4848 | GlassFish admin | Exposed Java admin console |
| 9200, 9300 | Elasticsearch | Unauthenticated data access |
| 6379 | Redis | Unauthenticated cache/DB |
| 27017 | MongoDB | Unauthenticated database |
| 2375, 2376 | Docker API | Container escape |

!!! warning "Scope check"
    Some programs explicitly prohibit port scanning. Read the scope rules before running either tool. Scanning CIDR ranges is almost always out of scope — stick to resolved subdomains.

---

### 2.3 Visual Triage with Screenshots

**When to use:** When you have more than 30–40 live hosts. You cannot manually visit each one in a browser. Screenshots let you triage 200+ hosts in under 10 minutes.

=== "gowitness"

    ```bash title="gowitness_screenshots.sh"
    gowitness file -f httpx_out.txt --threads 10 -P ./screenshots
    gowitness report generate  # HTML report
    ```

=== "aquatone"

    ```bash title="aquatone_screenshots.sh"
    cat httpx_out.txt | aquatone -out ./aquatone_report -threads 5 -timeout 3000
    ```

=== "eyewitness"

    ```bash title="eyewitness_screenshots.sh"
    eyewitness --web -f httpx_out.txt --timeout 10 --no-prompt -d eyewitness_report
    ```

**What to flag during visual review:**

| Screenshot | What to Do |
|---|---|
| Generic "Welcome to nginx" / default page | Look for hidden paths — fuzz it |
| Login page separate from main app | Different auth surface — test default creds |
| Admin panel (any kind) | High priority — test all access controls |
| Error page with stack trace | Note tech stack, test injection points |
| Swagger UI / API docs exposed | Map the full API immediately |
| Kibana / Grafana / Jupyter | Internal tooling — check for unauth access |
| Staging/dev UI (different from prod) | Usually less hardened — test everything |

---

### 2.4 Technology Fingerprinting

**When to use:** Throughout — as you probe hosts. Knowing the stack maps directly to which attacks apply.

```bash title="tech_fingerprint.sh"
# WhatWeb — deeper fingerprinting on specific targets
whatweb -a 3 https://target.com

# nuclei tech detect templates across all hosts
nuclei -l httpx_out.txt -t technologies/ -o tech_detect.txt
```

**Manual fingerprinting signals:**

- HTTP response headers: `X-Powered-By`, `Server`, `X-Generator`, `X-Framework`
- Cookie names: `PHPSESSID` = PHP, `JSESSIONID` = Java, `_rails_session` = Rails
- URL patterns: `.php`, `.aspx`, `.jsp`; `/wp-content/`, `/wp-admin/`
- HTML source: `<meta name="generator">`, framework-specific HTML patterns

**Stack → what to test:**

| Technology | Priority Tests |
|---|---|
| WordPress | Plugin/theme CVEs, `xmlrpc.php`, user enumeration |
| Laravel | SSTI in blade templates, debug mode, `.env` exposure |
| Node.js / Express | Prototype pollution, SSRF in request libs |
| Spring (Java) | Actuator endpoints, deserialization, Thymeleaf SSTI |
| PHP (generic) | LFI, type juggling, deserialization |
| GraphQL | Introspection, DoS, IDOR, batching attacks |
| AWS S3 hosting | Bucket misconfiguration, public object access |
| Jenkins | Unauthenticated script console RCE |
| Elasticsearch | Unauthenticated data access via REST API |

---

## 3. JavaScript Analysis

JS files are the most underexploited recon surface in web bug bounty. Developers embed API endpoints, internal hostnames, access tokens, feature flags, and auth logic directly in client-side JS — and it sits there publicly, forever, indexed in the Wayback Machine.

A thorough JS pass regularly surfaces more attack surface than subdomain enumeration.

### 3.1 JS File Harvesting

**When to use:** After you have a list of live web apps. Collect from three sources: historical archives, live crawl, and authenticated crawl. The union gives the most complete picture.

```bash title="js_harvest.sh"
# gau — historical URLs from Wayback, Common Crawl, OTX, URLScan
gau target.com --threads 5 --o gau_urls.txt

# waybackurls — Wayback focused, fast
waybackurls target.com > wayback_urls.txt

# Katana — live crawler with JS rendering
katana -u https://target.com -jc -silent -o katana_urls.txt

# Katana authenticated (grab session cookie from browser DevTools)
katana -u https://target.com \
  -jc \
  -H "Cookie: session=<your_session_token>" \
  -silent -o katana_auth_urls.txt

# Extract only .js URLs
cat gau_urls.txt wayback_urls.txt katana_urls.txt | \
  grep -E "\.js(\?|$)" | sort -u > js_urls.txt

# Download all for offline analysis
cat js_urls.txt | xargs -I{} wget -q --directory-prefix=./js_files/ {}
```

!!! tip "Always crawl authenticated"
    Most apps load different JS bundles when logged in — admin routes, internal API paths, feature-specific code. The authenticated JS files reveal the most. Always crawl both.

!!! warning "Check for source maps"
    `*.js.map` files are regularly left deployed in production and contain the full original pre-minification source. Test: `https://target.com/static/app.js.map` — if it responds with 200, you have the original source.

---

### 3.2 Endpoint Extraction

**When to use:** After harvesting JS files.

```bash title="endpoint_extract.sh"
# LinkFinder — on a directory of downloaded files
for f in ./js_files/*.js; do
  python3 linkfinder.py -i "$f" -o cli 2>/dev/null
done | sort -u > extracted_endpoints.txt

# xnLinkFinder — faster, handles large files better
xnLinkFinder -i https://target.com -sf target.com -o endpoints.txt

# Manual grep for API path patterns
grep -rE '(\/api\/|\/v[0-9]+\/|\/internal\/|\/admin\/)' ./js_files/ | \
  grep -oE '"[^"]*\/[a-zA-Z][^"]*"' | sort -u

# GraphQL endpoint discovery
grep -rE "(graphql|__schema|mutation|subscription)" ./js_files/ | \
  grep -oE '"https?://[^"]*"' | sort -u
```

**Manual review — what to look for:**

- `fetch(`, `axios.get(`, `$.ajax(` — what URL is it calling
- `Authorization:`, `Bearer `, `api_key`, `apiKey` — hardcoded auth strings
- `localhost`, `127.0.0.1`, `10.`, `192.168.` — internal URLs hardcoded in prod code
- `TODO`, `FIXME`, `HACK`, `password`, `secret`, `debug` — developer comments
- `admin`, `internal`, `private`, `legacy` — path segments worth testing
- `graphql`, `__schema`, `mutation` — GraphQL surface

---

### 3.3 Secret Detection

**When to use:** After downloading JS files. A hardcoded AWS key in a public JS file is Critical on most programs. This is one of the fastest paths to a high-severity finding.

=== "trufflehog"

    ```bash title="trufflehog_scan.sh"
    # Verified only (makes live API calls to confirm validity)
    trufflehog filesystem ./js_files/ --only-verified --json > secrets_verified.json

    # All findings including unverified (more results, manual review needed)
    trufflehog filesystem ./js_files/ --json > secrets_all.json
    ```

=== "gitleaks"

    ```bash title="gitleaks_scan.sh"
    gitleaks detect \
      --source ./js_files/ \
      --report-format json \
      --report-path secrets_gitleaks.json
    ```

=== "manual grep"

    ```bash title="manual_secret_grep.sh"
    grep -rE "(AKIA[0-9A-Z]{16})" ./js_files/         # AWS Access Key ID
    grep -rE "(AIza[0-9A-Za-z_-]{35})" ./js_files/    # Google API Key
    grep -rE "(sk-[a-zA-Z0-9]{48})" ./js_files/       # OpenAI API Key
    grep -rE "-----BEGIN (RSA|EC|PGP)" ./js_files/    # Private keys
    grep -riE "(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}" ./js_files/
    grep -riE "(secret|token|key|api_key)\s*[:=]\s*['\"][^'\"]{8,}" ./js_files/
    ```

**When you find something — what to do:**

1. Confirm it's real, not a placeholder like `YOUR_API_KEY_HERE`
2. Verify format matches known pattern (don't call the API without permission)
3. AWS keys: test with `aws sts get-caller-identity` to confirm access
4. Assess scope — is the JS file in scope? Is the service in scope?
5. Report immediately. Hardcoded secrets are P1/Critical on most programs.
6. Include in report: the file URL, the line number, what the key grants access to

!!! danger "Never use `--only-verified` without explicit permission"
    The `--only-verified` flag makes live API calls to test found keys. Only enable this if you have explicit permission to test those services. Use `--json` without verification for initial triage.

---

### 3.4 LLM-Assisted Analysis

**When to use:** Large minified JS bundles that are painful to read manually. A local LLM finds logic branches, hidden auth checks, and developer notes faster than grep alone.

This is a signal amplifier, not a replacement for manual review. Verify everything it flags.

```bash title="llm_js_analysis.sh"
# Step 1: Beautify first
js-beautify ./js_files/app.chunk.js > ./js_files/app.chunk.pretty.js

# Step 2: Split large files (LLMs have context limits)
split -l 500 app.chunk.pretty.js chunk_

# Step 3: Feed to local Ollama — DO NOT send target data to cloud LLMs
ollama run mistral < chunk_aa
```

**Prompt template:**

```
You are a security researcher analyzing JavaScript for a bug bounty program.
Review the following code and identify:
1. All API endpoint paths (/api/*, /v1/*, /internal/*, etc.)
2. Hardcoded secrets, tokens, keys, or passwords
3. Internal hostnames or IP addresses
4. Auth/authorization logic that could be bypassed
5. Commented-out code that reveals hidden functionality
6. Debug flags or feature flags affecting security behavior

For each finding: quote the relevant code and explain why it matters.
Only report what is actually present. Do not hallucinate.

Code:
[paste chunk here]
```

!!! danger "Local LLM only"
    Never send target-specific JS to a cloud LLM (ChatGPT, Claude.ai, Gemini). Use local Ollama (Mistral-7B or DeepSeek-R1). Runs on 8GB RAM. This is not optional.

---

## 4. GitHub & Source Code Recon {#4-github--source-code-recon}

Companies commit secrets, internal endpoints, and auth logic to public repositories constantly — not just in incidents, but routinely. API keys in config files, database URLs in `.env` examples, internal domains in comments.

GitHub recon is often faster to a high-severity finding than any other technique.

### 4.1 GitHub Dorking

**When to use:** Before any active scanning. 20 minutes of manual GitHub search can surface Critical findings.

Run these searches at `github.com/search?type=code`:

```
# Credentials
"target.com" password
"target.com" secret
"target.com" api_key
"target.com" token
"target.com" "Authorization: Bearer"
"@target.com" password        ← email format, finds employee credentials

# Internal infrastructure  
"target.com" staging
"target.com" localhost
"target.com" "192.168."
"target.com" "10.0."
"target.com" db_password
"target.com" database_url

# Config files
"target.com" filename:.env
"target.com" filename:config.yml
"target.com" filename:settings.py
"target.com" filename:database.yml
"target.com" filename:*.pem

# Cloud credentials
"target.com" AKIA              ← AWS key prefix
"target.com" aws_access_key

# CI/CD (often contains injected secrets)
"target.com" filename:.travis.yml
"target.com" filename:.github
"target.com" filename:docker-compose.yml

# Org-level search
org:targetcompany filename:.env
org:targetcompany secret
org:targetcompany password
```

Sort results by "Recently indexed" to catch fresh leaks.

```bash title="automated_dorking.sh"
# trufflehog — scan GitHub org directly (no local clone needed)
trufflehog github --org=targetcompany \
  --token=<github_pat> \
  --only-verified

# Scan specific repository
trufflehog github --repo=https://github.com/company/repo \
  --token=<github_pat>
```

!!! warning "Rate limiting"
    GitHub heavily rate-limits unauthenticated search. Create a free account and generate a Personal Access Token for all tooling. Repositories also get deleted after exposure — use Google cache or Wayback Machine if a link is 404.

---

### 4.2 Historical Commit Scanning

**When to use:** When you have access to a public repository. A secret committed and then deleted still exists in git history. Developers frequently commit secrets, realize the mistake, delete them — but forget history is permanent.

```bash title="commit_scan.sh"
# Clone with full history (shallow clone misses old commits)
git clone --no-single-branch https://github.com/company/repo
cd repo

# trufflehog on local clone — scans all commits
trufflehog git file://. --json > repo_secrets.json

# gitleaks — full history
gitleaks detect --source . \
  --log-opts="--all --full-history" \
  --report-format json \
  --report-path repo_secrets.json

# Manual search for specific strings across all commits
git log -p --all -S "password" --source
git log -p --all -S "api_key" --source

# Find commits that deleted something — most likely to contain removed secrets
git log --all --oneline | grep -iE "(remove|delete|fix|revert|oops|accident|secret|key|token)"
```

The commit message search is often more valuable than the content scan. A message like "remove hardcoded api key" tells you exactly which commit to look at.

---

### 4.3 Org-Wide Repository Enumeration

**When to use:** Always. The target may have dozens of repos beyond the main product — internal tooling, mobile apps, infra configs, SDKs.

```bash title="org_enum.sh"
# List all public repos
for page in 1 2 3 4 5; do
  curl -s "https://api.github.com/orgs/targetcompany/repos?per_page=100&page=$page" \
    -H "Authorization: token <github_pat>" | \
    jq -r '.[].clone_url'
done | sort -u > org_repos.txt

# Flag high-value repo names
cat org_repos.txt | grep -iE "(internal|infra|config|deploy|admin|secret|key|auth|backend|api)"

# Bulk scan all repos
cat org_repos.txt | while read repo; do
  trufflehog git "$repo" --token=<github_pat> --only-verified --json 2>/dev/null
done > org_secrets.json
```

**Beyond secrets — what else to look for in repos:**

- `.github/workflows/` — CI/CD configs with injected env vars, deployment targets
- `docker-compose.yml` / Kubernetes configs — internal service hostnames, ports
- `README.md` in internal-looking repos — architecture details, internal URLs
- `CHANGELOG.md` — history of features with security implications
- Issues and PRs — bug reports, security discussions that reveal logic

---

## 5. Directory & Parameter Fuzzing {#5-directory--parameter-fuzzing}

Endpoints that aren't linked anywhere still exist and respond. Fuzzing finds them. The quality of your wordlist determines the quality of your results.

### 5.1 Directory Fuzzing

**When to use:** After httpx triage, on every interesting host. Start with common paths, then go tech-specific based on your fingerprint.

```bash title="ffuf_dirs.sh"
# General first pass
ffuf -u https://target.com/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/raft-large-directories.txt \
  -mc 200,201,301,302,401,403,405 \
  -o ffuf_dirs.json -of json

# Calibrate noise — note the size of a definitely-nonexistent path
# then filter it:
ffuf -u https://target.com/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/raft-large-directories.txt \
  -mc 200,301,401,403 \
  -fs 1234  # replace with your calibrated baseline size

# Recursive (goes into found directories)
ffuf -u https://target.com/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200,301,302,401,403 \
  -recursion -recursion-depth 2

# Authenticated fuzzing
ffuf -u https://target.com/api/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/api-endpoints.txt \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -mc 200,201,400,401,403,405

# File discovery with extensions
ffuf -u https://target.com/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/raft-large-files.txt \
  -e .php,.html,.js,.json,.bak,.old,.txt,.xml,.conf,.log \
  -mc 200,201,403 -fs 0
```

**Wordlist by scenario:**

| Scenario | Wordlist |
|---|---|
| General web (first pass) | `raft-large-directories.txt` |
| API endpoints | `httparchive_apiroutes_*.txt` (Assetnote) |
| PHP apps | `PHP.fuzz.txt` (SecLists) |
| Spring Boot | `spring-boot.txt` (Assetnote) |
| WordPress | `wordpress.fuzz.txt` |
| Backup files | `backup-filenames.txt` (SecLists) |

**403 bypass — always run these when you get a 403:**

```bash title="403_bypass.sh"
BASE="https://target.com/admin"

# Path variations
curl -sk -o /dev/null -w "%{http_code} %{url_effective}\n" "$BASE/"
curl -sk -o /dev/null -w "%{http_code} %{url_effective}\n" "$BASE%20"
curl -sk -o /dev/null -w "%{http_code} %{url_effective}\n" "$BASE%2f"
curl -sk -o /dev/null -w "%{http_code} %{url_effective}\n" "$BASE/."

# Header-based bypass
curl -sk -o /dev/null -w "%{http_code}\n" -H "X-Original-URL: /admin" "https://target.com/"
curl -sk -o /dev/null -w "%{http_code}\n" -H "X-Forwarded-For: 127.0.0.1" "$BASE"
curl -sk -o /dev/null -w "%{http_code}\n" -H "X-Rewrite-URL: /admin" "https://target.com/"
curl -sk -o /dev/null -w "%{http_code}\n" -H "X-Custom-IP-Authorization: 127.0.0.1" "$BASE"
```

---

### 5.2 Parameter Discovery

**When to use:** On any endpoint that accepts parameters. Undocumented parameters are where bugs hide — the difference between testing 5 and testing 50 parameters.

=== "Arjun"

    ```bash title="arjun_params.sh"
    # GET parameters
    arjun -u https://target.com/api/search -m GET --stable -o arjun_get.json

    # POST parameters
    arjun -u https://target.com/api/update -m POST --stable

    # With auth
    arjun -u https://target.com/api/user \
      -H "Authorization: Bearer <token>" -m GET
    ```

=== "x8"

    ```bash title="x8_params.sh"
    x8 -u "https://target.com/api/endpoint" \
      -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt \
      -X GET --output-file x8_results.txt
    ```

=== "OpenAPI/Swagger"

    ```bash title="swagger_params.sh"
    # Extract parameter names from exposed API spec
    curl -s https://target.com/swagger.json | \
      jq -r '.. | .parameters? // empty | .[].name' 2>/dev/null | sort -u

    # Extract from JS files
    grep -rhoE '"[a-zA-Z_][a-zA-Z0-9_]{2,20}":\s*(null|true|false|[0-9]+|"[^"]*")' \
      ./js_files/ | grep -oE '"[^"]*":' | tr -d '":' | sort -u
    ```

**High-value undocumented parameters to test manually:**

```
debug=true, debug=1
test=true, testing=1
admin=true, internal=true
verbose=true, trace=true
format=json, format=xml
callback=x          (JSONP probe)
_method=DELETE      (method override)
role=admin
user_id=<other_id>  (IDOR probe)
```

---

### 5.3 Sensitive File Discovery

**When to use:** On every interesting host. Always check these — the hit rate is higher than most people expect.

```bash title="sensitive_files.sh"
ffuf -u https://target.com/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/sensitive-files-linux.txt \
  -mc 200,403 -o sensitive_files.json
```

**Manual checklist — always test:**

```
/.env                  /.env.local            /.env.production
/config.php            /config.yml            /config.json
/settings.py           /database.yml          /wp-config.php
/appsettings.json      /web.config
/.git/HEAD             ← exposed git repo (see below)
/phpinfo.php           /info.php
/server-status         /server-info
/robots.txt            ← Disallow: entries are testing targets
/sitemap.xml           ← can reveal all endpoints
```

**Exposed `.git` directory:**

```bash title="git_dump.sh"
# Check if exposed
curl -s https://target.com/.git/HEAD
# Returns "ref: refs/heads/main" → git directory is exposed

# Pull the entire repo
git-dumper https://target.com/.git ./dumped_repo
cd dumped_repo && git log --oneline  # full source + history
```

!!! danger "Exposed .git is Critical"
    Full source code exposure. Report immediately. An exposed `.git` directory typically leads to credentials, internal infrastructure details, and additional attack surface within hours.

---

## 6. Subdomain Takeover

A subdomain takeover occurs when a subdomain's DNS record points to an external service no longer claimed by the target. An attacker registers the unclaimed service and takes control — serving content under the target's trusted domain, stealing cookies, bypassing CSP, or conducting phishing with a legitimate SSL cert.

Severity: High to Critical. The trust a subdomain inherits from the parent domain is what makes this dangerous.

### 6.1 Finding Dangling CNAMEs

**When to use:** Continuously, as part of the subdomain enumeration phase. The CNAME extraction from section 1.4 feeds directly into this.

```bash title="takeover_scan.sh"
# Step 1: Extract CNAME chains (already done in 1.4 — reuse output)
# dns_cnames.txt contains: subdomain.target.com → external-service.example.com

# Step 2: NXDOMAIN subdomains — immediate candidates
# nxdomain_subdomains.txt from step 1.4

# Step 3: subjack — automated fingerprinting across the subdomain list
subjack -w master_subdomains.txt \
  -t 100 -timeout 30 -ssl \
  -c /opt/subjack/fingerprints.json \
  -o subjack_results.txt

# Step 4: nuclei takeover templates
nuclei -l master_subdomains.txt -t takeovers/ -o nuclei_takeovers.txt
```

---

### 6.2 Service Fingerprinting

**When to use:** After identifying a dangling CNAME. Not every unclaimed CNAME is takeable — confirm the service and verify it's vulnerable before proceeding.

| Service | Response Body Contains | Takeover Method |
|---|---|---|
| GitHub Pages | `There isn't a GitHub Pages site here` | Create repo, enable Pages |
| Heroku | `No such app` | `heroku create <appname>` |
| Netlify | `Not Found - Request ID` | Create site with matching name |
| Vercel | `The deployment could not be found` | Deploy to matching domain |
| AWS S3 | `NoSuchBucket` | Create bucket with same name |
| Fastly | `Fastly error: unknown domain` | Add domain in dashboard |
| Shopify | `Sorry, this shop is currently unavailable` | Create Shopify store |
| Zendesk | `Help Center Closed` | Create Zendesk account |
| Tumblr | `There's nothing here` | Register Tumblr blog |
| Surge.sh | `project not found` | `surge` CLI claim |

```bash title="fingerprint_check.sh"
# Check response body for takeover fingerprints
curl -sk https://legacy-app.target.com | \
  grep -iE "(there isn't|no such app|not found|noSuchBucket|unknown domain|help center closed)"
```

Always check [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) before attempting — canonical list of vulnerable services and difficulty ratings.

---

### 6.3 Claiming and PoC

**When to use:** After confirming a vulnerable dangling CNAME. Most programs expect proof that the takeover actually works, not just that the CNAME is dangling.

=== "GitHub Pages"

    ```bash title="github_pages_takeover.sh"
    # CNAME: legacy.target.com → targetcompany.github.io (404)

    # Create GitHub repo named: targetcompany.github.io
    # Enable GitHub Pages in settings
    # Push benign PoC:
    cat > index.html << 'EOF'
    <h1>Subdomain Takeover PoC</h1>
    <p>legacy.target.com is vulnerable to subdomain takeover.
    No malicious action taken. Bug bounty submission.</p>
    EOF
    git add . && git commit -m "poc" && git push
    ```

=== "AWS S3"

    ```bash title="s3_takeover.sh"
    # CNAME: assets.target.com → assets.target.com.s3.amazonaws.com (NoSuchBucket)

    aws s3 mb s3://assets.target.com --region us-east-1
    echo "<h1>S3 Subdomain Takeover PoC</h1>" > index.html
    aws s3 cp index.html s3://assets.target.com/ --acl public-read
    aws s3 website s3://assets.target.com/ --index-document index.html
    ```

**What to include in the report:**

- The subdomain and full CNAME chain
- The third-party service and why it's unclaimed
- Screenshot of the PoC page loading under the target's subdomain
- Real-world impact: cookie theft (if same-site with main app), phishing under trusted domain, CSP bypass, OAuth redirect URI abuse

!!! warning "Release the claim after reporting"
    Don't hold it. Some programs also consider live PoC as out-of-scope active exploitation — check scope rules before claiming. If uncertain, report the dangling CNAME without a live PoC and note that you can provide one if needed.

---

## 7. Google & Advanced Dorking {#7-google--advanced-dorking}

Search engines have indexed things the target never intended to expose. Dorking is free, passive, fully legal, and takes 20 minutes. Do this before any active scanning — it regularly surfaces admin panels, exposed documents, and sensitive files that no scanner will find.

### 7.1 Google Dorks

Run these at `google.com/search`:

```
# Exposed files
site:target.com filetype:pdf
site:target.com filetype:xlsx OR filetype:csv
site:target.com filetype:sql
site:target.com filetype:env OR filetype:log OR filetype:bak
site:target.com filetype:conf OR filetype:config OR filetype:pem

# Admin and login surfaces
site:target.com inurl:admin
site:target.com inurl:dashboard
site:target.com inurl:panel
site:target.com intitle:"admin panel"
site:target.com intitle:"login" inurl:admin

# Exposed internal tooling
site:target.com inurl:jenkins
site:target.com inurl:grafana
site:target.com inurl:kibana
site:target.com inurl:jira
site:target.com inurl:gitlab
site:target.com inurl:phpmyadmin
site:target.com intitle:"index of /"

# API and dev exposure
site:target.com inurl:swagger
site:target.com inurl:graphql
site:target.com inurl:api-docs
site:target.com inurl:debug

# Error and stack traces in production
site:target.com "Internal Server Error"
site:target.com "Stack trace"
site:target.com "SQL syntax"

# Subdomains Google has indexed (often misses passive tools)
site:*.target.com -site:www.target.com
```

Same syntax works on Bing — run the same dorks there. Google and Bing index different things.

---

### 7.2 Shodan, Censys, FOFA

These index the entire Internet continuously. Query them instead of scanning the target directly.

=== "Shodan"

    ```
    # All hosts with target.com SSL cert
    ssl.cert.subject.cn:"target.com"
    ssl.cert.subject.o:"Target Company Inc"

    # Specific exposed services
    hostname:"target.com" port:6379
    hostname:"target.com" port:9200
    hostname:"target.com" port:2375

    # Favicon hash (from httpx output)
    http.favicon.hash:<hash_value>
    ```

    ```bash title="shodan_cli.sh"
    shodan search 'ssl.cert.subject.cn:"target.com"' --fields ip_str,port,org
    shodan search 'hostname:"target.com"' --fields ip_str,port,product > shodan_out.txt
    ```

=== "Censys"

    ```
    # Certificate search
    parsed.names: target.com
    services.tls.certificates.leaf_data.subject.common_name: target.com

    # HTML title match
    services.http.response.html_title: "Target App"

    # By ASN
    autonomous_system.asn: 12345
    ```

=== "FOFA"

    ```
    domain="target.com"
    cert="target.com"
    header="target.com"
    title="Target App"
    ```

!!! warning "CDN IPs"
    IPs found via Shodan often belong to CDN nodes (Cloudflare, Fastly, Akamai), not origin servers. An IP that resolves to target.com but returns generic CDN content is not the origin. Look for it via historical DNS records, cert mismatches, or `X-Forwarded-For` misconfiguration.

---

### 7.3 Wayback Machine for Deleted Endpoints

**When to use:** On every target. Deleted pages, old API versions, deprecated endpoints — often still alive on the backend even after being removed from navigation.

```bash title="wayback_mining.sh"
# Pull all archived URLs (CDX API — no browser needed)
curl -s "http://web.archive.org/cdx/search/cdx?\
url=*.target.com/*\
&output=text\
&fl=original\
&collapse=urlkey\
&limit=100000" > wayback_all_urls.txt

# Filter interesting patterns
cat wayback_all_urls.txt | grep -iE \
  "(admin|internal|api|login|debug|test|backup|config|staging|legacy|upload)"

# Filter by file extension
cat wayback_all_urls.txt | grep -E "\.(php|asp|aspx|jsp|json|xml|env|bak|sql)$"

# Test if old paths still respond on the live site
cat wayback_all_urls.txt | \
  grep "target.com" | \
  sed 's|https\?://[^/]*/||' | sort -u | \
  while read path; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com/$path")
    [ "$code" != "404" ] && echo "$code https://target.com/$path"
  done
```

**What to look for:**

- Old API versions: `/api/v1/`, `/api/v0/` — may have fewer security controls
- Deprecated endpoints: `/old/`, `/legacy/`, `/backup/`
- Admin paths removed from navigation but not from routing
- Parameter patterns that reveal how the app used to work
- File upload endpoints that may still function

---

## 8. Recon Automation & Pipelines {#8-recon-automation--pipelines}

Manual recon once is not enough. New subdomains get added. New features ship. New S3 buckets get created. The hunter who catches these changes first — before anyone else runs recon — has the lowest duplicate rate and the highest hit rate.

### 8.1 The Delta Principle

The core idea: don't process the same data twice. On every run, compare new results against what you already have. Only investigate the difference. This is what `anew` enables.

```bash title="delta_example.sh"
# First run — everything is new
subfinder -d target.com -silent > master_subdomains.txt

# Every subsequent run — only new lines pass through
subfinder -d target.com -silent | anew master_subdomains.txt
# anew prints ONLY lines not already in the file
# and appends them — pipe to notification or further processing

# Full delta pipeline — pipe new subdomains directly into processing
subfinder -d target.com -silent | \
  anew master_subdomains.txt | \
  httpx -silent -status-code -title | \
  notify  # Telegram/Slack alert
```

Your morning routine becomes reviewing 0–5 new assets instead of re-processing thousands of known ones.

---

### 8.2 Nightly Pipeline

```bash title="recon_pipeline.sh"
#!/bin/bash
# Runs nightly. Alerts on new findings only.

TARGET="target.com"
BASE_DIR="/opt/recon/$TARGET"
mkdir -p "$BASE_DIR"

echo "[*] Starting: $TARGET — $(date)"

# Step 1: Subdomain enumeration — delta only
subfinder -d "$TARGET" -all -silent 2>/dev/null | \
  anew "$BASE_DIR/subdomains.txt" > /tmp/new_subs.txt

[ ! -s /tmp/new_subs.txt ] && echo "[*] No new subdomains" && exit 0
echo "[+] New subdomains: $(wc -l < /tmp/new_subs.txt)"

# Step 2: DNS resolution of new subdomains
dnsx -l /tmp/new_subs.txt -silent -a -o /tmp/new_resolved.txt 2>/dev/null

# Step 3: HTTP probe
httpx -l /tmp/new_resolved.txt \
  -silent -status-code -title -tech-detect \
  -o /tmp/new_httpx.txt 2>/dev/null

# Step 4: Nuclei on new hosts only
nuclei -l /tmp/new_resolved.txt \
  -t cves/ -t exposures/ -t takeovers/ \
  -severity medium,high,critical \
  -silent -o /tmp/new_nuclei.txt 2>/dev/null

# Step 5: Telegram alert
if [ -s /tmp/new_nuclei.txt ] || [ -s /tmp/new_httpx.txt ]; then
  MESSAGE="*Recon Alert: $TARGET*%0A"
  MESSAGE+="New subdomains: $(wc -l < /tmp/new_subs.txt)%0A"
  MESSAGE+="New HTTP hosts: $(wc -l < /tmp/new_httpx.txt)%0A"
  [ -s /tmp/new_nuclei.txt ] && \
    MESSAGE+="Nuclei findings: $(wc -l < /tmp/new_nuclei.txt)%0A"

  curl -s -X POST \
    "https://api.telegram.org/bot<BOT_TOKEN>/sendMessage" \
    -d "chat_id=<CHAT_ID>&text=$MESSAGE&parse_mode=Markdown" > /dev/null
fi

echo "[*] Done: $(date)"
```

**Cron schedule (stagger per target to avoid overlap):**

```bash title="crontab_entries"
0 2 * * * /opt/scripts/recon_pipeline.sh target1.com
0 3 * * * /opt/scripts/recon_pipeline.sh target2.com
0 4 * * * /opt/scripts/recon_pipeline.sh target3.com
```

---

### 8.3 GitHub Change Monitoring

**When to use:** For any target with active public repositories.

```bash title="github_monitor.sh"
#!/bin/bash
REPO="company/repo"
STORED_FILE="/opt/recon/commits/${REPO//\//_}.txt"
PAT="<github_pat>"

CURRENT=$(curl -s "https://api.github.com/repos/$REPO/commits?per_page=1" \
  -H "Authorization: token $PAT" | jq -r '.[0].sha')

STORED=$(cat "$STORED_FILE" 2>/dev/null)

if [ "$STORED" != "$CURRENT" ]; then
  echo "[+] New commit: $CURRENT"

  # What files changed
  curl -s "https://api.github.com/repos/$REPO/commits/$CURRENT" \
    -H "Authorization: token $PAT" | \
    jq -r '.files[].filename' > /tmp/changed_files.txt

  # Scan for secrets in new commit
  trufflehog github \
    --repo="https://github.com/$REPO" \
    --since-commit="$STORED" \
    --token="$PAT" --only-verified

  echo "$CURRENT" > "$STORED_FILE"
fi
```

---

### 8.4 Morning Triage Routine

What to do when you wake up to alerts:

<div class="grid cards" markdown>

-   :octicons-globe-16: __New subdomain alert__

    ---

    Visit in browser. Check gowitness screenshot. Note tech fingerprint from httpx.
    If it looks like dev/staging/admin: run targeted ffuf immediately.

-   :material-shield-alert: __Nuclei finding alert__

    ---

    Manually verify before anything else — nuclei has false positives.
    If confirmed: assess severity, write report.
    If false positive: add to exclusion list.

-   :octicons-mark-github-16: __GitHub commit alert__

    ---

    Review changed file list. Look for new routes/controllers with API endpoints.
    Review trufflehog output manually. Test new endpoints for standard vuln classes.

-   :material-check-circle: __No alerts__

    ---

    Not a failure. The system is working — nothing new appeared.
    Spend the session doing deep manual testing on existing surface.

</div>

---

## Quick Reference

### Tool Inventory

| Phase | Tool | Purpose |
|---|---|---|
| Passive enum | subfinder, assetfinder | Multi-source subdomain discovery |
| Active brute | puredns, shuffledns | DNS brute-force with wildcard filtering |
| Permutations | alterx, gotator | Variant generation from known subdomains |
| DNS resolution | dnsx, massdns | Bulk validation and CNAME extraction |
| HTTP probe | httpx | Status, title, tech, favicon |
| Port scan | naabu, nmap | Open ports on live hosts |
| Screenshots | gowitness, aquatone | Visual triage |
| JS harvest | gau, waybackurls, katana | URL collection from archives + live crawl |
| Endpoint extract | linkfinder, xnLinkFinder | Path extraction from JS |
| Secrets | trufflehog, gitleaks | Key and credential detection |
| Directory fuzz | ffuf | Path and file brute-force |
| Parameter fuzz | arjun, x8 | Undocumented parameter discovery |
| Takeover | subjack, nuclei | Dangling CNAME fingerprinting |
| Delta | anew | Continuous recon deduplication |
| Alerts | notify | Telegram/Slack dispatcher |

### Wordlist Sources

| Source | Best For |
|---|---|
| [SecLists](https://github.com/danielmiessler/SecLists) | General web, DNS, files |
| [Assetnote Wordlists](https://wordlists.assetnote.io) | Tech-specific API routes (highest quality) |
| [jhaddix/all.txt](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056) | DNS brute-force (~2M entries) |
| [trickest/resolvers](https://github.com/trickest/resolvers) | Updated public resolver lists |