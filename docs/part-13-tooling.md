---
icon: lucide/wrench
tags:
  - bug-bounty
  - tools
  - recon
  - exploitation
  - mobile
description: A field reference for every tool in the workflow — what it does, the flags you'll actually use, and where it fits. Not a tutorial.
---
# Tooling Reference

This is a reference, not a tutorial. Each entry answers three questions: what the tool does, the flags you'll actually use, and where it fits in the workflow. External docs handle the rest. Cross-referenced throughout the manual wherever the tool appears in context.

---

<div class="grid cards" markdown>

-   :material-radar:{ .lg .middle } __Recon Tools__

    ---

    Subdomain enumeration, DNS resolution, HTTP probing, crawling, and URL discovery.

    [:octicons-arrow-right-24: Recon tools](#recon-tools)

-   :material-shield-bug:{ .lg .middle } __Exploitation Tools__

    ---

    Burp Suite and its extensions, fuzzers, scanners, and specialised attack tools.

    [:octicons-arrow-right-24: Exploitation tools](#exploitation-tools)

-   :material-cellphone:{ .lg .middle } __Mobile Tools__

    ---

    Static analysis, APK decompilation, dynamic instrumentation, and SSL pinning bypass.

    [:octicons-arrow-right-24: Mobile tools](#mobile-tools)

-   :material-format-list-bulleted:{ .lg .middle } __Wordlists and Payload Banks__

    ---

    SecLists, PayloadsAllTheThings, Assetnote, and the quick installation script.

    [:octicons-arrow-right-24: Wordlists](#wordlists-and-payload-banks)

</div>

## Decision Flow

```
Starting subdomain enumeration?
→ Run Subfinder first. Run Assetfinder in parallel. Merge outputs with anew.
  Use puredns for brute-force after passive enum completes.

Need to identify live HTTP services?
→ Pipe resolved subdomains into httpx. Follow with Naabu for port scanning.
  Use gowitness for visual triage on large host lists.

Finding hidden endpoints or parameters?
→ ffuf for directory/path fuzzing. Arjun for hidden parameter discovery.
  Kiterunner for API route discovery with framework-specific wordlists.

Testing for SQLi?
→ Manual confirmation in Burp first. Then sqlmap -r request.txt with level=1 risk=1 delay=2.
  Never submit sqlmap output directly — verify all findings manually.

Testing for XSS?
→ Dalfox for automated scanning. DOM Invader (Burp extension) for DOM XSS.
  interactsh for blind XSS callbacks.

Testing JWTs?
→ jwt_tool for algorithm confusion, alg:none, secret cracking, and claim tampering.
  JWT Editor extension in Burp for in-proxy testing.

Testing mobile apps?
→ MobSF for initial static analysis. JADX for readable source review.
  apk-mitm for standard SSL pinning bypass. Objection or Frida for runtime analysis.

Looking for secrets in source or repos?
→ trufflehog on filesystem, git history, or GitHub org. Use --only-verified to reduce noise.

Need OOB callbacks for SSRF, XXE, or blind injection?
→ interactsh-client. Gives you a callback domain. Shows DNS, HTTP, SMTP interactions.
```

---

## Recon Tools

### Subfinder

Passive subdomain enumeration from multiple API sources. Always run first in the subdomain pipeline.

```bash title="subfinder_usage"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

subfinder -d target.com -silent -o subs.txt
subfinder -dL domains.txt -all -o subs.txt   # all sources, domain list
subfinder -d target.com -recursive -silent    # recurse on found subdomains
```

Configure API keys at `~/.config/subfinder/provider-config.yaml`. Sources worth configuring: `shodan`, `securitytrails`, `censys`, `virustotal`, `github`, `hunter`.

---

### Amass

Active and passive subdomain enumeration with ASN/CIDR mapping. Slower than Subfinder — use for thoroughness on high-value targets.

```bash title="amass_usage"
go install -v github.com/owasp-amass/amass/v4/...@master

amass enum -passive -d target.com
amass enum -active -brute -w wordlist.txt -d target.com -o output.txt
```

Runs in parallel with Subfinder. Merge outputs with `anew`.

---

### Assetfinder

Fast passive subdomain enum with minimal setup. Fewer sources than Subfinder but faster. Good for quick passes.

```bash title="assetfinder_usage"
go install github.com/tomnomnom/assetfinder@latest

assetfinder --subs-only target.com | anew master_subs.txt
```

---

### puredns

Mass DNS resolution with wildcard detection and filtering. Use instead of massdns for brute-force.

```bash title="puredns_usage"
go install github.com/d3mondev/puredns/v2@latest

puredns bruteforce wordlist.txt target.com -r /opt/resolvers.txt -o resolved.txt
puredns resolve subdomains.txt -r /opt/resolvers.txt -o resolved.txt
```

Resolver list: `https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt`

---

### dnsx

DNS resolution, CNAME extraction, and record queries. Feeds resolved hosts into httpx.

```bash title="dnsx_usage"
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

cat subdomains.txt | dnsx -silent -a -resp -o resolved.txt
cat subdomains.txt | dnsx -silent -cname -o cnames.txt   # CNAME for takeover hunting
cat subdomains.txt | dnsx -silent -rc NXDOMAIN           # filter by response code
```

---

### httpx

HTTP probing — status codes, titles, tech detection, favicon hashes. Core surface mapping tool.

```bash title="httpx_usage"
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

cat resolved.txt | httpx -silent -status-code -title -tech-detect -web-server -o live.txt
cat resolved.txt | httpx -silent -favicon -content-length -follow-redirects -json -o live.json
cat resolved.txt | httpx -silent -mc 200,403                 # match specific status codes
```

---

### Naabu

Fast port scanning. Run after httpx on all live hosts.

```bash title="naabu_usage"
go install -v github.com/projectdiscovery/naabu/cmd/naabu@latest

naabu -l live.txt -top-ports 1000 -silent -o ports.txt
naabu -l live.txt -p 80,443,8080,8443,9200 -rate 1000 -silent
```

---

### Katana

Fast web crawler with JavaScript rendering and authenticated session support.

```bash title="katana_usage"
go install github.com/projectdiscovery/katana/cmd/katana@latest

katana -u https://target.com -jc -silent -o crawl.txt          # JS crawl
katana -u https://target.com -H "Cookie: session=X" -d 5       # authenticated crawl
```

---

### gau / waybackurls

Historical URL discovery from archives and crawl data. Run before active crawling.

```bash title="historical_urls"
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest

gau target.com --threads 5 -o gau_urls.txt
waybackurls target.com > wayback_urls.txt

cat gau_urls.txt wayback_urls.txt | anew all_urls.txt
```

---

### AlterX

Subdomain permutation generation from known subdomains. Runs after passive/active enum.

```bash title="alterx_usage"
go install github.com/projectdiscovery/alterx/cmd/alterx@latest

cat subdomains.txt | alterx | dnsx -silent -o permutations_resolved.txt
cat subdomains.txt | alterx -enrich | dnsx -silent
```

---

### anew

Append only new lines to a file — delta tracking for continuous recon pipelines. Prevents re-processing known data.

```bash title="anew_usage"
go install github.com/tomnomnom/anew@latest

cat new_results.txt | anew master.txt
# Outputs ONLY new lines (not already in master.txt) to stdout
# Appends those new lines to master.txt
```

---

### gowitness

Automated screenshots of web pages for visual triage of large host lists.

```bash title="gowitness_usage"
go install github.com/sensepost/gowitness@latest

gowitness file -f urls.txt --threads 10 -P ./screenshots/
gowitness report generate   # generates browsable HTML report
```

---

## Exploitation Tools

### Burp Suite Community

Core proxy, interceptor, intruder, and repeater. The hub every other tool feeds into.

**Essential extensions (all free, BApp Store):**

| Extension | Purpose |
|---|---|
| Autorize | Automated IDOR/access control testing |
| ParamMiner | Hidden parameter discovery |
| JWT Editor | JWT attack suite |
| SAML Raider | SAML/SSO attack suite |
| InQL | GraphQL schema discovery and testing |
| HTTP Request Smuggler | Request smuggling detection |
| DOM Invader | DOM XSS source/sink identification |
| Turbo Intruder | High-speed fuzzing and race conditions |
| Logger++ | Enhanced request logging |
| Hackvertor | Encoding/decoding transforms |
| Active Scan++ | Enhanced active scanning rules |

**Key shortcuts:**

| Shortcut | Action |
|---|---|
| `Ctrl+R` | Send to Repeater |
| `Ctrl+I` | Send to Intruder |
| `Ctrl+F` | Search in current view |

Download: `https://portswigger.net/burp/communitydownload`

---

### ffuf

Fast web fuzzer for directory, parameter, and virtual host discovery.

```bash title="ffuf_usage"
go install github.com/ffuf/ffuf/v2@latest

# Directory fuzzing
ffuf -u https://target.com/FUZZ -w /opt/SecLists/Discovery/Web-Content/raft-large-directories.txt \
  -mc 200,301,302,403 -fs <noise_size> -t 40 -o output.json -of json

# Parameter fuzzing (POST)
ffuf -u https://target.com/api/endpoint -X POST -d "FUZZ=test" \
  -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt -mc 200

# Virtual host discovery
ffuf -u https://target.com -H "Host: FUZZ.target.com" \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -fs <noise_size>
```

!!! tip "Always calibrate before running"
    Run once without filters to identify the noise response size. Add `-fs <noise_size>` to every subsequent run. Skipping this step makes output useless.

---

### Nuclei

Template-based vulnerability scanner. Run across all live hosts for broad coverage.

```bash title="nuclei_usage"
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates   # run regularly

nuclei -l live.txt -t cves/ -t exposures/ -t takeovers/ -severity medium,high,critical -o findings.txt
nuclei -l live.txt -t misconfiguration/ -t technologies/ -silent -json -o findings.json
```

!!! danger "Always verify before reporting"
    Nuclei's false positive rate is real. Never submit Nuclei output directly to a program. Every finding requires manual confirmation in Burp before reporting.

---

### sqlmap

Automated SQL injection detection and exploitation.

```bash title="sqlmap_usage"
pip install sqlmap --break-system-packages

# From saved Burp request (preferred)
sqlmap -r request.txt --level=1 --risk=1 --batch --delay=2 --threads=1

# URL target
sqlmap -u "https://target.com/search?q=test" --cookie "session=X" \
  --level=1 --risk=1 --batch --delay=2

# After detection: enumerate
sqlmap -r request.txt --dbs                           # list databases
sqlmap -r request.txt -D dbname --tables              # list tables
sqlmap -r request.txt -D dbname -T tablename --dump   # dump (2–3 rows max on live targets)
```

!!! warning "Live target rules"
    Always use `--level=1 --risk=1 --delay=2 --threads=1` on live targets. Never use `--os-shell`. Dump 2–3 rows maximum to demonstrate impact — do not perform a full data dump.

---

### Dalfox

XSS scanner — fast, accurate, context-aware.

```bash title="dalfox_usage"
go install github.com/hahwul/dalfox/v2@latest

dalfox url "https://target.com/search?q=FUZZ" --cookie "session=X"
dalfox file urls.txt --cookie "session=X" --output results.txt
cat urls.txt | dalfox pipe --blind https://your.interactsh.com
```

---

### jwt_tool

JWT analysis and attack suite — algorithm confusion, alg:none, secret cracking, claim tampering.

```bash title="jwt_tool_usage"
git clone https://github.com/ticarpi/jwt_tool
pip3 install -r jwt_tool/requirements.txt

python3 jwt_tool.py <token>                             # analyze token
python3 jwt_tool.py <token> -X a -pk public.pem         # algorithm confusion
python3 jwt_tool.py <token> -X n                        # alg:none attack
python3 jwt_tool.py <token> -C -d /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
python3 jwt_tool.py <token> -I -pc role -pv admin       # tamper claim
python3 jwt_tool.py <token> -M at \
  -t "https://target.com/api" -rh "Authorization: Bearer JWT_HERE"
```

---

### interactsh

OOB interaction server for DNS/HTTP/SMTP callbacks. Use as the callback in SSRF, XXE, blind SQLi, blind XSS, and command injection.

```bash title="interactsh_usage"
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

interactsh-client
# → Generates: abc123.interactsh.com
# → Use this domain as the callback URL in payloads
# → Client shows all incoming DNS, HTTP, SMTP interactions in real-time
```

---

### Kiterunner

API endpoint discovery using framework-specific wordlists in `.kite` format.

```bash title="kiterunner_usage"
# Download binary: https://github.com/assetnote/kiterunner/releases

kr scan https://target.com/api/ -w routes-large.kite -H "Authorization: Bearer X" -o results.txt
kr scan https://target.com/api/ -w /opt/wordlists/api-endpoints.txt --max-connection-errors 3
```

Wordlists: `https://wordlists.assetnote.io` — download `httparchive_apiroutes_*.kite`.

---

### Arjun

Hidden parameter discovery via brute-force.

```bash title="arjun_usage"
pip install arjun --break-system-packages

arjun -u https://target.com/api/endpoint -m GET --stable
arjun -u https://target.com/api/endpoint -m POST -H "Authorization: Bearer X" -o results.json
arjun -u https://target.com/api/endpoint -m JSON
```

---

### trufflehog

Secret detection in code, files, git history, and cloud storage.

```bash title="trufflehog_usage"
go install github.com/trufflesecurity/trufflehog/v3@latest

trufflehog filesystem ./target_dir/ --only-verified
trufflehog git https://github.com/org/repo --only-verified
trufflehog github --org=targetcompany --only-verified --json
trufflehog s3 --bucket=target-bucket --only-verified
```

!!! tip "Use --only-verified"
    Without `--only-verified`, output volume is high and mostly noise. Use it for initial passes, then remove it for a thorough sweep if nothing surfaces.

---

## Mobile Tools

### MobSF

Automated static and dynamic analysis for Android and iOS. First stop for any mobile target.

```bash title="mobsf_usage"
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf
# Upload APK or IPA at http://localhost:8000
```

**Output covers:** hardcoded secrets, insecure API endpoints, manifest issues, exported components, Firebase config, dangerous permissions, SSL pinning status.

---

### APKTool

APK decoding to resources, manifest, and smali bytecode.

```bash title="apktool_usage"
apktool d target.apk -o decoded/    # decode
apktool b decoded/ -o rebuilt.apk   # rebuild (for patching)
```

**Key files after decoding:**

| File | What to look for |
|---|---|
| `AndroidManifest.xml` | Permissions, exported components, deep links |
| `res/values/strings.xml` | Hardcoded URLs, API keys, credentials |
| `smali/` | Disassembled bytecode — readable but not Java |

---

### JADX

APK decompilation to readable Java/Kotlin source. Best tool for code review.

```bash title="jadx_usage"
# GUI (recommended for exploration)
jadx-gui target.apk

# CLI
jadx target.apk -d output/
```

`Ctrl+Shift+F` in the GUI runs a global text search across all decompiled code. Use it to find API endpoints, hardcoded secrets, and auth logic.

---

### Frida

Dynamic instrumentation — hook methods, bypass SSL pinning, analyse runtime behaviour.

```bash title="frida_usage"
pip install frida frida-tools --break-system-packages
# Push frida-server to device: https://github.com/frida/frida/releases

frida -U -f com.target.app -l script.js    # spawn and instrument
frida -U com.target.app -l script.js       # attach to running app
frida-ps -Ua                               # list running apps on device

# Universal SSL pinning bypass (no custom script needed)
frida -U -f com.target.app \
  --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida
```

---

### Objection

Frida-based runtime exploration framework. Simpler than raw Frida for common tasks.

```bash title="objection_usage"
pip install objection --break-system-packages

objection -g com.target.app explore
```

**Key commands inside the Objection shell:**

| Command | Action |
|---|---|
| `android sslpinning disable` | Bypass SSL pinning |
| `android root disable` | Bypass root detection |
| `android hooking list classes` | List all app classes |
| `android filesystem ls` | Browse app filesystem |
| `android filesystem download <path>` | Download a file from device |
| `ios keychain dump` | Dump iOS keychain |
| `ios nsuserdefaults get all` | Read iOS preferences |
| `env` | Show data directory paths |

---

### apk-mitm

Patches an APK to disable SSL pinning and trust user certificates. No root required. Easiest SSL pinning bypass for standard apps.

```bash title="apk_mitm_usage"
npm install -g apk-mitm

apk-mitm target.apk
# Output: target-patched.apk
adb install target-patched.apk
```

---

## Wordlists and Payload Banks

| Resource | Best For | Location |
|---|---|---|
| SecLists | Standard wordlists for all phases | `git clone https://github.com/danielmiessler/SecLists /opt/SecLists` |
| PayloadsAllTheThings | Payload reference for every vulnerability class | `https://github.com/swisskyrepo/PayloadsAllTheThings` |
| Assetnote Wordlists | Framework-specific API route discovery | `https://wordlists.assetnote.io` |
| jhaddix all.txt | Best subdomain brute-force list (~2M entries) | See install script below |
| fuzz.txt | ffuf-specific path fuzzing | `https://github.com/Bo0oM/fuzz.txt` |
| PortSwigger XSS Cheat Sheet | Filterable XSS payload reference | `https://portswigger.net/web-security/cross-site-scripting/cheat-sheet` |

**Key SecLists paths:**

```
/opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt     subdomain brute-force
/opt/SecLists/Discovery/Web-Content/raft-large-directories.txt    directory fuzzing
/opt/SecLists/Discovery/Web-Content/raft-large-files.txt          file fuzzing
/opt/SecLists/Discovery/Web-Content/api-endpoints.txt             API route fuzzing
/opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt      parameter fuzzing
/opt/SecLists/Passwords/Leaked-Databases/rockyou.txt              JWT/password cracking
```

### Quick Installation Script

Installs the full toolkit on Kali, Ubuntu, or Debian. Run once on a fresh machine.

```bash title="install_tools.sh"
#!/bin/bash
# chmod +x install_tools.sh && ./install_tools.sh

echo "[*] Setting up Go environment..."
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
export GOPATH=$HOME/go

echo "[*] Installing Go recon tools..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/d3mondev/puredns/v2@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/cmd/naabu@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/tomnomnom/anew@latest
go install github.com/sensepost/gowitness@latest

echo "[*] Installing Go scanning tools..."
go install github.com/ffuf/ffuf/v2@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/hahwul/dalfox/v2@latest
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install github.com/haccer/subjack@latest
go install -v github.com/projectdiscovery/notify/cmd/notify@latest

echo "[*] Installing Python tools..."
pip install sqlmap trufflehog3 arjun objection frida frida-tools \
  --break-system-packages

echo "[*] Updating Nuclei templates..."
nuclei -update-templates

echo "[*] Cloning wordlists..."
git clone https://github.com/danielmiessler/SecLists /opt/SecLists --depth 1
git clone https://github.com/swisskyrepo/PayloadsAllTheThings /opt/PayloadsAllTheThings --depth 1

echo "[*] Downloading jhaddix all.txt..."
mkdir -p /opt/wordlists
wget -q -O /opt/wordlists/all.txt \
  "https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/all.txt"

echo "[*] Fetching DNS resolvers..."
wget -q -O /opt/resolvers.txt \
  "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"

echo "[+] Done. Add ~/go/bin to PATH if not already set."
echo "[+] Install manually: Burp Suite (portswigger.net), JADX (github.com/skylot/jadx)"
```

---

## References

<div class="grid cards" markdown>

-   :simple-go:{ .lg .middle } __ProjectDiscovery Tools__

    ---

    Subfinder, httpx, dnsx, Naabu, Katana, Nuclei, interactsh, AlterX, and Notify.

    [:octicons-arrow-right-24: projectdiscovery.io](https://projectdiscovery.io)

-   :simple-portswigger:{ .lg .middle } __Burp Suite and Extensions__

    ---

    Community edition download and the BApp Store for all extensions.

    [:octicons-arrow-right-24: Burp download](https://portswigger.net/burp/communitydownload) · [:octicons-arrow-right-24: BApp Store](https://portswigger.net/bappstore)

-   :material-format-list-text:{ .lg .middle } __Wordlist Resources__

    ---

    SecLists, PayloadsAllTheThings, and Assetnote framework wordlists.

    [:octicons-arrow-right-24: SecLists](https://github.com/danielmiessler/SecLists) · [:octicons-arrow-right-24: Assetnote](https://wordlists.assetnote.io) · [:octicons-arrow-right-24: PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

-   :material-cellphone-lock:{ .lg .middle } __Mobile Testing__

    ---

    MobSF, JADX, Frida, and Objection documentation.

    [:octicons-arrow-right-24: MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) · [:octicons-arrow-right-24: Frida](https://frida.re) · [:octicons-arrow-right-24: JADX](https://github.com/skylot/jadx)

</div>