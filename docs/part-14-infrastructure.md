---
icon: lucide/server-cog
tags:
  - bug-bounty
  - recon
  - automation
  - infrastructure
description: A nightly pipeline running on a free VPS that delivers new attack surface every morning — subdomains, ports, vulnerabilities, and GitHub commits — while you sleep.
---

# Infrastructure

The goal is simple: wake up every morning to a list of new attack surface that didn't exist yesterday. While you slept, the pipeline ran. New subdomains were found, ports were scanned, vulnerabilities were flagged, and GitHub commits were checked for secrets. Your morning routine is review, not execution. This section covers everything needed to build and maintain that infrastructure.

---

<div class="grid cards" markdown>

-   :material-cloud-outline:{ .lg .middle } __VPS Setup__

    ---

    Oracle Free Tier provisioning, SSH hardening, and Telegram alert configuration.

    [:octicons-arrow-right-24: VPS setup](#vps-setup)

-   :material-pipe:{ .lg .middle } __Nightly Pipeline__

    ---

    The full annotated recon script and cron schedule for multiple targets.

    [:octicons-arrow-right-24: Nightly pipeline](#nightly-pipeline)

-   :simple-github:{ .lg .middle } __GitHub Monitoring__

    ---

    Automated commit monitoring and secret detection across organisation repositories.

    [:octicons-arrow-right-24: GitHub monitoring](#github-monitoring)

-   :material-bell-check:{ .lg .middle } __Alert Triage__

    ---

    The morning review workflow, what to test immediately, and VPS maintenance.

    [:octicons-arrow-right-24: Alert triage](#alert-triage)

</div>

## Decision Flow

```
Setting up for the first time?
→ Provision Oracle Free Tier VM → install Go and tools (Part 13 script) →
  create Telegram bot → test alert function → deploy pipeline script → add cron entries.

Adding a new target to the pipeline?
→ Add one crontab entry staggered by 1 hour from existing targets.
  Run manually first: ./recon_pipeline.sh target.com — verify alert arrives.

Morning Telegram alert shows new subdomains?
→ Open gowitness screenshot report. Flag admin/staging/dev/api hosts.
  Pick 2–3 most interesting. Manual test begins there.

Morning alert shows Nuclei findings?
→ Manually verify in Burp before anything else. Nuclei has false positives.
  If confirmed: start the report immediately.

Morning alert shows GitHub commit with secrets detected?
→ Review the diff at github.com/repo/commit/<sha> same day.
  Test any new endpoints that appear in the diff.

Subdomain name contains admin, internal, staging, dev, api, or legacy?
→ Drop everything and test immediately. The window is short.

VPS disk getting full?
→ Run cleanup: find /opt/recon -name "*.txt" -mtime +30 -delete
  Check df -h / — pipeline txt files accumulate fast on active targets.
```

---

## VPS Setup

### Oracle Free Tier Provisioning

Oracle Cloud Always Free gives two AMD VMs (1 OCPU, 1GB RAM each) and optionally up to 4 OCPU / 24GB RAM on ARM — permanently free, no credit card expiry in most regions.

```bash title="provisioning_steps"
# 1. Register at cloud.oracle.com
# 2. Choose home region: US East or EU West (closest to targets)
# 3. Create VM Instance:
#    Shape: VM.Standard.E2.1.Micro (Always Free AMD)
#      OR: VM.Standard.A1.Flex (Always Free ARM — better performance)
#    Image: Ubuntu 22.04 LTS
#    Boot volume: 50GB
# 4. Generate SSH key pair during setup — download private key immediately
# 5. Open TCP 22 in Security List

# Connect:
ssh -i ~/.ssh/oracle_key ubuntu@<instance_public_ip>
```

### Initial Setup and Hardening

```bash title="vps_setup.sh"
# System update
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl wget jq tmux python3-pip unzip

# Install Go
wget https://go.dev/dl/go1.22.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
source ~/.bashrc

# Run the Part 13 install script to install all tools

# Restrict SSH to your IP only
sudo ufw allow from <your_ip> to any port 22
sudo ufw enable
```

### Telegram Bot Alert Setup

```bash title="telegram_setup.sh"
# Step 1: Create bot via @BotFather on Telegram
# Send: /newbot → receive BOT_TOKEN

# Step 2: Get your Chat ID
curl "https://api.telegram.org/bot<BOT_TOKEN>/getUpdates"
# Find: result[0].message.chat.id = CHAT_ID

# Step 3: Test the bot
curl -s -X POST "https://api.telegram.org/bot<BOT_TOKEN>/sendMessage" \
  -d "chat_id=<CHAT_ID>&text=Recon+server+online"
```

```yaml title="~/.config/notify/provider-config.yaml"
telegram:
  - id: "main"
    telegram_api_key: "BOT_TOKEN"
    telegram_chat_id: "CHAT_ID"
    telegram_format: "{{data}}"
    telegram_parsemode: "Markdown"
```

```bash title="notify_usage"
# Send any output to Telegram:
echo "finding" | notify -provider telegram -id main
```

---

## Nightly Pipeline

### Full Pipeline Script

```bash title="recon_pipeline.sh"
#!/bin/bash
# Usage: ./recon_pipeline.sh target.com

TARGET="${1:-target.com}"
BASE="/opt/recon/$TARGET"
TIMESTAMP=$(date +%Y%m%d_%H%M)
BOT_TOKEN="<BOT_TOKEN>"
CHAT_ID="<CHAT_ID>"

mkdir -p "$BASE"/{subdomains,httpx,nuclei,screenshots,ports}

alert() {
  curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
    -d "chat_id=${CHAT_ID}" --data-urlencode "text=$1" > /dev/null
}

# STEP 1: Subdomain enumeration
subfinder -d "$TARGET" -all -silent 2>/dev/null > /tmp/subs_new.txt
assetfinder --subs-only "$TARGET" 2>/dev/null >> /tmp/subs_new.txt
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" 2>/dev/null | \
  jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' >> /tmp/subs_new.txt

# Delta — only new subdomains trigger the rest of the pipeline
sort -u /tmp/subs_new.txt | anew "$BASE/subdomains/master.txt" > /tmp/new_subs.txt
NEW_COUNT=$(wc -l < /tmp/new_subs.txt)
[ "$NEW_COUNT" -eq 0 ] && echo "[*] No new subdomains." && exit 0

# STEP 2: DNS resolution
dnsx -l /tmp/new_subs.txt -silent -a -resp \
  -o /tmp/new_resolved.txt 2>/dev/null
awk '{print $1}' /tmp/new_resolved.txt > /tmp/new_hosts.txt

# STEP 3: HTTP probing
httpx -l /tmp/new_hosts.txt -silent \
  -status-code -title -tech-detect \
  -o "$BASE/httpx/new_${TIMESTAMP}.txt" 2>/dev/null
HTTP_COUNT=$(wc -l < "$BASE/httpx/new_${TIMESTAMP}.txt")

# STEP 4: Port scan (non-80/443 results are the interesting ones)
naabu -l /tmp/new_hosts.txt -top-ports 100 -silent \
  -o "$BASE/ports/new_${TIMESTAMP}.txt" 2>/dev/null
grep -vE ":80$|:443$" "$BASE/ports/new_${TIMESTAMP}.txt" \
  > /tmp/interesting_ports.txt

# STEP 5: Nuclei
nuclei -l /tmp/new_hosts.txt \
  -t exposures/ -t cves/ -t takeovers/ -t misconfiguration/ \
  -severity medium,high,critical -silent \
  -o "$BASE/nuclei/new_${TIMESTAMP}.txt" 2>/dev/null
NUCLEI_COUNT=0
[ -f "$BASE/nuclei/new_${TIMESTAMP}.txt" ] && \
  NUCLEI_COUNT=$(wc -l < "$BASE/nuclei/new_${TIMESTAMP}.txt")

# STEP 6: Screenshots
gowitness file -f "$BASE/httpx/new_${TIMESTAMP}.txt" \
  --threads 5 -P "$BASE/screenshots/" 2>/dev/null

# STEP 7: Telegram alert
MSG="Recon: ${TARGET}
${TIMESTAMP}
New subdomains: ${NEW_COUNT}
Live HTTP hosts: ${HTTP_COUNT}
Interesting ports: $(wc -l < /tmp/interesting_ports.txt)"

[ "$NUCLEI_COUNT" -gt 0 ] && \
  MSG="${MSG}
Nuclei findings: ${NUCLEI_COUNT}
$(head -3 $BASE/nuclei/new_${TIMESTAMP}.txt)"

alert "$MSG"
echo "[$(date)] Done: $TARGET"
```

### Cron Schedule

```bash title="crontab_entries"
crontab -e

# Stagger targets by 1 hour to avoid resource contention
0 2 * * * /opt/scripts/recon_pipeline.sh target1.com >> /var/log/recon1.log 2>&1
0 3 * * * /opt/scripts/recon_pipeline.sh target2.com >> /var/log/recon2.log 2>&1
0 4 * * * /opt/scripts/recon_pipeline.sh target3.com >> /var/log/recon3.log 2>&1

# Weekly: update Nuclei templates
0 1 * * 0 nuclei -update-templates >> /var/log/nuclei_update.log 2>&1

# Weekly: refresh resolver list
0 1 * * 0 wget -q -O /opt/resolvers.txt \
  https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt
```

!!! tip "Test before scheduling"
    Run the script manually for each target before adding cron entries. Confirm the Telegram alert arrives and the output files are created in the expected directories. Silent failures in cron are hard to debug after the fact.

---

## GitHub Monitoring

Monitors an organisation's repositories for new commits and scans each delta for verified secrets using trufflehog.

```bash title="github_monitor.sh"
#!/bin/bash
ORG="targetcompany"
GH_TOKEN="<github_pat>"
BASE="/opt/recon/github"
BOT_TOKEN="<bot_token>"
CHAT_ID="<chat_id>"
mkdir -p "$BASE"

alert() {
  curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
    -d "chat_id=${CHAT_ID}" --data-urlencode "text=$1" > /dev/null
}

# Enumerate org repos
curl -s "https://api.github.com/orgs/${ORG}/repos?per_page=100" \
  -H "Authorization: token ${GH_TOKEN}" | \
  jq -r '.[].full_name' > "$BASE/repos.txt"

while read repo; do
  SAFE=$(echo "$repo" | tr '/' '_')
  STORED="$BASE/last_${SAFE}.txt"

  LATEST=$(curl -s "https://api.github.com/repos/${repo}/commits?per_page=1" \
    -H "Authorization: token ${GH_TOKEN}" | jq -r '.[0].sha' 2>/dev/null)

  [ -z "$LATEST" ] || [ "$LATEST" = "null" ] && continue
  STORED_VAL=$(cat "$STORED" 2>/dev/null)
  [ "$LATEST" = "$STORED_VAL" ] && continue

  # New commit detected — scan for secrets
  SECRETS=$(trufflehog github \
    --repo="https://github.com/${repo}" \
    --since-commit="${STORED_VAL:-HEAD~1}" \
    --token="${GH_TOKEN}" --only-verified --json 2>/dev/null | wc -l)

  MSG="New commit: ${repo}
${LATEST:0:8}
https://github.com/${repo}/commit/${LATEST}"
  [ "$SECRETS" -gt 0 ] && MSG="${MSG}
${SECRETS} secrets detected!"

  alert "$MSG"
  echo "$LATEST" > "$STORED"
done < "$BASE/repos.txt"
```

```bash title="github_monitor_cron"
# Every 6 hours
0 */6 * * * /opt/scripts/github_monitor.sh >> /var/log/github_monitor.log 2>&1
```

!!! warning "GitHub PAT scope"
    Generate the PAT with `repo:read` scope only. Never use a token with write access on a monitoring script. Rotate the token quarterly.

---

## Alert Triage

### Morning Routine

The pipeline delivers; the morning session reviews. Target 30–45 minutes.

```
1. Open Telegram — scan overnight alerts

2. New subdomains alert received?
   → Open gowitness screenshot report for visual review
   → Flag: admin panels, staging environments, exposed tools, error pages
   → Select 2–3 most interesting hosts for today's manual testing session

3. Nuclei findings alert received?
   → Manually verify each finding in Burp before doing anything else
   → Nuclei has false positives — never report without manual confirmation
   → Confirmed finding: start the report immediately

4. Interesting ports alert received?
   → Visit host:port in browser
   → Test default credentials, enumerate the service

5. GitHub commit alert received?
   → Review the full diff at github.com/repo/commit/<sha>
   → Look for: new endpoints, auth logic changes, config changes, hardcoded secrets
   → Test new endpoints the same day — they're the freshest attack surface

6. No alerts?
   → Expected on mature targets. Use the session for deep manual testing of known surface.
```

### Drop Everything and Test Immediately

Some alerts warrant stopping whatever else is planned. The window is short — other hunters may run the same pipeline.

| Signal | Why it's urgent |
|---|---|
| Subdomain with `admin`, `internal`, `staging`, `dev`, `api`, or `legacy` in name | Likely misconfigured or forgotten |
| New host on non-standard port with HTTP response | Often exposed internal tooling |
| Nuclei High or Critical finding | Needs manual verification before duplicate |
| Nuclei takeover match | Short window before others grab it |
| Exposed `.git` or `.env` | Immediate secret/credential exposure |
| Elasticsearch, Redis, or MongoDB on standard port, unauthenticated | Direct data access |
| GitHub commit with secrets detected | Credentials may still be live |
| Spring Boot `/actuator/env` accessible | Environment variable and credential dump |
| Firebase database open read | Direct data access |
| S3/GCS CNAME pointing to unclaimed bucket | Subdomain takeover path |

### VPS Maintenance

```bash title="maintenance_tasks.sh"
# Weekly cleanup — add to crontab
0 3 * * 0 find /opt/recon -name "*.txt" -mtime +30 -delete
0 3 * * 0 find /opt/recon -name "*.json" -mtime +30 -delete

# Check disk usage
df -h /

# Verify pipeline ran overnight
tail -20 /var/log/recon1.log
grep CRON /var/log/syslog | tail -10

# Monthly: update all tools
# Re-run the full install script from Part 13 — easiest way to update everything
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

---

## References

<div class="grid cards" markdown>

-   :material-cloud:{ .lg .middle } __Oracle Cloud Free Tier__

    ---

    Always-free VM provisioning — no credit card expiry, 200GB block storage included.

    [:octicons-arrow-right-24: oracle.com/cloud/free](https://www.oracle.com/cloud/free/)

-   :simple-telegram:{ .lg .middle } __Telegram Bot API__

    ---

    Bot creation, message sending, and webhook configuration reference.

    [:octicons-arrow-right-24: core.telegram.org/bots/api](https://core.telegram.org/bots/api)

-   :material-bell-ring-outline:{ .lg .middle } __ProjectDiscovery Notify__

    ---

    Multi-provider alert tool — Telegram, Slack, Discord, email from a single config.

    [:octicons-arrow-right-24: github.com/projectdiscovery/notify](https://github.com/projectdiscovery/notify)

-   :material-dns:{ .lg .middle } __Trickest Resolvers__

    ---

    Continuously maintained DNS resolver list for puredns and dnsx.

    [:octicons-arrow-right-24: github.com/trickest/resolvers](https://github.com/trickest/resolvers)

</div>

---

??? note "Expand full checklist"

    ```
    INITIAL SETUP
    □ Oracle Cloud VM provisioned (Always Free)
    □ SSH private key saved securely and backed up
    □ Firewall configured — SSH restricted to your IP only
    □ Go installed, all tools installed via Part 13 script
    □ SecLists cloned, Nuclei templates updated

    TELEGRAM
    □ Bot created via @BotFather, BOT_TOKEN saved
    □ Chat ID obtained and confirmed
    □ Alert curl command tested manually
    □ notify tool configured at ~/.config/notify/provider-config.yaml

    PIPELINE
    □ recon_pipeline.sh deployed to /opt/scripts/ and chmod +x
    □ Tested manually for at least one target before scheduling
    □ Cron entries added for all targets, staggered by 1 hour
    □ Log files checked after first automated run
    □ Nuclei template auto-update scheduled weekly

    GITHUB MONITORING
    □ GitHub PAT generated with repo:read scope only
    □ github_monitor.sh deployed and tested manually
    □ Cron entry added (every 6 hours)
    □ PAT rotation reminder set for 90 days

    MAINTENANCE SCHEDULE
    □ Monthly: re-run Part 13 install script (updates all tools)
    □ Weekly: check disk usage and log health
    □ Weekly: resolver list auto-refreshed via cron
    □ Quarterly: rotate GitHub PAT and Telegram bot token
    □ As needed: add new targets to cron pipeline
    ```