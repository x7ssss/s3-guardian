# s3-guardian

[![npm version](https://img.shields.io/badge/npm-v1.5.0-blue.svg)](https://www.npmjs.com/package/s3-guardian)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Runtime Dependencies](https://img.shields.io/badge/dependencies-0%20(AWS%20SDK%20v3%20only)-success.svg)](https://github.com/x7ssss/s3-guardian)
[![Node Version](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen.svg)](https://nodejs.org/)

Enterprise-grade CLI and SDK to detect, quantify, and safely clean up abandoned multipart uploads, noncurrent object versions, and lifecycle transition traps across AWS S3 and multi-cloud S3 stores (Cloudflare R2, Wasabi, Backblaze B2, MinIO, Ceph).

---

## Architectural Workflow

```
               ┌─────────────────────────────────────────────────┐
               │              Storage Lens Export CSV            │
               └───────────────────────┬─────────────────────────┘
                                       │ (lens: zero data-plane)
                                       ▼
┌──────────────────┐           ┌──────────────┐
│ AWS Organizations│ ──(org)─▶ │   SCANNER    │ ◀── Ambient Credentials / STS Pool
└──────────────────┘           └───────┬──────┘
                                       │
                                       ▼
                               ┌──────────────┐
                               │   PLANNER    │ ── Schema 1.3 + RFC 8785 SHA-256
                               └───────┬──────┘
                                       │
                                       ▼
                               ┌──────────────┐
                               │ BLAST RADIUS │ ── Pre-Flight Simulator:
                               │  SIMULATOR   │    • S3 Object Lock (Compliance/Governance)
                               └───────┬──────┘    • CRR/SRR Replication Divergence Guard
                                       │           • Protected Prefixes (_wal/, iceberg/, ...)
                                       │           • Tag Exclusions & Active Churn (<24h)
                                       ▼
                               ┌──────────────┐
                               │   EXECUTOR   │ ── Bounded Concurrency (max 10)
                               └───────┬──────┘    • Quiet Batch Deletion + Error Inspection
                                       │           • Forensic CloudTrail Correlation Tracing
                                       ▼
                   ┌───────────────────────────────────────┐
                   │ S3 Multipart Aborts / Version Purges  │
                   └───────────────────────────────────────┘
```

---

## The Problem

1. **Invisible Multipart Bloat ("Zombie Uploads"):**
   When multipart uploads terminate abnormally (network drops, container preemption, client crashes), the uploaded byte parts remain in S3 indefinitely. They **never** appear in `ListObjectsV2` or the AWS Console, yet accrue baseline S3 Standard storage charges ($0.023/GB/month) forever.
2. **Versioning Bleed & Ghost Delete Markers:**
   Version-enabled buckets silently accumulate millions of noncurrent versions and Expired Object Delete Markers (EODMs), degrading listing latency and accumulating immense financial waste.
3. **Drift-Prone Direct API Mutations:**
   Blindly overwriting S3 lifecycle rules with manual API calls destroys existing Terraform and CloudFormation state. `s3-guardian` is **GitOps-first**, generating clean IaC code by default.
4. **Glacier & Standard-IA Small-Object Transition Traps:**
   S3 Standard-IA, One Zone-IA, and Glacier Instant Retrieval (GIR) enforce a 128 KiB minimum billable size floor. Glacier Flexible Retrieval (GFR) and Deep Archive (GDA) charge 40 KiB metadata overhead per object (8 KiB at Standard rate + 32 KiB at Glacier rate). Unconstrained transition rules lacking `ObjectSizeGreaterThan` filters force sub-128 KiB objects into archive tiers, increasing ongoing monthly storage costs up to 70x and charging $0.01–$0.05/1k transition request fees.

---

## Core Enterprise Invariants

- **Zero Third-Party Runtime Dependencies:** Runs purely on Node.js 20+ built-ins (`node:crypto`, `node:readline`, `node:util`) and official modular AWS SDK clients (`@aws-sdk/client-s3`, `@aws-sdk/client-sts`, `@aws-sdk/client-organizations`).
- **Destructive Operations Safety Gate:** `apply` strictly requires an immutable, cryptographically verified `plan.json` file and the explicit `--confirm` flag.
- **Pre-Flight Blast Radius Engine:** Simulates mutation safety before making any destructive API calls:
  - Blocks deletions under Object Lock `COMPLIANCE` mode.
  - Requires `--bypass-governance` for `GOVERNANCE` mode (never sends bypass headers on non-locked buckets).
  - Guards against replication divergence under CRR/SRR via `--acknowledge-replication-divergence`.
  - Hard-blocks state and ingestion pipeline prefixes (`checkpoints/`, `_wal/`, `iceberg/`, `terraform/`, `state/`).
  - Guards against active pipeline churn (<24h age) unless explicitly overridden.
- **RFC 8785 Cryptographic Plan Integrity:** Plans are canonicalized via RFC 8785 (JCS) and signed with a SHA-256 target hash. Tampered or modified plan files are rejected immediately.
- **Forensic CloudTrail Traceability:** Captures and outputs `$metadata.requestId` (`x-amz-request-id`) and `$metadata.extendedRequestId` (`x-amz-id-2`) for audit correlation.
- **Node Single Executable Application (SEA):** Configured for self-contained, dependency-free binary compilation via `sea-config.json`.

---

## Installation

### Run via npx (Zero Install)
```bash
npx s3-guardian --help
```

### Install Globally
```bash
npm install -g s3-guardian
```

### Build Single Executable Application (SEA)
```bash
npm run build:sea
```

---

## Commands & Usage Guide

### 1. `scan`: Read-Only Inspection

Inspect incomplete multipart uploads without modifying bucket state:

```bash
# Scan a single bucket (older than 7 days by default)
s3-guardian scan my-bucket

# Include noncurrent versions and expired delete markers
s3-guardian scan my-bucket --include-versions

# Scan all buckets in the AWS account (fleet mode)
s3-guardian scan --all-buckets

# Sweep all member accounts in an AWS Organization
s3-guardian scan --org --role-name OrganizationAccountAccessRole

# Custom age threshold, prefix, and JSON output
s3-guardian scan my-bucket --older-than 14 --prefix logs/ --json
```

### 2. `plan`: Deterministic, Cryptographic Planning

Generates a reviewable, immutable Schema 1.3 `plan.json` embedding RFC 8785 SHA-256 target verification and blast radius audit summary:

```bash
# Generate plan for zombie multipart uploads
s3-guardian plan my-bucket --out plan.json --older-than 7

# Generate plan including versioning waste
s3-guardian plan my-bucket --include-versions --out plan.json

# Generate fleet-wide plan
s3-guardian plan --all-buckets --out fleet-plan.json
```

Example `plan.json` (Schema 1.3):
```json
{
  "schemaVersion": "1.3",
  "generatedAt": "2026-09-20T12:00:00.000Z",
  "bucket": "production-data-lake",
  "endpoint": null,
  "olderThanDays": 7,
  "totalZombieUploads": 1,
  "totalStrandedBytes": 10737418240,
  "estimatedMonthlyWasteUSD": 0.23,
  "planHash": "3f8a4e9b72c1d0e5f6a8b7c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4",
  "blastRadiusAudit": {
    "bucket": "production-data-lake",
    "riskLevel": "LOW",
    "isBlocked": false,
    "findings": []
  },
  "uploads": [
    {
      "key": "raw/events/2026-09-01.parquet",
      "uploadId": "mpu-xyz-987",
      "initiated": "2026-09-01T04:00:00.000Z",
      "partsCount": 64,
      "bytes": 10737418240,
      "storageClass": "STANDARD",
      "lifecycleStatus": "UNPROTECTED"
    }
  ]
}
```

### 3. `apply`: Safe Execution

Executes aborts and version deletions defined in the plan with cryptographic integrity verification, pre-flight safety checks, and bounded concurrency:

```bash
# Execute plan (strictly requires --confirm)
s3-guardian apply --plan plan.json --confirm

# Bypass Object Lock GOVERNANCE mode retention (when authorized)
s3-guardian apply --plan plan.json --confirm --bypass-governance

# Acknowledge replication divergence for replicated buckets
s3-guardian apply --plan plan.json --confirm --acknowledge-replication-divergence

# Allow deletion of items modified within 24 hours
s3-guardian apply --plan plan.json --confirm --allow-active-churn
```

### 4. `remediate`: GitOps-First Lifecycle Policies

Generates non-destructive, drift-free Infrastructure as Code snippets to permanently automate MPU cleanup:

```bash
# Generate Terraform HCL configuration snippet
s3-guardian remediate my-bucket --format terraform

# Generate CloudFormation YAML template
s3-guardian remediate my-bucket --format cloudformation --out-iac lifecycle.yaml

# Fleet remediation for all unprotected buckets
s3-guardian remediate --all-buckets --format terraform --out-iac main.tf

# Opt-in direct API mutation (atomic Read-Modify-Write preserving all existing rules)
s3-guardian remediate my-bucket --danger-direct-api-apply --days 7
```

### 5. `lens`: Zero-Data-Plane Storage Lens Triage

Triages macroscopic metrics directly from local or S3 Storage Lens export CSV files without issuing a single object-level API call:

```bash
# Triage top offending buckets from local CSV export
s3-guardian lens ./storage-lens-export.csv --top 10

# Stream export directly from S3
s3-guardian lens s3://audit-bucket/StorageLens/report.csv --min-waste-usd 50.00
```

### 6. `audit-transitions`: Lifecycle Transition Trap Auditor

Audits S3 lifecycle configuration rules for dangerous unconstrained transitions targeting Infrequent Access or Glacier classes without a 128 KiB minimum size filter:

```bash
# Audit a single bucket's lifecycle transition rules
s3-guardian audit-transitions my-data-bucket

# Audit all buckets across the account
s3-guardian audit-transitions --all-buckets

# Include transition audit during standard scan
s3-guardian scan my-data-bucket --audit-transitions

# Machine-readable JSON output
s3-guardian audit-transitions my-data-bucket --json
```

Terminal Output Table:
```
Rule ID                     Target Tier     Days    Min Size Filter     Small-Object Risk   Est. Penalty/Mo   Status
-------------------------------------------------------------------------------------------------------------------------
archive-raw-telemetry       GLACIER         30      None (0 B)          HIGH (< 128 KiB)    $42.50/mo         TRAP DETECTED
```

Actionable remediation snippets with `object_size_greater_than = 131072` (128 KiB) are automatically emitted to remediate the small-object trap.

---

### 7. `daemon`: Continuous In-Process Governance Daemon

Runs continuous, automated FinOps and storage governance sweeps without external daemon managers (no `pm2`, no `node-cron`). Built purely on native Node.js 20+ runtime primitives.

#### Core Capabilities:
- **Drift-Free Monotonic Scheduler:** Calculates loop duration using `process.hrtime.bigint()` and dynamically adjusts sleep interval (`Math.max(0, intervalMs - lastRunDurationMs)`) to eliminate timing drift under heavy API load.
- **Single-Instance Atomic PID Lockfile:** Writes process PID to `${os.tmpdir()}/s3-guardian-<target>.lock` with atomic `{ flag: 'wx' }`. Automatically detects and reclaims stale locks if the previous process terminated abnormally.
- **Signal-Safe Graceful Shutdown:** Traps `SIGINT` (Ctrl+C) and `SIGTERM`, allowing in-flight network batches to complete before process exit, and cleanly unlinks lockfiles.
- **Memory Safety & Resource Monitoring:** Tracks `process.memoryUsage()` (heap used and RSS) on every iteration to guarantee zero memory leaks over long-running deployments.
- **Continuous Webhook Alerting:** Dispatches real-time summary notifications to Slack, Discord, PagerDuty, or Webhook endpoints after each iteration.

#### CLI Usage Examples:

```bash
# Continuous fleet scan every 1 hour (default)
s3-guardian scan --all-buckets --daemon

# Continuous single-bucket monitoring every 30 minutes with Slack alerts
s3-guardian scan my-bucket --daemon --interval 30m --webhook-url https://hooks.slack.com/services/...

# Continuous lifecycle transition trap monitoring every 12 hours
s3-guardian audit-transitions --all-buckets --daemon --interval 12h

# Execute exactly one iteration in daemon harness (validates lockfile, pipeline, and metrics)
s3-guardian scan --all-buckets --once
```

#### systemd Service Configuration (`/etc/systemd/system/s3-guardian.service`):

```ini
[Unit]
Description=s3-guardian Continuous Storage Governance Daemon
After=network.target

[Service]
Type=simple
User=s3guardian
Group=s3guardian
Environment=AWS_REGION=us-east-1
Environment=NODE_ENV=production
ExecStart=/usr/local/bin/s3-guardian scan --all-buckets --daemon --interval 6h --webhook-url https://hooks.slack.com/services/XXX
Restart=on-failure
RestartSec=30s
KillMode=mixed
TimeoutStopSec=60s

[Install]
WantedBy=multi-user.target
```

#### Docker / Container Deployment:

```dockerfile
FROM node:20-alpine
WORKDIR /app
RUN npm install -g s3-guardian
USER node
ENTRYPOINT ["s3-guardian"]
CMD ["scan", "--all-buckets", "--daemon", "--interval", "1h"]
```

---

### 8. `drift`: Terraform Lifecycle Drift Detection & Git Patch Generation

Detects discrepancies between deployed AWS S3 lifecycle rules and local Terraform Infrastructure as Code definitions (`.tf` source files or `terraform.tfstate` state files). Automatically generates standard POSIX unified diffs directly applicable via `git apply`.

#### Core Capabilities:
- **Terraform State (v4) Parsing:** Ingests `terraform.tfstate` to extract `aws_s3_bucket_lifecycle_configuration` and legacy `aws_s3_bucket` managed lifecycle rules without requiring a Terraform binary or network state lock.
- **Direct HCL Source Inspection:** Analyzes local `.tf` files to identify missing rule blocks, threshold drifts, and missing safety filters.
- **POSIX Unified Diff Patches:** Emits standard `--- a/path\n+++ b/path` unified diffs inserting missing `abort_incomplete_multipart_upload` blocks, version expirations, and `object_size_greater_than = 131072` transition trap filters.
- **Automated In-Place Patching:** When invoked with `--write`, atomically patches the local `.tf` file in place, achieving GitOps-first remediation with zero manual syntax errors.
- **Ghost Rule Flagging:** Identifies rules with Tag filters attached to MPU abort actions (which AWS S3 silently ignores).

#### CLI Usage Examples:

```bash
# Compare live S3 bucket against local Terraform source file
s3-guardian drift my-bucket --tf-file main.tf

# Compare live S3 bucket against terraform.tfstate JSON
s3-guardian drift my-bucket --tfstate terraform.tfstate

# Preview POSIX unified diff patch directly to stdout
s3-guardian drift my-bucket --tf-file main.tf --patch

# Apply patch directly to the .tf file in place
s3-guardian drift my-bucket --tf-file main.tf --write

# Output machine-readable JSON drift report for CI/CD pipelines
s3-guardian drift my-bucket --tfstate terraform.tfstate --json
```

Terminal Output Table:
```
Bucket                      Resource Type                             IaC State    Live State   Drift Status
--------------------------------------------------------------------------------------------------------------------
production-data-lake        aws_s3_bucket_lifecycle_configuration    1 Rule(s)    2 Rule(s)    ❌ DRIFT_DETECTED

Drift Details & Safety Gaps (2):
  - Unmanaged rule in AWS S3: 'ad-hoc-manual-rule' (present in live cloud but missing in IaC)
  - Safety gap: Transition rule 'archive-tier' lacks object_size_greater_than >= 128 KiB filter (small-object penalty trap)

💡 Tip: Run `s3-guardian drift production-data-lake --tf-file main.tf --patch` to view unified diff patch, or `--write` to apply automatically.
```

---

## Multi-Cloud Provider Hardening (v1.4.0)

`s3-guardian` automatically adapts to cross-cloud S3-compatible object storage backends via endpoint URL regex matching or explicit `--provider` specification:

```bash
# Explicit provider specification
s3-guardian scan my-bucket --provider r2
s3-guardian scan my-bucket --provider wasabi --endpoint https://s3.wasabisys.com
s3-guardian scan my-bucket --provider minio --endpoint http://localhost:9000

# Detected provider is displayed in the CLI banner:
# [Provider: Cloudflare R2]
# [Provider: Wasabi]
# [Provider: MinIO]
```

### Supported Providers & Automated Quirks

| Provider | Endpoint Pattern | Native Quirks Applied |
| :--- | :--- | :--- |
| **AWS S3** | `*.amazonaws.com` (or default) | Standard virtual-hosted routing, full SDK checksum support |
| **Cloudflare R2** | `*.r2.cloudflarestorage.com`, `*.r2.dev` | Sets `requestChecksumCalculation: "WHEN_REQUIRED"`, default region `auto`; middleware strips unsupported `x-amz-sdk-checksum-algorithm` and `x-amz-checksum-crc32` headers |
| **Wasabi** | `*.wasabisys.com` | Strict 90-day minimum retention guard (`--force-wasabi-early-delete` required for targets < 90 days) |
| **Backblaze B2** | `*.backblazeb2.com` | Automatic path-style addressing (`forcePathStyle: true`) |
| **MinIO** | `:9000`, `minio.*`, `localhost:9000` | Path-style addressing; deserializer middleware catches HTTP 405 MethodNotAllowed and yields safe fallback responses |
| **Ceph RADOS GW**| `:7480`, `*.ceph.*` | Path-style addressing; middleware suppresses HTTP 405 MethodNotAllowed for unsupported extension queries |
| **Custom S3** | Custom endpoint URL | Standard S3 compatibility fallback |

### Wasabi 90-Day Retention Guard
Wasabi enforces a **90-day minimum retention charge** on stored data. Prematurely deleting objects or incomplete multipart uploads younger than 90 days results in Timed Deleted Storage charges.
- `s3-guardian` pre-flight blast radius simulation inspects target timestamps when `provider === "wasabi"`.
- Targets `< 90` days old trip `HIGH_WASABI_RETENTION_RISK` and abort `apply`:
  `⚠️ Wasabi charges 90 days minimum retention. Deleting objects < 90 days old triggers Timed Deleted Storage fees.`
- To bypass when early deletion is intended, pass `--force-wasabi-early-delete`.

---

### 11. `dashboard` (TUI): Interactive Fleet Storage Governance Navigator

A terminal UI dashboard powered purely by native Node.js 20+ ANSI escape codes and alternate screen buffer hygiene. Browse buckets, inspect stranded storage, expand the detail inspector drawer, and generate remediation plans on the fly.

```bash
# Launch interactive dashboard across all fleet buckets
s3-guardian dashboard

# Or use the concise alias
s3-guardian tui

# Initialize instant zero data-plane triage from Storage Lens CSV export
s3-guardian dashboard --lens s3://my-inventory-bucket/lens/daily-export.csv
s3-guardian dashboard --lens /path/to/local-storage-lens-report.csv

# Multi-cloud & custom endpoints
s3-guardian dashboard --provider minio --endpoint http://localhost:9000
```

#### Hotkey Controls

| Hotkey | Action | Description |
| :--- | :--- | :--- |
| `↑` / `k` | **Navigate Up** | Move cursor up in the bucket list (with auto-scroll clamping) |
| `↓` / `j` | **Navigate Down** | Move cursor down in the bucket list |
| `Enter` | **Detail Inspector** | Expand/collapse selected bucket drawer (region, provider, oldest upload date, EODM count, lifecycle rule status, ghost rules) |
| `p` | **Create Plan** | Asynchronously generate an immutable, RFC 8785 signed `plan-<bucket>.json` in the background |
| `r` | **Refresh** | Asynchronously re-scan fleet metrics across accounts and regions without freezing the UI |
| `q` / `Esc` / `Ctrl+C` | **Quit** | Cleanly exit dashboard and restore primary terminal screen buffer |

#### Terminal Hygiene & CI Safety
- **Clean Alternate Screen Buffer:** `s3-guardian` switches to the terminal's alternate screen buffer (`\x1b[?1049h`) and hides the cursor (`\x1b[?25l`). On exit or interrupt signals (`SIGINT`, `SIGTERM`, `uncaughtException`), it unconditionally restores the primary screen buffer (`\x1b[?1049l`) and re-enables cursor visibility (`\x1b[?25h`).
- **Non-TTY Protection:** If launched in headless CI pipelines or piped commands without an interactive TTY (`!process.stdin.isTTY`), the dashboard cleanly halts with exit code 2 and prompts:
  `Error: Interactive dashboard requires an interactive terminal (TTY). Run 's3-guardian scan --all-buckets' for non-interactive / CI environments.`

---

## Full CLI Reference

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `dashboard` / `tui` | command | — | Interactive terminal dashboard for fleet storage governance |
| `--lens <source>` | string | — | Initialize dashboard triage or run macroscopic ranking from Storage Lens CSV export |
| `--provider <name>` | string | auto | Target S3 provider (`aws`, `r2`, `wasabi`, `b2`, `minio`, `ceph`, `custom`) |
| `--force-wasabi-early-delete` | flag | `false` | Bypass Wasabi 90-day retention guard for uploads/versions < 90 days old |
| `--tf-file <path>` | string | — | Target Terraform `.tf` source file to compare against |
| `--tfstate <path>` | string | — | Target `terraform.tfstate` JSON file |
| `--patch` | flag | `false` | Output POSIX unified diff patch directly to stdout |
| `--write` | flag | `false` | Atomically update the target `.tf` file in-place with patch applied |
| `--daemon` | flag | `false` | Continuous in-process daemon execution mode |
| `--interval <duration>` | string | `1h` | Interval between daemon runs (`10s`, `30m`, `1h`, `12h`, `24h`) |
| `--once` | flag | `false` | Run exactly one iteration in daemon harness (validates lock & metrics) |
| `--older-than <days>` | number | `7` | Age threshold in days for multipart uploads and versions |
| `--include-versions` | flag | `false` | Scan and plan for noncurrent versions and expired delete markers |
| `--audit-transitions` | flag | `false` | Audit lifecycle transitions for Glacier/IA small-object traps during scan |
| `--out <file>` | string | `plan.json` | Destination path for plan output file |
| `--plan <file>` | string | — | Path to plan file to execute |
| `--confirm` | flag | `false` | Explicit confirmation required for destructive apply |
| `--bypass-governance` | flag | `false` | Bypass S3 Object Lock GOVERNANCE mode retention |
| `--acknowledge-replication-divergence` | flag | `false` | Acknowledge replica divergence on CRR/SRR replicated buckets |
| `--allow-active-churn` | flag | `false` | Allow deletion of uploads or versions modified within 24 hours |
| `--all-buckets` | flag | `false` | Fleet mode: scan or remediate across all account buckets |
| `--org` | flag | `false` | Multi-account sweep across AWS Organizations accounts |
| `--role-name <name>` | string | `OrganizationAccountAccessRole` | IAM role assumed into member accounts |
| `--accounts <ids>` | string | — | Comma-separated target AWS account IDs |
| `--account-concurrency <n>` | number | `5` | Concurrent member account workers (max 5) |
| `--endpoint <url>` | string | — | Custom endpoint URL for MinIO, Cloudflare R2, LocalStack |
| `--force-path-style` | flag | `false` | Enable S3 path-style addressing |
| `--max-waste-usd <amount>`| number | — | Policy gate: exit code 1 if total monthly waste exceeds threshold |
| `--fail-on-unprotected` | flag | `false` | Policy gate: exit code 1 if any bucket lacks an MPU lifecycle rule |
| `--format <fmt>` | string | `table` | Output format: `table`, `json`, `github`, `terraform`, `cloudformation` |
| `--danger-direct-api-apply`| flag | `false` | Direct API mutation applying lifecycle rule to S3 |
| `--webhook-url <url>` | string | — | Dispatch alerts to Slack, Discord, PagerDuty, or generic webhooks |
| `--notify-always` | flag | `false` | Bypass alert circuit breaker ($0.00 waste suppression) |
| `--checkpoint <s3-uri>` | string | — | S3 URI for resumable fleet scanning across execution limits |

---

## POSIX Exit Codes

| Exit Code | Classification | Description |
| :--- | :--- | :--- |
| `0` | `SUCCESS` | Scan clean, plan generated, apply completed, or policies satisfied |
| `1` | `POLICY_VIOLATION` | Safety gate tripped (Object Lock, churn, tampered plan, Wasabi retention) or CI/CD budget breached |
| `2` | `ARG_ERROR` | Missing required parameters, invalid flags, or syntax error |
| `3` | `DISCOVERY_AUTH_ERROR` | AWS Organizations discovery failure, STS AssumeRole denied, or missing credentials |

---

## Production Safety Matrix

| Threat / Invariant | Risk Level | Defense Mechanism | Override Flag |
| :--- | :--- | :--- | :--- |
| **Object Lock COMPLIANCE** | `CRITICAL_BLOCKED` | Hard abort before sending API calls. Deletions strictly forbidden. | None (Immutable) |
| **Object Lock GOVERNANCE** | `HIGH` | Verified via `GetObjectLockConfiguration`. Header withheld unless verified. | `--bypass-governance` |
| **Replication Divergence** | `HIGH` | Detects CRR/SRR rules via `GetBucketReplication`. Prevents replica drift. | `--acknowledge-replication-divergence` |
| **Protected State Prefixes** | `CRITICAL_BLOCKED` | Hard-blocks `checkpoints/`, `_wal/`, `iceberg/`, `manifests/`, `state/`. | None (Immutable) |
| **Protected Bucket Tags** | `CRITICAL_BLOCKED` | Excludes `s3-guardian:ignore=true`, `Backup=true`, `Protection=locked`. | Remove tag in AWS |
| **Active Pipeline Churn** | `HIGH` | Blocks deletion of uploads or versions initiated within 24 hours. | `--allow-active-churn` |
| **Wasabi Early Deletion Guard** | `HIGH` | Blocks deletion of objects or uploads < 90 days old to avoid Timed Deleted fees. | `--force-wasabi-early-delete` |
| **Plan Tampering** | `POLICY_VIOLATION` | RFC 8785 JCS canonicalization with SHA-256 target hash verification. | Re-generate plan |
| **S3 503 Throttling** | Handled | Exponential backoff with full jitter (Decorrelated Jitter). | Automatic |

---

## License

MIT © Google Antigravity & contributors.

