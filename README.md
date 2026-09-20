# s3-guardian

[![npm version](https://img.shields.io/badge/npm-v2.0.0-blue.svg)](https://www.npmjs.com/package/s3-guardian)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Runtime Dependencies](https://img.shields.io/badge/dependencies-0%20(AWS%20SDK%20v3%20only)-success.svg)](https://github.com/x7ssss/s3-guardian)
[![Node Version](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen.svg)](https://nodejs.org/)

Enterprise-grade autonomous cloud storage governance platform and CLI to detect, quantify, and safely clean up abandoned multipart uploads, noncurrent object versions, and lifecycle transition traps across AWS S3 and multi-cloud S3 stores (Cloudflare R2, Wasabi, Backblaze B2, MinIO, Ceph).

---

## Autonomous Sovereign Operator State Machine

`s3-guardian v2.0.0` introduces the **Autonomous Sovereign Operator**, a continuous 9-phase daemon engine running autonomous storage governance:

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────────┐
│  DISCOVERY  │ ──▶ │ POLICY_MATCH │ ──▶ │ BLAST_RADIUS_AUDIT  │
└─────────────┘     └──────────────┘     └──────────┬──────────┘
                                                    │
       ┌────────────────────────────────────────────┘
       ▼
┌─────────────┐     ┌────────────────┐     ┌──────────────┐
│ CANARY_TEST │ ──▶ │ CIRCUIT_VERIFY │ ──▶ │ BULK_EXECUTE │
└─────────────┘     └────────────────┘     └───────┬──────┘
                                                   │
       ┌───────────────────────────────────────────┘
       ▼
┌─────────────┐     ┌─────────────┐     ┌───────┐
│  AUDIT_LOG  │ ──▶ │ UNDO_EXPORT │ ──▶ │ SLEEP │ ──(next epoch)──▶ [DISCOVERY]
└─────────────┘     └─────────────┘     └───────┘
```

1. **DISCOVERY**: Paginates targets across accounts/buckets with cursor resumption.
2. **POLICY_MATCH**: Evaluates discovered inventory against declarative policy engine (YAML subset).
3. **BLAST_RADIUS_AUDIT**: Simulates relative mutation ceiling ($\le 5\%$), Object Lock (`COMPLIANCE`/`GOVERNANCE`), and replication divergence.
4. **CANARY_TEST**: Dispatches isolated canary deletion probe before bulk mutation.
5. **CIRCUIT_VERIFY**: Verifies circuit breaker state; halts immediately if error rates spiked.
6. **BULK_EXECUTE**: Bounded concurrency worker pool draining mutation queue.
7. **AUDIT_LOG**: Streaming JSONL append to immutable audit ledger.
8. **UNDO_EXPORT**: Generates cryptographic `UndoManifest` and SOC 2 / ISO 27001 `DeletionCertificate`.
9. **SLEEP**: High-resolution monotonic sleep subtracting epoch run duration; resets circuit breaker half-open probes.
10. **HALTED**: Safety state entered if safety gates trip, preventing catastrophic fleet mutations.

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
- **Autonomous Circuit Breaker & Zero-Allocation Ring Buffer:** Scoped per (bucket, operation). Tracks error rates in $O(1)$ time with zero GC churn using a pre-allocated `Float32Array` ring buffer. Trips to `OPEN` on 3 consecutive 403s, halves concurrency on 503s (burst trips on $\ge 3$ in 5s or $>10\%$ moving error rate), and quarantines on 400 BadDigest.
- **Pre-Flight Canary Verification Gate:** Runs isolated deletions on up to 10 oldest targets with `HeadObject` probe verification before admitting the remaining fleet batch loop.
- **Relative Mutation Ceiling:** Caps autonomous deletions to $\le 5\%$ of total bucket inventory (or 1,000 objects absolute fallback) to prevent catastrophic accidental wipeouts.
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

### Single Executable Application (SEA)
Download pre-built, self-contained standalone binaries (zero Node.js runtime required) from GitHub Releases for:
- Linux (`x86_64`, `aarch64`)
- macOS (`x86_64`, `arm64` Apple Silicon)
- Windows (`x64`)

Or compile locally for your current host platform:
```bash
npm run build:sea
# Generates dist/s3-guardian (or dist/s3-guardian.exe on Windows)
./dist/s3-guardian --version
```

### Air-Gapped Trust Stores (`NODE_EXTRA_CA_CERTS`)
In air-gapped or private cloud environments with corporate intercepting proxies or custom internal Root CAs, point `NODE_EXTRA_CA_CERTS` to your PEM bundle:
```bash
export NODE_EXTRA_CA_CERTS=/etc/ssl/certs/corporate-root-ca.pem
s3-guardian operate --all-buckets
```
`s3-guardian` dynamically registers all PEM certificates into Node's secure context and HTTPS agent on initialization.

---

## Commands & Usage Guide

### 1. `operate`: Autonomous Sovereign Operator (v2.0.0)

Executes continuous 9-phase autonomous storage governance state machine:

```bash
# Continuous fleet governance with 1-hour intervals and 5% mutation ceiling
s3-guardian operate --interval 1h --max-blast-radius 5

# Continuous governance governed by declarative policy document
s3-guardian operate --policy ./corporate-storage-policy.yaml

# Single bucket one-shot dry-run epoch with JSON metrics output
s3-guardian operate my-bucket --once --dry-run --json

# Run against S3-compatible private cloud (MinIO / Ceph)
s3-guardian operate my-bucket --endpoint https://s3.internal.lan --force-path-style
```

### 2. `scan`: Read-Only Inspection

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

## Append-Only State Ledger, Streaming Compaction & Audit History (v1.7.0)

`s3-guardian` records every diagnostic and mutative decision as a linearizable, strictly-typed JSONL event in `${stateDir}/audit.jsonl`:

```bash
# Compact active audit.jsonl into compressed snapshot (snapshots/snapshot-<timestamp>.json.gz)
s3-guardian state compact

# Compact state and mirror the compressed snapshot to a designated S3 audit bucket
s3-guardian state compact --s3-mirror my-enterprise-audit-bucket

# Inspect historical remediation and FinOps metrics for a specific bucket
s3-guardian state history production-data-lake

# Output machine-readable JSON history report
s3-guardian state history production-data-lake --json
```

### Key Capabilities & Invariants
- **Append-Only Serialization:** `AuditLogWriter` serializes events through an internal promise queue, preventing interleaved writes under concurrency, and respects write stream backpressure (`drain`).
- **Zero-Memory Streaming Compaction:** `Compactor.compactAuditLog` streams `audit.jsonl` line-by-line via `node:readline`, maintaining a strict $< 50\text{ MB}$ RSS memory footprint regardless of log size. High-volume `DISCOVERY` lines are pruned while preserving per-bucket FinOps totals.
- **Atomic Multi-Step State Rotation:** Rotates active `audit.jsonl` to `audit.jsonl.rotating.<timestamp>`, immediately initializes a clean empty `audit.jsonl`, compresses aggregates into `snapshots/snapshot-<timestamp>.json.gz`, and unlinks the rotated file upon commit.
- **Windows NTFS Safety (`writeAtomic`):** Writes temporary files to the same directory, flushes data with `fd.sync()`, and retries with exponential backoff + full jitter (up to 3s) on transient `EPERM`/`EBUSY` locks before skipping unsupported directory fsync on Windows.

---

## Cryptographic Rollback Engine, Soft Delete Re-hydration & SOC 2 Certificates (v1.8.0)

### 12. `rollback`: Cryptographic State Inversion with Remote Drift Verification
Inverts reversible mutations (lifecycle configuration updates, bucket tagging updates, soft delete markers) recorded in an `UndoManifest`. Computes live remote state hashes via RFC 8785 canonical JSON and SHA-256, halting on divergence unless `--force` is passed:

```bash
# Verify live remote state and rollback mutation
s3-guardian rollback .s3-guardian/undo/undo-my-bucket-2026-09-20T17-00-00.json

# Force rollback execution despite live remote state drift
s3-guardian rollback .s3-guardian/undo/undo-my-bucket-2026-09-20T17-00-00.json --force

# Output machine-readable JSON restoration summary
s3-guardian rollback .s3-guardian/undo/undo-my-bucket-2026-09-20T17-00-00.json --json
```

### 13. `certificate`: SOC 2 CC6.8 / ISO 27001 A.8.10 Deletion Certificates
Displays and validates unforgeable deletion certificates generated at the conclusion of permanent object version purges and aborted multipart uploads:

```bash
# View formatted compliance certificate with item ledger
s3-guardian certificate .s3-guardian/certificates/deletion-certificate-my-bucket-2026-09-20T17-00-00.json

# Export raw JSON certificate for compliance archiving
s3-guardian certificate .s3-guardian/certificates/deletion-certificate-my-bucket-2026-09-20T17-00-00.json --json
```

### 14. `rehydrate`: Soft Delete Tombstone Popping
Safely un-deletes soft-deleted items by permanently removing latest Delete Markers (`IsLatest === true`) using `DeleteObjectsCommand` with `Quiet: true`, elevating the previous data version to active status:

```bash
# Simulate soft delete rehydration without deleting markers (dry run)
s3-guardian rehydrate my-bucket --dry-run

# Rehydrate all soft-deleted objects in the bucket
s3-guardian rehydrate my-bucket

# Rehydrate delete markers matching an ISO 8601 or interval threshold
s3-guardian rehydrate my-bucket --older-than 2026-08-01T00:00:00Z --json
```

---

## Declarative Storage Policy Engine & Precedence Hierarchy (v1.9.0)

Define centralized, declarative storage lifecycle rules using native JSON or the zero-dependency Guardian YAML subset:

```yaml
schemaVersion: "1"
policyId: enterprise-standard-lifecycle
scope:
  level: BUCKET_TAG
  priority: 100
defaults:
  action: AUTO_REMEDIATE
  mpuAbortDays: 7d
rules:
  - id: cleanup-temp-uploads
    match:
      object:
        prefix: tmp/
    expirationDays: 7d
  - id: archive-production-data
    match:
      object:
        prefix: data/
        tags:
          RetentionTier: Archive
        minSizeKb: 128KiB
    transitions:
      - days: 30d
        storageClass: STANDARD_IA
      - days: 90d
        storageClass: GLACIER
    expirationDays: 365d
```

### Key Capabilities:
- **Zero-Dependency YAML/JSON Subset Parser:** Line tokenization, indentation tracking (tabs strictly rejected), human durations (`7d`, `24h`), and human sizes (`128KiB`, `1MiB`).
- **Precedence Hierarchy:** `OBJECT_TAG (40)` > `BUCKET_TAG (30)` > `ACCOUNT (25)` > `OU (20)` > `GLOBAL (10)`. Leaf-level property merging with provenance tracking.
- **Fail-Safe Action Mode:** Most restrictive wins: `MONITOR_ONLY (1)` < `PLAN_ONLY (2)` < `AUTO_REMEDIATE (3)`.
- **Static FinOps Safety Guards:** Enforces 128 KiB minimum transition size floor, MPU churn guard ($\ge 7$d), tag/MPU contradiction separation, and Glacier ($\ge 90$d) / Deep Archive ($\ge 180$d) early deletion penalties.

### CLI Usage Examples:

```bash
# Statically validate policy syntax and FinOps safety guards
s3-guardian policy validate policy.yaml

# Generate live plan preview with leaf merge and provenance tracking
s3-guardian policy plan my-bucket --policy policy.yaml --out plan.json

# Apply compiled lifecycle configuration to AWS S3 with UndoManifest
s3-guardian policy apply my-bucket --policy policy.yaml --confirm

# Audit declarative policy compliance across fleet buckets
s3-guardian scan --all-buckets --policy policy.yaml
```

---

## Full CLI Reference

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `policy validate <file>` | command | — | Statically validate JSON or Guardian YAML subset policy document |
| `policy plan <bucket>` | command | — | Evaluate bucket tags, resolve precedence, and output preview |
| `policy apply <bucket>` | command | — | Apply compiled configuration and write UndoManifest (requires `--confirm`) |
| `--policy <file>` | string | — | Path to declarative storage policy file (JSON or YAML subset) |
| `rollback <manifest>` | command | — | Invert mutation from UndoManifest with RFC 8785 state verification |
| `certificate <cert>` | command | — | Format and display SOC 2 / ISO 27001 immutable deletion certificate |
| `rehydrate <bucket>` | command | — | Safely pop Delete Markers to un-delete and restore hidden data versions |
| `--force` | flag | `false` | Force rollback execution even if remote state has diverged |
| `--dry-run` | flag | `false` | Simulate soft delete rehydration without deleting Delete Markers |
| `state compact` | command | — | Compact active audit log into compressed snapshot and rotate log |
| `state history <bucket>` | command | — | View synthesized historical FinOps metrics and audit events for a bucket |
| `--state-dir <path>` | string | `.s3-guardian` | Path to persistent state directory for audit ledger and snapshots |
| `--s3-mirror <bucket>` | string | — | S3 bucket destination to mirror compressed state snapshots |
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
| `--bypass-mutation-ceiling` | flag | `false` | Bypass relative bucket mutation ceiling safety check (default <= 5%) |
| `--no-canary` | flag | `false` | Skip pre-flight canary verification probe |
| `--max-deletion-percent <pct>` | number | `5` | Custom relative mutation ceiling percentage (e.g. 10 for 10%) |
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

## SemVer 2.0 Exit Code Contract

`s3-guardian v2.0.0` establishes a strict, stable exit code contract across all CLI subcommands, operators, and CI/CD pipelines:

| Exit Code | Classification | SemVer Contract Description |
| :--- | :--- | :--- |
| `0` | `SUCCESS` | Successful execution; scan clean, plan generated, apply completed, or policies satisfied |
| `1` | `CONFIG_ARG_ERROR` | CLI configuration, syntax, or argument error (invalid duration, missing required bucket/manifest) |
| `2` | `AUTH_IAM_ERROR` | Authentication failure, IAM AccessDenied, Organizations discovery failure, or STS AssumeRole rejection |
| `3` | `POLICY_VIOLATION` | Declarative policy rule violation, policy validation invariant breach, `--max-waste-usd` exceeded, or unapproved IaC drift |
| `4` | `CIRCUIT_CANARY_BLAST_RADIUS` | Circuit breaker tripped (OPEN), canary verification probe failed, relative blast radius ceiling breached, or Wasabi 90-day retention guard triggered |
| `5` | `FS_STATE_ERROR` | Local or remote filesystem / state store corruption, unreadable state file, or I/O failure |
| `6` | `NETWORK_TIMEOUT` | Network connection refused, DNS timeout, socket timeout (`ETIMEDOUT`), or AWS SDK `TimeoutError` |

---

## Production Safety Matrix

| Threat / Invariant | Risk Level | Defense Mechanism | Override Flag |
| :--- | :--- | :--- | :--- |
| **Object Lock COMPLIANCE** | `CRITICAL_BLOCKED` | Hard abort before sending API calls. Deletions strictly forbidden. | None (Immutable) |
| **Object Lock GOVERNANCE** | `HIGH` | Verified via `GetObjectLockConfiguration`. Header withheld unless verified. | `--bypass-governance` |
| **Proportional Mutation Ceiling** | `POLICY_VIOLATION` | Caps deletions to <= 5% of bucket inventory (or 1,000 objects fallback). | `--bypass-mutation-ceiling` |
| **Canary Verification Gate Failure** | `POLICY_VIOLATION` | 10 oldest targets pre-flight probed via HeadObject before batch execution. | `--no-canary` |
| **Circuit Breaker (403 Cliff)** | `OPEN` | Trips immediately after 3 consecutive AccessDenied errors to prevent IAM hammering. | Fix IAM permissions |
| **Circuit Breaker (503 Throttling)** | `ADAPTIVE` | Halves concurrency; trips to OPEN on burst (>= 3 in 5s) or >10% sustained error rate. | Automatic backoff |
| **Circuit Breaker (400 BadDigest)** | `QUARANTINE` | Immediate trip to OPEN and bucket quarantine on checksum mismatch / integrity corruption. | Investigate corruption |
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

