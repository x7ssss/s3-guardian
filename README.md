# s3-guardian

[![npm version](https://img.shields.io/badge/npm-v1.0.1-blue.svg)](https://www.npmjs.com/package/s3-guardian)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Runtime Dependencies](https://img.shields.io/badge/dependencies-0%20(AWS%20SDK%20v3%20only)-success.svg)](https://github.com/x7ssss/s3-guardian)
[![Node Version](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen.svg)](https://nodejs.org/)

Enterprise-grade CLI and SDK to detect, quantify, and safely clean up abandoned multipart uploads, noncurrent object versions, and expired delete markers across AWS S3 and S3-compatible object stores (Cloudflare R2, MinIO).

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

---

## Full CLI Reference

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--older-than <days>` | number | `7` | Age threshold in days for multipart uploads and versions |
| `--include-versions` | flag | `false` | Scan and plan for noncurrent versions and expired delete markers |
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
| `1` | `POLICY_VIOLATION` | Safety gate tripped (Object Lock, churn, tampered plan) or CI/CD budget breached |
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
| **Plan Tampering** | `POLICY_VIOLATION` | RFC 8785 JCS canonicalization with SHA-256 target hash verification. | Re-generate plan |
| **S3 503 Throttling** | Handled | Exponential backoff with full jitter (Decorrelated Jitter). | Automatic |

---

## License

MIT © Google Antigravity & contributors.
