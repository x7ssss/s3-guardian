# s3-guardian — Technical Specification & Invariants

## Core Mission
A zero-runtime-dependency CLI that detects, quantifies, and safely eliminates invisible cloud storage bleed across AWS S3 and S3-compatible providers (Cloudflare R2, MinIO).

## Critical Pain Points Solved
1. **Incomplete Multipart Uploads ("Zombie Uploads"):**
   - Parts uploaded via `UploadPart` that were never completed or aborted due to crashes, network failures, or timeouts.
   - Completely invisible in AWS Console file listings and standard `s3:ListObjectsV2`.
   - Billed at standard object storage rates ($0.023/GB/month on AWS S3 Standard).
2. **Delete Marker Bloat & Non-Current Version Graveyards:**
   - Soft-deleted versioned buckets accumulating millions of tombstone delete markers.
   - Causes severe directory degradation (List Objects Slowdown Factor) and ongoing storage fees.
3. **Missing Lifecycle Policies:**
   - Buckets missing `AbortIncompleteMultipartUpload` lifecycle rules.

## Core Architectural Invariants
1. **Zero Runtime Dependencies:**
   - Built with modern Node.js 20+ (ESM) and native `node:https` / `node:crypto` (or the official lightweight `@aws-sdk/client-s3` without enterprise framework bloat). Zero bloated CLI frameworks.
2. **Safety-First / Read-Only Default:**
   - `scan` and `audit` commands are 100% non-destructive and strictly read-only.
   - Deletions are never executed directly via interactive wildcards.
   - Every cleanup requires a two-step workflow:
     1. `scan` / `plan` generates a strictly deterministic, inspectable JSON plan (e.g., `plan-2026-09-20.json`).
     2. `apply` strictly requires passing `--plan <file>` and `--confirm`.
3. **Deterministic Financial Run-Rate Calculations:**
   - Quantifies exact wasted bytes and outputs projected monthly financial run-rate based on region-aware storage rates.
   - Computes both bytes and dollar bleed down to the cent.
4. **Local-First & Standard Credentials:**
   - Authenticates strictly using standard AWS ambient credentials (`~/.aws/credentials`, environment variables `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, or instance metadata).
   - Zero SaaS logins, no hosted dependencies, no accounts required, no telemetry.

## Command Interface
- `s3-guardian scan [bucket]`: Read-only scan of incomplete multipart uploads and un-expiring delete markers.
- `s3-guardian audit --all`: Scans all accessible buckets in the region/profile.
- `s3-guardian plan --bucket <name> --older-than <days> --out plan.json`: Emits an immutable, signed reviewable JSON deletion plan.
- `s3-guardian apply --plan plan.json --confirm`: Executes batch aborts/deletions defined in the plan file with progress reporting and exponential backoff on 503 Slow Down.
- `s3-guardian heal --bucket <name> --lifecycle-days 7`: Idempotently attaches an `AbortIncompleteMultipartUpload` lifecycle configuration.