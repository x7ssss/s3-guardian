# s3-guardian

CLI tool to detect, quantify, and safely clean up abandoned multipart uploads in AWS S3 and S3-compatible object stores (MinIO, Cloudflare R2).

## The Problem

When a multipart upload starts in S3, storage charges begin accruing the moment parts are uploaded. If the upload process crashes, times out, or disconnects without completing or aborting:

- Uploaded parts **never** appear in `ListObjectsV2` or the standard AWS Console file browser.
- Storage fees accrue indefinitely at AWS S3 Standard baseline rates ($0.023/GB/month).
- Over months and years, abandoned uploads can silently waste gigabytes or terabytes of stranded storage.

`s3-guardian` solves this by enumerating incomplete multipart uploads, calculating stranded byte volumes and projected financial bleed down to the cent, and safely aborting them through a deterministic two-phase workflow.

## Core Invariants

1. **Zero Runtime Bloat:** Depends solely on the official `@aws-sdk/client-s3` (v3). No heavy CLI frameworks (uses Node's native `node:util` `parseArgs`), no utility bloat, no telemetry.
2. **Safety-First / Two-Step Deletion:** `scan` and `plan` commands are 100% read-only. Deletions require generating a deterministic `plan.json` first, followed by an explicit `apply --plan <file> --confirm`.
3. **Deterministic Output:** Plan files sort uploads deterministically by key and upload ID, with exact stranded byte tallies and estimated monthly run-rate waste.
4. **Rate-Limit & Concurrency Control:** Part listing and abort execution are capped at a concurrency limit of 10, backed by exponential backoff with full jitter on `503 Slow Down` rate-limits.
5. **S3-Compatible & Ambient Credentials:** Uses standard AWS credential chains (`~/.aws/credentials`, environment variables, IAM roles). Compatible with MinIO, Cloudflare R2, and LocalStack via `--endpoint` (or `AWS_ENDPOINT_URL`) and `--force-path-style`.

## Quickstart

Run directly with `npx` (requires Node.js 20+):

### 1. Scan a Bucket (Read-Only)

List zombie uploads older than 7 days (default) and quantify stranded storage:

```bash
npx s3-guardian scan my-bucket
```

Options:
```bash
# Scan with custom age threshold (e.g. older than 14 days)
npx s3-guardian scan my-bucket --older-than 14

# Output machine-readable JSON
npx s3-guardian scan my-bucket --json

# S3-compatible providers (MinIO / Cloudflare R2 / LocalStack)
npx s3-guardian scan my-bucket --endpoint http://localhost:9000 --force-path-style
```

### 2. Generate an Execution Plan (Read-Only)

Generate an inspectable, reviewable `plan.json`:

```bash
npx s3-guardian plan my-bucket --out plan.json --older-than 7
```

Example `plan.json`:

```json
{
  "schemaVersion": "1.0",
  "generatedAt": "2026-09-20T12:00:00.000Z",
  "bucket": "my-bucket",
  "endpoint": null,
  "olderThanDays": 7,
  "totalZombieUploads": 2,
  "totalStrandedBytes": 104857600,
  "estimatedMonthlyWasteUSD": 0.02,
  "uploads": [
    {
      "key": "backups/db-2026-09-01.tar",
      "uploadId": "4vQ3...",
      "initiated": "2026-09-01T04:12:00.000Z",
      "partsCount": 20,
      "bytes": 104857600
    }
  ]
}
```

### 3. Apply the Plan (Requires Confirmation)

Execute deletions bounded at concurrency 10 with automatic retry on throttling:

```bash
npx s3-guardian apply --plan plan.json --confirm
```

> **Note:** Running `apply` without `--confirm` will refuse execution with exit code 1 to prevent accidental data loss. Uploads that were already completed or aborted externally are gracefully caught as `SKIPPED_ALREADY_ABORTED`.

## CLI Reference

```
USAGE:
  s3-guardian scan <bucket> [options]
  s3-guardian plan <bucket> --out <file> [options]
  s3-guardian apply --plan <file> --confirm [options]

COMMANDS:
  scan <bucket>           Read-only scan of incomplete multipart uploads
  plan <bucket>           Generate an inspectable, deterministic JSON plan file
  apply                   Execute aborts defined in a plan file (requires --confirm)

OPTIONS:
  --older-than <days>     Age threshold in days (default: 7)
  --out <file>            Output path for plan file (default: plan.json)
  --plan <file>           Plan file to apply
  --confirm               Explicit confirmation required to execute apply deletions
  --endpoint <url>        Custom S3 endpoint URL (MinIO, Cloudflare R2, LocalStack)
  --force-path-style      Use S3 path-style addressing
  --region <region>       AWS Region (default: us-east-1 or AWS_REGION)
  --prefix <prefix>       Filter uploads by object key prefix
  --json                  Output results in JSON format
  -h, --help              Show help message
  -v, --version           Show version
```

## Development & Testing

```bash
# Install dependencies
npm install

# Run unit test suite (Vitest + aws-sdk-client-mock)
npm test

# Build TypeScript
npm run build
```

## License

MIT
