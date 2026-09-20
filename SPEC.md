# s3-guardian — Technical Specification & Invariants

**Version:** 2.0.0 (General Availability)  
**Classification:** Enterprise System Architecture & Protocol Specification  
**Status:** Approved for Production  

---

## 1. Architectural Mission & Core Invariants

`s3-guardian` is an enterprise-grade CLI and SDK designed to detect, quantify, and safely eliminate invisible cloud storage bleed across AWS S3 and S3-compatible object stores (Cloudflare R2, MinIO) without generating out-of-band infrastructure drift.

### 1.1 Non-Negotiable Invariants

1. **Zero Third-Party Runtime Dependencies:**
   - Permitted dependencies are strictly the official AWS SDK v3 client modules: `@aws-sdk/client-s3`, `@aws-sdk/client-sts`, and `@aws-sdk/client-organizations`.
   - All other functionality utilizes native Node.js 20+ runtime primitives (`node:crypto`, `node:readline`, `node:util`, native `fetch`, native ESM).
2. **Two-Phase Commit Safety Model:**
   - Read-only commands (`scan`, `scan-versions`, `plan`, `lens`) never mutate object state or lifecycle configurations.
   - Destructive operations (`apply`) strictly require an immutable, cryptographically verified `plan.json` and explicit operator confirmation via `--confirm`.
3. **Pre-Flight Blast Radius Validation:**
   - Every mutation is preceded by a simulated blast-radius assessment.
   - Deletions are forbidden when buckets are protected by Object Lock Compliance, protected tags, or streaming pipeline prefixes.
4. **GitOps First (Anti-Drift):**
   - Remediation defaults to generating deterministic Terraform HCL or CloudFormation YAML code.
   - Opt-in direct API mutation (`--danger-direct-api-apply`) executes an atomic Read-Modify-Write operation that preserves 100% of existing bucket lifecycle rules.
5. **Memory Safety & Bounded Resource Consumption:**
   - Massive object listings stream via paginated async generators. Storage Lens CSV parsing operates in $O(1)$ constant memory using native `node:readline`.

---

## 2. Plan Specification & Schema Evolution

The Plan format represents an immutable contract between inspection and mutation.

### 2.1 Schema Version Matrix

| Schema | Version Introduced | Key Additions / Capabilities |
| :--- | :--- | :--- |
| **1.0** | v0.1.0 | Initial release: basic bucket metadata and upload key/uploadId array. |
| **1.1** | v0.2.0 | Added `storageClass`, per-upload `lifecycleStatus`, and bucket `lifecycleAudit`. |
| **1.2** | v0.6.0 | Added `versionDeletions` array, noncurrent version tracking, and Expired Object Delete Marker (EODM) counts. |
| **1.3** | v1.0.0 (GA) | Upgraded with RFC 8785 SHA-256 `planHash`, embedded `blastRadiusAudit`, and `highVolumeWarning` (>10k targets). |

### 2.2 Schema 1.3 Specification

```typescript
interface Plan {
  schemaVersion: "1.3";
  generatedAt: string;                // ISO 8601 UTC timestamp
  bucket: string;                     // Target bucket identifier
  endpoint: string | null;            // Custom endpoint (e.g. MinIO/R2) or null for AWS S3
  olderThanDays: number;              // Age threshold applied during scanning
  totalZombieUploads: number;         // Count of multipart uploads scheduled for abort
  totalStrandedBytes: number;         // Aggregate stranded byte volume
  estimatedMonthlyWasteUSD: number;   // Projected monthly bleed at $0.023/GiB-month
  lifecycleAudit: {
    bucketHasLifecyclePolicy: boolean;
    hasCoveringRule: boolean;
    ghostRulesDetected: string[];
    providerNotes?: string;
  };
  blastRadiusAudit?: BlastRadiusAssessment; // Pre-flight safety audit results
  planHash?: string;                  // RFC 8785 SHA-256 target payload digest (64 hex characters)
  highVolumeWarning?: string;         // Emitted if total deletion targets exceed 10,000 items
  uploads: ZombieUploadItem[];        // Deterministically sorted upload items
  versionDeletions?: VersionDeletionEntry[]; // Noncurrent versions & delete markers
  totalNoncurrentVersions?: number;
  totalExpiredDeleteMarkers?: number;
  versioningStrandedBytes?: number;
  versioningMonthlyWasteUSD?: number;
}
```

---

## 3. RFC 8785 JSON Canonicalization Scheme (JCS) & Plan Verification

To eliminate attack vectors involving unauthorized modification of deletion targets between the `plan` and `apply` phases, Schema 1.3 enforces cryptographic target verification.

### 3.1 Canonicalization Algorithm (RFC 8785)

1. **Key Sorting:** Object keys are sorted lexicographically according to UTF-16 code units.
2. **Whitespace Stripping:** Structural characters (`:`, `,`, `{`, `}`, `[`, `]`) have zero whitespace padding.
3. **Primitives Representation:**
   - Strings: Escaped per ECMAScript `JSON.stringify`.
   - Numbers: Deterministic ECMAScript string representation.
   - Booleans: `true` / `false`.
   - Nulls: `null`. `undefined` object properties are omitted; `undefined` array elements map to `null`.

### 3.2 Canonical Target Payload & Hash Computation

The plan target payload extracts strictly the mutation targets:

```typescript
interface PlanHashableTargets {
  bucket: string;
  olderThanDays: number;
  uploads: Array<{ key: string; uploadId: string }>;
  versionDeletions: Array<{ key: string; versionId: string; type: string }>;
}
```

```
planHash = SHA-256( JCS(PlanHashableTargets) )
```

At `apply` time, `verifyPlanIntegrity(plan)` recalculates the canonical payload and hash. If the computed hash does not strictly match `plan.planHash`, execution aborts with exit code `1` (`POLICY_VIOLATION`).

---

## 4. Pre-Flight Blast Radius Engine

Before issuing deletion commands, the executor initiates pre-flight simulation against the target bucket.

```
                  ┌──────────────────────────────┐
                  │  assessBucketBlastRadius()   │
                  └──────────────┬───────────────┘
                                 │
     ┌───────────────────────────┼───────────────────────────┐
     ▼                           ▼                           ▼
[Object Lock]              [Replication]               [Prefixes & Tags]
  • COMPLIANCE:               • Active CRR/SRR:           • Protected Prefixes:
    CRITICAL_BLOCKED            HIGH Risk                   CRITICAL_BLOCKED
  • GOVERNANCE:               • Divergence Ack:           • Protected Tags:
    HIGH (needs bypass)         MEDIUM                      CRITICAL_BLOCKED
```

### 4.1 Safety Assessment Rules

1. **Object Lock Compliance Mode:**
   - Detects `ObjectLockConfiguration.Rule.DefaultRetention.Mode === "COMPLIANCE"`.
   - Emits `BLOCKED_COMPLIANCE_LOCK`. Risk: `CRITICAL_BLOCKED`. Hard-blocks execution.
2. **Object Lock Governance Mode:**
   - Detects `Mode === "GOVERNANCE"`.
   - Emits `GOVERNANCE_LOCK_ACTIVE`. Risk: `HIGH`. Requires explicit `--bypass-governance`.
   - **Critical Invariant:** `BypassGovernanceRetention: true` is strictly prohibited on buckets without verified GOVERNANCE mode Object Lock.
3. **Replication Divergence (CRR / SRR):**
   - Detects active replication rules via `GetBucketReplication`.
   - Warns that permanent version deletions do not replicate across regions. Emits `REPLICATION_DETECTED`. Risk: `HIGH`. Requires `--acknowledge-replication-divergence`.
4. **Protected Pipeline & Ingestion Prefixes:**
   - Target keys matching any of `checkpoints/`, `savepoints/`, `_wal/`, `manifests/`, `iceberg/`, `glue-shuffle-data/`, `terraform/`, or `state/` are flagged as `PROTECTED_PREFIX_DETECTED`.
   - Risk: `CRITICAL_BLOCKED`. Hard-blocks execution to prevent pipeline state corruption.
5. **Protected Tags:**
   - Buckets tagged with `s3-guardian:ignore=true`, `Backup=true`, or `Protection=locked` emit `PROTECTED_TAG_DETECTED`.
   - Risk: `CRITICAL_BLOCKED`. Excluded from fleet mutations.
6. **Active Churn Guard (<24 Hours):**
   - Uploads or versions initiated or modified within 24 hours of execution emit `ACTIVE_CHURN_DETECTED`.
   - Risk: `HIGH`. Requires `--allow-active-churn` to prevent deleting in-flight writes.

---

## 5. Concurrency, Throttling & Fault Isolation

### 5.1 Concurrency Limits

- **S3 API Worker Concurrency:** Bounded at maximum **10** concurrent promises per bucket.
- **Multi-Account Sweep Concurrency:** Bounded at maximum **5** concurrent member account sessions.
- **Account-Level Rate Limit:** Bounded at **10 TPS** per member account to avoid STS throttling.

### 5.2 Exponential Backoff with Full Jitter

When S3 or STS responds with `SlowDown`, `503 Service Unavailable`, `Throttling`, or `InternalError`:

$$\text{Delay} = \text{random}(0, \min(\text{cap}, \text{base} \times 2^{\text{attempt}}))$$

Where $\text{base} = 100\,\text{ms}$, $\text{cap} = 20{,}000\,\text{ms}$, and $\text{maxRetries} = 5$.

### 5.3 Account-Level & Bucket-Level Fault Isolation

- An authorization failure (`403 Forbidden`, SCP block) on bucket $N$ isolates the error to bucket $N$ and proceeds to bucket $N+1$.
- Member account STS assumption failures isolate the error to account $M$ and proceed to account $M+1$.
- Multi-account sweeps aggregate partial results and return exit code 0 unless policy gates are breached.

---

## 6. Bulk Mutation Safety & CloudTrail Correlation

### 6.1 Quiet Bulk Deletion with Unconditional Error Inspection

When executing `DeleteObjectsCommand`:
- Batches are partitioned into chunks of maximum 1,000 objects.
- `Quiet: true` is enabled to minimize network payload.
- `response.Errors` is **unconditionally inspected**. Transient errors (`SlowDown`, `InternalError`) are retried with jitter; permanent failures are recorded in the execution audit log.

### 6.2 Forensic CloudTrail Correlation

Every mutation batch captures HTTP response metadata:
- `x-amz-request-id` (`$metadata.requestId`)
- `x-amz-id-2` (`$metadata.extendedRequestId`)

These identifiers are correlated with bucket and key targets in structured progress output, enabling instant cross-referencing against AWS CloudTrail Data Events.

---

## 7. Deterministic POSIX Exit Codes

| Code | Label | Trigger Condition |
| :--- | :--- | :--- |
| `0` | `SUCCESS` | Normal operation completed without policy or safety violations. |
| `1` | `POLICY_VIOLATION` | Safety gate tripped (Object Lock, churn, tampered plan) or `--max-waste-usd` breached. |
| `2` | `ARG_ERROR` | Malformed CLI arguments, unknown flags, or invalid threshold parameters. |
| `3` | `DISCOVERY_AUTH_ERROR` | Fatal authentication failure, Organizations discovery error, or missing credentials. |

---

## 8. Single Executable Application (SEA) Protocol

`s3-guardian` supports packaging into a self-contained single executable application using Node.js 20+ SEA capabilities:

```json
{
  "main": "./dist/cli.js",
  "output": "./dist/sea-prep.blob",
  "disableExperimentalSEAWarning": true
}
```

Generation command:
```bash
npm run build:sea
```
This produces a standalone binary preparation blob ready for node injection without external `node_modules` distribution requirements.

---

## 9. Glacier & Storage Class Transition Trap Auditor Specification (v1.1.0)

### 9.1 Small-Object Transition Penalty Mechanics & Exact Byte-Level Math

Transitioning small objects into archive or infrequent access tiers often causes significant financial penalties rather than savings due to minimum billable size floors, fixed metadata overhead, and transition request fees.

#### Mathematical Pricing Invariants (US-East-1 Baseline):
1. **S3 Standard Baseline Rate:** $0.023 / GiB / month ($0.00000002142 / byte / month).
2. **Standard-IA / One Zone-IA Floor:**
   - Minimum billable size floor: 128 KiB (131,072 bytes).
   - Any object with size $< 131,072$ bytes is billed for 131,072 bytes at $0.0125 / GiB / month (or $0.0100 for One Zone-IA).
   - Transition request fee: $0.01 / 1,000 requests ($0.00001 / request).
3. **Glacier Instant Retrieval (GIR) Floor:**
   - Minimum billable size floor: 128 KiB (131,072 bytes).
   - Storage rate: $0.0040 / GiB / month.
   - Transition request fee: $0.05 / 1,000 requests ($0.00005 / request).
4. **Glacier Flexible Retrieval (GFR) & Deep Archive (GDA) Fixed Metadata Overhead:**
   - Actual object size is billed with NO 128 KiB floor.
   - **Fixed 40 KiB metadata overhead per object:**
     - 8 KiB billed at S3 Standard rate ($0.023 / GiB / month) for object name and metadata.
     - 32 KiB billed at target Glacier tier rate ($0.0036 / GiB / month for GFR, $0.00099 / GiB / month for GDA) for index and vault metadata.
   - Transition request fee: $0.05 / 1,000 requests ($0.00005 / request).

#### Net Monthly Delta & Breakeven Formula:
- $\text{EffectiveBillableSize} = \max(\text{AverageSizeBytes}, \text{MinBillableFloor})$
- $\text{TargetMonthlyStorage} = (\text{ObjectCount} \times \text{EffectiveBillableSize} / \text{GiB}) \times \text{TierRate}$
- $\text{MetadataOverheadMonthly} = (\text{ObjectCount} \times 8192 / \text{GiB}) \times 0.023 + (\text{ObjectCount} \times 32768 / \text{GiB}) \times \text{GlacierRate}$
- $\text{AmortizedTransitionFee} = \text{TransitionRequestFee} / (\text{DurationDays} / 30)$
- $\text{NetMonthlyDelta} = \text{TargetMonthlyStorage} + \text{MetadataOverheadMonthly} + \text{AmortizedTransitionFee} - \text{BaselineStandardCost}$
- $\text{isPenalty} = \text{NetMonthlyDelta} > 0$
- If ongoing monthly savings $\le 0$: $\text{breakevenMonths} = \text{null}$ (penalty in perpetuity).
- If ongoing monthly savings $> 0$: $\text{breakevenMonths} = \text{TransitionRequestFee} / \text{OngoingMonthlySavings}$.

### 9.2 Transition Rule Audit Protocol

The `auditBucketTransitions` engine inspects all enabled `LifecycleRule` elements returned by `GetBucketLifecycleConfigurationCommand`:
1. Inspects both standard `Transitions` and `NoncurrentVersionTransitions`.
2. Flags any rule targeting `STANDARD_IA`, `ONEZONE_IA`, `GLACIER_IR`, `GLACIER`, or `DEEP_ARCHIVE` that:
   - Completely LACKS an `ObjectSizeGreaterThan` filter constraint, OR
   - Defines `ObjectSizeGreaterThan < 131072` bytes (128 KiB).
3. Samples bucket small-object density ($< 128$ KiB) via `ListObjectsV2Command` to quantify actual object count and average small-object size.
4. Computes deterministic projected financial penalty in USD/month.

### 9.3 Automated IaC Remediation & Filter Injection

To eliminate drift and ensure GitOps compliance:
- Lifecycle remediation generators automatically inject `object_size_greater_than = 131072` (Terraform) and `ObjectSizeGreaterThan: 131072` (CloudFormation) inside rule filters when transition targets are specified.
- Dedicated remediation generators (`generateTerraformTransitionRemediation`, `generateCloudFormationTransitionRemediation`) emit drop-in HCL / YAML snippets to instantly constrain unconstrained existing transition rules.

---

## 10. Continuous In-Process Daemon & Governance Engine Specification (v1.2.0)

### 10.1 Architecture & Native Invariants
`s3-guardian` provides a continuous storage governance and FinOps daemon designed for resilient production environments:
1. **Zero External Daemon Dependencies:** Strictly zero external scheduler or process manager libraries (no `node-cron`, no `pm2`, no external daemon packages). Operates 100% on Node.js 20+ runtime primitives (`process.hrtime.bigint()`, `process.memoryUsage()`, `os.tmpdir()`, and native `node:fs`).
2. **Signal-Safe Process Control:** Traps `SIGINT` (Ctrl+C) and `SIGTERM`, allowing in-flight network requests, multi-bucket audits, and version scans to finish before closing connections and exiting.
3. **Memory Safety & Non-Leaking Resource Management:** Tracks heap and resident set size (RSS) across runs to detect and prevent memory leaks during long-running daemon execution.

### 10.2 Drift-Free Monotonic Scheduler
Standard interval scheduling via `setInterval` or fixed `setTimeout(interval)` drifts cumulatively over time by the execution duration of each run. `s3-guardian` implements a drift-free monotonic scheduling algorithm:
1. **High-Resolution Monotonic Delta Timing:** Captures start and finish timestamps using `process.hrtime.bigint()` in nanoseconds.
2. **Drift Elimination:**
   $$\text{RunDurationMs} = \frac{\text{EndHr} - \text{StartHr}}{1,000,000}$$
   $$\text{NextDelayMs} = \max(0, \text{IntervalMs} - \text{RunDurationMs}) + \text{JitterMs}$$
   If an audit takes longer than the interval, `NextDelayMs` collapses to 0, running immediately without queue explosion or task starvation.
3. **Interruptible Sleep with AbortSignal:** The sleep mechanism hooks to an `AbortSignal`. When a termination signal (`SIGINT`, `SIGTERM`, or internal abort) is received during sleep, the timer aborts immediately without blocking process termination until the interval expires.

### 10.3 Single-Instance Atomic PID Lockfile Protocol
To prevent concurrent conflicting daemon runs on the same system:
1. **Deterministic Path:** Lockfiles are located at `${os.tmpdir()}/s3-guardian-${sanitizedLockName}.lock`.
2. **Atomic Creation:** Locks are acquired using `fs.writeFileSync(path, pid, { flag: 'wx' })`. If the file already exists, it fails with `EEXIST`.
3. **Stale Lock Detection & Reclamation:**
   - On `EEXIST`, the existing PID is read from the lockfile.
   - Process aliveness is evaluated via `process.kill(pid, 0)`.
   - If the error code is `ESRCH` (No such process), the process has died without releasing the lock (e.g. killed by SIGKILL or machine reboot).
   - The stale lockfile is cleanly unlinked and reacquired atomically.
   - If `process.kill(pid, 0)` succeeds or fails with `EPERM`, the process is active, and `DaemonLockError` is thrown, aborting the duplicate run with exit code 2.
4. **Lifecycle Hooks:** An `exit` listener removes the lockfile synchronously on process exit. Normal clean termination removes both the listener and lockfile.

### 10.4 CLI Flags & Orchestration Modes
- `--daemon`: Enables continuous in-process execution.
- `--interval <duration>`: Configures schedule interval. Accepts human shorthand: `10s`, `30m`, `1h`, `12h`, `24h`, `500ms`, or raw milliseconds.
- `--once`: Executes exactly one iteration in the daemon harness (useful for validating lock acquisition, execution pipeline, and metrics in CI/CD or smoke testing).
- Supported commands: `scan <bucket> --daemon`, `scan --all-buckets --daemon`, `audit-transitions <bucket> --daemon`, `audit-transitions --all-buckets --daemon`.

---

## 11. Terraform Lifecycle Drift Detection & Unified Git Patch Protocol (v1.3.0)

### 11.1 Native Architecture & Core Invariants
To maintain enterprise compliance without out-of-band state mutation:
1. **Zero Third-Party Parser or Diff Libraries:** Operates 100% on Node.js 20+ runtime built-ins. Incorporates native POSIX unified diff generation and native Terraform state v4 JSON parsing.
2. **Read-Only State Inspection:** Drift detection queries live AWS S3 lifecycle rules and reads local `.tf` or `.tfstate` files without modifying any cloud resources or local files, unless `--write` is explicitly passed.
3. **Standard POSIX Unified Diff Format:** Generated patches comply with standard POSIX unified diff specification (`--- a/path\n+++ b/path\n@@ -start,count +start,count @@`), directly applicable via `git apply`.

### 11.2 Terraform State (v4) Ingestion Protocol
The `parseTerraformState` engine reads raw `terraform.tfstate` JSON:
1. Validates schema version (`version === 4`).
2. Scans `resources` for:
   - `aws_s3_bucket_lifecycle_configuration`: Extracts target bucket name (`attributes.bucket` or `attributes.id`) and iterates `attributes.rule` array.
   - `aws_s3_bucket`: Extracts target bucket name and iterates legacy `attributes.lifecycle_rule` array.
   - Dedicated `aws_s3_bucket_lifecycle_configuration` overrides legacy `aws_s3_bucket` definitions when both target the same bucket.
3. Normalizes attributes into `ManagedLifecycleRule` objects:
   - `abortIncompleteMultipartUploadDays`: Extracted from `abort_incomplete_multipart_upload[0].days_after_initiation`.
   - `noncurrentVersionExpirationDays`: Extracted from `noncurrent_version_expiration[0].noncurrent_days`.
   - `expiredObjectDeleteMarker`: Boolean flag from `expiration[0].expired_object_delete_marker`.
   - `transitions` / `noncurrentVersionTransitions`: Storage classes, days, and dates.
   - `objectSizeGreaterThan`: Integer minimum byte filter from `filter[0].object_size_greater_than`.

### 11.3 HCL Patcher & Unified Git Diff Generation
`generateHclPatch` inspects target HCL `.tf` files and performs surgical insertions:
1. **Missing Resource Handling:** If no `aws_s3_bucket_lifecycle_configuration` resource block exists for the bucket, a complete modern resource block is synthesized and appended.
2. **Missing MPU Abort Insertion:** If the resource lacks an `abort_incomplete_multipart_upload` block, an enabled rule (`s3-guardian-abort-mpu`) is injected before the closing brace of the resource block.
3. **Small-Object Transition Trap Constraining:** Transition rules targeting `GLACIER`, `STANDARD_IA`, `ONEZONE_IA`, `GLACIER_IR`, or `DEEP_ARCHIVE` lacking an `object_size_greater_than` filter have `object_size_greater_than = 131072` injected into their `filter` block, preserving existing prefix or tag filters.
4. **POSIX Unified Diff Computation:** `createUnifiedDiff` computes the Longest Common Subsequence (LCS) edit script and formats hunks with 3 lines of contextual padding.

### 11.4 Drift Detection Status Resolution
`detectLifecycleDrift` evaluates discrepancies across five dimensions:
- `IN_SYNC`: All live AWS rules exist in IaC with identical thresholds, status, and safety filters.
- `GHOST_CONFIG`: Either live S3 or IaC declares an MPU abort rule with a Tag filter (which AWS S3 silently ignores).
- `DRIFT_DETECTED`:
  - **Unmanaged Rules:** Rule present in AWS S3 but absent in IaC.
  - **Missing Rules:** Rule declared in IaC but absent in live AWS S3.
  - **Threshold Drifts:** Days after initiation, noncurrent days, status, or transition targets differ.
  - **Safety Gaps:** Bucket lacks an MPU abort rule in IaC, or transition rules lack small-object filters.

---

## 12. Cross-Cloud S3 Provider Hardening & Wasabi Retention Guard (v1.4.0)

### 12.1 Provider Autodetection & Endpoint Regexes
The CLI and SDK support multi-cloud S3-compatible backends with automatic provider detection (`src/providers/detector.ts`):
- **Explicit Override:** `--provider <aws|r2|wasabi|b2|minio|ceph|custom>` overrides regex autodetection.
- **Endpoint Regex Matching:**
  - **Cloudflare R2:** `/\.r2\.cloudflarestorage\.com|\.r2\.dev/i`
  - **Wasabi:** `/\.wasabisys\.com/i`
  - **Backblaze B2:** `/\.backblazeb2\.com/i`
  - **MinIO:** `/:9000$|:9000\/|minio\./i` (or `localhost:9000` / `127.0.0.1:9000`)
  - **Ceph RADOS Gateway:** `/:7480$|:7480\/|\.ceph\.|ceph\./i`
  - **AWS S3:** `/\.amazonaws\.com/i` or fallback when no custom endpoint is provided.
  - **Custom S3:** Any other unmapped custom endpoint.

### 12.2 Provider Quirks & Client Configuration
`configureProviderClient` tailors the `S3ClientConfig` according to target provider semantics:
1. **Cloudflare R2:**
   - Withholds unsupported SDK-generated checksum calculations by configuring `requestChecksumCalculation: "WHEN_REQUIRED"` and `responseChecksumValidation: "WHEN_REQUIRED"`.
   - Defaults region to `'auto'` (if unspecified or `us-east-1`).
2. **MinIO, Ceph, and Backblaze B2:**
   - Enforces S3 path-style addressing (`forcePathStyle: true`).
3. **AWS S3 & Custom:**
   - Preserves standard virtual-hosted style addressing and regional routing.

### 12.3 Provider Middleware Pipeline
`applyProviderMiddleware` attaches custom middleware into the `@aws-sdk/client-s3` middleware stack:
1. **R2 Checksum Header Stripping (`finalizeRequest` step):**
   - Intercepts outgoing HTTP requests and strips `x-amz-sdk-checksum-algorithm` and `x-amz-checksum-crc32` headers case-insensitively before transmission, preventing R2 from rejecting requests with `400 InvalidArgument`.
2. **Ceph / MinIO 405 Suppression (`deserialize` step):**
   - Catches HTTP `405 MethodNotAllowed` errors returned by Ceph RADOS Gateway or MinIO for unsupported S3 extensions (such as `GetObjectLockConfiguration` or `GetBucketLifecycleConfiguration`).
   - Translates the error into a safe empty response payload with `$metadata.httpStatusCode = 405`, preventing fatal process termination during blast radius audits and drift scans.

### 12.4 Zero Socket Leaks (Invariant 2)
All operations consuming S3 object streams (such as `GetObjectCommand` in Storage Lens readers and S3 checkpoint loaders) wrap stream consumption in a `try / finally` block that unconditionally calls `(stream as any).destroy()` on termination or error, preventing keep-alive socket starvation.

### 12.5 Wasabi 90-Day Retention Guard (FinOps Safety)
Wasabi enforces a strict 90-day minimum retention charge policy: deleting objects or multipart uploads younger than 90 days results in Timed Deleted Storage fees equal to the remaining retention duration.
1. **Pre-flight Blast Radius Simulation:**
   - When `provider === "wasabi"`, targets in the deletion list are checked for initiation / last-modified timestamp.
   - If any target is less than 90 days old (`age < 90 * 24 * 60 * 60 * 1000`), the blast radius assessor raises `HIGH_WASABI_RETENTION_RISK` (`risk: "HIGH"`), flagging `requiresWasabiEarlyDeleteBypass = true`.
2. **Execution Gate:**
   - `apply` aborts execution with exit code 1 (`POLICY_VIOLATION`), emitting the warning:
     `"⚠️ Wasabi charges 90 days minimum retention. Deleting objects < 90 days old triggers Timed Deleted Storage fees."`
   - Bypassing this safety gate strictly requires the `--force-wasabi-early-delete` flag.
3. **Executor-Level Enforcement:**
   - Both `executeAbortPlan` and `executeVersionDeletion` directly enforce the Wasabi 90-day check, throwing a descriptive safety error if young targets are passed without `forceWasabiEarlyDelete: true`.

---

## 13. Interactive Terminal Dashboard & TUI Architecture (v1.5.0)

### 13.1 Design Principles & Invariants
1. **Zero External TUI Dependencies:** Built strictly on Node.js 20+ built-ins (`process.stdin.setRawMode`, ANSI escape sequences, `node:events`, `node:readline`). Strictly ZERO dependencies on `ink`, `blessed`, or `cli-cursor`.
2. **Strict Terminal Hygiene Protocol:**
   - On initialization, executes `enterAltScreen()` (`\x1b[?1049h`) to switch into the private alternate terminal screen buffer and `hideCursor()` (`\x1b[?25l`).
   - Hooks one-time signal handlers on `SIGINT`, `SIGTERM`, and `uncaughtException`.
   - On normal termination or interruption, unconditionally restores cursor visibility (`\x1b[?25h`) and the primary screen buffer (`\x1b[?1049l`), ensuring zero shell corruption.
3. **Non-Blocking Navigation:** Decoupled state reducer and event loop guarantee keypress interactions remain responsive and unblocked while network operations (`scanFleet`, `readStorageLensMetrics`, plan generation) run asynchronously in the background.
4. **TTY Protection Guard:**
   - Inspects `process.stdin.isTTY` prior to terminal initialization.
   - When executed in non-interactive CI/CD pipelines or piping environments, cleanly exits with exit code 2 (`ARG_ERROR`), directing users to batch mode: `s3-guardian scan --all-buckets`.

### 13.2 Hotkey Navigation & Interaction Model
- **`[↑]` / `[k]`:** Move selection up with view clamping and scroll synchronization.
- **`[↓]` / `[j]`:** Move selection down with view clamping and scroll synchronization.
- **`[Enter]`:** Toggle Selected Bucket Detail Drawer (displays region, provider, oldest zombie upload timestamp, EODM count, lifecycle rule status, and ghost rule warnings).
- **`[p]`:** Trigger background plan generation for selected bucket (`plan-<bucket>.json`), executing blast radius simulation and RFC 8785 cryptographic hash generation.
- **`[r]`:** Asynchronously re-scan fleet metrics and refresh table data.
- **`[q]` / `[Esc]` / `[Ctrl+C]`:** Cleanly teardown raw mode and restore terminal primary buffer.

### 13.3 Pure State Machine Reducer
The dashboard state is managed via a deterministic pure reducer `dashboardReducer(state, action)`:
- `NAVIGATE_UP` / `NAVIGATE_DOWN`: Updates `selectedIndex` and shifts `scrollOffset` against `maxVisibleRows`.
- `TOGGLE_DRAWER`: Flips `isDrawerOpen` boolean state.
- `SET_STATUS`: Updates footer status message.
- `SET_BUCKETS`: Ingests audited buckets, recalculates `totalMonthlyWasteUSD`, clamps `selectedIndex`, and resets `isLoading`.
- `PLAN_CREATED`: Records `lastPlanPath` and updates status line with completion feedback.
- `SET_LOADING`: Updates loading progress indicator.

### 13.4 Storage Lens Instant Triage Integration
When launched with `--lens <source>`, the dashboard bypasses live S3 bucket listing and immediately populates the fleet triage view from AWS Storage Lens CSV exports via `readStorageLensMetrics`, enabling instant macro-level governance with zero data-plane API overhead.

---

## 14. Autonomous Circuit Breakers, Canary Verification Gates & Mutation Ceilings (v1.6.0)

### 14.1 Zero-Allocation Error Tracking (Volumetric Ring Buffer)
To eliminate garbage collection (GC) churn during high-throughput mutation loops across hundreds of thousands of objects, error tracking is implemented via `VolumetricRingBuffer`:
- Allocates a contiguous typed array buffer `new Float32Array(windowSize)` once on initialization.
- Maintains an $O(1)$ circular write head index and running sum for instantaneous error rate calculation: `getErrorRate() = runningSum / count`.
- Strictly zero dynamic array allocations, memory reallocations, or object wrappers during batch ingestion loops.

### 14.2 Autonomous Circuit Breaker Architecture
Each deletion execution pipeline is governed by a scoped `CircuitBreaker` instance parameterized by `(bucket, operation)` (`DeleteObjects` or `AbortMultipartUpload`):
1. **Three-State Machine (`CLOSED`, `OPEN`, `HALF_OPEN`):**
   - **`CLOSED`:** Normal operation. Concurrency dynamically adjusts based on S3 API response characteristics.
   - **`OPEN`:** Execution halted immediately. In-flight tasks fail fast without sending further network mutations to S3. Exponential backoff cooldown ($5\text{s} \times 2^{\text{tripCount}-1}$, capped at 60s) governs recovery.
   - **`HALF_OPEN`:** After cooldown expiry, admits exactly one isolated probe batch. Success transitions state back to `CLOSED`; failure immediately re-trips state to `OPEN`.
2. **Deterministic Error Classification:**
   - **403 AccessDenied / Forbidden:** Tracks consecutive permission failures. On 3 consecutive 403 results, trips to `OPEN` immediately. Blind retries on hard permission cliffs are strictly prohibited.
   - **503 SlowDown / Throttling:** Halves active concurrency immediately (`Math.max(minConcurrency, Math.floor(current / 2))`). Trips to `OPEN` on burst throttling ($\ge 3$ throttle events within 5 seconds) or sustained moving error rate $> 10\%$.
   - **400 BadDigest / Checksum Mismatch:** Indicates payload corruption or data-plane integrity degradation. Immediately trips to `OPEN` and activates bucket quarantine (`isQuarantined() = true`), preventing automatic recovery.
3. **Unconditional Batch Error Inspection:**
   S3 `DeleteObjectsCommand` returns HTTP 200 OK even when sub-keys fail due to permissions, locks, or throttling. The circuit breaker inspects `response.Errors` unconditionally on every batch.

### 14.3 Relative Mutation Ceiling (FinOps Safety Invariant)
To protect cloud storage fleets against accidental mass wipeouts caused by misconfigured wildcards or corrupted scanning filters:
1. **Proportional Cap:** Caps autonomous deletions to $\le 5\%$ of total bucket inventory (`evaluateMutationCeiling`).
2. **Absolute Fallback:** If total bucket inventory is unknown or zero, enforces a strict absolute fallback ceiling of 1,000 objects.
3. **Explicit Override:** Exceeding this ceiling strictly requires the `--bypass-mutation-ceiling` CLI flag or a custom `--max-deletion-percent <pct>` threshold. Without bypass, execution halts cleanly with exit code 1 (`POLICY_VIOLATION`).

### 14.4 Canary Verification Gate (Pre-Flight Probing)
Before executing fleet batch deletion loops across thousands of objects:
1. **Canary Selection:** Isolates up to 10 oldest targeted items (by `initiated` timestamp for multipart uploads or `LastModified` timestamp for object versions).
2. **Isolated Canary Mutation:** Executes isolated deletion on the canary sample.
3. **`HeadObject` Probe Verification:** Performs a `HeadObject` probe on each canary target to confirm deletion or delete marker placement prior to admitting the remaining fleet batch loop.
4. **Failure Isolation:** Any failure during the canary phase immediately aborts execution, populates structured item outcomes (`ABORTED`, `SKIPPED_ALREADY_ABORTED`, `DELETED`, `FAILED`), and returns exit code 1 (`POLICY_VIOLATION`) without risking bulk mutation errors. Can be skipped when explicitly desired via `--no-canary`.

---

## 15. Append-Only Fleet Audit Ledger, Zero-Memory Streaming Compaction, and Atomic State Rotation (v1.7.0)

### 15.1 Strictly-Typed JSONL Audit Ledger (`audit.jsonl`)
Every mutative and diagnostic decision within `s3-guardian` emits a strictly-typed JSONL event to `${stateDir}/audit.jsonl`:
- **Linearizable Event Types:**
  - `DISCOVERY`: Records fleet bucket discovery, count of stranded multipart uploads, and candidate counts.
  - `BLAST_RADIUS_ASSESSMENT`: Records pre-flight blast radius simulation results, finding counts, and safety clearance.
  - `CANARY_VERIFIED`: Emitted upon successful completion of the pre-flight canary probe loop.
  - `REMEDIATION_EXECUTED`: Records executed object deletions/aborts, bytes freed, estimated savings in USD, target counts, and `x-amz-request-id` correlation traces.
  - `CIRCUIT_BREAKER_TRIPPED`: Emitted when an autonomous circuit breaker trips to `OPEN` (e.g., on consecutive 403s, 503 bursts, or 400 BadDigest quarantine).
- **Guaranteed Serialization & Stream Backpressure:**
  - Managed by `AuditLogWriter` with internal promise queue chaining, preventing concurrent chunk interleaving.
  - Monitors write stream backpressure: pauses and awaits `'drain'` when the underlying Node.js stream buffer fills.
  - Provides a clean teardown contract via `close()`, guaranteeing all in-flight buffers are flushed to disk before process exit.

### 15.2 Windows NTFS Safe Atomic File Replacement (`writeAtomic`)
File mutations (such as plan exports, checkpoints, and state files) must withstand process preemption and operating system file system quirks:
- **Same-Directory Staging:** Temporary files are staged strictly in the destination directory (`${targetPath}.${process.pid}.${Date.now()}.${randomUUID().slice(0, 8)}.tmp`) to prevent cross-device `EXDEV` move errors.
- **Data Flush:** File descriptor writes are forced to disk via `handle.sync()` before closing.
- **Windows Lock Mitigation:** Windows antivirus scanners and indexing services briefly hold exclusive locks on newly written files. `writeAtomic` implements a bounded exponential backoff retry loop with full jitter on `EPERM`, `EBUSY`, and `EACCES` (up to 3,000 ms).
- **Platform-Conditional Directory Fsync:** Safely skips directory fsync on Windows (where directory handles do not support `fsync`), while executing directory descriptor sync on POSIX platforms.
- **Clean Failure Recovery:** Automatically unlinks staging `.tmp` files upon unrecoverable errors.

### 15.3 Zero-Memory Streaming Compactor (`Compactor.compactAuditLog`)
Long-running daemon deployments accumulate high-volume audit event logs. The compactor aggregates historical trends without generating memory pressure:
- **Memory Footprint Bound (< 50 MB RSS):** Streams `audit.jsonl` line-by-line via `node:readline`. Never buffers raw events in memory; maintains an in-memory aggregation map keyed by `${accountId}:${bucketName}`:
  - `totalBytesFreed`: Cumulative byte volume freed by remediation runs.
  - `totalEstimatedSavingsUSD`: Cumulative projected FinOps savings in USD.
  - `eventCount`: Aggregate count of processed events.
  - `circuitBreakerTrips`: Cumulative counter of circuit breaker trips.
  - `lastSeenPlanHash`: Most recent plan hash executed against the bucket.
  - `lastEventTimestamp`: ISO 8601 timestamp of latest activity.
- **Discovery Pruning:** Raw, high-volume `DISCOVERY` records are discarded from permanent storage during compaction, preserving solely the aggregated FinOps impact metrics.
- **Atomic Multi-Step State Rotation:**
  1. Atomically renames `audit.jsonl` to `audit.jsonl.rotating.<timestamp>` using Windows lock safety retries.
  2. Immediately initializes a clean, empty `audit.jsonl` file to accept continuous in-flight writes without downtime.
  3. Streams the rotating file, optionally merging baseline metrics from the latest existing snapshot.
  4. Compresses the aggregated snapshot directly into `snapshots/snapshot-<timestamp>.json.gz` via `createGzip({ level: 9 })` and `stream.pipeline()`.
  5. Unlinks the rotating file upon successful snapshot creation.
- **Optional S3 Mirror Synchronization:** When configured with `--s3-mirror <bucket>`, the compactor automatically mirrors the compressed snapshot to `s3://<mirror-bucket>/guardian-state/<snapshot-name>.json.gz` via `PutObjectCommand`.

### 15.4 State Inspection & CLI Operations
- **`s3-guardian state compact`:** Manually or periodically compacts `${stateDir}/audit.jsonl` into a gzip snapshot and resets the active log.
- **`s3-guardian state history <bucket>`:** Transparently queries and synthesizes historical metrics for a specific bucket, merging the latest historical snapshot baseline with uncompacted live events in `audit.jsonl`.
- **Global Flags:**
  - `--state-dir <path>`: Custom state directory for audit logging and snapshots (defaults to `./.s3-guardian`).
  - `--s3-mirror <bucket>`: S3 bucket for mirror uploads of state snapshots.

---

## 16. Cryptographic Rollback Engine, Undo Manifests, Soft Delete Re-hydration & SOC 2 Deletion Certificates

### 16.1 Explicit Reversibility Taxonomy
All storage governance operations in `s3-guardian` are explicitly partitioned into two cryptographic domains:
1. **Reversible Mutations:**
   - Bucket lifecycle configuration modifications (`PutBucketLifecycleConfiguration`, `DeleteBucketLifecycleConfiguration`).
   - Bucket tagging mutations (`PutBucketTagging`, `DeleteBucketTagging`).
   - Soft Delete Marker cleanups (deleting tombstones restores the underlying data version as the active version).
   - *Requirement:* Must capture full pre-state and post-state, generating an atomic `UndoManifest`.
2. **Irreversible Operations:**
   - Permanent object version purges (`DeleteObjects` / `DeleteObject` with specific `VersionId`).
   - Aborted Multipart Uploads (`AbortMultipartUpload`).
   - *Requirement (SOC 2 CC6.8 / ISO 27001 A.8.10):* Because byte recovery is physically impossible once purged, every execution must generate an immutable, cryptographically sealed `DeletionCertificate`.

### 16.2 Undo Manifest Specification (`UndoManifest`)
Every reversible mutation automatically creates an immutable manifest written atomically to `${stateDir}/undo/undo-<bucket>-<timestamp>.json`:

```typescript
interface UndoManifest {
  manifestId: string;             // UUIDv4
  manifestVersion: "1.8.0";
  createdAt: string;              // ISO 8601 UTC timestamp
  bucketName: string;
  mutationType: 'LIFECYCLE_CONFIGURATION' | 'BUCKET_TAGGING' | 'SOFT_DELETE_MARKER';
  canonicalPreStateHash: string;  // 64-char hex SHA-256 (RFC 8785 JCS)
  canonicalPostStateHash: string; // 64-char hex SHA-256 (RFC 8785 JCS)
  preState: any;                  // null if 404 NoSuchLifecycleConfiguration or NoSuchTagSet
  postState: any;
  inverseCommandType: 'PutBucketLifecycleConfiguration' | 'DeleteBucketLifecycleConfiguration' | 'PutBucketTagging' | 'DeleteBucketTagging' | 'DeleteObjects';
  inversePayload: any;
  appliedPlanHash: string;
  requestIds: string[];
}
```

### 16.3 Remote State Drift Verification & Rollback Execution
When executing `s3-guardian rollback <manifest-path>`:
1. **Cryptographic State Verification (RFC 8785):**
   - Fetches live remote state directly from AWS S3 (`GetBucketLifecycleConfigurationCommand` or `GetBucketTaggingCommand`).
   - Normalizes and hashes live state using RFC 8785 canonical JSON and SHA-256.
   - Compares the live hash against `manifest.canonicalPostStateHash`.
   - If divergent, execution halts immediately by throwing `RemoteStateDriftError`.
   - Halting can only be bypassed by explicit operator override via `--force`.
2. **Deterministic State Inversion:**
   - Executes the inverse command (`PutBucketLifecycleConfiguration` / `DeleteBucketLifecycle` / `PutBucketTagging` / `DeleteBucketTagging` / `DeleteObjects`) using `manifest.preState`.
3. **Audit Ledger Non-Repudiation:**
   - Emits a `REMEDIATION_ROLLED_BACK` event to `${stateDir}/audit.jsonl` recording `manifestId`, `appliedPlanHash`, and `forced` status.

### 16.4 Soft Delete Tombstone Popping (`rehydrateSoftDeletes`)
AWS S3 soft deletes place a Delete Marker on top of the object version stack.
- **Dual-Marker Pagination:** Streams all object versions and delete markers via `paginateListObjectVersions`.
- **Target Filtering:** Targets markers where `marker.IsLatest === true` and optionally filters by timestamp threshold (`--older-than <timestamp>`).
- **Tombstone Popping:** Deletes targeted markers via `DeleteObjectsCommand` with `Quiet: true`, supplying explicit `{ Key, VersionId }`.
- **Activation Confirmation:** Once the tombstone Delete Marker is permanently deleted, the preceding data version is restored and elevated to active `IsLatest = true` status.
- **Dry-Run Simulation:** `--dry-run` discovers candidate markers and maps restorable versions without issuing destructive API calls.

### 16.5 SOC 2 CC6.8 / ISO 27001 A.8.10 Immutable Deletion Certificates
Irreversible version purges and aborted multipart uploads generate an unforgeable compliance record written atomically to `${stateDir}/certificates/deletion-certificate-<bucket>-<timestamp>.json`:

```typescript
interface DeletionCertificate {
  certificateId: string;         // UUIDv4
  timestamp: string;             // ISO 8601 UTC timestamp
  bucketName: string;
  operation: 'PERMANENT_VERSION_DELETE' | 'ABORT_MULTIPART_UPLOAD';
  targetCount: number;
  totalBytesReclaimed: number;
  planHash: string;              // Cryptographic plan SHA-256
  requestIds: string[];          // AWS CloudTrail request IDs
  itemLedger: Array<{
    key: string;
    versionId?: string;
    uploadId?: string;
    sizeBytes?: number;
  }>;
}
```

### 16.6 CLI Command Interfaces
- **`s3-guardian rollback <manifest-path> [--force] [--json] [--state-dir <path>]`:**
  Verifies remote configuration state, inverts recorded mutations, and restores pre-state.
- **`s3-guardian certificate <cert-path> [--json]`:**
  Displays formatted SOC 2 / ISO 27001 deletion certificates with cryptographic planHash and CloudTrail traces.
- **`s3-guardian rehydrate <bucket> [--dry-run] [--older-than <timestamp>] [--json]`:**
  Discovers latest Delete Markers and pops tombstones to restore hidden object data versions.

---

## 17. Declarative Storage Policy Engine & Precedence Hierarchy (v1.9.0)

### 17.1 Declarative Storage Policy Schema (`GuardianPolicy`)
Policies are expressed in JSON or the zero-dependency Guardian YAML subset conforming to `schemaVersion: "1"`.

```typescript
export interface GuardianPolicy {
  schemaVersion: "1";
  policyId: string;
  scope: {
    level: "GLOBAL" | "OU" | "ACCOUNT" | "BUCKET_TAG" | "OBJECT_TAG";
    organizationId?: string;
    ouId?: string;
    accountId?: string;
    priority?: number;
  };
  defaults?: {
    action?: "MONITOR_ONLY" | "PLAN_ONLY" | "AUTO_REMEDIATE";
    mpuAbortDays?: number;
    retainVersions?: number;
    maxNoncurrentDays?: number;
  };
  rules: PolicyRule[];
}
```

### 17.2 Zero-Dependency YAML/JSON Subset Parser
The parser processes declarative documents using Node 20+ built-ins with zero third-party dependencies:
- **Comments & Quotes:** Strips non-quoted comments (`#`) while preserving quoted strings and escaped quotes.
- **Indentation Hygiene:** Enforces indentation with spaces and strictly rejects tab characters (`\t`) with syntax errors.
- **Scalar Units:** Natively translates human duration scalars (`7d` $\to 7$, `24h` $\to 1$, `2w` $\to 14$) and human size scalars (`128KiB` $\to 128$, `1MiB` $\to 1024$, `1GiB` $\to 1048576$).

### 17.3 Precedence Hierarchy & Leaf-Level Merging
When multiple policies match a bucket, rules are resolved hierarchically:
$$\text{OBJECT\_TAG (40)} > \text{BUCKET\_TAG (30)} > \text{ACCOUNT (25)} > \text{OU (20)} > \text{GLOBAL (10)}$$
- **Explicit Priority:** Scope priority integers resolve ties between policies at the same organizational level.
- **Leaf-Level Merging:** Properties are merged per object match criteria at the leaf level (`mpuAbortDays`, `expirationDays`, `transitions`, `noncurrentExpirationDays`, `retainVersions`, `minSizeKb`).
- **Provenance Tracking:** Every effective property maintains provenance metadata (`{ policyId, ruleId, level }`) detailing its governance origin.

### 17.4 Fail-Safe Action Mode
To prevent accidental mutation across organizational hierarchies, the most restrictive action mode unconditionally wins:
$$\text{MONITOR\_ONLY (1)} < \text{PLAN\_ONLY (2)} < \text{AUTO\_REMEDIATE (3)}$$
If any matching policy or rule specifies `MONITOR_ONLY`, all automated and manual mutations on that bucket are prohibited.

### 17.5 Static FinOps Validator & Safety Guards
- **AWS API Constraints:** Rules per policy $\le 1000$, rule ID length $\le 255$, unique rule IDs, `retainVersions` $\in [1, 100]$.
- **MPU Churn Guard:** `mpuAbortDays` must be $\ge 7$ days in rules and defaults to avoid aborting active in-flight multipart uploads.
- **Tag/MPU Contradiction Guard:** AWS S3 strictly forbids tag filters inside `AbortIncompleteMultipartUpload`. The validator rejects rules combining `mpuAbortDays` with `object.tags`.
- **128 KiB Floor Guard:** Transitions to `STANDARD_IA`, `ONEZONE_IA`, `GLACIER_IR`, `GLACIER`, and `DEEP_ARCHIVE` require `minSizeKb >= 128` (`INTELLIGENT_TIERING` is exempt).
- **Early Deletion Penalty Guard:** Verifies minimum retention periods to prevent premature deletion charges: $\ge 90$ days for Glacier/GIR, and $\ge 180$ days for Deep Archive.

### 17.6 AWS Lifecycle Compiler (`compileToLifecycleConfiguration`)
- **MPU Abort Rule Splitting:** Automatically splits rules containing both MPU abort actions and object tags into an MPU abort rule (`${rule.id}-abort-mpu` without tags) and an object lifecycle rule (with tags and transitions).
- **Filter Synthesis:** Employs single criterion filters (`Prefix`, `Tag`, `ObjectSizeGreaterThan`) or multi-criteria `And` blocks.
- **128 KiB Floor Injection:** Enforces `ObjectSizeGreaterThan >= 131072` bytes for storage classes subject to minimum capacity charges.
- **Enabled Guarantee:** All compiled lifecycle rules enforce `Status: "Enabled"`.

### 17.7 CLI Commands
- **`s3-guardian policy validate <file> [--json]`:** Statically validates policy syntax, AWS constraints, and FinOps safety guards.
- **`s3-guardian policy plan <bucket> --policy <file> [--out <file>] [--json]`:** Resolves bucket tags, hierarchy precedence, leaf merges, and outputs compiled PutBucketLifecycleConfiguration JSON preview.
- **`s3-guardian policy apply <bucket> --policy <file> --confirm [--state-dir <path>] [--json]`:** Captures pre-state, applies compiled configuration to AWS S3, and writes an immutable `UndoManifest` for rollback.
- **`s3-guardian scan --all-buckets --policy <file>`:** Audits declarative storage policy compliance across all discovered fleet buckets.

---

## 18. Phase 19: The Autonomous Sovereign Operator & v2.0.0 General Availability

Phase 19 delivers the pinnacle milestone for `s3-guardian`: continuous, fully autonomous storage governance with cryptographic rollback guarantees, air-gapped enterprise CA support, standalone single executable distribution, and a strict SemVer 2.0 exit code taxonomy.

### 18.1 9-Phase Sovereign Operator State Machine

The `SovereignOperator` engine (`s3-guardian operate`) unites all scanning, planning, safety verification, execution, and rollback capabilities into an in-process, non-terminating daemon executing across 9 discrete phases:

```
[DISCOVERY] ──▶ [POLICY_MATCH] ──▶ [BLAST_RADIUS_AUDIT] ──▶ [CANARY_TEST]
                                                                  │
      ┌───────────────────────────────────────────────────────────┘
      ▼
[CIRCUIT_VERIFY] ──▶ [BULK_EXECUTE] ──▶ [AUDIT_LOG] ──▶ [UNDO_EXPORT]
                                                              │
      ┌───────────────────────────────────────────────────────┘
      ▼
   [SLEEP] ──(interval elapsed)──▶ [DISCOVERY]
```

1. **DISCOVERY:** Paginates target accounts and buckets with cursor resumption. Emits candidate mutation targets.
2. **POLICY_MATCH:** Evaluates discovered inventory against declarative policy rules (v1.9.0 engine). Excludes items matching `MONITOR_ONLY` or compliant configurations.
3. **BLAST_RADIUS_AUDIT:** Pre-flight simulator enforces relative bucket mutation ceilings ($\le 5\%$), blocks buckets with S3 Object Lock in `COMPLIANCE` mode, and verifies replication configuration (`CRR`/`SRR`).
4. **CANARY_TEST:** Dispatches isolated canary aborts/deletions against oldest candidate targets with post-action `HeadObject` probe verification.
5. **CIRCUIT_VERIFY:** Queries moving error rates from the zero-allocation `CircuitBreaker`. If `OPEN`, halts execution and trips safety state.
6. **BULK_EXECUTE:** Drains remaining mutation queue using bounded concurrency worker pool (`createConcurrencyLimiter`).
7. **AUDIT_LOG:** Appends atomic JSONL audit records into local `.s3-guardian/audit.jsonl` with optional remote S3 mirroring.
8. **UNDO_EXPORT:** Computes RFC 8785 canonical hashes and generates immutable `UndoManifest` and SOC 2 / ISO 27001 `DeletionCertificate` JSON files on disk.
9. **SLEEP:** Measures epoch execution duration via monotonic timers (`process.hrtime.bigint()`), deducts elapsed execution time from the configured interval, and sleeps interruptibly via `AbortSignal`. Resets half-open probes upon healthy cycle completion.
10. **HALTED:** Explicit terminal safe-state entered whenever blast radius, Object Lock, canary gates, or circuit breakers trip. Prevents destructive churn during infrastructure anomalies.

### 18.2 Air-Gapped Trust Stores (`NODE_EXTRA_CA_CERTS`)

In air-gapped data centers, sovereign enclaves, and corporate proxy architectures, TLS inspection requires custom internal Root Certificate Authorities:
- **Environment Detection:** Automatically detects `NODE_EXTRA_CA_CERTS` on CLI startup.
- **PEM Extraction:** Reads and parses concatenated X.509 PEM certificates from disk using regex boundary matching (`-----BEGIN CERTIFICATE-----` to `-----END CERTIFICATE-----`).
- **Dynamic Context Injection:** Patches `tls.createSecureContext` dynamically to inject custom enterprise root certificates into all outbound TLS handshakes across AWS SDK v3 client pools and Node HTTPS agents.

### 18.3 Single Executable Application (SEA) Architecture

To eliminate runtime installation barriers (Node.js, npm, package managers), `s3-guardian` compiles into a standalone binary:
- **Bundling:** `esbuild` compiles `src/cli.ts` into a single CommonJS bundle (`dist/bundle.cjs`) in $<300\text{ms}$.
- **Blob Preparation:** Generates `dist/sea-prep.blob` via Node's native SEA preparation mechanism (`sea-config.json`).
- **Binary Injection:** Uses `postject` to fuse the SEA blob directly into the Node binary with sentinel fuse `NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2`.
- **Multi-Platform Matrix CI:** GitHub Actions compiles native binaries for `linux-x64`, `linux-arm64`, `macos-x64`, `macos-arm64`, and `windows-x64` with SHA-256 checksum verification (`SHA256SUMS`).

### 18.4 SemVer 2.0 Exit Code Contract Taxonomy

`s3-guardian v2.0.0` establishes a strict, stable exit code specification across all commands and automation:

| Code | Symbol | Trigger Condition |
| :--- | :--- | :--- |
| `0` | `SUCCESS` | Clean scan, plan generated, apply completed, or policies fully satisfied |
| `1` | `CONFIG_ARG_ERROR` | CLI configuration, syntax, or argument error; missing required parameters |
| `2` | `AUTH_IAM_ERROR` | Authentication failure, IAM AccessDenied, Organizations discovery failure, or STS AssumeRole rejection |
| `3` | `POLICY_VIOLATION` | Declarative policy violation, validation invariant breach, `--max-waste-usd` exceeded, or unapproved IaC drift |
| `4` | `CIRCUIT_CANARY_BLAST_RADIUS` | Circuit breaker tripped (OPEN), canary probe failure, blast radius ceiling breach, or Wasabi 90-day retention guard triggered |
| `5` | `FS_STATE_ERROR` | Filesystem or state store corruption, unreadable state file, or disk I/O error |
| `6` | `NETWORK_TIMEOUT` | Network connection refused, DNS timeout, socket timeout (`ETIMEDOUT`), or AWS SDK `TimeoutError` |