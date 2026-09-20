# s3-guardian — Technical Specification & Invariants

**Version:** 1.3.0  
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