import {
  S3Client,
  ListBucketsCommand,
  GetBucketLocationCommand,
  Bucket,
} from "@aws-sdk/client-s3";
import { S3ClientPool } from "../discovery/client-pool.js";
import { normalizeBucketRegion } from "../discovery/regions.js";
import { scanMultipartUploads, ScanOptions } from "../scanner/multipart.js";
import { auditBucketLifecycle, LifecycleAuditResult } from "../lifecycle/audit.js";
import { calculateMonthlyCostUSD } from "../cost/estimator.js";
import { createConcurrencyLimiter } from "../utils/concurrency.js";
import { ZombieUploadItem } from "../planner/plan.js";

// ─── Error types ──────────────────────────────────────────────────────────────

/**
 * Thrown when ListBuckets fails due to an authentication/authorization error.
 * Maps to CLI exit code 3.
 */
export class DiscoveryAuthError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = "DiscoveryAuthError";
  }
}

// ─── Result types ─────────────────────────────────────────────────────────────

export type BucketStatus =
  | "AUDITED"
  | "SKIPPED_REQUESTER_PAYS"
  | "SKIPPED_ACCESS_DENIED"
  | "SKIPPED_NOT_FOUND"
  | "SKIPPED_EXCLUDED"
  | "SKIPPED_EXCLUDED_REGION"
  | "SKIPPED_REGION_RESOLUTION_FAILED"
  | "ERROR";

export interface BucketAuditResult {
  bucket: string;
  region: string | null;
  status: BucketStatus;
  /** Only present when status === "AUDITED" */
  zombieUploads?: ZombieUploadItem[];
  totalZombieUploads?: number;
  totalStrandedBytes?: number;
  estimatedMonthlyWasteUSD?: number;
  lifecycleAudit?: Pick<
    LifecycleAuditResult,
    "bucketHasLifecyclePolicy" | "hasCoveringRule" | "ghostRulesDetected" | "providerNotes"
  >;
  /** Error message when status === "ERROR" or a skip reason */
  errorMessage?: string;
}

export interface FleetScanResult {
  bucketsDiscovered: number;
  bucketsAudited: number;
  bucketsSkipped: number;
  totalZombieUploads: number;
  totalStrandedBytes: number;
  totalEstimatedMonthlyWasteUSD: number;
  bucketResults: BucketAuditResult[];
}

// ─── Filter types ─────────────────────────────────────────────────────────────

export interface FleetScanOptions {
  /** Age threshold for uploads (default: 7 days) */
  olderThanDays?: number;
  /** Key prefix filter passed to individual bucket scans */
  prefix?: string;
  /** Max concurrent bucket audits in flight (default: 5) */
  bucketConcurrency?: number;
  /** Comma-separated bucket name substrings or glob patterns to exclude */
  excludeBuckets?: string[];
  /** AWS region strings to exclude entirely */
  excludeRegions?: string[];
  /** Reference "now" for testability */
  now?: Date;
  /** Custom endpoint (for provider detection) */
  endpoint?: string | null;
  /** Retry options forwarded to individual scanners */
  retryOptions?: ScanOptions["retryOptions"];
  /** Optional S3Client to use for ListBuckets + GetBucketLocation.
   *  When not provided, a new default client is constructed. */
  discoveryClient?: S3Client;
  /** Optional client pool to reuse regional clients across bucket audits */
  clientPool?: S3ClientPool;
}

// ─── Pattern matching ─────────────────────────────────────────────────────────

/**
 * Returns true if `name` matches any exclusion pattern.
 * Patterns are matched as:
 *   - Glob `*` (wildcard): `*foo*` matches substrings, `foo*` prefix, `*foo` suffix
 *   - Plain substring: if no `*` is present, checks simple substring inclusion
 */
export function matchesExcludePattern(name: string, patterns: string[]): boolean {
  for (const pattern of patterns) {
    if (pattern.includes("*")) {
      // Convert simple glob to regex: * → .*
      const regexStr = "^" + pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$";
      if (new RegExp(regexStr, "i").test(name)) return true;
    } else {
      // Plain substring match
      if (name.toLowerCase().includes(pattern.toLowerCase())) return true;
    }
  }
  return false;
}

// ─── Region resolution ────────────────────────────────────────────────────────

/**
 * Resolves the bucket's region using GetBucketLocation.
 * Returns null if resolution fails (network error, access denied on location).
 */
async function resolveBucketRegion(
  client: S3Client,
  bucket: string
): Promise<string | null> {
  try {
    const response = await client.send(
      new GetBucketLocationCommand({ Bucket: bucket })
    );
    return normalizeBucketRegion(response.LocationConstraint);
  } catch {
    return null;
  }
}

// ─── Error classification ─────────────────────────────────────────────────────

function classifyS3Error(err: unknown): {
  isAccessDenied: boolean;
  isRequesterPays: boolean;
  isNotFound: boolean;
  message: string;
} {
  const e = err as Record<string, unknown>;
  const name = String(e.name || e.Code || "");
  const status =
    (e.$metadata as Record<string, unknown> | undefined)?.httpStatusCode ??
    e.statusCode ??
    e.status;
  const message = String(e.message || "");

  const isAccessDenied =
    name === "AccessDenied" ||
    name === "Forbidden" ||
    status === 403;

  const isRequesterPays =
    name === "BucketIsRequesterPays" ||
    /requester.?pays/i.test(message) ||
    /RequesterPays/i.test(name);

  const isNotFound =
    name === "NoSuchBucket" ||
    status === 404;

  return { isAccessDenied, isRequesterPays, isNotFound, message };
}

// ─── Single-bucket audit ──────────────────────────────────────────────────────

async function auditOneBucket(
  bucket: string,
  region: string,
  options: FleetScanOptions,
  clientPool: S3ClientPool
): Promise<BucketAuditResult> {
  const client = clientPool.getClient(region);
  const scanOpts: ScanOptions = {
    olderThanDays: options.olderThanDays ?? 7,
    prefix: options.prefix,
    now: options.now,
    endpoint: options.endpoint,
    retryOptions: options.retryOptions,
  };

  try {
    const [scanResult, lifecycleAudit] = await Promise.all([
      scanMultipartUploads(client, bucket, scanOpts),
      auditBucketLifecycle(client, bucket, options.endpoint, options.retryOptions),
    ]);

    // Enrich lifecycle status on each upload
    const now = options.now ?? new Date();
    const { evaluateUploadCoverage } = await import("../lifecycle/audit.js");
    const enrichedUploads = scanResult.uploads.map((u) => {
      const coverage = evaluateUploadCoverage(
        u.key,
        new Date(u.initiated),
        lifecycleAudit.mpuRules ?? [],
        now
      );
      return { ...u, lifecycleStatus: coverage.status };
    });

    return {
      bucket,
      region,
      status: "AUDITED",
      zombieUploads: enrichedUploads,
      totalZombieUploads: scanResult.totalZombieUploads,
      totalStrandedBytes: scanResult.totalStrandedBytes,
      estimatedMonthlyWasteUSD: scanResult.estimatedMonthlyWasteUSD,
      lifecycleAudit: {
        bucketHasLifecyclePolicy: lifecycleAudit.bucketHasLifecyclePolicy,
        hasCoveringRule: lifecycleAudit.hasCoveringRule,
        ghostRulesDetected: lifecycleAudit.ghostRulesDetected,
        providerNotes: lifecycleAudit.providerNotes,
      },
    };
  } catch (err: unknown) {
    const { isAccessDenied, isRequesterPays, isNotFound, message } =
      classifyS3Error(err);

    if (isRequesterPays) {
      return {
        bucket,
        region,
        status: "SKIPPED_REQUESTER_PAYS",
        errorMessage: "Bucket is configured as Requester-Pays; skipped to avoid charges.",
      };
    }
    if (isAccessDenied) {
      return {
        bucket,
        region,
        status: "SKIPPED_ACCESS_DENIED",
        errorMessage: `Access denied: ${message}`,
      };
    }
    if (isNotFound) {
      return {
        bucket,
        region,
        status: "SKIPPED_NOT_FOUND",
        errorMessage: `Bucket not found: ${message}`,
      };
    }

    return {
      bucket,
      region,
      status: "ERROR",
      errorMessage: message || String(err),
    };
  }
}

// ─── Fleet Scanner ────────────────────────────────────────────────────────────

/**
 * Discovers all account buckets via ListBuckets, resolves their regions,
 * applies exclusion filters, then audits each bucket concurrently (max 5 at once).
 *
 * Failure on any single bucket is ISOLATED — it is recorded as a skip/error
 * and the fleet audit continues.
 *
 * @throws {DiscoveryAuthError} if ListBuckets itself fails with auth/access error.
 */
export async function scanFleet(
  options: FleetScanOptions = {}
): Promise<FleetScanResult> {
  const bucketConcurrency = Math.max(1, options.bucketConcurrency ?? 5);

  // ── Step 1: Discover account buckets ──────────────────────────────────────
  const discoveryClient =
    options.discoveryClient ?? new S3Client({ region: "us-east-1" });

  let allBuckets: Bucket[];
  try {
    const listResponse = await discoveryClient.send(new ListBucketsCommand({}));
    allBuckets = listResponse.Buckets ?? [];
  } catch (err: unknown) {
    const { isAccessDenied, message } = classifyS3Error(err);
    if (isAccessDenied) {
      throw new DiscoveryAuthError(
        `ListBuckets failed: Access denied. Ensure s3:ListAllMyBuckets permission is granted. (${message})`,
        err
      );
    }
    // Non-auth errors on ListBuckets are also discovery failures
    throw new DiscoveryAuthError(
      `ListBuckets failed unexpectedly: ${message}`,
      err
    );
  }

  const bucketsDiscovered = allBuckets.length;

  // ── Step 2: Resolve regions and apply filters ─────────────────────────────
  const clientPool = options.clientPool ?? new S3ClientPool();
  const bucketResults: BucketAuditResult[] = [];
  const toAudit: Array<{ name: string; region: string }> = [];

  for (const bucket of allBuckets) {
    const name = bucket.Name;
    if (!name) continue;

    // Apply name-based exclusion
    if (
      options.excludeBuckets &&
      options.excludeBuckets.length > 0 &&
      matchesExcludePattern(name, options.excludeBuckets)
    ) {
      bucketResults.push({
        bucket: name,
        region: null,
        status: "SKIPPED_EXCLUDED",
        errorMessage: "Matched --exclude-bucket pattern.",
      });
      continue;
    }

    // Resolve region
    const region = await resolveBucketRegion(discoveryClient, name);
    if (region === null) {
      bucketResults.push({
        bucket: name,
        region: null,
        status: "SKIPPED_REGION_RESOLUTION_FAILED",
        errorMessage: "Could not determine bucket region via GetBucketLocation.",
      });
      continue;
    }

    // Apply region-based exclusion
    if (
      options.excludeRegions &&
      options.excludeRegions.length > 0 &&
      options.excludeRegions.some(
        (r) => r.toLowerCase() === region.toLowerCase()
      )
    ) {
      bucketResults.push({
        bucket: name,
        region,
        status: "SKIPPED_EXCLUDED_REGION",
        errorMessage: `Region "${region}" is in --exclude-region list.`,
      });
      continue;
    }

    toAudit.push({ name, region });
  }

  // ── Step 3: Dispatch concurrent audits ────────────────────────────────────
  const limiter = createConcurrencyLimiter(bucketConcurrency);

  const auditPromises = toAudit.map(({ name, region }) =>
    limiter(() => auditOneBucket(name, region, options, clientPool))
  );

  const auditResults = await Promise.all(auditPromises);
  bucketResults.push(...auditResults);

  // ── Step 4: Aggregate totals ──────────────────────────────────────────────
  let totalZombieUploads = 0;
  let totalStrandedBytes = 0;
  let bucketsAudited = 0;
  let bucketsSkipped = 0;

  for (const r of bucketResults) {
    if (r.status === "AUDITED") {
      bucketsAudited++;
      totalZombieUploads += r.totalZombieUploads ?? 0;
      totalStrandedBytes += r.totalStrandedBytes ?? 0;
    } else {
      bucketsSkipped++;
    }
  }

  const totalEstimatedMonthlyWasteUSD = calculateMonthlyCostUSD(totalStrandedBytes);

  return {
    bucketsDiscovered,
    bucketsAudited,
    bucketsSkipped,
    totalZombieUploads,
    totalStrandedBytes,
    totalEstimatedMonthlyWasteUSD,
    bucketResults,
  };
}
