import * as fs from "node:fs/promises";
import * as path from "node:path";
import { calculateMonthlyCostUSD } from "../cost/estimator.js";
import type { LifecycleAuditResult } from "../lifecycle/audit.js";

export type LifecycleStatus =
  | "UNPROTECTED"
  | "COVERED"
  | "COVERED_LAGGING"
  | "GHOST_RULE";

export interface ZombieUploadItem {
  key: string;
  uploadId: string;
  initiated: string;
  partsCount: number;
  bytes: number;
  /** StorageClass reported by ListMultipartUploads. Non-STANDARD tiers bleed at S3 Standard rates. */
  storageClass: string;
  /** Lifecycle protection status for this specific upload's key */
  lifecycleStatus: LifecycleStatus;
}

export interface Plan {
  schemaVersion: "1.1";
  generatedAt: string;
  bucket: string;
  endpoint: string | null;
  olderThanDays: number;
  totalZombieUploads: number;
  totalStrandedBytes: number;
  estimatedMonthlyWasteUSD: number;
  lifecycleAudit: {
    bucketHasLifecyclePolicy: boolean;
    hasCoveringRule: boolean;
    ghostRulesDetected: string[];
    providerNotes?: string;
  };
  /** Only present when totalZombieUploads > 10,000 */
  highVolumeWarning?: string;
  uploads: ZombieUploadItem[];
}

export interface CreatePlanOptions {
  bucket: string;
  endpoint?: string | null;
  olderThanDays: number;
  uploads: ZombieUploadItem[];
  lifecycleAudit: LifecycleAuditResult;
  generatedAt?: string;
}

const HIGH_VOLUME_THRESHOLD = 10_000;
const HIGH_VOLUME_WARNING =
  "Executing apply on >10k uploads will generate substantial CloudTrail Data Events.";

/**
 * Creates a deterministic Plan object (schema 1.1) with sorted uploads,
 * calculated cost metrics, lifecycle audit summary, and optional high-volume warning.
 */
export function createPlan(options: CreatePlanOptions): Plan {
  const { bucket, endpoint = null, olderThanDays, generatedAt, lifecycleAudit } =
    options;

  // Deterministic sorting: sort primarily by key, secondarily by uploadId
  const sortedUploads = [...options.uploads].sort((a, b) => {
    const keyComp = a.key.localeCompare(b.key);
    if (keyComp !== 0) return keyComp;
    return a.uploadId.localeCompare(b.uploadId);
  });

  const totalZombieUploads = sortedUploads.length;
  const totalStrandedBytes = sortedUploads.reduce(
    (sum, item) => sum + item.bytes,
    0
  );
  const estimatedMonthlyWasteUSD = calculateMonthlyCostUSD(totalStrandedBytes);

  const plan: Plan = {
    schemaVersion: "1.1",
    generatedAt: generatedAt ?? new Date().toISOString(),
    bucket,
    endpoint: endpoint ?? null,
    olderThanDays,
    totalZombieUploads,
    totalStrandedBytes,
    estimatedMonthlyWasteUSD,
    lifecycleAudit: {
      bucketHasLifecyclePolicy: lifecycleAudit.bucketHasLifecyclePolicy,
      hasCoveringRule: lifecycleAudit.hasCoveringRule,
      ghostRulesDetected: lifecycleAudit.ghostRulesDetected,
      providerNotes: lifecycleAudit.providerNotes,
    },
    uploads: sortedUploads,
  };

  if (totalZombieUploads > HIGH_VOLUME_THRESHOLD) {
    plan.highVolumeWarning = HIGH_VOLUME_WARNING;
  }

  return plan;
}

/**
 * Validates that an arbitrary JSON object conforms to either Plan schema 1.0 or 1.1.
 * Schema 1.0 plans are up-converted to 1.1 with safe defaults.
 */
export function validatePlan(data: unknown): Plan {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("Invalid plan: expected a JSON object");
  }

  const obj = data as Record<string, unknown>;

  if (obj.schemaVersion !== "1.0" && obj.schemaVersion !== "1.1") {
    throw new Error(
      `Unsupported plan schemaVersion: "${obj.schemaVersion}". Expected "1.0" or "1.1".`
    );
  }

  if (typeof obj.bucket !== "string" || !obj.bucket.trim()) {
    throw new Error("Invalid plan: missing or invalid 'bucket' name");
  }

  if (typeof obj.olderThanDays !== "number" || obj.olderThanDays < 0) {
    throw new Error("Invalid plan: missing or invalid 'olderThanDays'");
  }

  if (!Array.isArray(obj.uploads)) {
    throw new Error("Invalid plan: 'uploads' must be an array");
  }

  const validatedUploads: ZombieUploadItem[] = [];

  for (let i = 0; i < obj.uploads.length; i++) {
    const item = obj.uploads[i];
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new Error(`Invalid plan: upload item at index ${i} is not an object`);
    }

    const u = item as Record<string, unknown>;
    if (typeof u.key !== "string" || !u.key) {
      throw new Error(`Invalid plan: upload item at index ${i} missing 'key'`);
    }
    if (typeof u.uploadId !== "string" || !u.uploadId) {
      throw new Error(
        `Invalid plan: upload item at index ${i} missing 'uploadId'`
      );
    }
    if (typeof u.initiated !== "string") {
      throw new Error(
        `Invalid plan: upload item at index ${i} missing 'initiated' string`
      );
    }
    if (typeof u.partsCount !== "number" || u.partsCount < 0) {
      throw new Error(
        `Invalid plan: upload item at index ${i} invalid 'partsCount'`
      );
    }
    if (typeof u.bytes !== "number" || u.bytes < 0) {
      throw new Error(
        `Invalid plan: upload item at index ${i} invalid 'bytes'`
      );
    }

    validatedUploads.push({
      key: u.key,
      uploadId: u.uploadId,
      initiated: u.initiated,
      partsCount: u.partsCount,
      bytes: u.bytes,
      // storageClass and lifecycleStatus: safe defaults for 1.0 up-conversion
      storageClass: typeof u.storageClass === "string" ? u.storageClass : "STANDARD",
      lifecycleStatus: isValidLifecycleStatus(u.lifecycleStatus)
        ? u.lifecycleStatus
        : "UNPROTECTED",
    });
  }

  const totalStrandedBytes = validatedUploads.reduce((sum, u) => sum + u.bytes, 0);

  // Lifecycle audit: parse from plan or use safe defaults (for 1.0 up-conversion)
  const rawAudit = obj.lifecycleAudit as Record<string, unknown> | undefined;
  const lifecycleAudit = {
    bucketHasLifecyclePolicy:
      typeof rawAudit?.bucketHasLifecyclePolicy === "boolean"
        ? rawAudit.bucketHasLifecyclePolicy
        : false,
    hasCoveringRule:
      typeof rawAudit?.hasCoveringRule === "boolean"
        ? rawAudit.hasCoveringRule
        : false,
    ghostRulesDetected: Array.isArray(rawAudit?.ghostRulesDetected)
      ? (rawAudit.ghostRulesDetected as string[]).filter(
          (s) => typeof s === "string"
        )
      : [],
    providerNotes:
      typeof rawAudit?.providerNotes === "string"
        ? rawAudit.providerNotes
        : undefined,
  };

  const plan: Plan = {
    schemaVersion: "1.1",
    generatedAt:
      typeof obj.generatedAt === "string"
        ? obj.generatedAt
        : new Date().toISOString(),
    bucket: obj.bucket,
    endpoint: typeof obj.endpoint === "string" ? obj.endpoint : null,
    olderThanDays: obj.olderThanDays,
    totalZombieUploads:
      typeof obj.totalZombieUploads === "number"
        ? obj.totalZombieUploads
        : validatedUploads.length,
    totalStrandedBytes:
      typeof obj.totalStrandedBytes === "number"
        ? obj.totalStrandedBytes
        : totalStrandedBytes,
    estimatedMonthlyWasteUSD:
      typeof obj.estimatedMonthlyWasteUSD === "number"
        ? obj.estimatedMonthlyWasteUSD
        : calculateMonthlyCostUSD(totalStrandedBytes),
    lifecycleAudit,
    uploads: validatedUploads,
  };

  if (
    typeof obj.highVolumeWarning === "string" ||
    validatedUploads.length > HIGH_VOLUME_THRESHOLD
  ) {
    plan.highVolumeWarning = HIGH_VOLUME_WARNING;
  }

  return plan;
}

function isValidLifecycleStatus(val: unknown): val is LifecycleStatus {
  return (
    val === "UNPROTECTED" ||
    val === "COVERED" ||
    val === "COVERED_LAGGING" ||
    val === "GHOST_RULE"
  );
}

/**
 * Saves a Plan to a file on disk formatted as JSON.
 */
export async function writePlanFile(
  filePath: string,
  plan: Plan
): Promise<void> {
  const dir = path.dirname(path.resolve(filePath));
  await fs.mkdir(dir, { recursive: true });
  const content = JSON.stringify(plan, null, 2);
  await fs.writeFile(filePath, content, "utf8");
}

/**
 * Loads and validates a Plan file from disk.
 */
export async function readPlanFile(filePath: string): Promise<Plan> {
  const resolved = path.resolve(filePath);
  const content = await fs.readFile(resolved, "utf8");
  const parsed = JSON.parse(content);
  return validatePlan(parsed);
}
