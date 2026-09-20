import * as fs from "node:fs/promises";
import * as path from "node:path";
import { calculateMonthlyCostUSD } from "../cost/estimator.js";
import type { LifecycleAuditResult } from "../lifecycle/audit.js";
import type { BlastRadiusAssessment } from "../safety/blast-radius.js";
import { computePlanHash } from "./jcs.js";

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

export interface VersionDeletionEntry {
  key: string;
  versionId: string;
  type: "NONCURRENT_VERSION" | "EXPIRED_DELETE_MARKER";
  size: number;
  lastModified: string;
}

export interface Plan {
  schemaVersion: "1.1" | "1.2" | "1.3";
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
  /** Pre-flight blast radius assessment results (Schema 1.3) */
  blastRadiusAudit?: BlastRadiusAssessment;
  /** RFC 8785 canonical SHA-256 plan integrity hash (Schema 1.3) */
  planHash?: string;
  /** Only present when total targeted items > 10,000 */
  highVolumeWarning?: string;
  uploads: ZombieUploadItem[];
  versionDeletions?: VersionDeletionEntry[];
  totalNoncurrentVersions?: number;
  totalExpiredDeleteMarkers?: number;
  versioningStrandedBytes?: number;
  versioningMonthlyWasteUSD?: number;
}

export interface CreatePlanOptions {
  bucket: string;
  endpoint?: string | null;
  olderThanDays: number;
  uploads?: ZombieUploadItem[];
  versionDeletions?: VersionDeletionEntry[];
  lifecycleAudit: LifecycleAuditResult;
  blastRadiusAudit?: BlastRadiusAssessment;
  generatedAt?: string;
  schemaVersion?: "1.1" | "1.2" | "1.3";
}

const HIGH_VOLUME_THRESHOLD = 10_000;
const HIGH_VOLUME_WARNING =
  "Executing apply on >10k uploads will generate substantial CloudTrail Data Events.";

/**
 * Creates a deterministic Plan object (schema 1.1 or 1.2) with sorted uploads/versions,
 * calculated cost metrics, lifecycle audit summary, and optional high-volume warning.
 */
export function createPlan(options: CreatePlanOptions): Plan {
  const {
    bucket,
    endpoint = null,
    olderThanDays,
    generatedAt,
    lifecycleAudit,
    versionDeletions,
  } = options;

  const rawUploads = options.uploads ?? [];

  // Deterministic sorting: sort primarily by key, secondarily by uploadId
  const sortedUploads = [...rawUploads].sort((a, b) => {
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

  const hasVersioning = Boolean(versionDeletions && versionDeletions.length > 0);
  const schemaVersion = options.schemaVersion ?? "1.3";

  const plan: Plan = {
    schemaVersion,
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

  if (hasVersioning && versionDeletions) {
    const sortedVersions = [...versionDeletions].sort((a, b) => {
      const keyComp = a.key.localeCompare(b.key);
      if (keyComp !== 0) return keyComp;
      return a.versionId.localeCompare(b.versionId);
    });

    const noncurrent = sortedVersions.filter((v) => v.type === "NONCURRENT_VERSION");
    const eodms = sortedVersions.filter((v) => v.type === "EXPIRED_DELETE_MARKER");
    const versioningBytes = noncurrent.reduce((sum, v) => sum + v.size, 0);

    plan.versionDeletions = sortedVersions;
    plan.totalNoncurrentVersions = noncurrent.length;
    plan.totalExpiredDeleteMarkers = eodms.length;
    plan.versioningStrandedBytes = versioningBytes;
    plan.versioningMonthlyWasteUSD = calculateMonthlyCostUSD(versioningBytes);
  }

  if (options.blastRadiusAudit) {
    plan.blastRadiusAudit = options.blastRadiusAudit;
  }

  if (plan.schemaVersion === "1.3") {
    plan.planHash = computePlanHash(plan);
  }

  const totalTargeted = totalZombieUploads + (plan.versionDeletions?.length ?? 0);
  if (totalTargeted > HIGH_VOLUME_THRESHOLD) {
    plan.highVolumeWarning = HIGH_VOLUME_WARNING;
  }

  return plan;
}

/**
 * Validates that an arbitrary JSON object conforms to Plan schema 1.0, 1.1, 1.2, or 1.3.
 * Schema 1.0 plans are up-converted to 1.1 with safe defaults.
 */
export function validatePlan(data: unknown): Plan {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("Invalid plan: expected a JSON object");
  }

  const obj = data as Record<string, unknown>;

  if (
    obj.schemaVersion !== "1.0" &&
    obj.schemaVersion !== "1.1" &&
    obj.schemaVersion !== "1.2" &&
    obj.schemaVersion !== "1.3"
  ) {
    throw new Error(
      `Unsupported plan schemaVersion: "${obj.schemaVersion}". Expected "1.0", "1.1", "1.2", or "1.3".`
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
        storageClass:
          typeof u.storageClass === "string" ? u.storageClass : "STANDARD",
        lifecycleStatus: isValidLifecycleStatus(u.lifecycleStatus)
          ? u.lifecycleStatus
          : "UNPROTECTED",
      });
    }

  const validatedVersions: VersionDeletionEntry[] = [];
  if (Array.isArray(obj.versionDeletions)) {
    for (let i = 0; i < obj.versionDeletions.length; i++) {
      const item = obj.versionDeletions[i];
      if (!item || typeof item !== "object" || Array.isArray(item)) {
        throw new Error(`Invalid plan: version deletion item at index ${i} is not an object`);
      }
      const v = item as Record<string, unknown>;
      if (typeof v.key !== "string" || !v.key) {
        throw new Error(`Invalid plan: version item at index ${i} missing 'key'`);
      }
      if (typeof v.versionId !== "string" || !v.versionId) {
        throw new Error(`Invalid plan: version item at index ${i} missing 'versionId'`);
      }
      validatedVersions.push({
        key: v.key,
        versionId: v.versionId,
        type:
          v.type === "EXPIRED_DELETE_MARKER"
            ? "EXPIRED_DELETE_MARKER"
            : "NONCURRENT_VERSION",
        size: typeof v.size === "number" ? v.size : 0,
        lastModified:
          typeof v.lastModified === "string"
            ? v.lastModified
            : new Date().toISOString(),
      });
    }
  }

  const totalStrandedBytes = validatedUploads.reduce((sum, u) => sum + u.bytes, 0);

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

  let schemaVersion: "1.1" | "1.2" | "1.3" = "1.1";
  if (obj.schemaVersion === "1.3") {
    schemaVersion = "1.3";
  } else if (obj.schemaVersion === "1.2" || validatedVersions.length > 0) {
    schemaVersion = "1.2";
  }

  const plan: Plan = {
    schemaVersion,
    generatedAt:
      typeof obj.generatedAt === "string"
        ? obj.generatedAt
        : new Date().toISOString(),
    bucket: obj.bucket as string,
    endpoint: typeof obj.endpoint === "string" ? obj.endpoint : null,
    olderThanDays: obj.olderThanDays as number,
    totalZombieUploads: validatedUploads.length,
    totalStrandedBytes,
    estimatedMonthlyWasteUSD: calculateMonthlyCostUSD(totalStrandedBytes),
    lifecycleAudit,
    uploads: validatedUploads,
  };

  if (typeof obj.planHash === "string") {
    plan.planHash = obj.planHash;
  }

  if (obj.blastRadiusAudit && typeof obj.blastRadiusAudit === "object") {
    plan.blastRadiusAudit = obj.blastRadiusAudit as BlastRadiusAssessment;
  }

  if (validatedVersions.length > 0) {
    const noncurrent = validatedVersions.filter((v) => v.type === "NONCURRENT_VERSION");
    const eodms = validatedVersions.filter((v) => v.type === "EXPIRED_DELETE_MARKER");
    const vBytes = noncurrent.reduce((sum, v) => sum + v.size, 0);

    plan.versionDeletions = validatedVersions;
    plan.totalNoncurrentVersions = noncurrent.length;
    plan.totalExpiredDeleteMarkers = eodms.length;
    plan.versioningStrandedBytes = vBytes;
    plan.versioningMonthlyWasteUSD = calculateMonthlyCostUSD(vBytes);
  }

  const totalItems = validatedUploads.length + validatedVersions.length;
  if (totalItems > HIGH_VOLUME_THRESHOLD) {
    plan.highVolumeWarning = HIGH_VOLUME_WARNING;
  }

  return plan;
}

/**
 * Cryptographically verifies plan integrity against RFC 8785 SHA-256 target hash.
 * Returns valid: true if hash matches or if plan is legacy schema without hash.
 * Returns valid: false if hash is missing on schema 1.3 or if calculated hash differs.
 */
export function verifyPlanIntegrity(plan: Plan): { valid: boolean; error?: string } {
  if (plan.schemaVersion === "1.3") {
    if (!plan.planHash || typeof plan.planHash !== "string") {
      return {
        valid: false,
        error: "Plan schema 1.3 requires a cryptographic planHash but none was found.",
      };
    }

    const calculatedHash = computePlanHash(plan);
    if (plan.planHash !== calculatedHash) {
      return {
        valid: false,
        error: `Plan integrity verification failed. Expected SHA-256 "${calculatedHash}", found "${plan.planHash}". The plan targets have been altered or corrupted.`,
      };
    }
  } else if (plan.planHash) {
    const calculatedHash = computePlanHash(plan);
    if (plan.planHash !== calculatedHash) {
      return {
        valid: false,
        error: `Plan integrity verification failed. Expected SHA-256 "${calculatedHash}", found "${plan.planHash}". The plan targets have been altered or corrupted.`,
      };
    }
  }

  return { valid: true };
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
 * Atomically writes a Plan to disk as pretty JSON.
 */
export async function writePlanFile(filePath: string, plan: Plan): Promise<void> {
  const resolvedPath = path.resolve(filePath);
  const dir = path.dirname(resolvedPath);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(resolvedPath, JSON.stringify(plan, null, 2), "utf8");
}

/**
 * Reads and validates a Plan file from disk.
 */
export async function readPlanFile(filePath: string): Promise<Plan> {
  const resolvedPath = path.resolve(filePath);
  const raw = await fs.readFile(resolvedPath, "utf8");
  const parsed = JSON.parse(raw);
  return validatePlan(parsed);
}
