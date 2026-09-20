import * as fs from "node:fs/promises";
import * as path from "node:path";
import { calculateMonthlyCostUSD } from "../cost/estimator.js";

export interface ZombieUploadItem {
  key: string;
  uploadId: string;
  initiated: string;
  partsCount: number;
  bytes: number;
}

export interface Plan {
  schemaVersion: "1.0";
  generatedAt: string;
  bucket: string;
  endpoint: string | null;
  olderThanDays: number;
  totalZombieUploads: number;
  totalStrandedBytes: number;
  estimatedMonthlyWasteUSD: number;
  uploads: ZombieUploadItem[];
}

export interface CreatePlanOptions {
  bucket: string;
  endpoint?: string | null;
  olderThanDays: number;
  uploads: ZombieUploadItem[];
  generatedAt?: string;
}

/**
 * Creates a deterministic Plan object with sorted uploads and calculated cost metrics.
 */
export function createPlan(options: CreatePlanOptions): Plan {
  const { bucket, endpoint = null, olderThanDays, generatedAt } = options;

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

  return {
    schemaVersion: "1.0",
    generatedAt: generatedAt ?? new Date().toISOString(),
    bucket,
    endpoint: endpoint ?? null,
    olderThanDays,
    totalZombieUploads,
    totalStrandedBytes,
    estimatedMonthlyWasteUSD,
    uploads: sortedUploads,
  };
}

/**
 * Validates that an arbitrary JSON object conforms to the Plan schema version 1.0.
 */
export function validatePlan(data: unknown): Plan {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("Invalid plan: expected a JSON object");
  }

  const obj = data as Record<string, unknown>;

  if (obj.schemaVersion !== "1.0") {
    throw new Error(
      `Unsupported plan schemaVersion: "${obj.schemaVersion}". Expected "1.0".`
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
    });
  }

  return {
    schemaVersion: "1.0",
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
        : validatedUploads.reduce((sum, u) => sum + u.bytes, 0),
    estimatedMonthlyWasteUSD:
      typeof obj.estimatedMonthlyWasteUSD === "number"
        ? obj.estimatedMonthlyWasteUSD
        : calculateMonthlyCostUSD(
            validatedUploads.reduce((sum, u) => sum + u.bytes, 0)
          ),
    uploads: validatedUploads,
  };
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
