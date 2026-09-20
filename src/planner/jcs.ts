import { createHash } from "node:crypto";

/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) serializer.
 *
 * Guarantees:
 *  - Deterministic key ordering sorted by UTF-16 code units.
 *  - Zero non-significant whitespace.
 *  - Preserves standard ECMAScript primitive representations.
 */
export function canonicalizeJson(value: unknown): string {
  if (value === null || value === undefined) {
    return "null";
  }

  if (typeof value === "boolean" || typeof value === "number") {
    // In RFC 8785, numbers format according to ECMAScript JSON.stringify
    return JSON.stringify(value);
  }

  if (typeof value === "string") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    const elements = value.map((el) =>
      el === undefined ? "null" : canonicalizeJson(el)
    );
    return `[${elements.join(",")}]`;
  }

  if (typeof value === "object") {
    const keys = Object.keys(value as Record<string, unknown>).sort();
    const entries: string[] = [];
    for (const key of keys) {
      const val = (value as Record<string, unknown>)[key];
      // Skip undefined object values just like JSON.stringify
      if (val !== undefined && typeof val !== "function" && typeof val !== "symbol") {
        entries.push(`${JSON.stringify(key)}:${canonicalizeJson(val)}`);
      }
    }
    return `{${entries.join(",")}}`;
  }

  return JSON.stringify(value);
}

/**
 * Computes a SHA-256 hexadecimal digest of UTF-8 encoded content.
 */
export function computeSha256Hex(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

export interface PlanHashableTargets {
  bucket: string;
  olderThanDays: number;
  uploads?: Array<{ key: string; uploadId: string }>;
  versionDeletions?: Array<{ key: string; versionId: string; type: string }>;
}

/**
 * Generates the canonical JCS string representing the plan's mutation targets.
 */
export function getPlanCanonicalPayload(plan: PlanHashableTargets): string {
  const normalized = {
    bucket: plan.bucket,
    olderThanDays: plan.olderThanDays,
    uploads: (plan.uploads ?? []).map((u) => ({
      key: u.key,
      uploadId: u.uploadId,
    })),
    versionDeletions: (plan.versionDeletions ?? []).map((v) => ({
      key: v.key,
      type: v.type,
      versionId: v.versionId,
    })),
  };
  return canonicalizeJson(normalized);
}

/**
 * Computes the cryptographic RFC 8785 SHA-256 plan hash for plan integrity verification.
 */
export function computePlanHash(plan: PlanHashableTargets): string {
  return computeSha256Hex(getPlanCanonicalPayload(plan));
}
