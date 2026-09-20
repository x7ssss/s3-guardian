import {
  S3Client,
  GetBucketLifecycleConfigurationCommand,
  LifecycleRule,
} from "@aws-sdk/client-s3";
import { withRetry, RetryOptions } from "../utils/retry.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ParsedMpuRule {
  ruleId: string;
  status: "Enabled" | "Disabled" | string;
  /** Days after which the incomplete multipart upload is aborted */
  daysAfterInitiation: number;
  /** Prefix filter, if any (empty string means "all objects") */
  prefix: string;
  /** True when the rule has a Tag filter — Tag-based filtering is ignored by S3
   *  for AbortIncompleteMultipartUpload, making the rule a "Ghost Rule". */
  hasTagFilter: boolean;
  /** True if multiple conflicting filters are present (AND/OR) that may prevent evaluation */
  hasConflictingFilters: boolean;
}

export type UploadLifecycleStatus =
  | "UNPROTECTED"    // No covering lifecycle rule found at all
  | "COVERED"        // Active rule covers this upload's prefix and it's within the threshold
  | "COVERED_LAGGING" // Covered, but the upload has already aged past the rule threshold
  | "GHOST_RULE";    // The only matching rule is a Ghost Rule (tag filter present)

export interface LifecycleAuditResult {
  bucketHasLifecyclePolicy: boolean;
  hasCoveringRule: boolean;
  mpuRules: ParsedMpuRule[];
  ghostRulesDetected: string[];
  providerNotes?: string;
}

export interface UploadCoverageResult {
  status: UploadLifecycleStatus;
  matchedRuleId?: string;
  daysAfterInitiation?: number;
}

import { detectProvider, S3Provider } from "../providers/detector.js";
export { detectProvider };

// ─── Ghost Rule Detection ─────────────────────────────────────────────────────

/**
 * Parses a lifecycle Rule and extracts MPU abort settings.
 * Returns null if the rule has no AbortIncompleteMultipartUpload action.
 *
 * Ghost Rule Detection:
 *   AWS S3 silently ignores AbortIncompleteMultipartUpload rules that use
 *   Tag-based filters. Such rules appear valid in GetBucketLifecycleConfiguration
 *   but are never applied to multipart uploads.
 */
export function parseMpuRule(rule: LifecycleRule): ParsedMpuRule | null {
  const abort = rule.AbortIncompleteMultipartUpload;
  if (!abort || typeof abort.DaysAfterInitiation !== "number") {
    return null;
  }

  let prefix = "";
  let hasTagFilter = false;
  let hasConflictingFilters = false;

  const filter = rule.Filter;
  if (filter) {
    if ("Prefix" in filter && typeof filter.Prefix === "string") {
      prefix = filter.Prefix;
    } else if ("And" in filter && filter.And) {
      // AND filter can combine Prefix + Tags; Tags make it a Ghost Rule
      const andFilter = filter.And;
      if (typeof andFilter.Prefix === "string") {
        prefix = andFilter.Prefix;
      }
      if (andFilter.Tags && andFilter.Tags.length > 0) {
        hasTagFilter = true;
      }
      hasConflictingFilters = true;
    } else if ("Tag" in filter && filter.Tag) {
      // Pure tag filter — always a Ghost Rule for MPU aborts
      hasTagFilter = true;
    }
  }

  return {
    ruleId: rule.ID ?? "(no id)",
    status: rule.Status ?? "Unknown",
    daysAfterInitiation: abort.DaysAfterInitiation,
    prefix,
    hasTagFilter,
    hasConflictingFilters,
  };
}

// ─── Coverage Evaluation ──────────────────────────────────────────────────────

/**
 * Determines if a specific upload (by key + initiated date) is covered
 * by any of the parsed MPU lifecycle rules.
 *
 * @param key             - The object key of the multipart upload
 * @param initiatedDate   - When the upload started
 * @param rules           - All parsed MPU rules from the bucket lifecycle
 * @param now             - Reference "now" (for testability)
 */
export function evaluateUploadCoverage(
  key: string,
  initiatedDate: Date,
  rules: ParsedMpuRule[],
  now: Date = new Date()
): UploadCoverageResult {
  const enabledRules = rules.filter((r) => r.status === "Enabled");
  if (enabledRules.length === 0) {
    return { status: "UNPROTECTED" };
  }

  // Find matching rules: prefix must match (empty prefix = matches all)
  const matchingRules = enabledRules.filter((r) =>
    key.startsWith(r.prefix)
  );

  if (matchingRules.length === 0) {
    return { status: "UNPROTECTED" };
  }

  // Check for Ghost Rules: if ALL matching rules have tag filters, it's a Ghost Rule
  const realRules = matchingRules.filter((r) => !r.hasTagFilter);
  const ghostRules = matchingRules.filter((r) => r.hasTagFilter);

  if (realRules.length === 0 && ghostRules.length > 0) {
    return {
      status: "GHOST_RULE",
      matchedRuleId: ghostRules[0].ruleId,
      daysAfterInitiation: ghostRules[0].daysAfterInitiation,
    };
  }

  // Pick the best real rule (shortest daysAfterInitiation = most aggressive cleanup)
  const bestRule = realRules.reduce((a, b) =>
    a.daysAfterInitiation <= b.daysAfterInitiation ? a : b
  );

  const ageMs = now.getTime() - initiatedDate.getTime();
  const ageDays = ageMs / (1000 * 60 * 60 * 24);

  if (ageDays > bestRule.daysAfterInitiation) {
    // Upload has already aged past the threshold — it should have been cleaned
    return {
      status: "COVERED_LAGGING",
      matchedRuleId: bestRule.ruleId,
      daysAfterInitiation: bestRule.daysAfterInitiation,
    };
  }

  return {
    status: "COVERED",
    matchedRuleId: bestRule.ruleId,
    daysAfterInitiation: bestRule.daysAfterInitiation,
  };
}

// ─── Main Audit Function ──────────────────────────────────────────────────────

/**
 * Fetches and audits the bucket lifecycle configuration.
 * - Handles NoSuchLifecycleConfiguration (404) gracefully.
 * - Detects Ghost Rules (tag filters on MPU abort rules).
 * - Provides provider-specific notes for MinIO and Cloudflare R2.
 */
export async function auditBucketLifecycle(
  client: S3Client,
  bucket: string,
  endpoint?: string | null,
  retryOptions?: RetryOptions
): Promise<LifecycleAuditResult> {
  const provider = detectProvider(endpoint);

  // Provider-specific short-circuits
  if (provider === "minio") {
    return {
      bucketHasLifecyclePolicy: false,
      hasCoveringRule: false,
      mpuRules: [],
      ghostRulesDetected: [],
      providerNotes:
        "MinIO detected (local endpoint). Lifecycle MPU abort rules behave differently from AWS S3; skipping lifecycle audit.",
    };
  }

  if (provider === "ceph") {
    return {
      bucketHasLifecyclePolicy: false,
      hasCoveringRule: false,
      mpuRules: [],
      ghostRulesDetected: [],
      providerNotes:
        "Ceph RADOS Gateway detected. Lifecycle MPU abort rules behave differently from AWS S3; skipping lifecycle audit.",
    };
  }

  if (provider === "r2") {
    return {
      bucketHasLifecyclePolicy: true,
      hasCoveringRule: true,
      mpuRules: [],
      ghostRulesDetected: [],
      providerNotes:
        "Cloudflare R2 detected. R2 automatically purges incomplete multipart uploads after 7 days by default.",
    };
  }

  // Fetch lifecycle configuration from AWS
  let rules: LifecycleRule[] = [];
  try {
    const response = await withRetry(
      () =>
        client.send(
          new GetBucketLifecycleConfigurationCommand({ Bucket: bucket })
        ),
      retryOptions
    );
    rules = response?.Rules ?? [];
  } catch (err: unknown) {
    const errorObj = err as Record<string, unknown>;
    const name = String(errorObj.name || "");
    const status =
      (errorObj.$metadata as Record<string, unknown> | undefined)
        ?.httpStatusCode ?? errorObj.statusCode;

    // NoSuchLifecycleConfiguration or 404/405/501 (unsupported on custom providers)
    if (
      name === "NoSuchLifecycleConfiguration" ||
      name === "MethodNotAllowed" ||
      name === "NotImplemented" ||
      status === 404 ||
      status === 405 ||
      status === 501
    ) {
      return {
        bucketHasLifecyclePolicy: false,
        hasCoveringRule: false,
        mpuRules: [],
        ghostRulesDetected: [],
      };
    }
    throw err;
  }

  // Parse MPU rules and detect ghost rules
  const mpuRules: ParsedMpuRule[] = [];
  const ghostRulesDetected: string[] = [];

  for (const rule of rules) {
    const parsed = parseMpuRule(rule);
    if (!parsed) continue;

    mpuRules.push(parsed);
    if (parsed.hasTagFilter) {
      ghostRulesDetected.push(
        `Rule '${parsed.ruleId}' uses a Tag filter which AWS S3 silently ignores for AbortIncompleteMultipartUpload. This rule will NEVER abort zombie uploads.`
      );
    }
  }

  const realEnabledRules = mpuRules.filter(
    (r) => r.status === "Enabled" && !r.hasTagFilter
  );
  const hasCoveringRule = realEnabledRules.length > 0;

  return {
    bucketHasLifecyclePolicy: rules.length > 0,
    hasCoveringRule,
    mpuRules,
    ghostRulesDetected,
  };
}
