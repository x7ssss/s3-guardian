import {
  S3Client,
  GetBucketLifecycleConfigurationCommand,
  ListObjectsV2Command,
  LifecycleRule,
} from "@aws-sdk/client-s3";
import {
  calculateTransitionCostDelta,
  normalizeStorageClass,
  MIN_BILLABLE_SIZE_128KIB,
} from "./calculator.js";
import { withRetry, RetryOptions } from "../utils/retry.js";

export const RECOMMENDED_MIN_TRANSITION_SIZE_BYTES = MIN_BILLABLE_SIZE_128KIB; // 131,072 bytes (128 KiB)

const IA_OR_GLACIER_TIERS = new Set([
  "STANDARD_IA",
  "ONEZONE_IA",
  "GLACIER_IR",
  "GLACIER",
  "DEEP_ARCHIVE",
]);

export interface DangerousTransitionRule {
  ruleId: string;
  targetStorageClass: string;
  days: number;
  currentFilterMinSize?: number;
  estimatedPenaltyUSD: number;
  recommendedMinSize: number;
  status?: string;
  transitionType?: "Current" | "Noncurrent";
}

export interface TransitionAuditOptions {
  sampleSize?: number;
  prefix?: string;
  durationDays?: number;
  retryOptions?: RetryOptions;
  overrideSmallObjectCount?: number;
  overrideAverageSmallSizeBytes?: number;
}

export interface BucketTransitionAuditResult {
  bucketName: string;
  hasLifecyclePolicy: boolean;
  dangerousRules: DangerousTransitionRule[];
  totalEstimatedPenaltyUSD: number;
  sampledObjectsCount: number;
  smallObjectsCount: number;
  averageSmallObjectSizeBytes: number;
}

/**
 * Extracts the ObjectSizeGreaterThan filter value from a LifecycleRule, if present.
 * Inspects both top-level filter and AND-composed filters.
 */
export function extractRuleMinSizeFilter(rule: LifecycleRule): number | undefined {
  if (!rule.Filter) {
    return undefined;
  }
  if (typeof rule.Filter.ObjectSizeGreaterThan === "number") {
    return rule.Filter.ObjectSizeGreaterThan;
  }
  if (rule.Filter.And && typeof rule.Filter.And.ObjectSizeGreaterThan === "number") {
    return rule.Filter.And.ObjectSizeGreaterThan;
  }
  return undefined;
}

/**
 * Determines if a storage class belongs to IA or Glacier tiers susceptible to small-object traps.
 */
export function isIaOrGlacierClass(storageClass: string): boolean {
  const normalized = normalizeStorageClass(storageClass);
  return IA_OR_GLACIER_TIERS.has(normalized);
}

/**
 * Audits a bucket's lifecycle configuration for transition traps.
 * 
 * Flags dangerous transition rules:
 * - Rule targets IA or Glacier classes but LACKS ObjectSizeGreaterThan filter,
 *   OR has ObjectSizeGreaterThan < 131072 (128 KiB).
 * - Samples bucket objects to approximate small-object density (< 128 KiB).
 * - Computes projected monthly financial penalty.
 */
export async function auditBucketTransitions(
  s3Client: S3Client,
  bucketName: string,
  options?: TransitionAuditOptions
): Promise<BucketTransitionAuditResult> {
  // 1. Fetch lifecycle configuration
  let rules: LifecycleRule[] = [];
  try {
    const res = await withRetry(
      () =>
        s3Client.send(
          new GetBucketLifecycleConfigurationCommand({ Bucket: bucketName })
        ),
      options?.retryOptions
    );
    rules = res.Rules ?? [];
  } catch (err: unknown) {
    const errorObj = err as Record<string, unknown>;
    const name = String(errorObj?.name || "");
    const status = (errorObj?.$metadata as Record<string, unknown> | undefined)?.httpStatusCode;

    // Gracefully handle buckets with no lifecycle configuration
    if (name === "NoSuchLifecycleConfiguration" || status === 404) {
      return {
        bucketName,
        hasLifecyclePolicy: false,
        dangerousRules: [],
        totalEstimatedPenaltyUSD: 0,
        sampledObjectsCount: 0,
        smallObjectsCount: 0,
        averageSmallObjectSizeBytes: 0,
      };
    }
    throw err;
  }

  // 2. Sample small-object density
  let sampledObjectsCount = 0;
  let smallObjectsCount = 0;
  let averageSmallObjectSizeBytes = 0;

  if (options?.overrideSmallObjectCount !== undefined) {
    smallObjectsCount = options.overrideSmallObjectCount;
    averageSmallObjectSizeBytes = options.overrideAverageSmallSizeBytes ?? 1024;
    sampledObjectsCount = smallObjectsCount;
  } else {
    try {
      const listRes = await withRetry(
        () =>
          s3Client.send(
            new ListObjectsV2Command({
              Bucket: bucketName,
              MaxKeys: options?.sampleSize ?? 1000,
              Prefix: options?.prefix,
            })
          ),
        options?.retryOptions
      );

      const contents = listRes.Contents ?? [];
      sampledObjectsCount = contents.length;
      const smallObjects = contents.filter(
        (obj) => (obj.Size ?? 0) < MIN_BILLABLE_SIZE_128KIB
      );
      smallObjectsCount = smallObjects.length;

      if (smallObjectsCount > 0) {
        const totalSmallBytes = smallObjects.reduce(
          (acc, obj) => acc + (obj.Size ?? 0),
          0
        );
        averageSmallObjectSizeBytes = Math.round(totalSmallBytes / smallObjectsCount);
      }
    } catch {
      // Gracefully continue if listing fails (e.g. permission or unmocked listing)
      sampledObjectsCount = 0;
      smallObjectsCount = 0;
      averageSmallObjectSizeBytes = 0;
    }
  }

  // 3. Parse and flag dangerous transition rules
  const dangerousRules: DangerousTransitionRule[] = [];

  for (const rule of rules) {
    // Only inspect enabled rules for active traps, but flag if status is missing/enabled
    const isEnabled = !rule.Status || rule.Status === "Enabled";
    const ruleId = rule.ID ?? "(no id)";
    const minSize = extractRuleMinSizeFilter(rule);

    // Rule is safe if minSize is explicitly configured >= 128 KiB (131072 bytes)
    const isSizeConstrained = minSize !== undefined && minSize >= RECOMMENDED_MIN_TRANSITION_SIZE_BYTES;

    // Check standard transitions
    if (rule.Transitions && rule.Transitions.length > 0) {
      for (const t of rule.Transitions) {
        const targetClass = t.StorageClass ?? "";
        if (isIaOrGlacierClass(targetClass) && !isSizeConstrained) {
          let estimatedPenaltyUSD = 0;
          if (smallObjectsCount > 0 && isEnabled) {
            const costDelta = calculateTransitionCostDelta({
              objectCount: smallObjectsCount,
              averageSizeBytes: averageSmallObjectSizeBytes,
              targetStorageClass: targetClass,
              durationDays: options?.durationDays ?? 30,
            });
            if (costDelta.isPenalty && costDelta.netMonthlyDelta > 0) {
              estimatedPenaltyUSD = Math.round(costDelta.netMonthlyDelta * 100) / 100;
            }
          }

          dangerousRules.push({
            ruleId,
            targetStorageClass: normalizeStorageClass(targetClass),
            days: t.Days ?? 0,
            currentFilterMinSize: minSize,
            estimatedPenaltyUSD,
            recommendedMinSize: RECOMMENDED_MIN_TRANSITION_SIZE_BYTES,
            status: rule.Status ?? "Enabled",
            transitionType: "Current",
          });
        }
      }
    }

    // Check noncurrent version transitions
    if (rule.NoncurrentVersionTransitions && rule.NoncurrentVersionTransitions.length > 0) {
      for (const t of rule.NoncurrentVersionTransitions) {
        const targetClass = t.StorageClass ?? "";
        if (isIaOrGlacierClass(targetClass) && !isSizeConstrained) {
          let estimatedPenaltyUSD = 0;
          if (smallObjectsCount > 0 && isEnabled) {
            const costDelta = calculateTransitionCostDelta({
              objectCount: smallObjectsCount,
              averageSizeBytes: averageSmallObjectSizeBytes,
              targetStorageClass: targetClass,
              durationDays: options?.durationDays ?? 30,
            });
            if (costDelta.isPenalty && costDelta.netMonthlyDelta > 0) {
              estimatedPenaltyUSD = Math.round(costDelta.netMonthlyDelta * 100) / 100;
            }
          }

          dangerousRules.push({
            ruleId,
            targetStorageClass: normalizeStorageClass(targetClass),
            days: t.NoncurrentDays ?? 0,
            currentFilterMinSize: minSize,
            estimatedPenaltyUSD,
            recommendedMinSize: RECOMMENDED_MIN_TRANSITION_SIZE_BYTES,
            status: rule.Status ?? "Enabled",
            transitionType: "Noncurrent",
          });
        }
      }
    }
  }

  const totalEstimatedPenaltyUSD = dangerousRules.reduce(
    (sum, r) => sum + r.estimatedPenaltyUSD,
    0
  );

  return {
    bucketName,
    hasLifecyclePolicy: rules.length > 0,
    dangerousRules,
    totalEstimatedPenaltyUSD: Math.round(totalEstimatedPenaltyUSD * 100) / 100,
    sampledObjectsCount,
    smallObjectsCount,
    averageSmallObjectSizeBytes,
  };
}
