import {
  PutBucketLifecycleConfigurationCommandInput,
  LifecycleRule,
  LifecycleRuleFilter,
  Tag,
} from "@aws-sdk/client-s3";
import { ResolvedPolicy, EffectivePolicyRule, StorageClass } from "./types.js";

const TRANSITIONS_REQUIRING_128KIB_FLOOR: StorageClass[] = [
  "STANDARD_IA",
  "ONEZONE_IA",
  "GLACIER_IR",
  "GLACIER",
  "DEEP_ARCHIVE",
];

const FLOOR_128_KIB_BYTES = 131072; // 128 * 1024 bytes

/**
 * Builds an AWS S3 LifecycleRuleFilter conforming to AWS API constraints.
 */
function buildLifecycleFilter(params: {
  prefix?: string;
  tags?: Record<string, string>;
  minSizeBytes?: number;
}): LifecycleRuleFilter {
  const hasPrefix = Boolean(params.prefix && params.prefix.trim().length > 0);
  const prefix = hasPrefix ? params.prefix!.trim() : undefined;

  const tagList: Tag[] = params.tags
    ? Object.entries(params.tags).map(([Key, Value]) => ({ Key, Value }))
    : [];

  const minSizeBytes = params.minSizeBytes && params.minSizeBytes > 0 ? params.minSizeBytes : undefined;

  const criteriaCount =
    (hasPrefix ? 1 : 0) +
    tagList.length +
    (minSizeBytes !== undefined ? 1 : 0);

  if (criteriaCount === 0) {
    return {};
  }

  // Single criterion
  if (criteriaCount === 1) {
    if (hasPrefix) {
      return { Prefix: prefix };
    }
    if (tagList.length === 1) {
      return { Tag: tagList[0]! };
    }
    if (minSizeBytes !== undefined) {
      return { ObjectSizeGreaterThan: minSizeBytes };
    }
  }

  // Multiple criteria -> use And block
  return {
    And: {
      ...(hasPrefix ? { Prefix: prefix } : {}),
      ...(tagList.length > 0 ? { Tags: tagList } : {}),
      ...(minSizeBytes !== undefined ? { ObjectSizeGreaterThan: minSizeBytes } : {}),
    },
  };
}

/**
 * Compiles a ResolvedPolicy into a valid AWS PutBucketLifecycleConfigurationCommandInput.
 *
 * Enforces Invariant 5:
 * - Separates MPU abort rules from tag-filtered rules to prevent AWS API rejection.
 * - Injects 128 KiB floor (ObjectSizeGreaterThan >= 131072 bytes) for Standard-IA, GIR, Glacier, and Deep Archive.
 * - Converts minSizeKb to exact bytes.
 * - Guarantees Status: "Enabled".
 */
export function compileToLifecycleConfiguration(
  bucketName: string,
  resolvedPolicy: ResolvedPolicy
): PutBucketLifecycleConfigurationCommandInput {
  const compiledRules: LifecycleRule[] = [];

  for (const rule of resolvedPolicy.effectiveRules) {
    const hasObjectTags =
      rule.match?.object?.tags &&
      Object.keys(rule.match.object.tags).length > 0;

    const hasMpuAbort = rule.mpuAbortDays !== undefined;

    // Check if 128 KiB floor is required
    let requires128KibFloor = false;
    if (rule.transitions && rule.transitions.length > 0) {
      for (const t of rule.transitions) {
        if (TRANSITIONS_REQUIRING_128KIB_FLOOR.includes(t.storageClass)) {
          requires128KibFloor = true;
          break;
        }
      }
    }

    // Determine effective minSizeBytes
    let minSizeBytes: number | undefined = undefined;
    const ruleMinSizeKb = rule.match?.object?.minSizeKb;

    if (ruleMinSizeKb !== undefined) {
      minSizeBytes = ruleMinSizeKb * 1024;
    }

    // If 128 KiB floor is required, ensure minSizeBytes >= 131072
    if (requires128KibFloor) {
      minSizeBytes = Math.max(minSizeBytes ?? 0, FLOOR_128_KIB_BYTES);
    }

    // If rule has MPU abort AND object tags, compile MPU abort as a separate rule
    // because AWS S3 strictly forbids AbortIncompleteMultipartUpload with Tag filters
    if (hasMpuAbort && hasObjectTags) {
      // 1. Standalone MPU rule without tags
      compiledRules.push({
        ID: `${rule.id}-abort-mpu`,
        Status: "Enabled",
        Filter: rule.match?.object?.prefix ? { Prefix: rule.match.object.prefix } : {},
        AbortIncompleteMultipartUpload: {
          DaysAfterInitiation: rule.mpuAbortDays,
        },
      });

      // 2. Object lifecycle rule with tags (transitions, expirations)
      const objectRule: LifecycleRule = {
        ID: rule.id,
        Status: "Enabled",
        Filter: buildLifecycleFilter({
          prefix: rule.match?.object?.prefix,
          tags: rule.match?.object?.tags,
          minSizeBytes,
        }),
      };

      if (rule.transitions && rule.transitions.length > 0) {
        objectRule.Transitions = rule.transitions.map((t) => ({
          Days: t.days,
          StorageClass: t.storageClass,
        }));
      }

      if (rule.expirationDays !== undefined) {
        objectRule.Expiration = {
          Days: rule.expirationDays,
        };
      }

      if (rule.noncurrentExpirationDays !== undefined) {
        objectRule.NoncurrentVersionExpiration = {
          NoncurrentDays: rule.noncurrentExpirationDays,
          ...(rule.retainVersions !== undefined
            ? { NewerNoncurrentVersions: rule.retainVersions }
            : {}),
        };
      }

      // Only push if there are actual lifecycle actions on the object rule
      if (
        objectRule.Transitions ||
        objectRule.Expiration ||
        objectRule.NoncurrentVersionExpiration
      ) {
        compiledRules.push(objectRule);
      }
    } else {
      // Rule does not combine MPU abort with tags -> single consolidated rule
      const consolidatedRule: LifecycleRule = {
        ID: rule.id,
        Status: "Enabled",
        Filter: buildLifecycleFilter({
          prefix: rule.match?.object?.prefix,
          tags: rule.match?.object?.tags,
          minSizeBytes,
        }),
      };

      if (hasMpuAbort) {
        consolidatedRule.AbortIncompleteMultipartUpload = {
          DaysAfterInitiation: rule.mpuAbortDays,
        };
      }

      if (rule.transitions && rule.transitions.length > 0) {
        consolidatedRule.Transitions = rule.transitions.map((t) => ({
          Days: t.days,
          StorageClass: t.storageClass,
        }));
      }

      if (rule.expirationDays !== undefined) {
        consolidatedRule.Expiration = {
          Days: rule.expirationDays,
        };
      }

      if (rule.noncurrentExpirationDays !== undefined) {
        consolidatedRule.NoncurrentVersionExpiration = {
          NoncurrentDays: rule.noncurrentExpirationDays,
          ...(rule.retainVersions !== undefined
            ? { NewerNoncurrentVersions: rule.retainVersions }
            : {}),
        };
      }

      compiledRules.push(consolidatedRule);
    }
  }

  return {
    Bucket: bucketName,
    LifecycleConfiguration: {
      Rules: compiledRules,
    },
  };
}
