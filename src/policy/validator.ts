import { GuardianPolicy, PolicyValidationResult, StorageClass } from "./types.js";

const VALID_STORAGE_CLASSES: StorageClass[] = [
  "STANDARD_IA",
  "ONEZONE_IA",
  "INTELLIGENT_TIERING",
  "GLACIER_IR",
  "GLACIER",
  "DEEP_ARCHIVE",
];

const VALID_ACTION_MODES = ["MONITOR_ONLY", "PLAN_ONLY", "AUTO_REMEDIATE"];

/**
 * Statically validates a GuardianPolicy against AWS constraints and FinOps safety invariants.
 */
export function validatePolicy(policy: GuardianPolicy): PolicyValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // AWS Limit: Max 1000 rules per bucket lifecycle policy
  if (policy.rules.length > 1000) {
    errors.push(`Policy '${policy.policyId}' exceeds maximum of 1,000 rules (has ${policy.rules.length}).`);
  }

  // Check defaults if present
  if (policy.defaults) {
    if (policy.defaults.action && !VALID_ACTION_MODES.includes(policy.defaults.action)) {
      errors.push(`Invalid default action '${policy.defaults.action}'.`);
    }

    // Invariant 5: MPU Churn Guard (mpuAbortAfter >= 7 days)
    if (policy.defaults.mpuAbortDays !== undefined) {
      if (policy.defaults.mpuAbortDays < 7) {
        errors.push(
          `Defaults mpuAbortDays must be >= 7 days to avoid aborting active in-flight multipart uploads (got ${policy.defaults.mpuAbortDays}d).`
        );
      }
    }

    if (policy.defaults.retainVersions !== undefined) {
      if (policy.defaults.retainVersions < 1 || policy.defaults.retainVersions > 100) {
        errors.push(
          `Defaults retainVersions must be between 1 and 100 (got ${policy.defaults.retainVersions}).`
        );
      }
    }
  }

  const seenRuleIds = new Set<string>();

  for (let i = 0; i < policy.rules.length; i++) {
    const rule = policy.rules[i]!;

    // AWS Limit: Rule ID length <= 255
    if (rule.id.length > 255) {
      errors.push(`Rule '${rule.id}' ID exceeds maximum length of 255 characters (length ${rule.id.length}).`);
    }

    if (seenRuleIds.has(rule.id)) {
      errors.push(`Duplicate rule ID '${rule.id}' detected in policy '${policy.policyId}'.`);
    }
    seenRuleIds.add(rule.id);

    if (rule.action && !VALID_ACTION_MODES.includes(rule.action)) {
      errors.push(`Rule '${rule.id}' specifies invalid action '${rule.action}'.`);
    }

    // Invariant 5: MPU Churn Guard
    if (rule.mpuAbortDays !== undefined) {
      if (rule.mpuAbortDays < 7) {
        errors.push(
          `Rule '${rule.id}' specifies mpuAbortDays < 7 (${rule.mpuAbortDays}d). Abort threshold must be at least 7 days to prevent active churn abortion.`
        );
      }
    }

    // Invariant 5: Tag/MPU Contradiction Guard
    // AWS S3 strictly rejects AbortIncompleteMultipartUpload rules with Tag filters
    const hasObjectTags =
      rule.match?.object?.tags &&
      Object.keys(rule.match.object.tags).length > 0;
    if (rule.mpuAbortDays !== undefined && hasObjectTags) {
      errors.push(
        `Rule '${rule.id}' combines mpuAbortDays with object.tags. AWS S3 does not permit tag filters on multipart upload abort configurations.`
      );
    }

    // Validate retainVersions
    if (rule.retainVersions !== undefined) {
      if (rule.retainVersions < 1 || rule.retainVersions > 100) {
        errors.push(
          `Rule '${rule.id}' specifies retainVersions (${rule.retainVersions}) outside the allowed 1-100 range.`
        );
      }
    }

    // Validate transitions
    if (rule.transitions && Array.isArray(rule.transitions)) {
      for (const t of rule.transitions) {
        if (!VALID_STORAGE_CLASSES.includes(t.storageClass)) {
          errors.push(
            `Rule '${rule.id}' specifies invalid storageClass '${t.storageClass}'. Allowed: ${VALID_STORAGE_CLASSES.join(", ")}.`
          );
        }

        // Invariant 5: 128 KiB Floor
        // Transitions to Standard-IA, OneZone-IA, GIR, Glacier, GDA must inject ObjectSizeGreaterThan >= 131072 bytes (128 KiB)
        if (t.storageClass !== "INTELLIGENT_TIERING") {
          const effectiveMinSizeKb = t.minSizeKb ?? rule.match?.object?.minSizeKb;
          if (effectiveMinSizeKb === undefined || effectiveMinSizeKb < 128) {
            errors.push(
              `Rule '${rule.id}' transition to ${t.storageClass} violates the 128 KiB floor. AWS enforces a 128 KiB minimum storage billing penalty for ${t.storageClass}. minSizeKb must be >= 128 (got ${effectiveMinSizeKb ?? "none"}).`
            );
          }
        }

        // Invariant 5: Early Deletion Penalty Guard
        // Glacier / GIR charges a minimum 90-day retention fee
        if (
          (t.storageClass === "GLACIER" || t.storageClass === "GLACIER_IR") &&
          rule.expirationDays !== undefined
        ) {
          const retentionDaysInTier = rule.expirationDays - t.days;
          if (retentionDaysInTier < 90) {
            errors.push(
              `Rule '${rule.id}' transition to ${t.storageClass} at ${t.days}d with expiration at ${rule.expirationDays}d yields only ${retentionDaysInTier} days in tier. AWS charges 90 days minimum retention for ${t.storageClass}, triggering premature deletion penalties.`
            );
          }
        }

        // Deep Archive charges a minimum 180-day retention fee
        if (
          t.storageClass === "DEEP_ARCHIVE" &&
          rule.expirationDays !== undefined
        ) {
          const retentionDaysInTier = rule.expirationDays - t.days;
          if (retentionDaysInTier < 180) {
            errors.push(
              `Rule '${rule.id}' transition to DEEP_ARCHIVE at ${t.days}d with expiration at ${rule.expirationDays}d yields only ${retentionDaysInTier} days in tier. AWS charges 180 days minimum retention for DEEP_ARCHIVE, triggering premature deletion penalties.`
            );
          }
        }
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}
