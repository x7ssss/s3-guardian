import {
  S3Client,
  GetBucketLifecycleConfigurationCommand,
  PutBucketLifecycleConfigurationCommand,
  LifecycleRule,
} from "@aws-sdk/client-s3";
import { withRetry, RetryOptions } from "../utils/retry.js";

export interface DirectApplyOptions {
  daysAfterInitiation?: number;
  dangerDirectApiApply?: boolean;
  retryOptions?: RetryOptions;
}

export interface ApplyLifecycleResult {
  bucket: string;
  appliedRule: LifecycleRule;
  totalRules: number;
  action: "CREATED" | "UPDATED";
  preservedRuleIds: string[];
  ghostRuleWarning?: string;
}

export const TARGET_RULE_ID = "s3-guardian-abort-mpu";

/**
 * Executes a safe, direct API Read-Modify-Write mutation on a bucket's lifecycle policy.
 *
 * Invariants:
 *  - Opt-in only: strictly requires `dangerDirectApiApply === true` to avoid wiping IaC state.
 *  - 100% preservation: retains all existing rules (IDs, Expirations, Transitions, Noncurrent versions).
 *  - Merges cleanly: updates rule 's3-guardian-abort-mpu' if already present, otherwise appends.
 *  - Flags existing ghost rules if detected.
 */
export async function applyLifecycleRuleDirectly(
  client: S3Client,
  bucket: string,
  daysOrOptions: number | DirectApplyOptions = 7,
  maybeOptions: DirectApplyOptions = {}
): Promise<ApplyLifecycleResult> {
  const daysAfterInitiation =
    typeof daysOrOptions === "number"
      ? daysOrOptions
      : daysOrOptions.daysAfterInitiation ?? 7;

  const options: DirectApplyOptions =
    typeof daysOrOptions === "object"
      ? daysOrOptions
      : maybeOptions;

  // Invariant: Direct API mutation requires explicit --danger-direct-api-apply
  if (options.dangerDirectApiApply !== true) {
    throw new Error(
      "Safety check failed: The '--danger-direct-api-apply' flag is strictly required to execute direct lifecycle configuration updates. Direct mutation can overwrite or conflict with IaC state (Terraform/CloudFormation)."
    );
  }

  // 1. Fetch existing lifecycle configuration
  let existingRules: LifecycleRule[] = [];
  try {
    const response = await withRetry(
      () =>
        client.send(
          new GetBucketLifecycleConfigurationCommand({ Bucket: bucket })
        ),
      options.retryOptions
    );
    existingRules = response.Rules ?? [];
  } catch (err: unknown) {
    const errorObj = err as Record<string, unknown>;
    const name = String(errorObj?.name || "");
    const status =
      (errorObj?.$metadata as Record<string, unknown> | undefined)
        ?.httpStatusCode ?? errorObj?.statusCode;

    // Gracefully handle buckets without an existing lifecycle policy
    if (name === "NoSuchLifecycleConfiguration" || status === 404) {
      existingRules = [];
    } else {
      throw err;
    }
  }

  // 2. Check for ghost rules among existing rules
  let ghostRuleWarning: string | undefined;
  for (const rule of existingRules) {
    if (rule.AbortIncompleteMultipartUpload) {
      const filter = rule.Filter;
      if (filter) {
        if ("Tag" in filter && filter.Tag) {
          ghostRuleWarning = `Existing rule '${rule.ID}' has a Tag filter which AWS S3 silently ignores for multipart aborts.`;
        } else if ("And" in filter && filter.And?.Tags && filter.And.Tags.length > 0) {
          ghostRuleWarning = `Existing rule '${rule.ID}' combines Tag filters which AWS S3 silently ignores for multipart aborts.`;
        }
      }
    }
  }

  // 3. Prepare target clean rule
  const cleanRule: LifecycleRule = {
    ID: TARGET_RULE_ID,
    Status: "Enabled",
    Filter: {},
    AbortIncompleteMultipartUpload: {
      DaysAfterInitiation: daysAfterInitiation,
    },
  };

  // 4. Merge: update if rule exists with this ID, otherwise append preserving all other rules
  const existingIndex = existingRules.findIndex((r) => r.ID === TARGET_RULE_ID);
  let mergedRules: LifecycleRule[];
  let action: "CREATED" | "UPDATED";

  if (existingIndex >= 0) {
    mergedRules = [...existingRules];
    mergedRules[existingIndex] = cleanRule;
    action = "UPDATED";
  } else {
    mergedRules = [...existingRules, cleanRule];
    action = "CREATED";
  }

  // 5. Apply the updated lifecycle configuration
  await withRetry(
    () =>
      client.send(
        new PutBucketLifecycleConfigurationCommand({
          Bucket: bucket,
          LifecycleConfiguration: {
            Rules: mergedRules,
          },
        })
      ),
    options.retryOptions
  );

  const preservedRuleIds = existingRules
    .filter((r) => r.ID !== TARGET_RULE_ID)
    .map((r) => r.ID ?? "(unnamed)");

  return {
    bucket,
    appliedRule: cleanRule,
    totalRules: mergedRules.length,
    action,
    preservedRuleIds,
    ghostRuleWarning,
  };
}
