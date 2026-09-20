import {
  S3Client,
  GetBucketLifecycleConfigurationCommand,
  PutBucketLifecycleConfigurationCommand,
  LifecycleRule,
} from "@aws-sdk/client-s3";
import { withRetry, RetryOptions } from "../utils/retry.js";
import { captureLifecyclePreState, createUndoManifest } from "../rollback/manifest-generator.js";
import { UndoManifest } from "../rollback/types.js";
import { computeSha256Hex, canonicalizeJson } from "../planner/jcs.js";

export interface DirectApplyOptions {
  daysAfterInitiation?: number;
  dangerDirectApiApply?: boolean;
  retryOptions?: RetryOptions;
  stateDir?: string;
  appliedPlanHash?: string;
}

export interface ApplyLifecycleResult {
  bucket: string;
  appliedRule: LifecycleRule;
  totalRules: number;
  action: "CREATED" | "UPDATED";
  preservedRuleIds: string[];
  ghostRuleWarning?: string;
  undoManifest?: UndoManifest;
  manifestPath?: string;
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

  // 1. Fetch existing lifecycle configuration & pre-state
  const preStateCapture = await captureLifecyclePreState(client, bucket);
  const existingRules: LifecycleRule[] = preStateCapture.preState?.Rules ?? [];

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
  const putResponse = await withRetry(
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

  let undoManifest: UndoManifest | undefined;
  let manifestPath: string | undefined;
  try {
    const manifestRes = await createUndoManifest({
      stateDir: options.stateDir,
      bucketName: bucket,
      mutationType: "LIFECYCLE_CONFIGURATION",
      preState: preStateCapture.preState,
      postState: { Rules: mergedRules },
      appliedPlanHash:
        options.appliedPlanHash ??
        computeSha256Hex(canonicalizeJson({ bucket, rules: mergedRules })),
      requestIds: putResponse?.$metadata?.requestId ? [putResponse.$metadata.requestId] : [],
    });
    undoManifest = manifestRes.manifest;
    manifestPath = manifestRes.manifestPath;
  } catch (mErr) {
    console.error("[s3-guardian:rollback] Failed to write undo manifest:", mErr);
  }

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
    undoManifest,
    manifestPath,
  };
}
