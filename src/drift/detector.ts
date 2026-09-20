import {
  S3Client,
  GetBucketLifecycleConfigurationCommand,
  LifecycleRule,
} from "@aws-sdk/client-s3";
import * as fs from "node:fs/promises";
import {
  parseTerraformState,
  ManagedLifecycleRule,
  ManagedBucketLifecycle,
} from "./tfstate-parser.js";
import {
  generateHclPatch,
  DriftRecommendations,
} from "./hcl-patcher.js";

export type DriftStatus = "IN_SYNC" | "DRIFT_DETECTED" | "GHOST_CONFIG";

export interface DetectLifecycleDriftOptions {
  tfFile?: string;
  tfContent?: string;
  tfStateFile?: string;
  tfStateContent?: string;
  prefix?: string;
  generatePatch?: boolean;
}

export interface LifecycleDriftResult {
  bucketName: string;
  isDrifted: boolean;
  status: DriftStatus;
  differences: string[];
  patch?: string;
  patchedTfContent?: string;
  liveRulesCount: number;
  iacRulesCount: number;
  resourceType?: string;
  targetTfFile?: string;
  liveRules?: LifecycleRule[];
  iacRules?: ManagedLifecycleRule[];
}

/**
 * Extracts ManagedLifecycleRule entries directly from HCL `.tf` file content.
 */
export function parseHclLifecycleRules(
  tfContent: string,
  bucketName: string
): { rules: ManagedLifecycleRule[]; resourceType?: string; resourceName?: string } {
  const resourceRegex = /resource\s+"aws_s3_bucket_lifecycle_configuration"\s+"([^"]+)"\s*\{/g;
  let match: RegExpExecArray | null;

  while ((match = resourceRegex.exec(tfContent)) !== null) {
    const resourceName = match[1];
    const startIndex = match.index;
    const openBrace = tfContent.indexOf("{", startIndex);
    if (openBrace === -1) continue;

    let depth = 1;
    let i = openBrace + 1;
    while (i < tfContent.length && depth > 0) {
      if (tfContent[i] === "{") depth++;
      else if (tfContent[i] === "}") depth--;
      i++;
    }

    if (depth === 0) {
      const blockBody = tfContent.slice(startIndex, i);
      const safeBucket = bucketName.replace(/[^a-zA-Z0-9_]/g, "_");

      const directMatch = new RegExp(`bucket\\s*=\\s*["']?${escapeRegExp(bucketName)}["']?`).test(blockBody);
      const nameMatch = resourceName === `lifecycle_${safeBucket}` || resourceName === safeBucket;
      const refMatch = new RegExp(`aws_s3_bucket\\.${escapeRegExp(safeBucket)}\\.(id|bucket)`).test(blockBody);

      if (directMatch || nameMatch || refMatch) {
        const rules = extractRulesFromHclBlock(blockBody);
        return {
          rules,
          resourceType: "aws_s3_bucket_lifecycle_configuration",
          resourceName,
        };
      }
    }
  }

  return { rules: [] };
}

function escapeRegExp(string: string): string {
  return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function extractRulesFromHclBlock(blockBody: string): ManagedLifecycleRule[] {
  const rules: ManagedLifecycleRule[] = [];
  const ruleRegex = /rule\s*\{/g;
  let ruleMatch: RegExpExecArray | null;

  while ((ruleMatch = ruleRegex.exec(blockBody)) !== null) {
    const rStart = ruleMatch.index;
    const openBrace = blockBody.indexOf("{", rStart);
    if (openBrace === -1) continue;

    let depth = 1;
    let i = openBrace + 1;
    while (i < blockBody.length && depth > 0) {
      if (blockBody[i] === "{") depth++;
      else if (blockBody[i] === "}") depth--;
      i++;
    }

    if (depth === 0) {
      const ruleBody = blockBody.slice(rStart, i);
      const idMatch = /id\s*=\s*"([^"]+)"/.exec(ruleBody);
      const id = idMatch ? idMatch[1] : "";

      const statusMatch = /status\s*=\s*"([^"]+)"/i.exec(ruleBody);
      const status: "Enabled" | "Disabled" =
        statusMatch && statusMatch[1].toLowerCase() === "disabled" ? "Disabled" : "Enabled";

      const prefixMatch = /prefix\s*=\s*"([^"]*)"/.exec(ruleBody);
      const prefix = prefixMatch && prefixMatch[1] ? prefixMatch[1] : undefined;

      const mpuMatch = /abort_incomplete_multipart_upload\s*\{[^}]*days_after_initiation\s*=\s*(\d+)/.exec(ruleBody);
      const abortDays = mpuMatch ? parseInt(mpuMatch[1], 10) : undefined;

      const ncMatch = /noncurrent_version_expiration\s*\{[^}]*noncurrent_days\s*=\s*(\d+)/.exec(ruleBody);
      const ncDays = ncMatch ? parseInt(ncMatch[1], 10) : undefined;

      const expiredMarker = /expired_object_delete_marker\s*=\s*true/.test(ruleBody);

      const sizeMatch = /object_size_greater_than\s*=\s*(\d+)/.exec(ruleBody);
      const objectSizeGreaterThan = sizeMatch ? parseInt(sizeMatch[1], 10) : undefined;

      const hasTagFilter = /tag\s*\{|tags\s*=/.test(ruleBody);

      const transitions: Array<{ days?: number; storageClass: string }> = [];
      const transRegex = /transition\s*\{([^}]+)\}/g;
      let tMatch: RegExpExecArray | null;
      while ((tMatch = transRegex.exec(ruleBody)) !== null) {
        const tBody = tMatch[1];
        const scMatch = /storage_class\s*=\s*"([^"]+)"/.exec(tBody);
        const dMatch = /days\s*=\s*(\d+)/.exec(tBody);
        if (scMatch) {
          transitions.push({
            storageClass: scMatch[1],
            days: dMatch ? parseInt(dMatch[1], 10) : undefined,
          });
        }
      }

      rules.push({
        id,
        status,
        prefix,
        abortIncompleteMultipartUploadDays: abortDays,
        noncurrentVersionExpirationDays: ncDays,
        expiredObjectDeleteMarker: expiredMarker,
        objectSizeGreaterThan,
        hasObjectSizeGreaterThanFilter: objectSizeGreaterThan !== undefined && objectSizeGreaterThan > 0,
        hasTagFilter,
        transitions: transitions.length > 0 ? transitions : undefined,
      });
    }
  }

  return rules;
}

/**
 * Checks if a live S3 lifecycle rule has a tag filter.
 */
function liveRuleHasTagFilter(rule: LifecycleRule): boolean {
  if (!rule.Filter) return false;
  if (rule.Filter.Tag) return true;
  if (rule.Filter.And && Array.isArray(rule.Filter.And.Tags) && rule.Filter.And.Tags.length > 0) return true;
  return false;
}

/**
 * Extracts live S3 object_size_greater_than filter if present.
 */
function getLiveRuleMinSize(rule: LifecycleRule): number | undefined {
  if (!rule.Filter) return undefined;
  if (typeof rule.Filter.ObjectSizeGreaterThan === "number") {
    return rule.Filter.ObjectSizeGreaterThan;
  }
  if (rule.Filter.And && typeof rule.Filter.And.ObjectSizeGreaterThan === "number") {
    return rule.Filter.And.ObjectSizeGreaterThan;
  }
  return undefined;
}

/**
 * Detects configuration drift between live S3 bucket lifecycle rules and local Terraform IaC.
 */
export async function detectLifecycleDrift(
  s3Client: S3Client,
  bucketName: string,
  options: DetectLifecycleDriftOptions = {}
): Promise<LifecycleDriftResult> {
  // 1. Fetch live S3 lifecycle configuration
  let liveRules: LifecycleRule[] = [];
  try {
    const res = await s3Client.send(
      new GetBucketLifecycleConfigurationCommand({ Bucket: bucketName })
    );
    liveRules = res.Rules ?? [];
  } catch (err: unknown) {
    const name = (err as Record<string, unknown>)?.name;
    const statusCode = (err as Record<string, unknown>)?.$metadata
      ? ((err as Record<string, unknown>).$metadata as Record<string, unknown>).httpStatusCode
      : undefined;

    if (name === "NoSuchLifecycleConfiguration" || statusCode === 404) {
      liveRules = [];
    } else {
      throw err;
    }
  }

  // 2. Load IaC configuration (from tfstate or .tf file)
  let iacRules: ManagedLifecycleRule[] = [];
  let resourceType: string | undefined;
  let tfFileContent: string | undefined = options.tfContent;

  if (!tfFileContent && options.tfFile) {
    try {
      tfFileContent = await fs.readFile(options.tfFile, "utf8");
    } catch {
      // Handled gracefully
    }
  }

  // Load from tfstate if provided
  let tfStateContent: string | undefined = options.tfStateContent;
  if (!tfStateContent && options.tfStateFile) {
    try {
      tfStateContent = await fs.readFile(options.tfStateFile, "utf8");
    } catch {
      // Handled gracefully
    }
  }

  if (tfStateContent) {
    const parseResult = parseTerraformState(tfStateContent);
    const managedBucket = parseResult.buckets[bucketName];
    if (managedBucket) {
      iacRules = managedBucket.rules;
      resourceType = managedBucket.resourceType;
    }
  } else if (tfFileContent) {
    const parsedHcl = parseHclLifecycleRules(tfFileContent, bucketName);
    iacRules = parsedHcl.rules;
    resourceType = parsedHcl.resourceType;
  }

  // 3. Compare live rules vs IaC rules
  const differences: string[] = [];
  let hasGhostConfig = false;
  const recommendations: DriftRecommendations = {
    missingTransitionFilterRuleIds: [],
    tfFilePath: options.tfFile,
  };

  const iacMap = new Map<string, ManagedLifecycleRule>();
  for (const ir of iacRules) {
    iacMap.set(ir.id, ir);
  }

  const liveMap = new Map<string, LifecycleRule>();
  for (const lr of liveRules) {
    if (lr.ID) {
      liveMap.set(lr.ID, lr);
    }
  }

  // A. Unmanaged rules: present in AWS S3 but absent in IaC
  for (const lr of liveRules) {
    const id = lr.ID ?? "(unnamed)";
    if (!iacMap.has(id)) {
      differences.push(
        `Unmanaged rule in AWS S3: '${id}' (present in live cloud but missing in IaC)`
      );
    }
  }

  // B. Missing rules: declared in IaC but missing in AWS S3
  for (const ir of iacRules) {
    if (!liveMap.has(ir.id)) {
      differences.push(
        `Missing rule in live S3: '${ir.id}' (declared in IaC but absent in cloud)`
      );
    }
  }

  // C. Drift in matching rules: thresholds, status, transitions
  for (const [id, ir] of iacMap.entries()) {
    const lr = liveMap.get(id);
    if (!lr) continue;

    // Status drift
    const lrStatus = lr.Status === "Enabled" ? "Enabled" : "Disabled";
    if (lrStatus !== ir.status) {
      differences.push(
        `Status drift in rule '${id}': live cloud is ${lrStatus}, but IaC declares ${ir.status}`
      );
    }

    // MPU Abort days drift
    const liveMpuDays = lr.AbortIncompleteMultipartUpload?.DaysAfterInitiation;
    const iacMpuDays = ir.abortIncompleteMultipartUploadDays;
    if (liveMpuDays !== undefined && iacMpuDays !== undefined && liveMpuDays !== iacMpuDays) {
      differences.push(
        `MPU abort threshold drift in rule '${id}': live cloud is ${liveMpuDays}d, but IaC declares ${iacMpuDays}d`
      );
    } else if (liveMpuDays !== undefined && iacMpuDays === undefined) {
      differences.push(
        `MPU abort drift in rule '${id}': live cloud has ${liveMpuDays}d abort, but IaC lacks abort configuration`
      );
    } else if (liveMpuDays === undefined && iacMpuDays !== undefined) {
      differences.push(
        `MPU abort drift in rule '${id}': live cloud lacks abort rule, but IaC declares ${iacMpuDays}d abort`
      );
    }

    // Noncurrent expiration drift
    const liveNcDays = lr.NoncurrentVersionExpiration?.NoncurrentDays;
    const iacNcDays = ir.noncurrentVersionExpirationDays;
    if (liveNcDays !== undefined && iacNcDays !== undefined && liveNcDays !== iacNcDays) {
      differences.push(
        `Noncurrent expiration drift in rule '${id}': live cloud is ${liveNcDays}d, but IaC declares ${iacNcDays}d`
      );
    }

    // Transition storage class & days drift
    const liveTransitions = lr.Transitions ?? [];
    const iacTransitions = ir.transitions ?? [];
    if (liveTransitions.length > 0 || iacTransitions.length > 0) {
      const liveSummary = liveTransitions.map((t) => `${t.StorageClass}:${t.Days ?? "date"}`).sort().join(",");
      const iacSummary = iacTransitions.map((t) => `${t.storageClass}:${t.days ?? "date"}`).sort().join(",");
      if (liveSummary !== iacSummary) {
        differences.push(
          `Transition drift in rule '${id}': live cloud specifies [${liveSummary}], but IaC declares [${iacSummary}]`
        );
      }
    }

    // Transition small-object filter drift
    const liveMinSize = getLiveRuleMinSize(lr);
    const iacMinSize = ir.objectSizeGreaterThan;
    if (liveMinSize !== iacMinSize) {
      differences.push(
        `Transition filter drift in rule '${id}': live cloud filter is ${liveMinSize ?? "none"}, but IaC declares ${
          iacMinSize ?? "none"
        }`
      );
    }
  }

  // D. Safety Gap: Missing MPU Abort Coverage
  const iacHasCoveringMpu = iacRules.some(
    (r) => r.status === "Enabled" && typeof r.abortIncompleteMultipartUploadDays === "number" && r.abortIncompleteMultipartUploadDays > 0
  );
  const liveHasCoveringMpu = liveRules.some(
    (r) => r.Status === "Enabled" && r.AbortIncompleteMultipartUpload?.DaysAfterInitiation !== undefined
  );

  if (!iacHasCoveringMpu) {
    differences.push(
      `Safety gap: Bucket '${bucketName}' has no MPU abort rule in IaC (zombie multipart uploads will accumulate indefinitely)`
    );
    recommendations.missingAbortMpu = true;
  }

  // E. Safety Gap: Small-Object Transition Traps (< 128 KiB)
  const allTransitions = [
    ...liveRules.filter((r) => r.Transitions && r.Transitions.length > 0).map((r) => ({
      source: "live",
      ruleId: r.ID ?? "unnamed",
      transitions: r.Transitions!,
      minSize: getLiveRuleMinSize(r),
    })),
    ...iacRules.filter((r) => r.transitions && r.transitions.length > 0).map((r) => ({
      source: "iac",
      ruleId: r.id,
      transitions: r.transitions!,
      minSize: r.objectSizeGreaterThan,
    })),
  ];

  for (const tRule of allTransitions) {
    const isDangerousClass = tRule.transitions.some((t: unknown) => {
      const sc =
        (typeof (t as { StorageClass?: unknown }).StorageClass === "string"
          ? (t as { StorageClass: string }).StorageClass
          : typeof (t as { storageClass?: unknown }).storageClass === "string"
          ? (t as { storageClass: string }).storageClass
          : "") || "";
      return ["GLACIER", "STANDARD_IA", "ONEZONE_IA", "GLACIER_IR", "DEEP_ARCHIVE"].includes(sc);
    });

    if (isDangerousClass && (!tRule.minSize || tRule.minSize < 131072)) {
      differences.push(
        `Safety gap: Transition rule '${tRule.ruleId}' (${tRule.source}) lacks object_size_greater_than >= 128 KiB filter (small-object penalty trap)`
      );
      if (tRule.source === "iac" && !recommendations.missingTransitionFilterRuleIds?.includes(tRule.ruleId)) {
        recommendations.missingTransitionFilterRuleIds?.push(tRule.ruleId);
      }
    }
  }

  // F. Ghost Configuration Detection: Tag filter on MPU abort rules
  for (const lr of liveRules) {
    if (lr.AbortIncompleteMultipartUpload && liveRuleHasTagFilter(lr)) {
      hasGhostConfig = true;
      differences.push(
        `Ghost rule detected: Live rule '${lr.ID}' has a Tag filter which AWS S3 silently ignores for multipart aborts`
      );
    }
  }
  for (const ir of iacRules) {
    if (ir.abortIncompleteMultipartUploadDays && ir.hasTagFilter) {
      hasGhostConfig = true;
      differences.push(
        `Ghost rule detected: IaC rule '${ir.id}' specifies Tag filters which AWS S3 silently ignores for multipart aborts`
      );
    }
  }

  // Status computation
  let status: DriftStatus = "IN_SYNC";
  if (hasGhostConfig) {
    status = "GHOST_CONFIG";
  } else if (differences.length > 0) {
    status = "DRIFT_DETECTED";
  }

  const isDrifted = status !== "IN_SYNC";

  // Generate unified diff patch if tfContent is available
  let patch: string | undefined;
  let patchedTfContent: string | undefined;

  if (tfFileContent) {
    const patchRes = generateHclPatch(tfFileContent, bucketName, recommendations);
    if (patchRes.modified) {
      patch = patchRes.patch;
      patchedTfContent = patchRes.patchedContent;
    }
  }

  return {
    bucketName,
    isDrifted,
    status,
    differences,
    patch,
    patchedTfContent,
    liveRulesCount: liveRules.length,
    iacRulesCount: iacRules.length,
    resourceType: resourceType ?? (iacRules.length > 0 ? "aws_s3_bucket_lifecycle_configuration" : undefined),
    targetTfFile: options.tfFile,
    liveRules,
    iacRules,
  };
}
