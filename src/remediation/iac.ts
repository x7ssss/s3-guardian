import * as fs from "node:fs/promises";
import * as path from "node:path";

export const DEFAULT_TRANSITION_MIN_SIZE_BYTES = 131072; // 128 KiB

export type IacFormat = "terraform" | "cloudformation";

export interface IacSnippetOptions {
  daysAfterInitiation?: number;
  includeVersioning?: boolean;
  noncurrentDays?: number;
  includeTransitions?: boolean;
  transitionDays?: number;
  transitionStorageClass?: string;
  filterMinSize?: number;
}

export interface GenerateIacOptions extends IacSnippetOptions {
  format?: IacFormat;
  outIac?: string;
}

export interface DangerousRuleRemediationInput {
  ruleId?: string;
  targetStorageClass?: string;
  days?: number;
  recommendedMinSize?: number;
}

interface ResolvedSnippetOptions {
  daysAfterInitiation: number;
  includeVersioning: boolean;
  noncurrentDays: number;
  includeTransitions: boolean;
  transitionDays: number;
  transitionStorageClass: string;
  filterMinSize: number;
}

function resolveSnippetOptions(
  optionsOrDays: number | IacSnippetOptions = 7
): ResolvedSnippetOptions {
  if (typeof optionsOrDays === "number") {
    return {
      daysAfterInitiation: optionsOrDays,
      includeVersioning: false,
      noncurrentDays: 30,
      includeTransitions: false,
      transitionDays: 30,
      transitionStorageClass: "GLACIER",
      filterMinSize: DEFAULT_TRANSITION_MIN_SIZE_BYTES,
    };
  }
  return {
    daysAfterInitiation: optionsOrDays.daysAfterInitiation ?? 7,
    includeVersioning: optionsOrDays.includeVersioning ?? false,
    noncurrentDays: optionsOrDays.noncurrentDays ?? 30,
    includeTransitions:
      optionsOrDays.includeTransitions ??
      (optionsOrDays.transitionDays !== undefined ||
        optionsOrDays.transitionStorageClass !== undefined),
    transitionDays: optionsOrDays.transitionDays ?? 30,
    transitionStorageClass: optionsOrDays.transitionStorageClass ?? "GLACIER",
    filterMinSize: optionsOrDays.filterMinSize ?? DEFAULT_TRANSITION_MIN_SIZE_BYTES,
  };
}

/**
 * Generates a modern Terraform (AWS Provider v4+) resource block
 * for `aws_s3_bucket_lifecycle_configuration`.
 *
 * Invariants:
 *  - GitOps-first: emits deterministic, readable HCL snippet.
 *  - MalformedXML Prevention: ExpiredObjectDeleteMarker is isolated in a dedicated rule
 *    with an empty filter and NO Days/Date/Tag constraints.
 *  - Small-Object Trap Prevention: Automatically injects `object_size_greater_than = 131072` (128 KiB)
 *    inside transition rule filters.
 */
export function generateTerraformSnippet(
  bucket: string,
  optionsOrDays: number | IacSnippetOptions = 7
): string {
  const {
    daysAfterInitiation,
    includeVersioning,
    noncurrentDays,
    includeTransitions,
    transitionDays,
    transitionStorageClass,
    filterMinSize,
  } = resolveSnippetOptions(optionsOrDays);
  const resourceName = `lifecycle_${bucket.replace(/[^a-zA-Z0-9_]/g, "_")}`;

  let rulesHcl = `  rule {
    id     = "s3-guardian-abort-mpu"
    status = "Enabled"

    filter {}

    # abort_incomplete_multipart_upload_days: ${daysAfterInitiation}
    abort_incomplete_multipart_upload {
      days_after_initiation = ${daysAfterInitiation}
    }
  }`;

  if (includeVersioning) {
    rulesHcl += `\n\n  rule {
    id     = "s3-guardian-expire-noncurrent-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = ${noncurrentDays}
    }
  }\n\n  # Invariant 4 (MalformedXML Prevention): Dedicated rule for expired delete markers
  # with clean empty filter and NO Days/Date/Tag constraints.
  rule {
    id     = "s3-guardian-cleanup-eodm"
    status = "Enabled"

    filter {}

    expiration {
      expired_object_delete_marker = true
    }
  }`;
  }

  if (includeTransitions) {
    rulesHcl += `\n\n  # Safe transition rule: object_size_greater_than prevents Glacier small-object traps
  rule {
    id     = "s3-guardian-safe-transition"
    status = "Enabled"

    filter {
      object_size_greater_than = ${filterMinSize}
    }

    transition {
      days          = ${transitionDays}
      storage_class = "${transitionStorageClass}"
    }
  }`;
  }

  return `# Terraform (AWS Provider v4+) Lifecycle Configuration for '${bucket}'
resource "aws_s3_bucket_lifecycle_configuration" "${resourceName}" {
  bucket = "${bucket}"

${rulesHcl}
}
`;
}

/**
 * Generates a CloudFormation YAML snippet for `AWS::S3::Bucket`
 * containing `LifecycleConfiguration.Rules`.
 */
export function generateCloudFormationSnippet(
  bucket: string,
  optionsOrDays: number | IacSnippetOptions = 7
): string {
  const {
    daysAfterInitiation,
    includeVersioning,
    noncurrentDays,
    includeTransitions,
    transitionDays,
    transitionStorageClass,
    filterMinSize,
  } = resolveSnippetOptions(optionsOrDays);

  let rulesYaml = `        - Id: s3-guardian-abort-mpu
          Status: Enabled
          AbortIncompleteMultipartUpload:
            DaysAfterInitiation: ${daysAfterInitiation}`;

  if (includeVersioning) {
    rulesYaml += `\n        - Id: s3-guardian-expire-noncurrent-versions
          Status: Enabled
          NoncurrentVersionExpiration:
            NoncurrentDays: ${noncurrentDays}
        - Id: s3-guardian-cleanup-eodm
          Status: Enabled
          ExpiredObjectDeleteMarker: true`;
  }

  if (includeTransitions) {
    rulesYaml += `\n        - Id: s3-guardian-safe-transition
          Status: Enabled
          Filter:
            ObjectSizeGreaterThan: ${filterMinSize}
          Transitions:
            - Days: ${transitionDays}
              StorageClass: ${transitionStorageClass}`;
  }

  return `# CloudFormation LifecycleConfiguration snippet for '${bucket}'
Type: AWS::S3::Bucket
Properties:
  BucketName: "${bucket}"
  LifecycleConfiguration:
    Rules:
${rulesYaml}
`;
}

/**
 * Dedicated remediation generator: Generates Terraform HCL to fix existing unconstrained
 * transition rules by injecting `object_size_greater_than = 131072` (128 KiB).
 */
export function generateTerraformTransitionRemediation(
  bucket: string,
  rulesOrRule?: DangerousRuleRemediationInput[] | DangerousRuleRemediationInput
): string {
  const resourceName = `lifecycle_${bucket.replace(/[^a-zA-Z0-9_]/g, "_")}`;
  const rawRules = rulesOrRule
    ? Array.isArray(rulesOrRule)
      ? rulesOrRule
      : [rulesOrRule]
    : [{ ruleId: "s3-guardian-remediated-transition", targetStorageClass: "GLACIER", days: 30 }];

  const ruleBlocks = rawRules
    .map((r) => {
      const ruleId = r.ruleId || "s3-guardian-remediated-transition";
      const storageClass = r.targetStorageClass || "GLACIER";
      const days = r.days ?? 30;
      const minSize = r.recommendedMinSize ?? DEFAULT_TRANSITION_MIN_SIZE_BYTES;

      return `  rule {
    id     = "${ruleId}"
    status = "Enabled"

    filter {
      object_size_greater_than = ${minSize}
    }

    transition {
      days          = ${days}
      storage_class = "${storageClass}"
    }
  }`;
    })
    .join("\n\n");

  return `# Terraform Transition Remediation for '${bucket}'
# Fixes Glacier / Infrequent Access small-object trap by injecting 128 KiB filter
resource "aws_s3_bucket_lifecycle_configuration" "${resourceName}" {
  bucket = "${bucket}"

${ruleBlocks}
}
`;
}

/**
 * Dedicated remediation generator: Generates CloudFormation YAML to fix existing unconstrained
 * transition rules by injecting `ObjectSizeGreaterThan: 131072` (128 KiB).
 */
export function generateCloudFormationTransitionRemediation(
  bucket: string,
  rulesOrRule?: DangerousRuleRemediationInput[] | DangerousRuleRemediationInput
): string {
  const rawRules = rulesOrRule
    ? Array.isArray(rulesOrRule)
      ? rulesOrRule
      : [rulesOrRule]
    : [{ ruleId: "s3-guardian-remediated-transition", targetStorageClass: "GLACIER", days: 30 }];

  const rulesYaml = rawRules
    .map((r) => {
      const ruleId = r.ruleId || "s3-guardian-remediated-transition";
      const storageClass = r.targetStorageClass || "GLACIER";
      const days = r.days ?? 30;
      const minSize = r.recommendedMinSize ?? DEFAULT_TRANSITION_MIN_SIZE_BYTES;

      return `        - Id: ${ruleId}
          Status: Enabled
          Filter:
            ObjectSizeGreaterThan: ${minSize}
          Transitions:
            - Days: ${days}
              StorageClass: ${storageClass}`;
    })
    .join("\n");

  return `# CloudFormation Transition Remediation for '${bucket}'
# Fixes Glacier / Infrequent Access small-object trap by injecting 128 KiB filter
Type: AWS::S3::Bucket
Properties:
  BucketName: "${bucket}"
  LifecycleConfiguration:
    Rules:
${rulesYaml}
`;
}

/**
 * Formats dedicated transition remediation snippet in either Terraform or CloudFormation.
 */
export function generateTransitionRemediationSnippet(
  bucket: string,
  rulesOrRule?: DangerousRuleRemediationInput[] | DangerousRuleRemediationInput,
  format: IacFormat = "terraform"
): string {
  if (format === "cloudformation") {
    return generateCloudFormationTransitionRemediation(bucket, rulesOrRule);
  }
  return generateTerraformTransitionRemediation(bucket, rulesOrRule);
}

/**
 * Formats IaC snippets for one or more buckets and optionally saves to disk.
 *
 * @param buckets One or more bucket names
 * @param options Format and output configuration
 * @returns The formatted IaC text
 */
export async function formatOrSaveIac(
  buckets: string | string[],
  options: GenerateIacOptions = {}
): Promise<string> {
  const format = options.format ?? "terraform";
  const bucketList = Array.isArray(buckets) ? buckets : [buckets];

  let output = "";
  if (format === "cloudformation") {
    output = bucketList
      .map((b) => generateCloudFormationSnippet(b, options))
      .join("\n---\n\n");
  } else {
    output = bucketList
      .map((b) => generateTerraformSnippet(b, options))
      .join("\n");
  }

  if (options.outIac) {
    const resolvedPath = path.resolve(options.outIac);
    await fs.mkdir(path.dirname(resolvedPath), { recursive: true });
    await fs.writeFile(resolvedPath, output, "utf8");
  }

  return output;
}
