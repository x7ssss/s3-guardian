import * as fs from "node:fs/promises";
import * as path from "node:path";

export type IacFormat = "terraform" | "cloudformation";

export interface IacSnippetOptions {
  daysAfterInitiation?: number;
  includeVersioning?: boolean;
  noncurrentDays?: number;
}

export interface GenerateIacOptions extends IacSnippetOptions {
  format?: IacFormat;
  outIac?: string;
}

function resolveSnippetOptions(
  optionsOrDays: number | IacSnippetOptions = 7
): Required<IacSnippetOptions> {
  if (typeof optionsOrDays === "number") {
    return {
      daysAfterInitiation: optionsOrDays,
      includeVersioning: false,
      noncurrentDays: 30,
    };
  }
  return {
    daysAfterInitiation: optionsOrDays.daysAfterInitiation ?? 7,
    includeVersioning: optionsOrDays.includeVersioning ?? false,
    noncurrentDays: optionsOrDays.noncurrentDays ?? 30,
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
 */
export function generateTerraformSnippet(
  bucket: string,
  optionsOrDays: number | IacSnippetOptions = 7
): string {
  const { daysAfterInitiation, includeVersioning, noncurrentDays } =
    resolveSnippetOptions(optionsOrDays);
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
  const { daysAfterInitiation, includeVersioning, noncurrentDays } =
    resolveSnippetOptions(optionsOrDays);

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
