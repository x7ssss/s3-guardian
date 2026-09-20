import * as fs from "node:fs/promises";
import * as path from "node:path";

export type IacFormat = "terraform" | "cloudformation";

export interface GenerateIacOptions {
  format?: IacFormat;
  daysAfterInitiation?: number;
  outIac?: string;
}

/**
 * Generates a modern Terraform (AWS Provider v4+) resource block
 * for `aws_s3_bucket_lifecycle_configuration` targeting MPU cleanup.
 *
 * Invariant: GitOps-first. Emits deterministic, readable HCL snippet.
 */
export function generateTerraformSnippet(
  bucket: string,
  daysAfterInitiation: number = 7
): string {
  const resourceName = `lifecycle_${bucket.replace(/[^a-zA-Z0-9_]/g, "_")}`;
  return `# Terraform (AWS Provider v4+) Lifecycle Configuration for '${bucket}'
resource "aws_s3_bucket_lifecycle_configuration" "${resourceName}" {
  bucket = "${bucket}"

  rule {
    id     = "s3-guardian-abort-mpu"
    status = "Enabled"

    filter {}

    # abort_incomplete_multipart_upload_days: ${daysAfterInitiation}
    abort_incomplete_multipart_upload {
      days_after_initiation = ${daysAfterInitiation}
    }
  }
}
`;
}

/**
 * Generates a CloudFormation YAML snippet for `AWS::S3::Bucket`
 * containing `LifecycleConfiguration.Rules` with an MPU abort rule.
 */
export function generateCloudFormationSnippet(
  bucket: string,
  daysAfterInitiation: number = 7
): string {
  return `# CloudFormation LifecycleConfiguration snippet for '${bucket}'
Type: AWS::S3::Bucket
Properties:
  BucketName: "${bucket}"
  LifecycleConfiguration:
    Rules:
      - Id: s3-guardian-abort-mpu
        Status: Enabled
        AbortIncompleteMultipartUpload:
          DaysAfterInitiation: ${daysAfterInitiation}
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
  const days = options.daysAfterInitiation ?? 7;
  const bucketList = Array.isArray(buckets) ? buckets : [buckets];

  let output = "";
  if (format === "cloudformation") {
    output = bucketList
      .map((b) => generateCloudFormationSnippet(b, days))
      .join("\n---\n\n");
  } else {
    output = bucketList
      .map((b) => generateTerraformSnippet(b, days))
      .join("\n");
  }

  if (options.outIac) {
    const resolvedPath = path.resolve(options.outIac);
    await fs.mkdir(path.dirname(resolvedPath), { recursive: true });
    await fs.writeFile(resolvedPath, output, "utf8");
  }

  return output;
}
