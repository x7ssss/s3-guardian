import { describe, it, expect } from "vitest";
import { parseTerraformState } from "../src/drift/tfstate-parser.js";

describe("Terraform State Parser (v4)", () => {
  it("parses modern aws_s3_bucket_lifecycle_configuration resources", () => {
    const stateJson = JSON.stringify({
      version: 4,
      terraform_version: "1.5.7",
      resources: [
        {
          mode: "managed",
          type: "aws_s3_bucket_lifecycle_configuration",
          name: "prod_lifecycle",
          instances: [
            {
              schema_version: 0,
              attributes: {
                bucket: "production-data-bucket",
                id: "production-data-bucket",
                rule: [
                  {
                    id: "s3-guardian-abort-mpu",
                    status: "Enabled",
                    prefix: "uploads/",
                    abort_incomplete_multipart_upload: [
                      {
                        days_after_initiation: 7,
                      },
                    ],
                    filter: [
                      {
                        prefix: "uploads/",
                        object_size_greater_than: "",
                      },
                    ],
                  },
                  {
                    id: "archive-tier",
                    status: "Enabled",
                    filter: [
                      {
                        object_size_greater_than: "131072",
                      },
                    ],
                    transition: [
                      {
                        days: 90,
                        storage_class: "GLACIER",
                      },
                    ],
                    noncurrent_version_expiration: [
                      {
                        noncurrent_days: 30,
                      },
                    ],
                    expiration: [
                      {
                        expired_object_delete_marker: true,
                      },
                    ],
                  },
                ],
              },
            },
          ],
        },
      ],
    });

    const result = parseTerraformState(stateJson);
    expect(result.version).toBe(4);
    expect(result.totalManagedBuckets).toBe(1);

    const managed = result.buckets["production-data-bucket"];
    expect(managed).toBeDefined();
    expect(managed.bucket).toBe("production-data-bucket");
    expect(managed.resourceType).toBe("aws_s3_bucket_lifecycle_configuration");
    expect(managed.rules).toHaveLength(2);

    // Rule 1: MPU abort
    const rule1 = managed.rules[0];
    expect(rule1.id).toBe("s3-guardian-abort-mpu");
    expect(rule1.status).toBe("Enabled");
    expect(rule1.prefix).toBe("uploads/");
    expect(rule1.abortIncompleteMultipartUploadDays).toBe(7);

    // Rule 2: Transitions and versioning
    const rule2 = managed.rules[1];
    expect(rule2.id).toBe("archive-tier");
    expect(rule2.status).toBe("Enabled");
    expect(rule2.hasObjectSizeGreaterThanFilter).toBe(true);
    expect(rule2.objectSizeGreaterThan).toBe(131072);
    expect(rule2.transitions).toEqual([
      {
        days: 90,
        date: undefined,
        storageClass: "GLACIER",
      },
    ]);
    expect(rule2.noncurrentVersionExpirationDays).toBe(30);
    expect(rule2.expiredObjectDeleteMarker).toBe(true);
  });

  it("parses legacy aws_s3_bucket inline lifecycle_rule resources", () => {
    const stateJson = JSON.stringify({
      version: 4,
      terraform_version: "0.14.0",
      resources: [
        {
          mode: "managed",
          type: "aws_s3_bucket",
          name: "legacy_bucket",
          instances: [
            {
              attributes: {
                bucket: "legacy-analytics",
                id: "legacy-analytics",
                lifecycle_rule: [
                  {
                    id: "cleanup-old-uploads",
                    enabled: true,
                    prefix: "temp/",
                    abort_incomplete_multipart_upload_days: 14,
                    noncurrent_version_expiration: [
                      {
                        days: 60,
                      },
                    ],
                    tags: {
                      Environment: "production",
                    },
                  },
                ],
              },
            },
          ],
        },
      ],
    });

    const result = parseTerraformState(stateJson);
    expect(result.totalManagedBuckets).toBe(1);

    const managed = result.buckets["legacy-analytics"];
    expect(managed).toBeDefined();
    expect(managed.resourceType).toBe("aws_s3_bucket");
    expect(managed.rules).toHaveLength(1);

    const rule = managed.rules[0];
    expect(rule.id).toBe("cleanup-old-uploads");
    expect(rule.status).toBe("Enabled");
    expect(rule.abortIncompleteMultipartUploadDays).toBe(14);
    expect(rule.noncurrentVersionExpirationDays).toBe(60);
    expect(rule.hasTagFilter).toBe(true);
  });

  it("prefers aws_s3_bucket_lifecycle_configuration over legacy aws_s3_bucket", () => {
    const stateJson = JSON.stringify({
      version: 4,
      resources: [
        {
          mode: "managed",
          type: "aws_s3_bucket",
          name: "raw",
          instances: [
            {
              attributes: {
                bucket: "shared-bucket",
                lifecycle_rule: [{ id: "legacy-rule", enabled: true }],
              },
            },
          ],
        },
        {
          mode: "managed",
          type: "aws_s3_bucket_lifecycle_configuration",
          name: "modern",
          instances: [
            {
              attributes: {
                bucket: "shared-bucket",
                rule: [{ id: "modern-rule", status: "Enabled" }],
              },
            },
          ],
        },
      ],
    });

    const result = parseTerraformState(stateJson);
    expect(result.totalManagedBuckets).toBe(1);
    expect(result.buckets["shared-bucket"].resourceType).toBe("aws_s3_bucket_lifecycle_configuration");
    expect(result.buckets["shared-bucket"].rules[0].id).toBe("modern-rule");
  });

  it("handles empty or missing resources array gracefully", () => {
    const stateJson = JSON.stringify({ version: 4 });
    const result = parseTerraformState(stateJson);
    expect(result.totalManagedBuckets).toBe(0);
    expect(result.buckets).toEqual({});
  });

  it("throws informative error on invalid JSON", () => {
    expect(() => parseTerraformState("not-json")).toThrow(/Invalid Terraform state JSON/);
  });
});
