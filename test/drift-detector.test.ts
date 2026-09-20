import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  S3Client,
  GetBucketLifecycleConfigurationCommand,
} from "@aws-sdk/client-s3";
import { detectLifecycleDrift } from "../src/drift/detector.js";

const s3Mock = mockClient(S3Client);

describe("Lifecycle Drift Detector", () => {
  beforeEach(() => {
    s3Mock.reset();
  });

  it("detects IN_SYNC when live S3 rules match IaC rules perfectly", async () => {
    s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
      Rules: [
        {
          ID: "s3-guardian-abort-mpu",
          Status: "Enabled",
          Filter: {},
          AbortIncompleteMultipartUpload: {
            DaysAfterInitiation: 7,
          },
        },
      ],
    });

    const tfContent = `
resource "aws_s3_bucket_lifecycle_configuration" "lifecycle_test" {
  bucket = "in-sync-bucket"

  rule {
    id     = "s3-guardian-abort-mpu"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}
`.trim();

    const client = new S3Client({});
    const result = await detectLifecycleDrift(client, "in-sync-bucket", {
      tfContent,
    });

    expect(result.status).toBe("IN_SYNC");
    expect(result.isDrifted).toBe(false);
    expect(result.differences).toHaveLength(0);
    expect(result.liveRulesCount).toBe(1);
    expect(result.iacRulesCount).toBe(1);
  });

  it("detects DRIFT_DETECTED when AWS has unmanaged rules missing in IaC", async () => {
    s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
      Rules: [
        {
          ID: "s3-guardian-abort-mpu",
          Status: "Enabled",
          Filter: {},
          AbortIncompleteMultipartUpload: { DaysAfterInitiation: 7 },
        },
        {
          ID: "rogue-manual-rule",
          Status: "Enabled",
          Filter: {},
          Expiration: { Days: 90 },
        },
      ],
    });

    const tfContent = `
resource "aws_s3_bucket_lifecycle_configuration" "lifecycle_test" {
  bucket = "drift-bucket"

  rule {
    id     = "s3-guardian-abort-mpu"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}
`.trim();

    const client = new S3Client({});
    const result = await detectLifecycleDrift(client, "drift-bucket", {
      tfContent,
    });

    expect(result.status).toBe("DRIFT_DETECTED");
    expect(result.isDrifted).toBe(true);
    expect(result.differences.some((d) => d.includes("Unmanaged rule in AWS S3: 'rogue-manual-rule'"))).toBe(true);
  });

  it("detects threshold drift when live MPU abort days differ from IaC", async () => {
    s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
      Rules: [
        {
          ID: "s3-guardian-abort-mpu",
          Status: "Enabled",
          Filter: {},
          AbortIncompleteMultipartUpload: { DaysAfterInitiation: 14 },
        },
      ],
    });

    const tfContent = `
resource "aws_s3_bucket_lifecycle_configuration" "lifecycle_test" {
  bucket = "thresh-bucket"

  rule {
    id     = "s3-guardian-abort-mpu"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}
`.trim();

    const client = new S3Client({});
    const result = await detectLifecycleDrift(client, "thresh-bucket", {
      tfContent,
    });

    expect(result.status).toBe("DRIFT_DETECTED");
    expect(result.isDrifted).toBe(true);
    expect(
      result.differences.some((d) => d.includes("live cloud is 14d, but IaC declares 7d"))
    ).toBe(true);
  });

  it("detects safety gap when transition rule lacks object_size_greater_than filter and generates patch", async () => {
    s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
      Rules: [
        {
          ID: "s3-guardian-abort-mpu",
          Status: "Enabled",
          Filter: {},
          AbortIncompleteMultipartUpload: { DaysAfterInitiation: 7 },
        },
        {
          ID: "archive-rule",
          Status: "Enabled",
          Filter: {},
          Transitions: [{ Days: 30, StorageClass: "GLACIER" }],
        },
      ],
    });

    const tfContent = `
resource "aws_s3_bucket_lifecycle_configuration" "lifecycle_test" {
  bucket = "trap-bucket"

  rule {
    id     = "s3-guardian-abort-mpu"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "archive-rule"
    status = "Enabled"

    filter {}

    transition {
      days          = 30
      storage_class = "GLACIER"
    }
  }
}
`.trim();

    const client = new S3Client({});
    const result = await detectLifecycleDrift(client, "trap-bucket", {
      tfContent,
      generatePatch: true,
    });

    expect(result.status).toBe("DRIFT_DETECTED");
    expect(result.isDrifted).toBe(true);
    expect(
      result.differences.some((d) =>
        d.includes("Transition rule 'archive-rule'") && d.includes("lacks object_size_greater_than")
      )
    ).toBe(true);

    expect(result.patch).toBeDefined();
    expect(result.patch).toContain("+      object_size_greater_than = 131072");
  });

  it("detects GHOST_CONFIG when a rule defines tag filters on MPU aborts", async () => {
    s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
      Rules: [
        {
          ID: "ghost-abort-rule",
          Status: "Enabled",
          Filter: {
            Tag: { Key: "Environment", Value: "Production" },
          },
          AbortIncompleteMultipartUpload: { DaysAfterInitiation: 7 },
        },
      ],
    });

    const tfContent = `
resource "aws_s3_bucket_lifecycle_configuration" "lifecycle_test" {
  bucket = "ghost-bucket"

  rule {
    id     = "ghost-abort-rule"
    status = "Enabled"

    filter {
      tag {
        key   = "Environment"
        value = "Production"
      }
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}
`.trim();

    const client = new S3Client({});
    const result = await detectLifecycleDrift(client, "ghost-bucket", {
      tfContent,
    });

    expect(result.status).toBe("GHOST_CONFIG");
    expect(result.isDrifted).toBe(true);
    expect(
      result.differences.some((d) => d.includes("Ghost rule detected"))
    ).toBe(true);
  });

  it("handles NoSuchLifecycleConfiguration (404) gracefully", async () => {
    const err = new Error("NoSuchLifecycleConfiguration");
    err.name = "NoSuchLifecycleConfiguration";
    (err as Record<string, unknown>).$metadata = { httpStatusCode: 404 };

    s3Mock.on(GetBucketLifecycleConfigurationCommand).rejects(err);

    const tfContent = `
resource "aws_s3_bucket_lifecycle_configuration" "lifecycle_test" {
  bucket = "empty-bucket"

  rule {
    id     = "s3-guardian-abort-mpu"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}
`.trim();

    const client = new S3Client({});
    const result = await detectLifecycleDrift(client, "empty-bucket", {
      tfContent,
    });

    expect(result.status).toBe("DRIFT_DETECTED");
    expect(result.liveRulesCount).toBe(0);
    expect(result.iacRulesCount).toBe(1);
    expect(
      result.differences.some((d) => d.includes("Missing rule in live S3: 's3-guardian-abort-mpu'"))
    ).toBe(true);
  });
});
