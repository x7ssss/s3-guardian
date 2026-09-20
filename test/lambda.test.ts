import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  S3Client,
  ListBucketsCommand,
  GetBucketLocationCommand,
  ListMultipartUploadsCommand,
  GetBucketLifecycleConfigurationCommand,
} from "@aws-sdk/client-s3";
import { handler } from "../src/lambda.js";

const s3Mock = mockClient(S3Client);

describe("AWS Lambda Handler (src/lambda.ts)", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    s3Mock.reset();
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it("returns 400 when neither allBuckets nor bucket is specified", async () => {
    const response = await handler({});
    expect(response.statusCode).toBe(400);
    expect(response.body.error).toContain("allBuckets");
  });

  it("executes single bucket audit via event payload", async () => {
    s3Mock
      .on(ListMultipartUploadsCommand, { Bucket: "my-lambda-bucket" })
      .resolvesOnce({ IsTruncated: false, Uploads: [] });

    s3Mock
      .on(GetBucketLifecycleConfigurationCommand, { Bucket: "my-lambda-bucket" })
      .resolvesOnce({
        Rules: [
          {
            ID: "mpu-rule",
            Status: "Enabled",
            Filter: {},
            AbortIncompleteMultipartUpload: { DaysAfterInitiation: 7 },
          },
        ],
      });

    const response = await handler({
      bucket: "my-lambda-bucket",
      olderThan: 7,
    });

    expect(response.statusCode).toBe(200);
    expect(response.body.bucket).toBe("my-lambda-bucket");
    expect(response.body.totalZombieUploads).toBe(0);
    expect((response.body.lifecycleAudit as any).hasCoveringRule).toBe(true);
  });

  it("executes fleet scan using environment variables", async () => {
    process.env.S3_GUARDIAN_ALL_BUCKETS = "true";
    process.env.S3_GUARDIAN_OLDER_THAN = "14";

    s3Mock.on(ListBucketsCommand).resolvesOnce({
      Buckets: [{ Name: "lambda-fleet-bucket" }],
    });

    s3Mock
      .on(GetBucketLocationCommand, { Bucket: "lambda-fleet-bucket" })
      .resolvesOnce({ LocationConstraint: null });

    const lcErr = new Error("NoSuchLifecycleConfiguration");
    lcErr.name = "NoSuchLifecycleConfiguration";
    (lcErr as any).$metadata = { httpStatusCode: 404 };
    s3Mock
      .on(GetBucketLifecycleConfigurationCommand, { Bucket: "lambda-fleet-bucket" })
      .rejects(lcErr);

    s3Mock
      .on(ListMultipartUploadsCommand, { Bucket: "lambda-fleet-bucket" })
      .resolvesOnce({ IsTruncated: false, Uploads: [] });

    const response = await handler();

    expect(response.statusCode).toBe(200);
    expect(response.body.bucketsDiscovered).toBe(1);
    expect(response.body.bucketsAudited).toBe(1);
    expect(response.body.totalZombieUploads).toBe(0);
  });

  it("dispatches webhook notification when configured", async () => {
    s3Mock
      .on(ListMultipartUploadsCommand, { Bucket: "notif-bucket" })
      .resolvesOnce({ IsTruncated: false, Uploads: [] });

    s3Mock
      .on(GetBucketLifecycleConfigurationCommand, { Bucket: "notif-bucket" })
      .resolvesOnce({ Rules: [] });

    const mockFetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    const originalFetch = globalThis.fetch;
    globalThis.fetch = mockFetch as any;

    try {
      const response = await handler({
        bucket: "notif-bucket",
        webhookUrl: "https://hooks.slack.com/services/T/B/X",
        notifyAlways: true,
      });

      expect(response.statusCode).toBe(200);
      expect(mockFetch).toHaveBeenCalledTimes(1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("returns 500 with error details on unexpected client failure", async () => {
    s3Mock.on(ListBucketsCommand).rejectsOnce(new Error("Fatal AWS error"));

    const response = await handler({ allBuckets: true });
    expect(response.statusCode).toBe(500);
    expect(response.body.error).toContain("Fatal AWS error");
  });
});
