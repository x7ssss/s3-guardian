import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import { S3Client, AbortMultipartUploadCommand } from "@aws-sdk/client-s3";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";
import { executeAbortPlan } from "../src/executor/abort.js";
import { Plan, writePlanFile } from "../src/planner/plan.js";

const s3Mock = mockClient(S3Client);

describe("Executor: safe multipart abort execution", () => {
  beforeEach(() => {
    s3Mock.reset();
  });

  const samplePlan: Plan = {
    schemaVersion: "1.0",
    generatedAt: "2026-09-20T12:00:00.000Z",
    bucket: "cleanup-bucket",
    endpoint: null,
    olderThanDays: 7,
    totalZombieUploads: 2,
    totalStrandedBytes: 3000,
    estimatedMonthlyWasteUSD: 0,
    uploads: [
      {
        key: "file-1.bin",
        uploadId: "uid-1",
        initiated: "2026-09-01T00:00:00.000Z",
        partsCount: 1,
        bytes: 1000,
      },
      {
        key: "file-2.bin",
        uploadId: "uid-2",
        initiated: "2026-09-01T00:00:00.000Z",
        partsCount: 2,
        bytes: 2000,
      },
    ],
  };

  it("strictly requires --confirm flag and rejects execution if false", async () => {
    const s3Client = new S3Client({});

    await expect(
      executeAbortPlan(s3Client, samplePlan, { confirm: false })
    ).rejects.toThrow(/Safety check failed/);

    await expect(
      executeAbortPlan(s3Client, samplePlan, {})
    ).rejects.toThrow(/Safety check failed/);

    expect(s3Mock.calls().length).toBe(0);
  });

  it("aborts all uploads in plan when --confirm is true", async () => {
    const s3Client = new S3Client({});
    s3Mock.on(AbortMultipartUploadCommand).resolves({});

    const result = await executeAbortPlan(s3Client, samplePlan, {
      confirm: true,
      retryOptions: { initialDelayMs: 1 },
    });

    expect(result.total).toBe(2);
    expect(result.aborted).toBe(2);
    expect(result.failed).toBe(0);
    expect(result.bytesFreed).toBe(3000);
    expect(result.errors).toHaveLength(0);

    const calls = s3Mock.commandCalls(AbortMultipartUploadCommand);
    expect(calls.length).toBe(2);
    expect(calls[0].args[0].input).toEqual({
      Bucket: "cleanup-bucket",
      Key: "file-1.bin",
      UploadId: "uid-1",
    });
    expect(calls[1].args[0].input).toEqual({
      Bucket: "cleanup-bucket",
      Key: "file-2.bin",
      UploadId: "uid-2",
    });
  });

  it("handles partial failures gracefully and records errors", async () => {
    const s3Client = new S3Client({});

    s3Mock
      .on(AbortMultipartUploadCommand, {
        Bucket: "cleanup-bucket",
        Key: "file-1.bin",
        UploadId: "uid-1",
      })
      .resolves({});

    s3Mock
      .on(AbortMultipartUploadCommand, {
        Bucket: "cleanup-bucket",
        Key: "file-2.bin",
        UploadId: "uid-2",
      })
      .rejects(new Error("Access Denied"));

    const result = await executeAbortPlan(s3Client, samplePlan, {
      confirm: true,
      retryOptions: { initialDelayMs: 1, maxRetries: 0 },
    });

    expect(result.total).toBe(2);
    expect(result.aborted).toBe(1);
    expect(result.failed).toBe(1);
    expect(result.bytesFreed).toBe(1000);
    expect(result.errors.length).toBe(1);
    expect(result.errors[0].key).toBe("file-2.bin");
    expect(result.errors[0].error).toContain("Access Denied");
  });

  it("gracefully catches NoSuchUpload / 404 errors as SKIPPED_ALREADY_ABORTED", async () => {
    const s3Client = new S3Client({});

    s3Mock
      .on(AbortMultipartUploadCommand, {
        Bucket: "cleanup-bucket",
        Key: "file-1.bin",
        UploadId: "uid-1",
      })
      .resolves({});

    const noSuchUploadError = new Error("The specified upload does not exist");
    noSuchUploadError.name = "NoSuchUpload";
    (noSuchUploadError as any).$metadata = { httpStatusCode: 404 };

    s3Mock
      .on(AbortMultipartUploadCommand, {
        Bucket: "cleanup-bucket",
        Key: "file-2.bin",
        UploadId: "uid-2",
      })
      .rejects(noSuchUploadError);

    const result = await executeAbortPlan(s3Client, samplePlan, {
      confirm: true,
      retryOptions: { initialDelayMs: 1, maxRetries: 0 },
    });

    expect(result.total).toBe(2);
    expect(result.aborted).toBe(1);
    expect(result.skipped).toBe(1);
    expect(result.failed).toBe(0);
    expect(result.errors).toHaveLength(0);
    expect(result.bytesFreed).toBe(1000);

    const skippedItem = result.items?.find((i) => i.key === "file-2.bin");
    expect(skippedItem?.status).toBe("SKIPPED_ALREADY_ABORTED");
  });

  it("retries on 503 Slow Down during aborts", async () => {
    const s3Client = new S3Client({});

    const slowDownError = new Error("Slow Down");
    (slowDownError as any).$metadata = { httpStatusCode: 503 };
    slowDownError.name = "SlowDown";

    s3Mock
      .on(AbortMultipartUploadCommand)
      .rejectsOnce(slowDownError)
      .resolves({});

    const singlePlan: Plan = {
      ...samplePlan,
      uploads: [samplePlan.uploads[0]],
      totalZombieUploads: 1,
      totalStrandedBytes: 1000,
    };

    const result = await executeAbortPlan(s3Client, singlePlan, {
      confirm: true,
      retryOptions: { initialDelayMs: 1, maxRetries: 2 },
    });

    expect(result.aborted).toBe(1);
    expect(result.failed).toBe(0);
    expect(s3Mock.commandCalls(AbortMultipartUploadCommand).length).toBe(2);
  });

  it("loads and applies plan directly from file path", async () => {
    const s3Client = new S3Client({});
    s3Mock.on(AbortMultipartUploadCommand).resolves({});

    const tempPath = path.join(
      os.tmpdir(),
      `plan-exec-test-${Date.now()}.json`
    );
    await writePlanFile(tempPath, samplePlan);

    try {
      const result = await executeAbortPlan(s3Client, tempPath, {
        confirm: true,
        retryOptions: { initialDelayMs: 1 },
      });

      expect(result.aborted).toBe(2);
      expect(result.bytesFreed).toBe(3000);
    } finally {
      await fs.unlink(tempPath).catch(() => {});
    }
  });
});
