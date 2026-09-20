import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  S3Client,
  DeleteObjectsCommand,
} from "@aws-sdk/client-s3";
import { executeVersionDeletion } from "../src/versioning/executor.js";

const s3Mock = mockClient(S3Client);

describe("Versioning Executor (executeVersionDeletion)", () => {
  beforeEach(() => {
    s3Mock.reset();
  });

  it("strictly enforces confirm flag and throws if confirm !== true", async () => {
    const client = new S3Client({});
    const entries = [{ Key: "test.txt", VersionId: "v1" }];

    await expect(
      // @ts-expect-error testing missing confirm
      executeVersionDeletion(client, "my-bucket", entries, { confirm: false })
    ).rejects.toThrow(/Safety check failed.*--confirm/);

    expect(s3Mock.calls().length).toBe(0);
  });

  it("chunks batches of >1,000 items into max 1,000 chunks", async () => {
    const client = new S3Client({});
    // 2,500 entries should be chunked into 1000, 1000, 500
    const entries = Array.from({ length: 2500 }, (_, i) => ({
      Key: `file-${i}.bin`,
      VersionId: `v-${i}`,
    }));

    s3Mock.on(DeleteObjectsCommand).resolves({
      Deleted: [],
      Errors: [],
    });

    const result = await executeVersionDeletion(client, "my-bucket", entries, {
      confirm: true,
    });

    expect(result.total).toBe(2500);
    expect(result.deleted).toBe(2500);
    expect(result.failed).toBe(0);

    const deleteCalls = s3Mock.commandCalls(DeleteObjectsCommand);
    expect(deleteCalls.length).toBe(3);
    expect(deleteCalls[0].args[0].input.Delete?.Objects).toHaveLength(1000);
    expect(deleteCalls[1].args[0].input.Delete?.Objects).toHaveLength(1000);
    expect(deleteCalls[2].args[0].input.Delete?.Objects).toHaveLength(500);
    expect(deleteCalls[0].args[0].input.Delete?.Quiet).toBe(true);
  });

  it("handles 'null' version IDs properly", async () => {
    const client = new S3Client({});
    const entries = [{ Key: "unversioned.txt", VersionId: "null" }];

    s3Mock.on(DeleteObjectsCommand).resolvesOnce({
      Deleted: [],
      Errors: [],
    });

    const result = await executeVersionDeletion(client, "my-bucket", entries, {
      confirm: true,
    });

    expect(result.deleted).toBe(1);
    const calls = s3Mock.commandCalls(DeleteObjectsCommand);
    expect(calls[0].args[0].input.Delete?.Objects?.[0].VersionId).toBe("null");
  });

  it("unconditionally inspects response.Errors with Quiet: true and handles partial errors", async () => {
    const client = new S3Client({});
    const entries = [
      { Key: "good-1.txt", VersionId: "v1" },
      { Key: "bad-1.txt", VersionId: "v2" },
      { Key: "good-2.txt", VersionId: "v3" },
    ];

    s3Mock.on(DeleteObjectsCommand).resolvesOnce({
      Deleted: [], // Quiet: true omits Deleted elements
      Errors: [
        {
          Key: "bad-1.txt",
          VersionId: "v2",
          Code: "AccessDenied",
          Message: "Access Denied to object version",
        },
      ],
    });

    const result = await executeVersionDeletion(client, "my-bucket", entries, {
      confirm: true,
    });

    expect(result.total).toBe(3);
    expect(result.deleted).toBe(2);
    expect(result.failed).toBe(1);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].Key).toBe("bad-1.txt");
    expect(result.errors[0].Code).toBe("AccessDenied");
  });

  it("retries transient errors (SlowDown) with jittered backoff", async () => {
    const client = new S3Client({});
    const entries = [{ Key: "throttled.txt", VersionId: "v1" }];

    // Attempt 1: Throttling / SlowDown, Attempt 2: Succeeds
    s3Mock
      .on(DeleteObjectsCommand)
      .resolvesOnce({
        Deleted: [],
        Errors: [
          {
            Key: "throttled.txt",
            VersionId: "v1",
            Code: "SlowDown",
            Message: "Please reduce your request rate",
          },
        ],
      })
      .resolvesOnce({
        Deleted: [],
        Errors: [],
      });

    const result = await executeVersionDeletion(client, "my-bucket", entries, {
      confirm: true,
      retryOptions: { maxRetries: 2, initialDelayMs: 1 },
    });

    expect(result.deleted).toBe(1);
    expect(result.failed).toBe(0);
    expect(s3Mock.commandCalls(DeleteObjectsCommand)).toHaveLength(2);
  });
});
