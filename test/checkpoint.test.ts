import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  S3Client,
  GetObjectCommand,
  PutObjectCommand,
  ListBucketsCommand,
  GetBucketLocationCommand,
  ListMultipartUploadsCommand,
  GetBucketLifecycleConfigurationCommand,
} from "@aws-sdk/client-s3";
import {
  parseS3Uri,
  loadCheckpoint,
  saveCheckpoint,
  CheckpointState,
} from "../src/checkpoint/s3-checkpoint.js";
import { scanFleet } from "../src/fleet/scanner.js";
import { S3ClientPool } from "../src/discovery/client-pool.js";

const s3Mock = mockClient(S3Client);

describe("S3 Resumable Checkpoint", () => {
  beforeEach(() => {
    s3Mock.reset();
  });

  describe("parseS3Uri()", () => {
    it("parses valid s3://bucket/key URI", () => {
      const parsed = parseS3Uri("s3://my-ops-bucket/checkpoints/audit.json");
      expect(parsed.bucket).toBe("my-ops-bucket");
      expect(parsed.key).toBe("checkpoints/audit.json");
    });

    it("throws error for non-s3 scheme", () => {
      expect(() => parseS3Uri("https://s3.amazonaws.com/b/k")).toThrow(
        /must start with "s3:\/\/"/
      );
    });

    it("throws error for missing bucket or key", () => {
      expect(() => parseS3Uri("s3://")).toThrow(/specify both bucket and object key/);
      expect(() => parseS3Uri("s3://bucket-only")).toThrow(
        /specify both bucket and object key/
      );
      expect(() => parseS3Uri("s3://bucket/")).toThrow(
        /specify both bucket and object key/
      );
    });
  });

  describe("loadCheckpoint()", () => {
    it("loads and deserializes existing checkpoint", async () => {
      const client = new S3Client({});
      const existingState: CheckpointState = {
        completedBuckets: [
          {
            bucket: "already-audited-bucket",
            region: "us-east-1",
            status: "AUDITED",
            totalZombieUploads: 2,
            totalStrandedBytes: 2048,
            estimatedMonthlyWasteUSD: 0,
          },
        ],
        lastUpdatedAt: "2026-09-20T12:00:00.000Z",
      };

      // Mock GetObjectCommand returning string
      s3Mock.on(GetObjectCommand).resolvesOnce({
        Body: {
          transformToString: async () => JSON.stringify(existingState),
        } as any,
      });

      const loaded = await loadCheckpoint(
        client,
        "s3://my-checkpoint-bucket/state.json"
      );

      expect(loaded.completedBuckets).toHaveLength(1);
      expect(loaded.completedBuckets[0].bucket).toBe("already-audited-bucket");
      expect(loaded.lastUpdatedAt).toBe("2026-09-20T12:00:00.000Z");
    });

    it("handles 404 NoSuchKey cleanly returning empty checkpoint", async () => {
      const client = new S3Client({});
      const err = new Error("NoSuchKey");
      err.name = "NoSuchKey";
      (err as any).$metadata = { httpStatusCode: 404 };

      s3Mock.on(GetObjectCommand).rejectsOnce(err);

      const loaded = await loadCheckpoint(
        client,
        "s3://my-checkpoint-bucket/non-existent.json"
      );

      expect(loaded.completedBuckets).toEqual([]);
      expect(typeof loaded.lastUpdatedAt).toBe("string");
    });
  });

  describe("saveCheckpoint()", () => {
    it("serializes and saves checkpoint with PutObjectCommand", async () => {
      const client = new S3Client({});
      s3Mock.on(PutObjectCommand).resolvesOnce({});

      const stateToSave: CheckpointState = {
        completedBuckets: [
          {
            bucket: "bucket-a",
            region: "us-east-1",
            status: "AUDITED",
            totalZombieUploads: 1,
            totalStrandedBytes: 1024,
            estimatedMonthlyWasteUSD: 0,
          },
        ],
        lastUpdatedAt: new Date().toISOString(),
      };

      await saveCheckpoint(client, "s3://my-checkpoint-bucket/out.json", stateToSave);

      const calls = s3Mock.commandCalls(PutObjectCommand);
      expect(calls.length).toBe(1);
      expect(calls[0].args[0].input.Bucket).toBe("my-checkpoint-bucket");
      expect(calls[0].args[0].input.Key).toBe("out.json");
      const parsedBody = JSON.parse(calls[0].args[0].input.Body as string);
      expect(parsedBody.completedBuckets).toHaveLength(1);
      expect(parsedBody.completedBuckets[0].bucket).toBe("bucket-a");
    });
  });

  describe("Fleet scan integration with checkpoint", () => {
    it("skips buckets already in checkpoint and saves progress incrementally", async () => {
      const pool = new S3ClientPool();
      const discoveryClient = new S3Client({});

      // Account has 2 buckets: bucket-1 (already completed in checkpoint), bucket-2 (needs audit)
      s3Mock.on(ListBucketsCommand).resolves({
        Buckets: [{ Name: "bucket-1" }, { Name: "bucket-2" }],
      });

      // Existing checkpoint has bucket-1 already completed
      const existingCheckpoint: CheckpointState = {
        completedBuckets: [
          {
            bucket: "bucket-1",
            region: "us-east-1",
            status: "AUDITED",
            totalZombieUploads: 3,
            totalStrandedBytes: 3000,
            estimatedMonthlyWasteUSD: 0,
          },
        ],
        lastUpdatedAt: "2026-09-20T10:00:00.000Z",
      };

      s3Mock.on(GetObjectCommand).resolves({
        Body: {
          transformToString: async () => JSON.stringify(existingCheckpoint),
        } as any,
      });

      // bucket-2 GetBucketLocation
      s3Mock
        .on(GetBucketLocationCommand, { Bucket: "bucket-2" })
        .resolves({ LocationConstraint: null });

      // bucket-2 lifecycle
      const lcErr = new Error("NoSuchLifecycleConfiguration");
      lcErr.name = "NoSuchLifecycleConfiguration";
      (lcErr as any).$metadata = { httpStatusCode: 404 };
      s3Mock
        .on(GetBucketLifecycleConfigurationCommand, { Bucket: "bucket-2" })
        .rejects(lcErr);

      // bucket-2 uploads: clean
      s3Mock
        .on(ListMultipartUploadsCommand, { Bucket: "bucket-2" })
        .resolves({ IsTruncated: false, Uploads: [] });

      s3Mock.on(PutObjectCommand).resolves({});

      const result = await scanFleet({
        discoveryClient,
        clientPool: pool,
        checkpointUri: "s3://ops-bucket/checkpoints/fleet.json",
      });

      await pool.destroy();

      expect(result.bucketsDiscovered).toBe(2);
      expect(result.bucketsAudited).toBe(2);
      expect(result.totalZombieUploads).toBe(3); // 3 from bucket-1 + 0 from bucket-2

      // Verify bucket-1 was NOT re-queried for ListMultipartUploads
      const mpuCalls = s3Mock.commandCalls(ListMultipartUploadsCommand);
      expect(mpuCalls.length).toBe(1);
      expect(mpuCalls[0].args[0].input.Bucket).toBe("bucket-2");

      // Verify checkpoint was updated and saved
      const putCalls = s3Mock.commandCalls(PutObjectCommand);
      expect(putCalls.length).toBeGreaterThanOrEqual(1);
    });
  });
});
