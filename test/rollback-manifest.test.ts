import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  S3Client,
  GetBucketLifecycleConfigurationCommand,
  GetBucketTaggingCommand,
} from "@aws-sdk/client-s3";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";
import {
  captureLifecyclePreState,
  captureTaggingPreState,
  createUndoManifest,
  computeCanonicalStateHash,
} from "../src/rollback/manifest-generator.js";
import { canonicalizeJson, computeSha256Hex } from "../src/planner/jcs.js";

const s3Mock = mockClient(S3Client);

describe("Rollback Manifest Generator", () => {
  let tempDir: string;

  beforeEach(async () => {
    s3Mock.reset();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "s3-guardian-manifest-test-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  describe("captureLifecyclePreState", () => {
    it("captures existing lifecycle rules and computes RFC 8785 canonical hash", async () => {
      const client = new S3Client({});
      const rules = [
        {
          ID: "expire-old-data",
          Status: "Enabled" as const,
          Expiration: { Days: 365 },
        },
      ];

      s3Mock
        .on(GetBucketLifecycleConfigurationCommand, { Bucket: "prod-bucket" })
        .resolvesOnce({
          Rules: rules,
          $metadata: { requestId: "req-123", httpStatusCode: 200 },
        });

      const result = await captureLifecyclePreState(client, "prod-bucket");

      expect(result.preState).toEqual({ Rules: rules });
      expect(result.state).toEqual({ Rules: rules });
      const expectedHash = computeSha256Hex(canonicalizeJson({ Rules: rules }));
      expect(result.canonicalHash).toBe(expectedHash);
      expect(result.hash).toBe(expectedHash);
    });

    it("traps 404 NoSuchLifecycleConfiguration and returns null state with canonical null hash", async () => {
      const client = new S3Client({});
      const err = new Error("NoSuchLifecycleConfiguration");
      err.name = "NoSuchLifecycleConfiguration";
      (err as any).$metadata = { httpStatusCode: 404 };

      s3Mock
        .on(GetBucketLifecycleConfigurationCommand, { Bucket: "empty-bucket" })
        .rejectsOnce(err);

      const result = await captureLifecyclePreState(client, "empty-bucket");

      expect(result.preState).toBeNull();
      expect(result.state).toBeNull();
      const expectedNullHash = computeSha256Hex(canonicalizeJson(null));
      expect(result.canonicalHash).toBe(expectedNullHash);
      expect(result.hash).toBe(expectedNullHash);
    });

    it("re-throws unexpected errors like 403 AccessDenied", async () => {
      const client = new S3Client({});
      const deniedErr = new Error("AccessDenied");
      deniedErr.name = "AccessDenied";
      (deniedErr as any).$metadata = { httpStatusCode: 403 };

      s3Mock
        .on(GetBucketLifecycleConfigurationCommand, { Bucket: "secret-bucket" })
        .rejectsOnce(deniedErr);

      await expect(
        captureLifecyclePreState(client, "secret-bucket")
      ).rejects.toThrow("AccessDenied");
    });
  });

  describe("captureTaggingPreState", () => {
    it("captures existing bucket tags and computes RFC 8785 canonical hash", async () => {
      const client = new S3Client({});
      const tagSet = [
        { Key: "Environment", Value: "Production" },
        { Key: "Owner", Value: "FinOps" },
      ];

      s3Mock
        .on(GetBucketTaggingCommand, { Bucket: "tagged-bucket" })
        .resolvesOnce({
          TagSet: tagSet,
          $metadata: { requestId: "req-tag-123" },
        });

      const result = await captureTaggingPreState(client, "tagged-bucket");

      expect(result.preState).toEqual({ TagSet: tagSet });
      const expectedHash = computeSha256Hex(canonicalizeJson({ TagSet: tagSet }));
      expect(result.canonicalHash).toBe(expectedHash);
    });

    it("traps 404 NoSuchTagSet and returns null state with canonical null hash", async () => {
      const client = new S3Client({});
      const err = new Error("NoSuchTagSet");
      err.name = "NoSuchTagSet";
      (err as any).$metadata = { httpStatusCode: 404 };

      s3Mock
        .on(GetBucketTaggingCommand, { Bucket: "untagged-bucket" })
        .rejectsOnce(err);

      const result = await captureTaggingPreState(client, "untagged-bucket");

      expect(result.preState).toBeNull();
      expect(result.canonicalHash).toBe(computeSha256Hex(canonicalizeJson(null)));
    });
  });

  describe("RFC 8785 Canonical JCS hashing", () => {
    it("produces identical SHA-256 hashes regardless of object key order", () => {
      const objA = { b: 2, a: 1, c: { z: 10, y: 20 } };
      const objB = { a: 1, c: { y: 20, z: 10 }, b: 2 };

      const hashA = computeCanonicalStateHash(objA);
      const hashB = computeCanonicalStateHash(objB);

      expect(hashA).toBe(hashB);
      expect(hashA).toHaveLength(64);
    });
  });

  describe("createUndoManifest", () => {
    it("generates and atomically writes undo-<bucket>-<timestamp>.json to stateDir/undo", async () => {
      const preState = { Rules: [{ ID: "rule-1" }] };
      const postState = { Rules: [{ ID: "rule-1" }, { ID: "s3-guardian-abort-mpu" }] };

      const result = await createUndoManifest({
        stateDir: tempDir,
        bucketName: "my-target-bucket",
        mutationType: "LIFECYCLE_CONFIGURATION",
        preState,
        postState,
        appliedPlanHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        requestIds: ["req-put-123"],
      });

      expect(result.manifestId).toBeDefined();
      expect(result.manifestVersion).toBe("1.8.0");
      expect(result.bucketName).toBe("my-target-bucket");
      expect(result.mutationType).toBe("LIFECYCLE_CONFIGURATION");
      expect(result.canonicalPreStateHash).toBe(computeCanonicalStateHash(preState));
      expect(result.canonicalPostStateHash).toBe(computeCanonicalStateHash(postState));
      expect(result.inverseCommandType).toBe("PutBucketLifecycleConfiguration");
      expect(result.requestIds).toEqual(["req-put-123"]);

      // Verify file written to disk
      const stat = await fs.stat(result.manifestPath);
      expect(stat.isFile()).toBe(true);
      expect(result.manifestPath).toContain(path.join("undo", "undo-my-target-bucket-"));

      const fileContent = JSON.parse(await fs.readFile(result.manifestPath, "utf8"));
      expect(fileContent.manifestId).toBe(result.manifestId);
      expect(fileContent.canonicalPreStateHash).toBe(result.canonicalPreStateHash);
    });

    it("auto-infers DeleteBucketLifecycleConfiguration when preState is null", async () => {
      const postState = { Rules: [{ ID: "s3-guardian-abort-mpu" }] };

      const result = await createUndoManifest({
        stateDir: tempDir,
        bucketName: "fresh-bucket",
        mutationType: "LIFECYCLE_CONFIGURATION",
        preState: null,
        postState,
        appliedPlanHash: "abcdef",
      });

      expect(result.inverseCommandType).toBe("DeleteBucketLifecycleConfiguration");
      expect(result.inversePayload).toBeNull();
      expect(result.canonicalPreStateHash).toBe(computeCanonicalStateHash(null));
    });
  });
});
