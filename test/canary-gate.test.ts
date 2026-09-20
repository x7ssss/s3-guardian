import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  S3Client,
  DeleteObjectsCommand,
  AbortMultipartUploadCommand,
  HeadObjectCommand,
  ListPartsCommand,
} from "@aws-sdk/client-s3";
import { executeCanaryGate, CanaryVerificationError } from "../src/safety/canary.js";
import { CircuitBreaker } from "../src/circuit/breaker.js";

const s3Mock = mockClient(S3Client);

describe("Canary Gate (executeCanaryGate)", () => {
  let s3Client: S3Client;
  let breaker: CircuitBreaker;

  beforeEach(() => {
    s3Mock.reset();
    s3Client = new S3Client({});
    breaker = new CircuitBreaker("canary-bucket", "DeleteObjects");
  });

  it("returns immediate success on empty target list", async () => {
    const result = await executeCanaryGate(s3Client, "canary-bucket", [], breaker);
    expect(result.success).toBe(true);
    expect(result.canaryTargetCount).toBe(0);
    expect(result.remainingTargets).toEqual([]);
  });

  it("verifies version deletion slice and probes with HeadObject (404 NotFound)", async () => {
    const targets = [
      { Key: "obj-1.log", VersionId: "v1", LastModified: "2026-01-01T00:00:00Z" },
      { Key: "obj-2.log", VersionId: "v2", LastModified: "2026-01-02T00:00:00Z" },
      { Key: "obj-3.log", VersionId: "v3", LastModified: "2026-01-03T00:00:00Z" },
    ];

    s3Mock.on(DeleteObjectsCommand).resolves({
      $metadata: { requestId: "req-delete-123" },
      Deleted: [{ Key: "obj-1.log" }, { Key: "obj-2.log" }],
    });

    // Probe returns 404 (NotFound) indicating version is gone
    const notFoundErr = new Error("NotFound");
    notFoundErr.name = "NotFound";
    (notFoundErr as any).$metadata = { httpStatusCode: 404 };
    s3Mock.on(HeadObjectCommand).rejects(notFoundErr);

    const result = await executeCanaryGate(s3Client, "canary-bucket", targets, breaker, {
      maxCanaryCount: 2,
    });

    expect(result.success).toBe(true);
    expect(result.canaryTargetCount).toBe(2);
    expect(result.requestIds).toContain("req-delete-123");
    expect(result.canaryTargets.map((t) => t.Key)).toEqual(["obj-1.log", "obj-2.log"]);
    expect(result.remainingTargets.map((t) => t.Key)).toEqual(["obj-3.log"]);
  });

  it("verifies version deletion when HeadObject returns DeleteMarker: true", async () => {
    const targets = [
      { Key: "marker.log", VersionId: "v-marker", LastModified: "2026-01-01T00:00:00Z" },
    ];

    s3Mock.on(DeleteObjectsCommand).resolves({
      Deleted: [{ Key: "marker.log" }],
    });

    s3Mock.on(HeadObjectCommand).resolves({
      DeleteMarker: true,
    });

    const result = await executeCanaryGate(s3Client, "canary-bucket", targets, breaker);
    expect(result.success).toBe(true);
    expect(result.canaryTargetCount).toBe(1);
    expect(result.remainingTargets).toHaveLength(0);
  });

  it("throws CanaryVerificationError when DeleteObjects returns batch Errors", async () => {
    const targets = [
      { Key: "fail.log", VersionId: "v1", LastModified: "2026-01-01T00:00:00Z" },
    ];

    s3Mock.on(DeleteObjectsCommand).resolves({
      Errors: [{ Key: "fail.log", VersionId: "v1", Code: "AccessDenied", Message: "Access Denied" }],
    });

    await expect(
      executeCanaryGate(s3Client, "canary-bucket", targets, breaker)
    ).rejects.toThrow(CanaryVerificationError);
  });

  it("throws CanaryVerificationError when HeadObject probe reveals object still exists", async () => {
    const targets = [
      { Key: "zombie.log", VersionId: "v1", LastModified: "2026-01-01T00:00:00Z" },
    ];

    s3Mock.on(DeleteObjectsCommand).resolves({
      Deleted: [{ Key: "zombie.log" }],
    });

    // HeadObject returns 200 OK without DeleteMarker -> still exists!
    s3Mock.on(HeadObjectCommand).resolves({
      ContentLength: 1024,
      DeleteMarker: false,
    });

    await expect(
      executeCanaryGate(s3Client, "canary-bucket", targets, breaker)
    ).rejects.toThrow(/still exists after deletion/);
  });

  it("verifies MPU abort canary and probe", async () => {
    const mpuTargets = [
      { key: "upload-1.bin", uploadId: "uid-1", initiated: "2026-01-01T00:00:00Z", bytes: 100 },
      { key: "upload-2.bin", uploadId: "uid-2", initiated: "2026-01-02T00:00:00Z", bytes: 200 },
    ];

    s3Mock.on(AbortMultipartUploadCommand).resolves({
      $metadata: { requestId: "req-abort-1" },
    });

    const noUploadErr = new Error("NoSuchUpload");
    noUploadErr.name = "NoSuchUpload";
    (noUploadErr as any).$metadata = { httpStatusCode: 404 };
    s3Mock.on(ListPartsCommand).rejects(noUploadErr);

    const result = await executeCanaryGate(s3Client, "canary-bucket", mpuTargets, breaker, {
      maxCanaryCount: 1,
    });

    expect(result.success).toBe(true);
    expect(result.canaryTargetCount).toBe(1);
    expect(result.canaryTargets[0].key).toBe("upload-1.bin");
    expect(result.remainingTargets[0].key).toBe("upload-2.bin");
  });
});
