import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import {
  S3Client,
  ListBucketsCommand,
  GetBucketLocationCommand,
  GetBucketTaggingCommand,
  GetObjectLockConfigurationCommand,
  GetBucketReplicationCommand,
  ListMultipartUploadsCommand,
  ListPartsCommand,
  AbortMultipartUploadCommand,
  HeadObjectCommand,
} from "@aws-sdk/client-s3";
import { SovereignOperator } from "../src/operator/sovereign-operator.js";

const s3Mock = mockClient(S3Client);

describe("SovereignOperator Circuit & Safety Halting (operator-circuit-halt.test.ts)", () => {
  let tempDir: string;
  let s3Client: S3Client;

  beforeEach(() => {
    s3Mock.reset();
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "s3-guardian-halt-test-"));
    s3Client = new S3Client({ region: "us-east-1" });

    // Mock defaults
    s3Mock.on(GetBucketLocationCommand).resolves({ LocationConstraint: null });
    const noTagErr = new Error("NoSuchTagSet");
    noTagErr.name = "NoSuchTagSet";
    s3Mock.on(GetBucketTaggingCommand).rejects(noTagErr);

    const noReplErr = new Error("ReplicationConfigurationNotFoundError");
    noReplErr.name = "ReplicationConfigurationNotFoundError";
    s3Mock.on(GetBucketReplicationCommand).rejects(noReplErr);
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  });

  it("halts execution when relative blast-radius mutation ceiling is breached", async () => {
    const oldDate = new Date(Date.now() - 15 * 24 * 60 * 60 * 1000);

    const noLockErr = new Error("ObjectLockConfigurationNotFoundError");
    noLockErr.name = "ObjectLockConfigurationNotFoundError";
    s3Mock.on(GetObjectLockConfigurationCommand).rejects(noLockErr);

    // 10 planned items, default maxBlastRadiusPercent = 0.05 (5%) -> ceiling limit = floor(10 * 0.05) = 0 items
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: Array.from({ length: 10 }, (_, i) => ({
        Key: `zombie-${i}.bin`,
        UploadId: `uid-${i}`,
        Initiated: oldDate,
      })),
    });

    s3Mock.on(ListPartsCommand).resolves({
      IsTruncated: false,
      Parts: [{ PartNumber: 1, Size: 1000 }],
    });

    const operator = new SovereignOperator({
      stateDir: tempDir,
      client: s3Client,
      targetBucket: "ceiling-breach-bucket",
      maxBlastRadiusPercent: 0.05, // 5% ceiling
      canaryCount: 2,
      once: true,
    });

    const context = await operator.runOnce();

    expect(context.isHalted).toBe(true);
    expect(context.haltReason).toContain("exceed");
    expect(operator.getState()).toBe("HALTED");
    expect(context.totalMutations).toBe(0);
    // AbortMultipartUploadCommand should never have been dispatched
    expect(s3Mock.commandCalls(AbortMultipartUploadCommand).length).toBe(0);
  });

  it("halts execution when pre-flight Object Lock is in COMPLIANCE mode", async () => {
    const oldDate = new Date(Date.now() - 15 * 24 * 60 * 60 * 1000);

    // Object Lock in COMPLIANCE mode
    s3Mock.on(GetObjectLockConfigurationCommand).resolves({
      ObjectLockConfiguration: {
        ObjectLockEnabled: "Enabled",
        Rule: {
          DefaultRetention: {
            Mode: "COMPLIANCE",
            Days: 365,
          },
        },
      },
    });

    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [{ Key: "locked.bin", UploadId: "uid-locked", Initiated: oldDate }],
    });

    s3Mock.on(ListPartsCommand).resolves({
      IsTruncated: false,
      Parts: [{ PartNumber: 1, Size: 1000 }],
    });

    const operator = new SovereignOperator({
      stateDir: tempDir,
      client: s3Client,
      targetBucket: "compliance-locked-bucket",
      maxBlastRadiusPercent: 1.0,
      once: true,
    });

    const context = await operator.runOnce();

    expect(context.isHalted).toBe(true);
    expect(context.haltReason).toContain("Object Lock in COMPLIANCE mode");
    expect(operator.getState()).toBe("HALTED");
    expect(context.totalMutations).toBe(0);
    expect(s3Mock.commandCalls(AbortMultipartUploadCommand).length).toBe(0);
  });

  it("halts execution when canary gate verification probe fails", async () => {
    const oldDate = new Date(Date.now() - 15 * 24 * 60 * 60 * 1000);

    const noLockErr = new Error("ObjectLockConfigurationNotFoundError");
    noLockErr.name = "ObjectLockConfigurationNotFoundError";
    s3Mock.on(GetObjectLockConfigurationCommand).rejects(noLockErr);

    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [
        { Key: "canary-fail-1.bin", UploadId: "uid-fail-1", Initiated: oldDate },
        { Key: "canary-fail-2.bin", UploadId: "uid-fail-2", Initiated: oldDate },
      ],
    });

    s3Mock.on(ListPartsCommand).resolves({
      IsTruncated: false,
      Parts: [{ PartNumber: 1, Size: 1000 }],
    });

    // Abort command fails with 500 InternalError during canary
    const internalErr = new Error("InternalServerError from S3");
    internalErr.name = "InternalError";
    (internalErr as any).$metadata = { httpStatusCode: 500 };
    s3Mock.on(AbortMultipartUploadCommand).rejects(internalErr);

    const operator = new SovereignOperator({
      stateDir: tempDir,
      client: s3Client,
      targetBucket: "canary-halt-bucket",
      maxBlastRadiusPercent: 1.0,
      canaryCount: 1,
      once: true,
    });

    const context = await operator.runOnce();

    expect(context.isHalted).toBe(true);
    expect(context.haltReason).toContain("Canary verification failure");
    expect(operator.getState()).toBe("HALTED");
    // Bulk execution must NOT have run
    expect(context.totalMutations).toBe(0);
    expect(context.undoManifests.length).toBe(0);
  });

  it("halts execution during CIRCUIT_VERIFY phase when circuit breaker is tripped (OPEN)", async () => {
    const oldDate = new Date(Date.now() - 15 * 24 * 60 * 60 * 1000);

    const noLockErr = new Error("ObjectLockConfigurationNotFoundError");
    noLockErr.name = "ObjectLockConfigurationNotFoundError";
    s3Mock.on(GetObjectLockConfigurationCommand).rejects(noLockErr);

    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [{ Key: "cb-test.bin", UploadId: "uid-cb", Initiated: oldDate }],
    });

    s3Mock.on(ListPartsCommand).resolves({
      IsTruncated: false,
      Parts: [{ PartNumber: 1, Size: 1000 }],
    });

    const operator = new SovereignOperator({
      stateDir: tempDir,
      client: s3Client,
      targetBucket: "circuit-open-bucket",
      maxBlastRadiusPercent: 1.0,
      once: true,
    });

    // Manually trip the circuit breaker into OPEN state by recording 3 consecutive AccessDenied errors
    const ctx = operator.getContext();
    const accessDeniedErr = new Error("AccessDenied");
    accessDeniedErr.name = "AccessDenied";
    (accessDeniedErr as any).$metadata = { httpStatusCode: 403 };

    ctx.circuitBreaker.recordError(accessDeniedErr);
    ctx.circuitBreaker.recordError(accessDeniedErr);
    ctx.circuitBreaker.recordError(accessDeniedErr);

    expect(ctx.circuitBreaker.getState()).toBe("OPEN");

    await operator.stepDiscovery();
    await operator.stepPolicyMatch();
    await operator.stepBlastRadiusAudit();
    await operator.stepCircuitVerify();

    expect(ctx.isHalted).toBe(true);
    expect(ctx.haltReason).toContain("Circuit breaker is OPEN");
    expect(operator.getState()).toBe("HALTED");
  });
});
