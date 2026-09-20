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

describe("SovereignOperator 9-Phase Governance State Machine", () => {
  let tempDir: string;
  let s3Client: S3Client;

  beforeEach(() => {
    s3Mock.reset();
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "s3-guardian-operator-test-"));
    s3Client = new S3Client({ region: "us-east-1" });

    // Mock bucket location & tagging defaults
    s3Mock.on(GetBucketLocationCommand).resolves({ LocationConstraint: null });
    const noTagErr = new Error("NoSuchTagSet");
    noTagErr.name = "NoSuchTagSet";
    s3Mock.on(GetBucketTaggingCommand).rejects(noTagErr);

    // Mock Object Lock & Replication defaults
    const noLockErr = new Error("ObjectLockConfigurationNotFoundError");
    noLockErr.name = "ObjectLockConfigurationNotFoundError";
    s3Mock.on(GetObjectLockConfigurationCommand).rejects(noLockErr);

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

  it("executes full 9-phase state machine cycle with mocked S3 responses", async () => {
    const initiatedOld = new Date(Date.now() - 15 * 24 * 60 * 60 * 1000); // 15 days old

    s3Mock.on(ListBucketsCommand).resolves({
      Buckets: [{ Name: "governance-bucket" }],
    });

    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [
        { Key: "zombie-1.bin", UploadId: "upload-1", Initiated: initiatedOld },
        { Key: "zombie-2.bin", UploadId: "upload-2", Initiated: initiatedOld },
        { Key: "zombie-3.bin", UploadId: "upload-3", Initiated: initiatedOld },
      ],
    });

    s3Mock.on(ListPartsCommand).resolves({
      IsTruncated: false,
      Parts: [{ PartNumber: 1, Size: 1024 * 1024 }],
    });

    s3Mock.on(AbortMultipartUploadCommand).resolves({
      $metadata: { requestId: "req-abort-xyz" },
    });

    // Canary probe returns 404 NotFound
    const notFoundErr = new Error("NotFound");
    notFoundErr.name = "NotFound";
    s3Mock.on(HeadObjectCommand).rejects(notFoundErr);

    const operator = new SovereignOperator({
      stateDir: tempDir,
      client: s3Client,
      targetBucket: "governance-bucket",
      canaryCount: 1,
      maxBlastRadiusPercent: 1.0, // Allow 100% for test
      once: true,
      intervalMs: 100,
    });

    const context = await operator.runOnce();

    expect(context.isHalted).toBe(false);
    expect(context.epoch).toBe(1);
    expect(context.discoveredBuckets.length).toBe(1);
    expect(context.discoveredTargets.length).toBe(3);
    expect(context.matchedViolations.length).toBe(3);
    expect(context.canaryResult).toBeDefined();
    expect(context.canaryResult?.success).toBe(true);
    expect(context.totalMutations).toBe(3);
    expect(context.totalBytesFreed).toBeGreaterThan(0);
    expect(context.undoManifests.length).toBe(1);
    expect(context.deletionCertificates.length).toBe(1);

    // Verify persisted state files
    const undoFiles = fs.readdirSync(path.join(tempDir, "undo"));
    expect(undoFiles.length).toBe(1);
    expect(undoFiles[0]).toContain("undo-governance-bucket");

    const certFiles = fs.readdirSync(path.join(tempDir, "certificates"));
    expect(certFiles.length).toBe(1);
    expect(certFiles[0]).toContain("deletion-certificate-governance-bucket");

    const auditContent = fs.readFileSync(path.join(tempDir, "audit.jsonl"), "utf8");
    expect(auditContent).toContain("CANARY_VERIFIED");
    expect(auditContent).toContain("REMEDIATION_EXECUTED");
  });

  it("evaluates custom declarative policy document (policy matching phase)", async () => {
    const policyPath = path.join(tempDir, "test-policy.yaml");
    fs.writeFileSync(
      policyPath,
      `
schemaVersion: "1"
policyId: "enterprise-strict"
scope:
  level: "GLOBAL"
defaults:
  action: "AUTO_REMEDIATE"
  mpuAbortDays: 10
rules:
  - id: "archive-rule"
    match:
      bucket:
        nameRegex: ".*"
    mpuAbortDays: 14
`,
      "utf8"
    );

    const now = Date.now();
    const initiated8Days = new Date(now - 8 * 24 * 60 * 60 * 1000);
    const initiated20Days = new Date(now - 20 * 24 * 60 * 60 * 1000);

    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [
        { Key: "recent.bin", UploadId: "u-1", Initiated: initiated8Days },
        { Key: "old.bin", UploadId: "u-2", Initiated: initiated20Days },
      ],
    });

    s3Mock.on(ListPartsCommand).resolves({
      IsTruncated: false,
      Parts: [{ PartNumber: 1, Size: 500 }],
    });

    s3Mock.on(AbortMultipartUploadCommand).resolves({
      $metadata: { requestId: "req-abort-rule" },
    });

    const notFoundErr = new Error("NotFound");
    notFoundErr.name = "NotFound";
    s3Mock.on(HeadObjectCommand).rejects(notFoundErr);

    const operator = new SovereignOperator({
      stateDir: tempDir,
      client: s3Client,
      targetBucket: "policy-bucket",
      policyPath,
      maxBlastRadiusPercent: 1.0,
      once: true,
      intervalMs: 100,
    });

    await operator.stepDiscovery();
    await operator.stepPolicyMatch();

    const ctx = operator.getContext();
    expect(ctx.discoveredTargets.length).toBe(2);
    // Only the 20-day-old upload should match the 14-day threshold
    expect(ctx.matchedViolations.length).toBe(1);
    expect(ctx.matchedViolations[0]?.key).toBe("old.bin");
  });

  it("respects MONITOR_ONLY policy action mode without queuing mutations", async () => {
    const policyPath = path.join(tempDir, "monitor-policy.yaml");
    fs.writeFileSync(
      policyPath,
      `
schemaVersion: "1"
policyId: "audit-only"
scope:
  level: "GLOBAL"
defaults:
  action: "MONITOR_ONLY"
  mpuAbortDays: 3
rules: []
`,
      "utf8"
    );

    const oldDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [{ Key: "zombie.bin", UploadId: "u-monitor", Initiated: oldDate }],
    });

    s3Mock.on(ListPartsCommand).resolves({
      IsTruncated: false,
      Parts: [{ PartNumber: 1, Size: 1000 }],
    });

    const operator = new SovereignOperator({
      stateDir: tempDir,
      client: s3Client,
      targetBucket: "monitor-bucket",
      policyPath,
      once: true,
    });

    await operator.stepDiscovery();
    await operator.stepPolicyMatch();

    const ctx = operator.getContext();
    expect(ctx.discoveredTargets.length).toBe(1);
    expect(ctx.matchedViolations.length).toBe(0); // None queued because action is MONITOR_ONLY
  });

  it("simulates mutations cleanly in dry-run mode without issuing AWS abort commands", async () => {
    const oldDate = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000);

    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [{ Key: "dry.bin", UploadId: "u-dry", Initiated: oldDate }],
    });

    s3Mock.on(ListPartsCommand).resolves({
      IsTruncated: false,
      Parts: [{ PartNumber: 1, Size: 2048 }],
    });

    const operator = new SovereignOperator({
      stateDir: tempDir,
      client: s3Client,
      targetBucket: "dry-run-bucket",
      dryRun: true,
      maxBlastRadiusPercent: 1.0,
      once: true,
    });

    const context = await operator.runOnce();

    expect(context.isHalted).toBe(false);
    expect(context.totalMutations).toBe(1);
    // In dry-run mode, AbortMultipartUploadCommand must never be dispatched
    expect(s3Mock.commandCalls(AbortMultipartUploadCommand).length).toBe(0);
  });
});
