import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  S3Client,
  GetBucketLifecycleConfigurationCommand,
  PutBucketLifecycleConfigurationCommand,
  DeleteBucketLifecycleCommand,
  GetBucketTaggingCommand,
  PutBucketTaggingCommand,
  DeleteObjectsCommand,
  ListObjectVersionsCommand,
} from "@aws-sdk/client-s3";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";
import { executeRollback } from "../src/rollback/executor.js";
import { createUndoManifest, computeCanonicalStateHash } from "../src/rollback/manifest-generator.js";
import { RemoteStateDriftError } from "../src/rollback/types.js";

const s3Mock = mockClient(S3Client);

describe("Rollback Executor (executeRollback)", () => {
  let tempDir: string;

  beforeEach(async () => {
    s3Mock.reset();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "s3-guardian-executor-test-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it("executes lifecycle rollback to preState when remote state has not diverged", async () => {
    const client = new S3Client({});
    const preRules = [{ ID: "original-rule", Status: "Enabled" as const, Expiration: { Days: 90 } }];
    const postRules = [
      { ID: "original-rule", Status: "Enabled" as const, Expiration: { Days: 90 } },
      { ID: "s3-guardian-abort-mpu", Status: "Enabled" as const, Filter: {} },
    ];

    const manifestRes = await createUndoManifest({
      stateDir: tempDir,
      bucketName: "app-data",
      mutationType: "LIFECYCLE_CONFIGURATION",
      preState: { Rules: preRules },
      postState: { Rules: postRules },
      appliedPlanHash: "hash-12345",
      requestIds: ["req-1"],
    });

    // Mock live state matching postState
    s3Mock
      .on(GetBucketLifecycleConfigurationCommand, { Bucket: "app-data" })
      .resolves({ Rules: postRules });

    s3Mock
      .on(PutBucketLifecycleConfigurationCommand, { Bucket: "app-data" })
      .resolves({});

    const result = await executeRollback(client, manifestRes.manifestPath, {
      stateDir: tempDir,
    });

    expect(result.status).toBe("RESTORED");
    expect(result.bucketName).toBe("app-data");
    expect(result.manifestId).toBe(manifestRes.manifestId);
    expect(result.restoredAt).toBeDefined();

    // Verify PutBucketLifecycleConfigurationCommand was called with preRules
    const putCalls = s3Mock.commandCalls(PutBucketLifecycleConfigurationCommand);
    expect(putCalls.length).toBe(1);
    expect(putCalls[0]?.args[0].input.LifecycleConfiguration?.Rules).toEqual(preRules);

    // Verify REMEDIATION_ROLLED_BACK event in audit.jsonl
    const auditPath = path.join(tempDir, "audit.jsonl");
    const auditContent = await fs.readFile(auditPath, "utf8");
    const event = JSON.parse(auditContent.trim());
    expect(event.eventType).toBe("REMEDIATION_ROLLED_BACK");
    expect(event.bucketName).toBe("app-data");
    expect(event.planHash).toBe("hash-12345");
    expect(event.details.forced).toBe(false);
  });

  it("deletes lifecycle configuration when preState was null (clean bucket)", async () => {
    const client = new S3Client({});
    const postRules = [{ ID: "s3-guardian-abort-mpu", Status: "Enabled" as const }];

    const manifestRes = await createUndoManifest({
      stateDir: tempDir,
      bucketName: "fresh-bucket",
      mutationType: "LIFECYCLE_CONFIGURATION",
      preState: null,
      postState: { Rules: postRules },
      appliedPlanHash: "hash-abc",
    });

    s3Mock
      .on(GetBucketLifecycleConfigurationCommand, { Bucket: "fresh-bucket" })
      .resolves({ Rules: postRules });

    s3Mock
      .on(DeleteBucketLifecycleCommand, { Bucket: "fresh-bucket" })
      .resolves({});

    const result = await executeRollback(client, manifestRes.manifestPath, {
      stateDir: tempDir,
    });

    expect(result.status).toBe("RESTORED");
    expect(s3Mock.commandCalls(DeleteBucketLifecycleCommand).length).toBe(1);
  });

  it("halts execution and throws RemoteStateDriftError when remote state diverges without --force", async () => {
    const client = new S3Client({});
    const preRules = [{ ID: "rule-1" }];
    const postRules = [{ ID: "rule-1" }, { ID: "s3-guardian-abort-mpu" }];

    const manifestRes = await createUndoManifest({
      stateDir: tempDir,
      bucketName: "divergent-bucket",
      mutationType: "LIFECYCLE_CONFIGURATION",
      preState: { Rules: preRules },
      postState: { Rules: postRules },
      appliedPlanHash: "hash-drift",
    });

    // Remote state has diverged! A third party modified the lifecycle policy
    const divergentLiveRules = [
      { ID: "rule-1" },
      { ID: "s3-guardian-abort-mpu" },
      { ID: "external-rule-added-by-admin" },
    ];

    s3Mock
      .on(GetBucketLifecycleConfigurationCommand, { Bucket: "divergent-bucket" })
      .resolves({ Rules: divergentLiveRules });

    // Should halt with RemoteStateDriftError
    await expect(
      executeRollback(client, manifestRes.manifestPath, { force: false })
    ).rejects.toThrow(RemoteStateDriftError);

    // Verify error properties
    try {
      await executeRollback(client, manifestRes.manifestPath, { force: false });
    } catch (err) {
      expect(err instanceof RemoteStateDriftError).toBe(true);
      const driftErr = err as RemoteStateDriftError;
      expect(driftErr.bucketName).toBe("divergent-bucket");
      expect(driftErr.expectedHash).toBe(computeCanonicalStateHash({ Rules: postRules }));
      expect(driftErr.actualHash).toBe(computeCanonicalStateHash({ Rules: divergentLiveRules }));
    }

    // Zero mutation calls should have been made
    expect(s3Mock.commandCalls(PutBucketLifecycleConfigurationCommand).length).toBe(0);
    expect(s3Mock.commandCalls(DeleteBucketLifecycleCommand).length).toBe(0);
  });

  it("proceeds with rollback despite remote state drift when --force is true", async () => {
    const client = new S3Client({});
    const preRules = [{ ID: "rule-1" }];
    const postRules = [{ ID: "rule-1" }, { ID: "s3-guardian-abort-mpu" }];

    const manifestRes = await createUndoManifest({
      stateDir: tempDir,
      bucketName: "force-override-bucket",
      mutationType: "LIFECYCLE_CONFIGURATION",
      preState: { Rules: preRules },
      postState: { Rules: postRules },
      appliedPlanHash: "hash-force",
    });

    const divergentLiveRules = [{ ID: "completely-different-rule" }];

    s3Mock
      .on(GetBucketLifecycleConfigurationCommand, { Bucket: "force-override-bucket" })
      .resolves({ Rules: divergentLiveRules });

    s3Mock
      .on(PutBucketLifecycleConfigurationCommand, { Bucket: "force-override-bucket" })
      .resolves({});

    const result = await executeRollback(client, manifestRes.manifestPath, {
      force: true,
      stateDir: tempDir,
    });

    expect(result.status).toBe("RESTORED");
    expect(s3Mock.commandCalls(PutBucketLifecycleConfigurationCommand).length).toBe(1);

    // Verify forced flag in audit event
    const auditPath = path.join(tempDir, "audit.jsonl");
    const auditContent = await fs.readFile(auditPath, "utf8");
    const event = JSON.parse(auditContent.trim());
    expect(event.details.forced).toBe(true);
  });

  it("rolls back bucket tagging mutation", async () => {
    const client = new S3Client({});
    const preTags = [{ Key: "Env", Value: "Dev" }];
    const postTags = [{ Key: "Env", Value: "Prod" }];

    const manifestRes = await createUndoManifest({
      stateDir: tempDir,
      bucketName: "tagged-bucket",
      mutationType: "BUCKET_TAGGING",
      preState: { TagSet: preTags },
      postState: { TagSet: postTags },
      appliedPlanHash: "hash-tag",
    });

    s3Mock
      .on(GetBucketTaggingCommand, { Bucket: "tagged-bucket" })
      .resolves({ TagSet: postTags });

    s3Mock
      .on(PutBucketTaggingCommand, { Bucket: "tagged-bucket" })
      .resolves({});

    const result = await executeRollback(client, manifestRes.manifestPath, {
      stateDir: tempDir,
    });

    expect(result.status).toBe("RESTORED");
    const putTagCalls = s3Mock.commandCalls(PutBucketTaggingCommand);
    expect(putTagCalls.length).toBe(1);
    expect(putTagCalls[0]?.args[0].input.Tagging?.TagSet).toEqual(preTags);
  });

  it("rolls back soft delete markers by executing DeleteObjectsCommand with Quiet: true", async () => {
    const client = new S3Client({});
    const objectsToPop = [
      { Key: "file-1.json", VersionId: "v-marker-1" },
      { Key: "file-2.json", VersionId: "v-marker-2" },
    ];

    const manifestRes = await createUndoManifest({
      stateDir: tempDir,
      bucketName: "marker-bucket",
      mutationType: "SOFT_DELETE_MARKER",
      preState: objectsToPop,
      postState: objectsToPop,
      inverseCommandType: "DeleteObjects",
      inversePayload: { Objects: objectsToPop },
      appliedPlanHash: "hash-markers",
    });

    s3Mock
      .on(ListObjectVersionsCommand, { Bucket: "marker-bucket" })
      .resolves({ DeleteMarkers: [], Versions: [], IsTruncated: false });

    s3Mock
      .on(DeleteObjectsCommand, { Bucket: "marker-bucket" })
      .resolves({});

    const result = await executeRollback(client, manifestRes.manifestPath, {
      stateDir: tempDir,
      force: true,
    });

    expect(result.status).toBe("RESTORED");
    const delCalls = s3Mock.commandCalls(DeleteObjectsCommand);
    expect(delCalls.length).toBe(1);
    expect(delCalls[0]?.args[0].input.Delete?.Quiet).toBe(true);
    expect(delCalls[0]?.args[0].input.Delete?.Objects).toEqual(objectsToPop);
  });
});
