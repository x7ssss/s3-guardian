import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  S3Client,
  AbortMultipartUploadCommand,
  DeleteObjectsCommand,
} from "@aws-sdk/client-s3";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";
import { createDeletionCertificate } from "../src/rollback/manifest-generator.js";
import { executeAbortPlan } from "../src/executor/abort.js";
import { executeVersionDeletion } from "../src/versioning/executor.js";
import { Plan } from "../src/planner/plan.js";

const s3Mock = mockClient(S3Client);

describe("SOC 2 / ISO 27001 Deletion Certificate", () => {
  let tempDir: string;

  beforeEach(async () => {
    s3Mock.reset();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "s3-guardian-cert-test-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it("creates an immutable deletion certificate atomically on disk", async () => {
    const ledger = [
      { key: "backups/db.tar.gz", versionId: "v-1", sizeBytes: 1048576 },
      { key: "backups/logs.tar.gz", versionId: "v-2", sizeBytes: 524288 },
    ];

    const result = await createDeletionCertificate({
      stateDir: tempDir,
      bucketName: "compliance-bucket",
      operation: "PERMANENT_VERSION_DELETE",
      totalBytesReclaimed: 1572864,
      planHash: "abc123canonicalplanhash",
      requestIds: ["req-1", "req-2"],
      itemLedger: ledger,
    });

    expect(result.certificateId).toBeDefined();
    expect(result.timestamp).toBeDefined();
    expect(result.bucketName).toBe("compliance-bucket");
    expect(result.operation).toBe("PERMANENT_VERSION_DELETE");
    expect(result.targetCount).toBe(2);
    expect(result.totalBytesReclaimed).toBe(1572864);
    expect(result.planHash).toBe("abc123canonicalplanhash");
    expect(result.requestIds).toEqual(["req-1", "req-2"]);
    expect(result.itemLedger).toEqual(ledger);

    // Verify file on disk
    const stat = await fs.stat(result.certificatePath);
    expect(stat.isFile()).toBe(true);
    expect(result.certificatePath).toContain(path.join("certificates", "deletion-certificate-compliance-bucket-"));

    const content = JSON.parse(await fs.readFile(result.certificatePath, "utf8"));
    expect(content.certificateId).toBe(result.certificateId);
    expect(content.planHash).toBe("abc123canonicalplanhash");
  });

  it("executeAbortPlan generates and persists a DeletionCertificate with CloudTrail request IDs", async () => {
    const client = new S3Client({});
    const plan: Plan = {
      schemaVersion: "1.3",
      bucket: "zombie-bucket",
      scannedAt: new Date().toISOString(),
      olderThanDays: 7,
      totalUploads: 1,
      totalBytes: 5000000,
      estimatedMonthlyWasteUSD: 0.12,
      planHash: "plan-hash-mpu-123",
      uploads: [
        {
          key: "large-video.mp4",
          uploadId: "mpu-upload-id-999",
          initiated: new Date("2026-01-01").toISOString(),
          bytes: 5000000,
          partsCount: 5,
        },
      ],
    };

    s3Mock
      .on(AbortMultipartUploadCommand, {
        Bucket: "zombie-bucket",
        Key: "large-video.mp4",
        UploadId: "mpu-upload-id-999",
      })
      .resolves({
        $metadata: { requestId: "aws-cloudtrail-req-mpu-1" },
      });

    const result = await executeAbortPlan(client, plan, {
      confirm: true,
      skipCanary: true,
      stateDir: tempDir,
    });

    expect(result.aborted).toBe(1);
    expect(result.deletionCertificate).toBeDefined();
    expect(result.deletionCertificate?.operation).toBe("ABORT_MULTIPART_UPLOAD");
    expect(result.deletionCertificate?.bucketName).toBe("zombie-bucket");
    expect(result.deletionCertificate?.planHash).toBe("plan-hash-mpu-123");
    expect(result.deletionCertificate?.requestIds).toContain("aws-cloudtrail-req-mpu-1");
    expect(result.certificatePath).toBeDefined();

    // Verify certificate file was written to disk
    const stat = await fs.stat(result.certificatePath!);
    expect(stat.isFile()).toBe(true);
  });

  it("executeVersionDeletion generates and persists a DeletionCertificate for version purges", async () => {
    const client = new S3Client({});
    const entries = [
      {
        Key: "old-secret.pem",
        VersionId: "v-secret-old",
        sizeBytes: 4096,
      },
    ];

    s3Mock
      .on(DeleteObjectsCommand, { Bucket: "secrets-bucket" })
      .resolves({
        $metadata: { requestId: "aws-cloudtrail-req-del-version" },
        Deleted: [{ Key: "old-secret.pem", VersionId: "v-secret-old" }],
      });

    const result = await executeVersionDeletion(client, "secrets-bucket", entries, {
      confirm: true,
      skipCanary: true,
      stateDir: tempDir,
      planHash: "plan-hash-version-xyz",
    });

    expect(result.deleted).toBe(1);
    expect(result.deletionCertificate).toBeDefined();
    expect(result.deletionCertificate?.operation).toBe("PERMANENT_VERSION_DELETE");
    expect(result.deletionCertificate?.bucketName).toBe("secrets-bucket");
    expect(result.deletionCertificate?.totalBytesReclaimed).toBe(4096);
    expect(result.deletionCertificate?.planHash).toBe("plan-hash-version-xyz");
    expect(result.deletionCertificate?.requestIds).toContain("aws-cloudtrail-req-del-version");
    expect(result.certificatePath).toBeDefined();

    const stat = await fs.stat(result.certificatePath!);
    expect(stat.isFile()).toBe(true);
  });
});
