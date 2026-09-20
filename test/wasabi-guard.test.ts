import { describe, it, expect, beforeEach } from "vitest";
import { S3Client, AbortMultipartUploadCommand, DeleteObjectsCommand } from "@aws-sdk/client-s3";
import { mockClient } from "aws-sdk-client-mock";
import { assessBucketBlastRadius } from "../src/safety/blast-radius.js";
import { executeAbortPlan } from "../src/executor/abort.js";
import { executeVersionDeletion } from "../src/versioning/executor.js";
import { Plan } from "../src/planner/plan.js";

describe("Wasabi 90-Day Retention Guard (test/wasabi-guard.test.ts)", () => {
  const s3Mock = mockClient(S3Client);
  let client: S3Client;

  beforeEach(() => {
    s3Mock.reset();
    client = new S3Client({ region: "us-east-1" });
  });

  describe("assessBucketBlastRadius() with Wasabi provider", () => {
    it("flags HIGH_WASABI_RETENTION_RISK when targets are less than 90 days old", async () => {
      const now = new Date("2026-06-01T00:00:00Z");
      // 30 days old (< 90 days)
      const recentTimestamp = new Date("2026-05-02T00:00:00Z");

      const assessment = await assessBucketBlastRadius(client, "wasabi-bucket", {
        provider: "wasabi",
        targets: [
          { key: "data/file1.csv", timestamp: recentTimestamp },
        ],
        now,
      });

      expect(assessment.requiresWasabiEarlyDeleteBypass).toBe(true);
      expect(assessment.riskLevel).toBe("HIGH");

      const wasabiFinding = assessment.findings.find(
        (f) => f.code === "HIGH_WASABI_RETENTION_RISK"
      );
      expect(wasabiFinding).toBeDefined();
      expect(wasabiFinding!.risk).toBe("HIGH");
      expect(wasabiFinding!.message).toContain(
        "⚠️ Wasabi charges 90 days minimum retention. Deleting objects < 90 days old triggers Timed Deleted Storage fees."
      );
    });

    it("permits deletion when --force-wasabi-early-delete is provided", async () => {
      const now = new Date("2026-06-01T00:00:00Z");
      const recentTimestamp = new Date("2026-05-02T00:00:00Z");

      const assessment = await assessBucketBlastRadius(client, "wasabi-bucket", {
        provider: "wasabi",
        targets: [
          { key: "data/file1.csv", timestamp: recentTimestamp },
        ],
        forceWasabiEarlyDelete: true,
        now,
      });

      expect(assessment.requiresWasabiEarlyDeleteBypass).toBe(false);
      // Risk is downgraded from HIGH to MEDIUM when overridden
      expect(assessment.riskLevel).toBe("MEDIUM");

      const wasabiFinding = assessment.findings.find(
        (f) => f.code === "HIGH_WASABI_RETENTION_RISK"
      );
      expect(wasabiFinding).toBeDefined();
      expect(wasabiFinding!.risk).toBe("MEDIUM");
    });

    it("does not flag retention risk when all targets are >= 90 days old", async () => {
      const now = new Date("2026-06-01T00:00:00Z");
      // 100 days old (>= 90 days)
      const oldTimestamp = new Date("2026-02-21T00:00:00Z");

      const assessment = await assessBucketBlastRadius(client, "wasabi-bucket", {
        provider: "wasabi",
        targets: [
          { key: "data/old-file.csv", timestamp: oldTimestamp },
        ],
        now,
      });

      expect(assessment.requiresWasabiEarlyDeleteBypass).toBe(false);
      const wasabiFinding = assessment.findings.find(
        (f) => f.code === "HIGH_WASABI_RETENTION_RISK"
      );
      expect(wasabiFinding).toBeUndefined();
    });

    it("does not apply Wasabi retention guard to AWS or other non-Wasabi providers", async () => {
      const now = new Date("2026-06-01T00:00:00Z");
      const recentTimestamp = new Date("2026-05-02T00:00:00Z");

      const assessment = await assessBucketBlastRadius(client, "aws-bucket", {
        provider: "aws",
        targets: [
          { key: "data/file1.csv", timestamp: recentTimestamp },
        ],
        now,
      });

      expect(assessment.requiresWasabiEarlyDeleteBypass).toBe(false);
      const wasabiFinding = assessment.findings.find(
        (f) => f.code === "HIGH_WASABI_RETENTION_RISK"
      );
      expect(wasabiFinding).toBeUndefined();
    });
  });

  describe("executeAbortPlan() with Wasabi guard", () => {
    it("aborts execution and throws error if uploads are younger than 90 days on Wasabi", async () => {
      const now = new Date("2026-06-01T00:00:00Z");
      const plan: Plan = {
        schemaVersion: "1.3",
        generatedAt: now.toISOString(),
        bucket: "wasabi-backup",
        endpoint: "https://s3.wasabisys.com",
        olderThanDays: 7,
        totalZombieUploads: 1,
        totalStrandedBytes: 1048576,
        estimatedMonthlyWasteUSD: 0.05,
        lifecycleAudit: {
          bucketHasLifecyclePolicy: false,
          hasCoveringRule: false,
          ghostRulesDetected: [],
        },
        uploads: [
          {
            key: "backups/db.dump",
            uploadId: "wasabi-upl-1",
            initiated: "2026-05-01T00:00:00Z", // 31 days old (< 90)
            partsCount: 2,
            bytes: 1048576,
            storageClass: "STANDARD",
            lifecycleStatus: "UNPROTECTED",
          },
        ],
      };

      await expect(
        executeAbortPlan(client, plan, {
          confirm: true,
          provider: "wasabi",
          now,
        })
      ).rejects.toThrow(
        "⚠️ Wasabi charges 90 days minimum retention. Deleting objects < 90 days old triggers Timed Deleted Storage fees."
      );
    });

    it("allows execution on Wasabi when --force-wasabi-early-delete is true", async () => {
      const now = new Date("2026-06-01T00:00:00Z");
      const plan: Plan = {
        schemaVersion: "1.3",
        generatedAt: now.toISOString(),
        bucket: "wasabi-backup",
        endpoint: "https://s3.wasabisys.com",
        olderThanDays: 7,
        totalZombieUploads: 1,
        totalStrandedBytes: 1048576,
        estimatedMonthlyWasteUSD: 0.05,
        lifecycleAudit: {
          bucketHasLifecyclePolicy: false,
          hasCoveringRule: false,
          ghostRulesDetected: [],
        },
        uploads: [
          {
            key: "backups/db.dump",
            uploadId: "wasabi-upl-1",
            initiated: "2026-05-01T00:00:00Z",
            partsCount: 2,
            bytes: 1048576,
            storageClass: "STANDARD",
            lifecycleStatus: "UNPROTECTED",
          },
        ],
      };

      s3Mock.on(AbortMultipartUploadCommand).resolves({});

      const result = await executeAbortPlan(client, plan, {
        confirm: true,
        provider: "wasabi",
        forceWasabiEarlyDelete: true,
        now,
      });

      expect(result.aborted).toBe(1);
      expect(result.failed).toBe(0);
    });
  });

  describe("executeVersionDeletion() with Wasabi guard", () => {
    it("aborts version deletions and throws error if versions are younger than 90 days on Wasabi", async () => {
      const now = new Date("2026-06-01T00:00:00Z");
      const entries = [
        {
          Key: "archive/report.pdf",
          VersionId: "v-123",
          LastModified: "2026-05-15T00:00:00Z", // 17 days old (< 90)
        },
      ];

      await expect(
        executeVersionDeletion(client, "wasabi-versions", entries, {
          confirm: true,
          provider: "wasabi",
          now,
        })
      ).rejects.toThrow(
        "⚠️ Wasabi charges 90 days minimum retention. Deleting objects < 90 days old triggers Timed Deleted Storage fees."
      );
    });

    it("allows version deletion on Wasabi when --force-wasabi-early-delete is true", async () => {
      const now = new Date("2026-06-01T00:00:00Z");
      const entries = [
        {
          Key: "archive/report.pdf",
          VersionId: "v-123",
          LastModified: "2026-05-15T00:00:00Z",
        },
      ];

      s3Mock.on(DeleteObjectsCommand).resolves({
        Deleted: [{ Key: "archive/report.pdf", VersionId: "v-123" }],
      });

      const result = await executeVersionDeletion(client, "wasabi-versions", entries, {
        confirm: true,
        provider: "wasabi",
        forceWasabiEarlyDelete: true,
        now,
      });

      expect(result.deleted).toBe(1);
      expect(result.failed).toBe(0);
    });
  });
});
