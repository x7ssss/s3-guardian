import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  S3Client,
  GetObjectLockConfigurationCommand,
  GetBucketReplicationCommand,
  GetBucketTaggingCommand,
} from "@aws-sdk/client-s3";
import {
  assessBucketBlastRadius,
  PROTECTED_PREFIXES,
} from "../src/safety/blast-radius.js";

const s3Mock = mockClient(S3Client);

describe("Pre-Flight Blast Radius Simulator", () => {
  beforeEach(() => {
    s3Mock.reset();
  });

  const stubSafeDefaults = () => {
    s3Mock.on(GetObjectLockConfigurationCommand).rejects({
      name: "ObjectLockConfigurationNotFoundError",
      $metadata: { httpStatusCode: 404 },
    });
    s3Mock.on(GetBucketReplicationCommand).rejects({
      name: "ReplicationConfigurationNotFoundError",
      $metadata: { httpStatusCode: 404 },
    });
    s3Mock.on(GetBucketTaggingCommand).rejects({
      name: "NoSuchTagSet",
      $metadata: { httpStatusCode: 404 },
    });
  };

  it("evaluates a standard unprotected bucket as LOW risk", async () => {
    stubSafeDefaults();
    const client = new S3Client({});

    const assessment = await assessBucketBlastRadius(client, "normal-bucket", {
      targetKeys: ["uploads/chunk1.part", "media/video.mp4"],
    });

    expect(assessment.riskLevel).toBe("LOW");
    expect(assessment.isBlocked).toBe(false);
    expect(assessment.requiresGovernanceBypass).toBe(false);
    expect(assessment.requiresReplicationAck).toBe(false);
    expect(assessment.findings).toHaveLength(0);
  });

  describe("S3 Object Lock Compliance", () => {
    it("hard-blocks execution on COMPLIANCE mode Object Lock (CRITICAL_BLOCKED)", async () => {
      stubSafeDefaults();
      s3Mock.on(GetObjectLockConfigurationCommand).resolves({
        ObjectLockConfiguration: {
          ObjectLockEnabled: "Enabled",
          Rule: {
            DefaultRetention: {
              Mode: "COMPLIANCE",
              Days: 30,
            },
          },
        },
      });

      const client = new S3Client({});
      const assessment = await assessBucketBlastRadius(client, "compliance-locked-bucket");

      expect(assessment.riskLevel).toBe("CRITICAL_BLOCKED");
      expect(assessment.isBlocked).toBe(true);
      expect(assessment.objectLock?.enabled).toBe(true);
      expect(assessment.objectLock?.mode).toBe("COMPLIANCE");

      const finding = assessment.findings.find((f) => f.code === "BLOCKED_COMPLIANCE_LOCK");
      expect(finding).toBeDefined();
      expect(finding?.risk).toBe("CRITICAL_BLOCKED");
      expect(finding?.message).toContain("COMPLIANCE mode");
    });

    it("requires --bypass-governance on GOVERNANCE mode Object Lock", async () => {
      stubSafeDefaults();
      s3Mock.on(GetObjectLockConfigurationCommand).resolves({
        ObjectLockConfiguration: {
          ObjectLockEnabled: "Enabled",
          Rule: {
            DefaultRetention: {
              Mode: "GOVERNANCE",
              Days: 14,
            },
          },
        },
      });

      const client = new S3Client({});
      const assessment = await assessBucketBlastRadius(client, "gov-locked-bucket", {
        bypassGovernance: false,
      });

      expect(assessment.riskLevel).toBe("HIGH");
      expect(assessment.isBlocked).toBe(false);
      expect(assessment.requiresGovernanceBypass).toBe(true);

      const finding = assessment.findings.find((f) => f.code === "GOVERNANCE_LOCK_ACTIVE");
      expect(finding).toBeDefined();
      expect(finding?.risk).toBe("HIGH");
    });

    it("allows execution on GOVERNANCE mode when bypassGovernance is true", async () => {
      stubSafeDefaults();
      s3Mock.on(GetObjectLockConfigurationCommand).resolves({
        ObjectLockConfiguration: {
          ObjectLockEnabled: "Enabled",
          Rule: {
            DefaultRetention: {
              Mode: "GOVERNANCE",
              Days: 14,
            },
          },
        },
      });

      const client = new S3Client({});
      const assessment = await assessBucketBlastRadius(client, "gov-locked-bucket", {
        bypassGovernance: true,
      });

      expect(assessment.riskLevel).toBe("MEDIUM");
      expect(assessment.isBlocked).toBe(false);
      expect(assessment.requiresGovernanceBypass).toBe(false);

      const finding = assessment.findings.find((f) => f.code === "GOVERNANCE_LOCK_BYPASSED");
      expect(finding).toBeDefined();
      expect(finding?.risk).toBe("MEDIUM");
    });
  });

  describe("Replication Divergence Guard (CRR / SRR)", () => {
    it("detects active replication and requires acknowledgment (HIGH risk)", async () => {
      stubSafeDefaults();
      s3Mock.on(GetBucketReplicationCommand).resolves({
        ReplicationConfiguration: {
          Rules: [
            {
              ID: "crr-rule-1",
              Status: "Enabled",
              Destination: { Bucket: "arn:aws:s3:::replica-bucket" },
              DeleteMarkerReplication: { Status: "Disabled" },
            },
          ],
        },
      });

      const client = new S3Client({});
      const assessment = await assessBucketBlastRadius(client, "replicated-bucket", {
        acknowledgeReplicationDivergence: false,
      });

      expect(assessment.riskLevel).toBe("HIGH");
      expect(assessment.requiresReplicationAck).toBe(true);
      expect(assessment.replication?.enabled).toBe(true);
      expect(assessment.replication?.ruleCount).toBe(1);

      const finding = assessment.findings.find((f) => f.code === "REPLICATION_DETECTED");
      expect(finding).toBeDefined();
      expect(finding?.risk).toBe("HIGH");
      expect(finding?.message).toContain("replica divergence");
    });

    it("accepts replication when acknowledgeReplicationDivergence is true", async () => {
      stubSafeDefaults();
      s3Mock.on(GetBucketReplicationCommand).resolves({
        ReplicationConfiguration: {
          Rules: [
            {
              ID: "crr-rule-1",
              Status: "Enabled",
              Destination: { Bucket: "arn:aws:s3:::replica-bucket" },
            },
          ],
        },
      });

      const client = new S3Client({});
      const assessment = await assessBucketBlastRadius(client, "replicated-bucket", {
        acknowledgeReplicationDivergence: true,
      });

      expect(assessment.riskLevel).toBe("MEDIUM");
      expect(assessment.requiresReplicationAck).toBe(false);

      const finding = assessment.findings.find((f) => f.code === "REPLICATION_ACKNOWLEDGED");
      expect(finding).toBeDefined();
      expect(finding?.risk).toBe("MEDIUM");
    });
  });

  describe("Protected Bucket Tags", () => {
    it("hard-blocks buckets tagged s3-guardian:ignore=true", async () => {
      stubSafeDefaults();
      s3Mock.on(GetBucketTaggingCommand).resolves({
        TagSet: [{ Key: "s3-guardian:ignore", Value: "true" }],
      });

      const client = new S3Client({});
      const assessment = await assessBucketBlastRadius(client, "ignored-bucket");

      expect(assessment.riskLevel).toBe("CRITICAL_BLOCKED");
      expect(assessment.isBlocked).toBe(true);
      const finding = assessment.findings.find((f) => f.code === "PROTECTED_TAG_DETECTED");
      expect(finding?.message).toContain("s3-guardian:ignore=true");
    });

    it("hard-blocks buckets tagged Backup=true", async () => {
      stubSafeDefaults();
      s3Mock.on(GetBucketTaggingCommand).resolves({
        TagSet: [{ Key: "Backup", Value: "true" }],
      });

      const client = new S3Client({});
      const assessment = await assessBucketBlastRadius(client, "backup-bucket");

      expect(assessment.riskLevel).toBe("CRITICAL_BLOCKED");
      expect(assessment.isBlocked).toBe(true);
      const finding = assessment.findings.find((f) => f.code === "PROTECTED_TAG_DETECTED");
      expect(finding?.message).toContain("Backup bucket");
    });

    it("hard-blocks buckets tagged Protection=locked", async () => {
      stubSafeDefaults();
      s3Mock.on(GetBucketTaggingCommand).resolves({
        TagSet: [{ Key: "Protection", Value: "locked" }],
      });

      const client = new S3Client({});
      const assessment = await assessBucketBlastRadius(client, "locked-bucket");

      expect(assessment.riskLevel).toBe("CRITICAL_BLOCKED");
      expect(assessment.isBlocked).toBe(true);
    });
  });

  describe("Streaming and Pipeline Protected Prefixes", () => {
    it.each(PROTECTED_PREFIXES)(
      "hard-blocks targets within protected prefix: %s",
      async (prefix) => {
        stubSafeDefaults();
        const client = new S3Client({});

        const assessment = await assessBucketBlastRadius(client, "pipeline-bucket", {
          targetKeys: [`${prefix}state-chunk-001.bin`],
        });

        expect(assessment.riskLevel).toBe("CRITICAL_BLOCKED");
        expect(assessment.isBlocked).toBe(true);
        const finding = assessment.findings.find((f) => f.code === "PROTECTED_PREFIX_DETECTED");
        expect(finding).toBeDefined();
      }
    );

    it("hard-blocks targets with nested protected prefixes (e.g. data/lake/_wal/)", async () => {
      stubSafeDefaults();
      const client = new S3Client({});

      const assessment = await assessBucketBlastRadius(client, "pipeline-bucket", {
        targetKeys: ["lakehouse/table/_wal/commit-0099.json"],
      });

      expect(assessment.riskLevel).toBe("CRITICAL_BLOCKED");
      expect(assessment.isBlocked).toBe(true);
    });
  });

  describe("Active Churn Guard (< 24 Hours)", () => {
    const now = new Date("2026-09-20T12:00:00.000Z");

    it("flags uploads modified less than 24 hours ago as HIGH risk", async () => {
      stubSafeDefaults();
      const client = new S3Client({});

      const twoHoursAgo = new Date(now.getTime() - 2 * 3600 * 1000).toISOString();
      const assessment = await assessBucketBlastRadius(client, "active-bucket", {
        now,
        targets: [{ key: "uploads/recent.bin", timestamp: twoHoursAgo }],
        allowActiveChurn: false,
      });

      expect(assessment.riskLevel).toBe("HIGH");
      const finding = assessment.findings.find((f) => f.code === "ACTIVE_CHURN_DETECTED");
      expect(finding).toBeDefined();
      expect(finding?.message).toContain("last 24 hours");
    });

    it("allows deletion of active churn items when allowActiveChurn is true", async () => {
      stubSafeDefaults();
      const client = new S3Client({});

      const twoHoursAgo = new Date(now.getTime() - 2 * 3600 * 1000).toISOString();
      const assessment = await assessBucketBlastRadius(client, "active-bucket", {
        now,
        targets: [{ key: "uploads/recent.bin", timestamp: twoHoursAgo }],
        allowActiveChurn: true,
      });

      expect(assessment.riskLevel).toBe("MEDIUM");
      const finding = assessment.findings.find((f) => f.code === "ACTIVE_CHURN_OVERRIDDEN");
      expect(finding).toBeDefined();
    });

    it("evaluates items older than 24 hours as safe", async () => {
      stubSafeDefaults();
      const client = new S3Client({});

      const threeDaysAgo = new Date(now.getTime() - 72 * 3600 * 1000).toISOString();
      const assessment = await assessBucketBlastRadius(client, "active-bucket", {
        now,
        targets: [{ key: "uploads/old.bin", timestamp: threeDaysAgo }],
        allowActiveChurn: false,
      });

      expect(assessment.riskLevel).toBe("LOW");
      expect(assessment.findings).toHaveLength(0);
    });
  });
});
