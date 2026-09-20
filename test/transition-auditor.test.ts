import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  S3Client,
  GetBucketLifecycleConfigurationCommand,
  ListObjectsV2Command,
} from "@aws-sdk/client-s3";
import {
  auditBucketTransitions,
  extractRuleMinSizeFilter,
  isIaOrGlacierClass,
  RECOMMENDED_MIN_TRANSITION_SIZE_BYTES,
} from "../src/transitions/auditor.js";

const s3Mock = mockClient(S3Client);

describe("Lifecycle Transition Auditor", () => {
  const client = new S3Client({ region: "us-east-1" });

  beforeEach(() => {
    s3Mock.reset();
  });

  describe("extractRuleMinSizeFilter() and isIaOrGlacierClass()", () => {
    it("identifies IA and Glacier storage classes correctly", () => {
      expect(isIaOrGlacierClass("GLACIER")).toBe(true);
      expect(isIaOrGlacierClass("STANDARD_IA")).toBe(true);
      expect(isIaOrGlacierClass("ONEZONE_IA")).toBe(true);
      expect(isIaOrGlacierClass("GLACIER_IR")).toBe(true);
      expect(isIaOrGlacierClass("DEEP_ARCHIVE")).toBe(true);
      expect(isIaOrGlacierClass("standard-ia")).toBe(true);
      expect(isIaOrGlacierClass("gir")).toBe(true);
      expect(isIaOrGlacierClass("STANDARD")).toBe(false);
      expect(isIaOrGlacierClass("INTELLIGENT_TIERING")).toBe(false);
    });

    it("extracts direct and AND-composed ObjectSizeGreaterThan filters", () => {
      expect(extractRuleMinSizeFilter({})).toBeUndefined();
      expect(extractRuleMinSizeFilter({ Filter: {} })).toBeUndefined();

      expect(
        extractRuleMinSizeFilter({
          Filter: { ObjectSizeGreaterThan: 131072 },
        })
      ).toBe(131072);

      expect(
        extractRuleMinSizeFilter({
          Filter: {
            And: {
              Prefix: "archive/",
              ObjectSizeGreaterThan: 262144,
            },
          },
        })
      ).toBe(262144);
    });
  });

  describe("auditBucketTransitions()", () => {
    it("handles NoSuchLifecycleConfiguration gracefully without throwing", () => {
      const error = new Error("The lifecycle configuration does not exist");
      error.name = "NoSuchLifecycleConfiguration";
      s3Mock.on(GetBucketLifecycleConfigurationCommand).rejects(error);

      return expect(
        auditBucketTransitions(client, "bucket-no-lifecycle")
      ).resolves.toEqual({
        bucketName: "bucket-no-lifecycle",
        hasLifecyclePolicy: false,
        dangerousRules: [],
        totalEstimatedPenaltyUSD: 0,
        sampledObjectsCount: 0,
        smallObjectsCount: 0,
        averageSmallObjectSizeBytes: 0,
      });
    });

    it("detects unconstrained transition rules lacking ObjectSizeGreaterThan filter", async () => {
      s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
        Rules: [
          {
            ID: "unconstrained-glacier-rule",
            Status: "Enabled",
            Filter: { Prefix: "data/" },
            Transitions: [
              {
                Days: 30,
                StorageClass: "GLACIER",
              },
            ],
          },
        ],
      });

      s3Mock.on(ListObjectsV2Command).resolves({
        Contents: [],
      });

      const result = await auditBucketTransitions(client, "my-target-bucket");

      expect(result.hasLifecyclePolicy).toBe(true);
      expect(result.dangerousRules).toHaveLength(1);

      const rule = result.dangerousRules[0];
      expect(rule.ruleId).toBe("unconstrained-glacier-rule");
      expect(rule.targetStorageClass).toBe("GLACIER");
      expect(rule.days).toBe(30);
      expect(rule.currentFilterMinSize).toBeUndefined();
      expect(rule.recommendedMinSize).toBe(RECOMMENDED_MIN_TRANSITION_SIZE_BYTES); // 131072
      expect(rule.estimatedPenaltyUSD).toBe(0); // 0 small objects sampled
    });

    it("detects transition rules with explicit ObjectSizeGreaterThan < 128 KiB filter", async () => {
      s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
        Rules: [
          {
            ID: "small-filter-rule",
            Status: "Enabled",
            Filter: {
              ObjectSizeGreaterThan: 65536, // 64 KiB (< 128 KiB)
            },
            Transitions: [
              {
                Days: 60,
                StorageClass: "STANDARD_IA",
              },
            ],
          },
        ],
      });

      s3Mock.on(ListObjectsV2Command).resolves({
        Contents: [],
      });

      const result = await auditBucketTransitions(client, "my-target-bucket");

      expect(result.dangerousRules).toHaveLength(1);
      const rule = result.dangerousRules[0];
      expect(rule.ruleId).toBe("small-filter-rule");
      expect(rule.targetStorageClass).toBe("STANDARD_IA");
      expect(rule.currentFilterMinSize).toBe(65536);
      expect(rule.recommendedMinSize).toBe(131072);
    });

    it("recognizes safe transition rules with ObjectSizeGreaterThan >= 131072 (128 KiB)", async () => {
      s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
        Rules: [
          {
            ID: "safe-glacier-rule",
            Status: "Enabled",
            Filter: {
              ObjectSizeGreaterThan: 131072, // Exactly 128 KiB
            },
            Transitions: [
              {
                Days: 90,
                StorageClass: "GLACIER",
              },
            ],
          },
          {
            ID: "safe-and-rule",
            Status: "Enabled",
            Filter: {
              And: {
                Prefix: "logs/",
                ObjectSizeGreaterThan: 262144, // 256 KiB
              },
            },
            Transitions: [
              {
                Days: 30,
                StorageClass: "DEEP_ARCHIVE",
              },
            ],
          },
        ],
      });

      s3Mock.on(ListObjectsV2Command).resolves({
        Contents: [],
      });

      const result = await auditBucketTransitions(client, "safe-bucket");
      expect(result.hasLifecyclePolicy).toBe(true);
      expect(result.dangerousRules).toHaveLength(0);
      expect(result.totalEstimatedPenaltyUSD).toBe(0);
    });

    it("audits NoncurrentVersionTransitions and flags unconstrained rules", async () => {
      s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
        Rules: [
          {
            ID: "archive-old-versions",
            Status: "Enabled",
            Filter: {},
            NoncurrentVersionTransitions: [
              {
                NoncurrentDays: 30,
                StorageClass: "GLACIER_IR",
              },
            ],
          },
        ],
      });

      s3Mock.on(ListObjectsV2Command).resolves({
        Contents: [],
      });

      const result = await auditBucketTransitions(client, "versioned-bucket");
      expect(result.dangerousRules).toHaveLength(1);
      expect(result.dangerousRules[0].ruleId).toBe("archive-old-versions");
      expect(result.dangerousRules[0].targetStorageClass).toBe("GLACIER_IR");
      expect(result.dangerousRules[0].transitionType).toBe("Noncurrent");
      expect(result.dangerousRules[0].days).toBe(30);
    });

    it("samples small objects and computes projected monthly financial penalty", async () => {
      s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
        Rules: [
          {
            ID: "trap-rule",
            Status: "Enabled",
            Filter: {},
            Transitions: [
              {
                Days: 30,
                StorageClass: "STANDARD_IA",
              },
            ],
          },
        ],
      });

      // Mock ListObjectsV2 returning 1,000 small objects (each 1024 bytes)
      const mockContents = Array.from({ length: 1000 }, (_, i) => ({
        Key: `small-obj-${i}.json`,
        Size: 1024,
      }));

      s3Mock.on(ListObjectsV2Command).resolves({
        Contents: mockContents,
      });

      const result = await auditBucketTransitions(client, "trap-bucket");

      expect(result.sampledObjectsCount).toBe(1000);
      expect(result.smallObjectsCount).toBe(1000);
      expect(result.averageSmallObjectSizeBytes).toBe(1024);
      expect(result.dangerousRules).toHaveLength(1);

      const rule = result.dangerousRules[0];
      expect(rule.estimatedPenaltyUSD).toBeGreaterThan(0);
      expect(result.totalEstimatedPenaltyUSD).toBe(rule.estimatedPenaltyUSD);
    });

    it("supports manual density overrides via options for deterministic testing", async () => {
      s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
        Rules: [
          {
            ID: "trap-rule",
            Status: "Enabled",
            Filter: {},
            Transitions: [
              {
                Days: 30,
                StorageClass: "GLACIER",
              },
            ],
          },
        ],
      });

      const result = await auditBucketTransitions(client, "override-bucket", {
        overrideSmallObjectCount: 10000,
        overrideAverageSmallSizeBytes: 2048,
      });

      expect(result.smallObjectsCount).toBe(10000);
      expect(result.averageSmallObjectSizeBytes).toBe(2048);
      expect(result.dangerousRules[0].estimatedPenaltyUSD).toBeGreaterThan(0);
      expect(result.totalEstimatedPenaltyUSD).toBeGreaterThan(0);
    });
  });
});
