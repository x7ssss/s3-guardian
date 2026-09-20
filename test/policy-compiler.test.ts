import { describe, it, expect } from "vitest";
import {
  ResolvedPolicy,
  compileToLifecycleConfiguration,
} from "../src/policy/index.js";

describe("Declarative Policy Compiler (AWS S3 Lifecycle Synthesis)", () => {
  it("separates MPU abort rules when object tags are present", () => {
    const resolved: ResolvedPolicy = {
      bucketName: "my-app-bucket",
      action: "AUTO_REMEDIATE",
      effectiveRules: [
        {
          id: "hybrid-rule-with-tags-and-mpu",
          action: "AUTO_REMEDIATE",
          match: {
            object: {
              prefix: "uploads/",
              tags: { Status: "pending", Tier: "hot" },
              minSizeKb: 128,
            },
          },
          mpuAbortDays: 7,
          transitions: [
            {
              days: 30,
              storageClass: "STANDARD_IA",
            },
          ],
          expirationDays: 90,
        },
      ],
      provenance: {},
    };

    const compiled = compileToLifecycleConfiguration("my-app-bucket", resolved);
    expect(compiled.Bucket).toBe("my-app-bucket");
    expect(compiled.LifecycleConfiguration?.Rules).toHaveLength(2);

    // Rule 1: Standalone MPU rule (NO tags)
    const mpuRule = compiled.LifecycleConfiguration?.Rules?.[0]!;
    expect(mpuRule.ID).toBe("hybrid-rule-with-tags-and-mpu-abort-mpu");
    expect(mpuRule.Status).toBe("Enabled");
    expect(mpuRule.AbortIncompleteMultipartUpload?.DaysAfterInitiation).toBe(7);
    expect(mpuRule.Filter).toEqual({ Prefix: "uploads/" }); // Prefix only, NO tags

    // Rule 2: Object lifecycle rule (with tags and transitions)
    const objectRule = compiled.LifecycleConfiguration?.Rules?.[1]!;
    expect(objectRule.ID).toBe("hybrid-rule-with-tags-and-mpu");
    expect(objectRule.Status).toBe("Enabled");
    expect(objectRule.AbortIncompleteMultipartUpload).toBeUndefined();
    expect(objectRule.Filter?.And).toBeDefined();
    expect(objectRule.Filter?.And?.Prefix).toBe("uploads/");
    expect(objectRule.Filter?.And?.Tags).toEqual([
      { Key: "Status", Value: "pending" },
      { Key: "Tier", Value: "hot" },
    ]);
    expect(objectRule.Transitions?.[0]?.StorageClass).toBe("STANDARD_IA");
    expect(objectRule.Expiration?.Days).toBe(90);
  });

  it("compiles consolidated rule when no object tags are present", () => {
    const resolved: ResolvedPolicy = {
      bucketName: "simple-bucket",
      action: "AUTO_REMEDIATE",
      effectiveRules: [
        {
          id: "consolidated-rule",
          action: "AUTO_REMEDIATE",
          match: {
            object: {
              prefix: "data/",
            },
          },
          mpuAbortDays: 7,
          expirationDays: 30,
        },
      ],
      provenance: {},
    };

    const compiled = compileToLifecycleConfiguration("simple-bucket", resolved);
    expect(compiled.LifecycleConfiguration?.Rules).toHaveLength(1);
    const rule = compiled.LifecycleConfiguration?.Rules?.[0]!;
    expect(rule.ID).toBe("consolidated-rule");
    expect(rule.Status).toBe("Enabled");
    expect(rule.AbortIncompleteMultipartUpload?.DaysAfterInitiation).toBe(7);
    expect(rule.Expiration?.Days).toBe(30);
    expect(rule.Filter).toEqual({ Prefix: "data/" });
  });

  it("enforces 128 KiB floor: injects ObjectSizeGreaterThan >= 131072 bytes", () => {
    const resolved: ResolvedPolicy = {
      bucketName: "ia-bucket",
      action: "AUTO_REMEDIATE",
      effectiveRules: [
        {
          id: "ia-transition-rule",
          action: "AUTO_REMEDIATE",
          match: {
            object: {
              prefix: "backups/",
            },
          },
          transitions: [
            {
              days: 30,
              storageClass: "STANDARD_IA",
            },
          ],
        },
      ],
      provenance: {},
    };

    const compiled = compileToLifecycleConfiguration("ia-bucket", resolved);
    const rule = compiled.LifecycleConfiguration?.Rules?.[0]!;
    expect(rule.Filter?.And?.ObjectSizeGreaterThan).toBe(131072);
  });

  it("converts minSizeKb to exact bytes in ObjectSizeGreaterThan", () => {
    const resolved: ResolvedPolicy = {
      bucketName: "custom-size-bucket",
      action: "AUTO_REMEDIATE",
      effectiveRules: [
        {
          id: "custom-size-rule",
          action: "AUTO_REMEDIATE",
          match: {
            object: {
              prefix: "large-files/",
              minSizeKb: 512, // 512 KiB = 524288 bytes
            },
          },
          transitions: [
            {
              days: 60,
              storageClass: "GLACIER",
            },
          ],
        },
      ],
      provenance: {},
    };

    const compiled = compileToLifecycleConfiguration("custom-size-bucket", resolved);
    const rule = compiled.LifecycleConfiguration?.Rules?.[0]!;
    expect(rule.Filter?.And?.ObjectSizeGreaterThan).toBe(512 * 1024);
  });

  it("compiles NoncurrentVersionExpiration with NewerNoncurrentVersions", () => {
    const resolved: ResolvedPolicy = {
      bucketName: "versioned-bucket",
      action: "AUTO_REMEDIATE",
      effectiveRules: [
        {
          id: "version-retention-rule",
          action: "AUTO_REMEDIATE",
          match: {},
          noncurrentExpirationDays: 30,
          retainVersions: 5,
        },
      ],
      provenance: {},
    };

    const compiled = compileToLifecycleConfiguration("versioned-bucket", resolved);
    const rule = compiled.LifecycleConfiguration?.Rules?.[0]!;
    expect(rule.NoncurrentVersionExpiration).toEqual({
      NoncurrentDays: 30,
      NewerNoncurrentVersions: 5,
    });
  });
});
