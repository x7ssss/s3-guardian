import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  S3Client,
  GetBucketLifecycleConfigurationCommand,
  PutBucketLifecycleConfigurationCommand,
} from "@aws-sdk/client-s3";
import {
  applyLifecycleRuleDirectly,
  TARGET_RULE_ID,
} from "../src/remediation/api.js";

const s3Mock = mockClient(S3Client);

describe("Direct API Remediation (applyLifecycleRuleDirectly)", () => {
  beforeEach(() => {
    s3Mock.reset();
  });

  it("throws safety error if --danger-direct-api-apply is not provided", async () => {
    const client = new S3Client({});

    // Without options
    await expect(
      applyLifecycleRuleDirectly(client, "my-bucket", 7)
    ).rejects.toThrow(/Safety check failed.*--danger-direct-api-apply/);

    // With explicit dangerDirectApiApply: false
    await expect(
      applyLifecycleRuleDirectly(client, "my-bucket", 7, {
        dangerDirectApiApply: false,
      })
    ).rejects.toThrow(/Safety check failed.*--danger-direct-api-apply/);

    // No S3 commands should have been sent
    expect(s3Mock.calls().length).toBe(0);
  });

  it("handles 404 NoSuchLifecycleConfiguration gracefully and creates initial policy", async () => {
    const client = new S3Client({});
    const notFoundErr = new Error("NoSuchLifecycleConfiguration");
    notFoundErr.name = "NoSuchLifecycleConfiguration";
    (notFoundErr as any).$metadata = { httpStatusCode: 404 };

    s3Mock
      .on(GetBucketLifecycleConfigurationCommand, { Bucket: "brand-new-bucket" })
      .rejectsOnce(notFoundErr);

    s3Mock
      .on(PutBucketLifecycleConfigurationCommand, { Bucket: "brand-new-bucket" })
      .resolvesOnce({});

    const result = await applyLifecycleRuleDirectly(client, "brand-new-bucket", 7, {
      dangerDirectApiApply: true,
    });

    expect(result.action).toBe("CREATED");
    expect(result.totalRules).toBe(1);
    expect(result.preservedRuleIds).toHaveLength(0);
    expect(result.appliedRule.ID).toBe(TARGET_RULE_ID);
    expect(result.appliedRule.AbortIncompleteMultipartUpload?.DaysAfterInitiation).toBe(7);

    // Verify PutBucketLifecycleConfigurationCommand input
    const putCalls = s3Mock.commandCalls(PutBucketLifecycleConfigurationCommand);
    expect(putCalls.length).toBe(1);
    const rules = putCalls[0].args[0].input.LifecycleConfiguration?.Rules;
    expect(rules).toHaveLength(1);
    expect(rules?.[0].ID).toBe(TARGET_RULE_ID);
    expect(rules?.[0].Status).toBe("Enabled");
    expect(rules?.[0].AbortIncompleteMultipartUpload?.DaysAfterInitiation).toBe(7);
  });

  it("preserves 100% of existing lifecycle rules (transitions, expirations) during merge", async () => {
    const client = new S3Client({});

    const existingRules = [
      {
        ID: "glacier-archive-rule",
        Status: "Enabled",
        Filter: { Prefix: "archive/" },
        Transitions: [
          {
            Days: 30,
            StorageClass: "GLACIER",
          },
        ],
      },
      {
        ID: "delete-old-logs",
        Status: "Enabled",
        Filter: { Prefix: "logs/" },
        Expiration: {
          Days: 90,
        },
        NoncurrentVersionExpiration: {
          NoncurrentDays: 365,
        },
      },
    ];

    s3Mock
      .on(GetBucketLifecycleConfigurationCommand, { Bucket: "existing-policy-bucket" })
      .resolvesOnce({
        Rules: existingRules,
      });

    s3Mock
      .on(PutBucketLifecycleConfigurationCommand, { Bucket: "existing-policy-bucket" })
      .resolvesOnce({});

    const result = await applyLifecycleRuleDirectly(
      client,
      "existing-policy-bucket",
      14,
      { dangerDirectApiApply: true }
    );

    expect(result.action).toBe("CREATED");
    expect(result.totalRules).toBe(3);
    expect(result.preservedRuleIds).toEqual(["glacier-archive-rule", "delete-old-logs"]);

    // Verify the merged payload contains all original rules plus the new MPU rule
    const putCalls = s3Mock.commandCalls(PutBucketLifecycleConfigurationCommand);
    expect(putCalls.length).toBe(1);
    const rules = putCalls[0].args[0].input.LifecycleConfiguration?.Rules;
    expect(rules).toHaveLength(3);

    // Rule 1: glacier transition preserved exactly
    expect(rules?.[0].ID).toBe("glacier-archive-rule");
    expect(rules?.[0].Transitions?.[0].StorageClass).toBe("GLACIER");

    // Rule 2: log expiration preserved exactly
    expect(rules?.[1].ID).toBe("delete-old-logs");
    expect(rules?.[1].Expiration?.Days).toBe(90);
    expect(rules?.[1].NoncurrentVersionExpiration?.NoncurrentDays).toBe(365);

    // Rule 3: s3-guardian-abort-mpu appended
    expect(rules?.[2].ID).toBe(TARGET_RULE_ID);
    expect(rules?.[2].AbortIncompleteMultipartUpload?.DaysAfterInitiation).toBe(14);
  });

  it("updates existing 's3-guardian-abort-mpu' rule without duplicating", async () => {
    const client = new S3Client({});

    const existingRules = [
      {
        ID: "other-rule",
        Status: "Enabled",
        Filter: {},
        Expiration: { Days: 30 },
      },
      {
        ID: TARGET_RULE_ID,
        Status: "Enabled",
        Filter: {},
        AbortIncompleteMultipartUpload: { DaysAfterInitiation: 10 },
      },
    ];

    s3Mock
      .on(GetBucketLifecycleConfigurationCommand, { Bucket: "update-bucket" })
      .resolvesOnce({ Rules: existingRules });

    s3Mock
      .on(PutBucketLifecycleConfigurationCommand, { Bucket: "update-bucket" })
      .resolvesOnce({});

    const result = await applyLifecycleRuleDirectly(client, "update-bucket", 5, {
      dangerDirectApiApply: true,
    });

    expect(result.action).toBe("UPDATED");
    expect(result.totalRules).toBe(2);
    expect(result.preservedRuleIds).toEqual(["other-rule"]);

    const putCalls = s3Mock.commandCalls(PutBucketLifecycleConfigurationCommand);
    const rules = putCalls[0].args[0].input.LifecycleConfiguration?.Rules;
    expect(rules).toHaveLength(2);
    expect(rules?.[1].ID).toBe(TARGET_RULE_ID);
    expect(rules?.[1].AbortIncompleteMultipartUpload?.DaysAfterInitiation).toBe(5);
  });

  it("flags existing ghost rule warning when detected", async () => {
    const client = new S3Client({});

    const existingRules = [
      {
        ID: "broken-tag-rule",
        Status: "Enabled",
        Filter: { Tag: { Key: "Environment", Value: "Dev" } },
        AbortIncompleteMultipartUpload: { DaysAfterInitiation: 7 },
      },
    ];

    s3Mock
      .on(GetBucketLifecycleConfigurationCommand, { Bucket: "ghost-bucket" })
      .resolvesOnce({ Rules: existingRules });

    s3Mock
      .on(PutBucketLifecycleConfigurationCommand, { Bucket: "ghost-bucket" })
      .resolvesOnce({});

    const result = await applyLifecycleRuleDirectly(client, "ghost-bucket", 7, {
      dangerDirectApiApply: true,
    });

    expect(result.ghostRuleWarning).toBeDefined();
    expect(result.ghostRuleWarning).toContain("broken-tag-rule");
    expect(result.ghostRuleWarning).toContain("Tag filter");
  });
});
