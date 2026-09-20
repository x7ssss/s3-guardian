import { describe, it, expect } from "vitest";
import { GuardianPolicy, validatePolicy } from "../src/policy/index.js";

describe("Declarative Policy Validator (Static AWS & FinOps Invariants)", () => {
  const basePolicy: GuardianPolicy = {
    schemaVersion: "1",
    policyId: "finops-lifecycle-policy",
    scope: {
      level: "ACCOUNT",
      accountId: "123456789012",
    },
    rules: [],
  };

  it("passes validation for valid policy rules", () => {
    const policy: GuardianPolicy = {
      ...basePolicy,
      defaults: {
        action: "AUTO_REMEDIATE",
        mpuAbortDays: 7,
      },
      rules: [
        {
          id: "clean-mpu",
          mpuAbortDays: 7,
          action: "AUTO_REMEDIATE",
          match: {},
        },
        {
          id: "tier-to-ia",
          match: {
            object: {
              prefix: "archive/",
              minSizeKb: 128,
            },
          },
          transitions: [
            {
              days: 30,
              storageClass: "STANDARD_IA",
            },
          ],
          expirationDays: 365,
        },
        {
          id: "tier-to-glacier-safe",
          match: {
            object: {
              minSizeKb: 256,
            },
          },
          transitions: [
            {
              days: 30,
              storageClass: "GLACIER",
            },
          ],
          expirationDays: 130, // 130 - 30 = 100 >= 90 days
        },
        {
          id: "tier-to-intelligent-tiering-exempt",
          match: {
            object: {
              prefix: "small-files/",
              // minSizeKb not required for Intelligent-Tiering
            },
          },
          transitions: [
            {
              days: 0,
              storageClass: "INTELLIGENT_TIERING",
            },
          ],
        },
      ],
    };

    const result = validatePolicy(policy);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  describe("MPU Churn Guard (Invariant 5: mpuAbortDays >= 7)", () => {
    it("rejects mpuAbortDays < 7 in rule", () => {
      const policy: GuardianPolicy = {
        ...basePolicy,
        rules: [
          {
            id: "aggressive-mpu-abort",
            mpuAbortDays: 3, // < 7
            match: {},
          },
        ],
      };

      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => /mpuAbortDays < 7/i.test(e))).toBe(true);
    });

    it("rejects mpuAbortDays < 7 in defaults", () => {
      const policy: GuardianPolicy = {
        ...basePolicy,
        defaults: {
          mpuAbortDays: 2,
        },
        rules: [],
      };

      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => /Defaults mpuAbortDays must be >= 7/i.test(e))).toBe(true);
    });
  });

  describe("Tag/MPU Contradiction Guard (AWS S3 Lifecycle limitation)", () => {
    it("rejects rule that combines mpuAbortDays with object tags", () => {
      const policy: GuardianPolicy = {
        ...basePolicy,
        rules: [
          {
            id: "mpu-with-tags",
            mpuAbortDays: 7,
            match: {
              object: {
                tags: {
                  Environment: "production",
                },
              },
            },
          },
        ],
      };

      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(
        result.errors.some((e) => /combines mpuAbortDays with object\.tags/i.test(e))
      ).toBe(true);
    });
  });

  describe("128 KiB Floor Guard (AWS Minimum Storage Size)", () => {
    it("rejects transitions to STANDARD_IA without minSizeKb >= 128", () => {
      const policy: GuardianPolicy = {
        ...basePolicy,
        rules: [
          {
            id: "ia-without-floor",
            match: {},
            transitions: [
              {
                days: 30,
                storageClass: "STANDARD_IA",
              },
            ],
          },
        ],
      };

      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => /violates the 128 KiB floor/i.test(e))).toBe(true);
    });

    it("rejects transitions to GLACIER_IR when minSizeKb < 128", () => {
      const policy: GuardianPolicy = {
        ...basePolicy,
        rules: [
          {
            id: "gir-small-size",
            match: {
              object: {
                minSizeKb: 64, // < 128
              },
            },
            transitions: [
              {
                days: 60,
                storageClass: "GLACIER_IR",
              },
            ],
          },
        ],
      };

      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => /violates the 128 KiB floor/i.test(e))).toBe(true);
    });

    it("permits INTELLIGENT_TIERING without minSizeKb", () => {
      const policy: GuardianPolicy = {
        ...basePolicy,
        rules: [
          {
            id: "intelligent-tiering-unconstrained",
            match: {},
            transitions: [
              {
                days: 0,
                storageClass: "INTELLIGENT_TIERING",
              },
            ],
          },
        ],
      };

      const result = validatePolicy(policy);
      expect(result.valid).toBe(true);
    });
  });

  describe("Early Deletion Penalty Guard (Glacier 90d, Deep Archive 180d)", () => {
    it("rejects Glacier transition where retention in tier is < 90 days", () => {
      const policy: GuardianPolicy = {
        ...basePolicy,
        rules: [
          {
            id: "glacier-early-delete",
            match: {
              object: { minSizeKb: 128 },
            },
            transitions: [
              {
                days: 30,
                storageClass: "GLACIER",
              },
            ],
            expirationDays: 90, // 90 - 30 = 60 days in tier (< 90d)
          },
        ],
      };

      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(
        result.errors.some((e) => /charges 90 days minimum retention for GLACIER/i.test(e))
      ).toBe(true);
    });

    it("rejects Deep Archive transition where retention in tier is < 180 days", () => {
      const policy: GuardianPolicy = {
        ...basePolicy,
        rules: [
          {
            id: "deep-archive-early-delete",
            match: {
              object: { minSizeKb: 128 },
            },
            transitions: [
              {
                days: 60,
                storageClass: "DEEP_ARCHIVE",
              },
            ],
            expirationDays: 200, // 200 - 60 = 140 days in tier (< 180d)
          },
        ],
      };

      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(
        result.errors.some((e) => /charges 180 days minimum retention for DEEP_ARCHIVE/i.test(e))
      ).toBe(true);
    });
  });

  describe("AWS S3 Limits and Constraints", () => {
    it("rejects rule ID exceeding 255 characters", () => {
      const policy: GuardianPolicy = {
        ...basePolicy,
        rules: [
          {
            id: "a".repeat(256),
            match: {},
          },
        ],
      };

      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => /exceeds maximum length of 255/i.test(e))).toBe(true);
    });

    it("rejects duplicate rule IDs", () => {
      const policy: GuardianPolicy = {
        ...basePolicy,
        rules: [
          { id: "rule-dup", match: {} },
          { id: "rule-dup", match: {} },
        ],
      };

      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => /Duplicate rule ID 'rule-dup'/i.test(e))).toBe(true);
    });

    it("rejects retainVersions outside 1-100", () => {
      const policy: GuardianPolicy = {
        ...basePolicy,
        rules: [
          {
            id: "invalid-retain",
            match: {},
            retainVersions: 150,
          },
        ],
      };

      const result = validatePolicy(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => /outside the allowed 1-100 range/i.test(e))).toBe(true);
    });
  });
});
