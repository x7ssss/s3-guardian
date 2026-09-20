import { describe, it, expect } from "vitest";
import {
  GuardianPolicy,
  BucketMetadata,
  resolveBucketPolicy,
} from "../src/policy/index.js";

describe("Declarative Policy Resolver (Precedence, Fail-Safe Mode & Leaf Merging)", () => {
  const sampleBucket: BucketMetadata = {
    name: "prod-analytics-data-use1",
    region: "us-east-1",
    accountId: "111122223333",
    ouId: "ou-data-platform",
    tags: {
      Environment: "Production",
      DataClassification: "Confidential",
    },
  };

  it("enforces Precedence Hierarchy: BUCKET_TAG (30) overrides OU (20) and GLOBAL (10)", () => {
    const globalPolicy: GuardianPolicy = {
      schemaVersion: "1",
      policyId: "global-policy",
      scope: { level: "GLOBAL" },
      rules: [
        {
          id: "global-rule",
          match: {},
          expirationDays: 365,
          mpuAbortDays: 14,
        },
      ],
    };

    const ouPolicy: GuardianPolicy = {
      schemaVersion: "1",
      policyId: "ou-policy",
      scope: { level: "OU", ouId: "ou-data-platform" },
      rules: [
        {
          id: "ou-rule",
          match: {},
          expirationDays: 180,
        },
      ],
    };

    const bucketTagPolicy: GuardianPolicy = {
      schemaVersion: "1",
      policyId: "bucket-tag-policy",
      scope: { level: "BUCKET_TAG" },
      rules: [
        {
          id: "bucket-tag-rule",
          match: {
            bucket: {
              tags: { Environment: "Production" },
            },
          },
          expirationDays: 90,
        },
      ],
    };

    const resolved = resolveBucketPolicy(sampleBucket, [
      globalPolicy,
      ouPolicy,
      bucketTagPolicy,
    ]);

    // ExpirationDays should be overridden by BUCKET_TAG (90 days)
    expect(resolved.effectiveRules).toHaveLength(1);
    const rule = resolved.effectiveRules[0]!;
    expect(rule.expirationDays).toBe(90);

    // MpuAbortDays should fall through from GLOBAL (14 days)
    expect(rule.mpuAbortDays).toBe(14);

    // Provenance must track the exact source of each leaf property
    expect(rule.provenance?.["expirationDays"]).toEqual({
      policyId: "bucket-tag-policy",
      ruleId: "bucket-tag-rule",
      level: "BUCKET_TAG",
    });
    expect(rule.provenance?.["mpuAbortDays"]).toEqual({
      policyId: "global-policy",
      ruleId: "global-rule",
      level: "GLOBAL",
    });
  });

  it("enforces Fail-Safe Action Mode: lowest rank / most restrictive wins", () => {
    // MONITOR_ONLY (1) < PLAN_ONLY (2) < AUTO_REMEDIATE (3)
    const aggressivePolicy: GuardianPolicy = {
      schemaVersion: "1",
      policyId: "aggressive-policy",
      scope: { level: "GLOBAL" },
      rules: [
        {
          id: "rule-auto",
          action: "AUTO_REMEDIATE",
          match: {},
          mpuAbortDays: 7,
        },
      ],
    };

    const defensivePolicy: GuardianPolicy = {
      schemaVersion: "1",
      policyId: "defensive-policy",
      scope: { level: "ACCOUNT", accountId: "111122223333" },
      defaults: {
        action: "MONITOR_ONLY",
      },
      rules: [
        {
          id: "rule-plan",
          action: "PLAN_ONLY",
          match: {},
        },
      ],
    };

    const resolved = resolveBucketPolicy(sampleBucket, [
      aggressivePolicy,
      defensivePolicy,
    ]);

    // MONITOR_ONLY is most restrictive (rank 1), so it must win over AUTO_REMEDIATE and PLAN_ONLY
    expect(resolved.action).toBe("MONITOR_ONLY");
  });

  it("resolves priority tie-breaks when policies have the same level", () => {
    const policyA: GuardianPolicy = {
      schemaVersion: "1",
      policyId: "policy-low-prio",
      scope: { level: "ACCOUNT", priority: 10 },
      rules: [
        {
          id: "rule-a",
          match: {},
          expirationDays: 100,
        },
      ],
    };

    const policyB: GuardianPolicy = {
      schemaVersion: "1",
      policyId: "policy-high-prio",
      scope: { level: "ACCOUNT", priority: 50 },
      rules: [
        {
          id: "rule-b",
          match: {},
          expirationDays: 50,
        },
      ],
    };

    const resolved = resolveBucketPolicy(sampleBucket, [policyA, policyB]);
    expect(resolved.effectiveRules[0]?.expirationDays).toBe(50);
    expect(resolved.effectiveRules[0]?.provenance?.["expirationDays"]?.policyId).toBe(
      "policy-high-prio"
    );
  });

  it("filters out policies and rules that do not match bucket metadata", () => {
    const nonMatchingPolicy: GuardianPolicy = {
      schemaVersion: "1",
      policyId: "other-account-policy",
      scope: { level: "ACCOUNT", accountId: "999999999999" }, // different account
      rules: [
        {
          id: "rule-other",
          match: {},
          expirationDays: 30,
        },
      ],
    };

    const regexNonMatchingPolicy: GuardianPolicy = {
      schemaVersion: "1",
      policyId: "regex-policy",
      scope: { level: "GLOBAL" },
      rules: [
        {
          id: "dev-only-rule",
          match: {
            bucket: {
              nameRegex: "^dev-.*", // bucket is "prod-analytics-data-use1"
            },
          },
          expirationDays: 7,
        },
      ],
    };

    const resolved = resolveBucketPolicy(sampleBucket, [
      nonMatchingPolicy,
      regexNonMatchingPolicy,
    ]);

    expect(resolved.effectiveRules).toHaveLength(0);
  });

  it("falls back to policy defaults when rule properties are not specified", () => {
    const policy: GuardianPolicy = {
      schemaVersion: "1",
      policyId: "defaults-policy",
      scope: { level: "GLOBAL" },
      defaults: {
        mpuAbortDays: 7,
        maxNoncurrentDays: 30,
        retainVersions: 3,
      },
      rules: [
        {
          id: "custom-rule",
          match: {},
          expirationDays: 60,
        },
      ],
    };

    const resolved = resolveBucketPolicy(sampleBucket, [policy]);
    expect(resolved.effectiveRules).toHaveLength(1);
    const rule = resolved.effectiveRules[0]!;
    expect(rule.expirationDays).toBe(60);
    expect(rule.mpuAbortDays).toBe(7);
    expect(rule.noncurrentExpirationDays).toBe(30);
    expect(rule.retainVersions).toBe(3);
    expect(rule.provenance?.["mpuAbortDays"]?.ruleId).toBe("defaults");
  });
});
