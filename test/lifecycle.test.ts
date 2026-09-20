import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  S3Client,
  GetBucketLifecycleConfigurationCommand,
} from "@aws-sdk/client-s3";
import {
  auditBucketLifecycle,
  parseMpuRule,
  evaluateUploadCoverage,
  detectProvider,
  ParsedMpuRule,
} from "../src/lifecycle/audit.js";

const s3Mock = mockClient(S3Client);

describe("Lifecycle Audit", () => {
  beforeEach(() => {
    s3Mock.reset();
  });

  // ── detectProvider ──────────────────────────────────────────────────────────

  describe("detectProvider()", () => {
    it("returns 'aws' when endpoint is null or undefined", () => {
      expect(detectProvider(null)).toBe("aws");
      expect(detectProvider(undefined)).toBe("aws");
      expect(detectProvider("")).toBe("aws");
    });

    it("returns 'minio' for localhost endpoints", () => {
      expect(detectProvider("http://localhost:9000")).toBe("minio");
      expect(detectProvider("http://127.0.0.1:9000")).toBe("minio");
      expect(detectProvider("http://minio.internal:9000")).toBe("minio");
    });

    it("returns 'r2' for Cloudflare R2 endpoints", () => {
      expect(detectProvider("https://acct.r2.cloudflarestorage.com")).toBe("r2");
      expect(detectProvider("https://acct.r2.dev")).toBe("r2");
    });

    it("returns 'aws' for standard AWS endpoints", () => {
      expect(detectProvider("https://s3.amazonaws.com")).toBe("aws");
      expect(detectProvider("https://s3.us-east-1.amazonaws.com")).toBe("aws");
    });
  });

  // ── NoSuchLifecycleConfiguration (404) handling ─────────────────────────────

  describe("auditBucketLifecycle() - 404 / NoSuchLifecycleConfiguration", () => {
    it("returns empty ruleset when NoSuchLifecycleConfiguration error is thrown", async () => {
      const client = new S3Client({});
      const err = new Error("NoSuchLifecycleConfiguration");
      err.name = "NoSuchLifecycleConfiguration";
      (err as any).$metadata = { httpStatusCode: 404 };

      s3Mock.on(GetBucketLifecycleConfigurationCommand).rejectsOnce(err);

      const result = await auditBucketLifecycle(client, "empty-bucket");

      expect(result.bucketHasLifecyclePolicy).toBe(false);
      expect(result.hasCoveringRule).toBe(false);
      expect(result.mpuRules).toHaveLength(0);
      expect(result.ghostRulesDetected).toHaveLength(0);
      expect(result.providerNotes).toBeUndefined();
    });

    it("returns empty ruleset when HTTP 404 is thrown (generic)", async () => {
      const client = new S3Client({});
      const err = new Error("Not Found");
      err.name = "NotFound";
      (err as any).$metadata = { httpStatusCode: 404 };

      s3Mock.on(GetBucketLifecycleConfigurationCommand).rejectsOnce(err);

      const result = await auditBucketLifecycle(client, "empty-bucket");

      expect(result.bucketHasLifecyclePolicy).toBe(false);
      expect(result.hasCoveringRule).toBe(false);
    });

    it("re-throws non-404 errors", async () => {
      const client = new S3Client({});
      const err = new Error("Access Denied");
      err.name = "AccessDenied";
      (err as any).$metadata = { httpStatusCode: 403 };

      s3Mock.on(GetBucketLifecycleConfigurationCommand).rejectsOnce(err);

      await expect(auditBucketLifecycle(client, "restricted-bucket")).rejects.toThrow("Access Denied");
    });
  });

  // ── Provider short-circuits ─────────────────────────────────────────────────

  describe("auditBucketLifecycle() - provider short-circuits", () => {
    it("returns minio note without making S3 API call", async () => {
      const client = new S3Client({});
      const result = await auditBucketLifecycle(client, "bucket", "http://localhost:9000");

      expect(result.bucketHasLifecyclePolicy).toBe(false);
      expect(result.hasCoveringRule).toBe(false);
      expect(result.providerNotes).toMatch(/MinIO detected/);
      // No API call was made
      expect(s3Mock.commandCalls(GetBucketLifecycleConfigurationCommand).length).toBe(0);
    });

    it("returns R2 note with hasCoveringRule=true without making S3 API call", async () => {
      const client = new S3Client({});
      const result = await auditBucketLifecycle(
        client,
        "bucket",
        "https://acct.r2.cloudflarestorage.com"
      );

      expect(result.bucketHasLifecyclePolicy).toBe(true);
      expect(result.hasCoveringRule).toBe(true);
      expect(result.providerNotes).toMatch(/Cloudflare R2/);
      expect(s3Mock.commandCalls(GetBucketLifecycleConfigurationCommand).length).toBe(0);
    });
  });

  // ── parseMpuRule ─────────────────────────────────────────────────────────────

  describe("parseMpuRule()", () => {
    it("returns null for rules without AbortIncompleteMultipartUpload", () => {
      const result = parseMpuRule({
        ID: "rule-no-abort",
        Status: "Enabled",
        Expiration: { Days: 30 },
      });
      expect(result).toBeNull();
    });

    it("parses a simple prefix MPU abort rule", () => {
      const result = parseMpuRule({
        ID: "simple-rule",
        Status: "Enabled",
        Filter: { Prefix: "uploads/" },
        AbortIncompleteMultipartUpload: { DaysAfterInitiation: 7 },
      });

      expect(result).not.toBeNull();
      expect(result!.ruleId).toBe("simple-rule");
      expect(result!.prefix).toBe("uploads/");
      expect(result!.daysAfterInitiation).toBe(7);
      expect(result!.hasTagFilter).toBe(false);
      expect(result!.hasConflictingFilters).toBe(false);
    });

    it("parses a global MPU abort rule with no filter", () => {
      const result = parseMpuRule({
        ID: "global-rule",
        Status: "Enabled",
        AbortIncompleteMultipartUpload: { DaysAfterInitiation: 14 },
      });

      expect(result).not.toBeNull();
      expect(result!.prefix).toBe("");
      expect(result!.hasTagFilter).toBe(false);
    });

    it("detects Ghost Rule: pure Tag filter on MPU abort rule", () => {
      const result = parseMpuRule({
        ID: "ghost-rule",
        Status: "Enabled",
        Filter: { Tag: { Key: "env", Value: "dev" } },
        AbortIncompleteMultipartUpload: { DaysAfterInitiation: 7 },
      });

      expect(result).not.toBeNull();
      expect(result!.hasTagFilter).toBe(true);
      expect(result!.hasConflictingFilters).toBe(false);
    });

    it("detects Ghost Rule: AND filter with Tags present", () => {
      const result = parseMpuRule({
        ID: "and-ghost-rule",
        Status: "Enabled",
        Filter: {
          And: {
            Prefix: "uploads/",
            Tags: [{ Key: "env", Value: "prod" }],
          },
        },
        AbortIncompleteMultipartUpload: { DaysAfterInitiation: 3 },
      });

      expect(result).not.toBeNull();
      expect(result!.hasTagFilter).toBe(true);
      expect(result!.hasConflictingFilters).toBe(true);
      expect(result!.prefix).toBe("uploads/");
    });

    it("sets (no id) when rule has no ID", () => {
      const result = parseMpuRule({
        Status: "Enabled",
        AbortIncompleteMultipartUpload: { DaysAfterInitiation: 7 },
      });
      expect(result!.ruleId).toBe("(no id)");
    });
  });

  // ── Ghost Rule detection in auditBucketLifecycle ────────────────────────────

  describe("auditBucketLifecycle() - Ghost Rule detection", () => {
    it("detects ghost rule when MPU abort rule uses Tag filter", async () => {
      const client = new S3Client({});
      s3Mock.on(GetBucketLifecycleConfigurationCommand).resolvesOnce({
        Rules: [
          {
            ID: "ghost-rule",
            Status: "Enabled",
            Filter: { Tag: { Key: "env", Value: "dev" } },
            AbortIncompleteMultipartUpload: { DaysAfterInitiation: 7 },
          },
        ],
      });

      const result = await auditBucketLifecycle(client, "my-bucket");

      expect(result.bucketHasLifecyclePolicy).toBe(true);
      expect(result.hasCoveringRule).toBe(false); // Ghost rule does NOT count
      expect(result.ghostRulesDetected).toHaveLength(1);
      expect(result.ghostRulesDetected[0]).toContain("ghost-rule");
      expect(result.ghostRulesDetected[0]).toContain("Tag filter");
    });

    it("detects ghost rule with AND filter+Tags while a real rule also exists", async () => {
      const client = new S3Client({});
      s3Mock.on(GetBucketLifecycleConfigurationCommand).resolvesOnce({
        Rules: [
          {
            ID: "real-rule",
            Status: "Enabled",
            Filter: { Prefix: "uploads/" },
            AbortIncompleteMultipartUpload: { DaysAfterInitiation: 7 },
          },
          {
            ID: "and-ghost",
            Status: "Enabled",
            Filter: {
              And: {
                Prefix: "data/",
                Tags: [{ Key: "tier", Value: "cold" }],
              },
            },
            AbortIncompleteMultipartUpload: { DaysAfterInitiation: 14 },
          },
        ],
      });

      const result = await auditBucketLifecycle(client, "my-bucket");

      expect(result.hasCoveringRule).toBe(true); // real-rule is valid
      expect(result.ghostRulesDetected).toHaveLength(1);
      expect(result.ghostRulesDetected[0]).toContain("and-ghost");
    });

    it("returns hasCoveringRule=false for disabled real rules", async () => {
      const client = new S3Client({});
      s3Mock.on(GetBucketLifecycleConfigurationCommand).resolvesOnce({
        Rules: [
          {
            ID: "disabled-rule",
            Status: "Disabled",
            Filter: { Prefix: "" },
            AbortIncompleteMultipartUpload: { DaysAfterInitiation: 7 },
          },
        ],
      });

      const result = await auditBucketLifecycle(client, "my-bucket");

      expect(result.bucketHasLifecyclePolicy).toBe(true);
      expect(result.hasCoveringRule).toBe(false);
      expect(result.ghostRulesDetected).toHaveLength(0);
    });
  });

  // ── evaluateUploadCoverage ───────────────────────────────────────────────────

  describe("evaluateUploadCoverage()", () => {
    const now = new Date("2026-09-20T12:00:00.000Z");

    it("returns UNPROTECTED when no rules exist", () => {
      const result = evaluateUploadCoverage(
        "uploads/file.bin",
        new Date("2026-09-10T00:00:00.000Z"),
        [],
        now
      );
      expect(result.status).toBe("UNPROTECTED");
    });

    it("returns UNPROTECTED when all rules are disabled", () => {
      const rules: ParsedMpuRule[] = [
        {
          ruleId: "disabled",
          status: "Disabled",
          daysAfterInitiation: 7,
          prefix: "",
          hasTagFilter: false,
          hasConflictingFilters: false,
        },
      ];
      const result = evaluateUploadCoverage(
        "uploads/file.bin",
        new Date("2026-09-10T00:00:00.000Z"),
        rules,
        now
      );
      expect(result.status).toBe("UNPROTECTED");
    });

    it("returns UNPROTECTED when key does not match any rule prefix", () => {
      const rules: ParsedMpuRule[] = [
        {
          ruleId: "prefix-rule",
          status: "Enabled",
          daysAfterInitiation: 7,
          prefix: "videos/",
          hasTagFilter: false,
          hasConflictingFilters: false,
        },
      ];
      const result = evaluateUploadCoverage(
        "uploads/file.bin",
        new Date("2026-09-10T00:00:00.000Z"),
        rules,
        now
      );
      expect(result.status).toBe("UNPROTECTED");
    });

    it("returns COVERED when upload is within threshold of a matching rule", () => {
      // Upload is 5 days old, rule aborts at 7 days => still within threshold
      const rules: ParsedMpuRule[] = [
        {
          ruleId: "global-rule",
          status: "Enabled",
          daysAfterInitiation: 7,
          prefix: "",
          hasTagFilter: false,
          hasConflictingFilters: false,
        },
      ];
      const result = evaluateUploadCoverage(
        "uploads/file.bin",
        new Date("2026-09-15T00:00:00.000Z"), // 5 days old vs now=2026-09-20
        rules,
        now
      );
      expect(result.status).toBe("COVERED");
      expect(result.matchedRuleId).toBe("global-rule");
    });

    it("returns COVERED_LAGGING when upload has aged past the rule threshold", () => {
      // Upload is 12 days old, rule threshold is 7 days => lagging
      const rules: ParsedMpuRule[] = [
        {
          ruleId: "slow-cleanup",
          status: "Enabled",
          daysAfterInitiation: 7,
          prefix: "",
          hasTagFilter: false,
          hasConflictingFilters: false,
        },
      ];
      const result = evaluateUploadCoverage(
        "uploads/stale.bin",
        new Date("2026-09-08T00:00:00.000Z"), // 12 days old vs now=2026-09-20
        rules,
        now
      );
      expect(result.status).toBe("COVERED_LAGGING");
      expect(result.matchedRuleId).toBe("slow-cleanup");
      expect(result.daysAfterInitiation).toBe(7);
    });

    it("returns GHOST_RULE when only ghost rules match the key", () => {
      const rules: ParsedMpuRule[] = [
        {
          ruleId: "ghost",
          status: "Enabled",
          daysAfterInitiation: 7,
          prefix: "",
          hasTagFilter: true, // Ghost Rule
          hasConflictingFilters: false,
        },
      ];
      const result = evaluateUploadCoverage(
        "uploads/file.bin",
        new Date("2026-09-10T00:00:00.000Z"),
        rules,
        now
      );
      expect(result.status).toBe("GHOST_RULE");
      expect(result.matchedRuleId).toBe("ghost");
    });

    it("picks best (shortest days) real rule when multiple rules match", () => {
      const rules: ParsedMpuRule[] = [
        {
          ruleId: "slow-rule",
          status: "Enabled",
          daysAfterInitiation: 30,
          prefix: "",
          hasTagFilter: false,
          hasConflictingFilters: false,
        },
        {
          ruleId: "fast-rule",
          status: "Enabled",
          daysAfterInitiation: 7,
          prefix: "uploads/",
          hasTagFilter: false,
          hasConflictingFilters: false,
        },
      ];
      // Upload 5 days old -> within 7-day threshold -> COVERED by fast-rule
      const result = evaluateUploadCoverage(
        "uploads/file.bin",
        new Date("2026-09-15T00:00:00.000Z"),
        rules,
        now
      );
      expect(result.status).toBe("COVERED");
      expect(result.matchedRuleId).toBe("fast-rule");
    });

    it("prefers real rule over ghost rule when both match", () => {
      const rules: ParsedMpuRule[] = [
        {
          ruleId: "ghost",
          status: "Enabled",
          daysAfterInitiation: 1,
          prefix: "",
          hasTagFilter: true,
          hasConflictingFilters: false,
        },
        {
          ruleId: "real",
          status: "Enabled",
          daysAfterInitiation: 7,
          prefix: "",
          hasTagFilter: false,
          hasConflictingFilters: false,
        },
      ];
      // Upload 5 days old -> COVERED by real rule (not ghost)
      const result = evaluateUploadCoverage(
        "uploads/file.bin",
        new Date("2026-09-15T00:00:00.000Z"),
        rules,
        now
      );
      expect(result.status).toBe("COVERED");
      expect(result.matchedRuleId).toBe("real");
    });

    it("matches prefix correctly (exact prefix start)", () => {
      const rules: ParsedMpuRule[] = [
        {
          ruleId: "prefix-rule",
          status: "Enabled",
          daysAfterInitiation: 7,
          prefix: "uploads/2026/",
          hasTagFilter: false,
          hasConflictingFilters: false,
        },
      ];

      // Matching key
      const r1 = evaluateUploadCoverage(
        "uploads/2026/file.bin",
        new Date("2026-09-15T00:00:00.000Z"),
        rules,
        now
      );
      expect(r1.status).toBe("COVERED");

      // Non-matching key
      const r2 = evaluateUploadCoverage(
        "uploads/2025/file.bin",
        new Date("2026-09-15T00:00:00.000Z"),
        rules,
        now
      );
      expect(r2.status).toBe("UNPROTECTED");
    });
  });

  // ── Full round-trip audit ────────────────────────────────────────────────────

  describe("auditBucketLifecycle() - full AWS round-trip", () => {
    it("returns correct audit with real MPU abort rule", async () => {
      const client = new S3Client({});
      s3Mock.on(GetBucketLifecycleConfigurationCommand).resolvesOnce({
        Rules: [
          {
            ID: "cleanup-rule",
            Status: "Enabled",
            Filter: { Prefix: "" },
            AbortIncompleteMultipartUpload: { DaysAfterInitiation: 7 },
          },
        ],
      });

      const result = await auditBucketLifecycle(client, "prod-bucket");

      expect(result.bucketHasLifecyclePolicy).toBe(true);
      expect(result.hasCoveringRule).toBe(true);
      expect(result.mpuRules).toHaveLength(1);
      expect(result.mpuRules[0].ruleId).toBe("cleanup-rule");
      expect(result.ghostRulesDetected).toHaveLength(0);
    });

    it("returns correct audit for bucket with non-MPU lifecycle rules only", async () => {
      const client = new S3Client({});
      s3Mock.on(GetBucketLifecycleConfigurationCommand).resolvesOnce({
        Rules: [
          {
            ID: "expiration-only",
            Status: "Enabled",
            Filter: { Prefix: "logs/" },
            Expiration: { Days: 90 },
          },
        ],
      });

      const result = await auditBucketLifecycle(client, "logs-bucket");

      expect(result.bucketHasLifecyclePolicy).toBe(true);
      expect(result.hasCoveringRule).toBe(false); // No MPU abort rule
      expect(result.mpuRules).toHaveLength(0);
      expect(result.ghostRulesDetected).toHaveLength(0);
    });
  });
});
