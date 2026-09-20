import { describe, it, expect } from "vitest";
import {
  canonicalizeJson,
  computeSha256Hex,
  computePlanHash,
  getPlanCanonicalPayload,
} from "../src/planner/jcs.js";
import {
  createPlan,
  validatePlan,
  verifyPlanIntegrity,
  Plan,
} from "../src/planner/plan.js";

describe("RFC 8785 JSON Canonicalization Scheme (JCS) and Plan Integrity", () => {
  describe("canonicalizeJson", () => {
    it("sorts object keys lexicographically in UTF-16 order", () => {
      const input = { z: 1, a: 2, m: 3, b: { y: "test", x: 10 } };
      const canonical = canonicalizeJson(input);
      expect(canonical).toBe('{"a":2,"b":{"x":10,"y":"test"},"m":3,"z":1}');
    });

    it("eliminates non-significant whitespace", () => {
      const input = { key: "value", arr: [1, 2, 3] };
      const canonical = canonicalizeJson(input);
      expect(canonical).toBe('{"arr":[1,2,3],"key":"value"}');
      expect(canonical).not.toContain(" ");
      expect(canonical).not.toContain("\n");
    });

    it("preserves primitives correctly", () => {
      expect(canonicalizeJson(null)).toBe("null");
      expect(canonicalizeJson(undefined)).toBe("null");
      expect(canonicalizeJson(true)).toBe("true");
      expect(canonicalizeJson(false)).toBe("false");
      expect(canonicalizeJson(123)).toBe("123");
      expect(canonicalizeJson(0)).toBe("0");
      expect(canonicalizeJson(-45.67)).toBe("-45.67");
      expect(canonicalizeJson("hello world")).toBe('"hello world"');
    });

    it("handles arrays deterministically", () => {
      const input = [3, 1, 2, { b: 2, a: 1 }];
      expect(canonicalizeJson(input)).toBe('[3,1,2,{"a":1,"b":2}]');
    });

    it("handles null/undefined elements in arrays", () => {
      expect(canonicalizeJson([1, null, undefined, 4])).toBe("[1,null,null,4]");
    });
  });

  describe("computeSha256Hex and computePlanHash", () => {
    it("computes reproducible SHA-256 hexadecimal digests", () => {
      const hash1 = computeSha256Hex("hello world");
      const hash2 = computeSha256Hex("hello world");
      expect(hash1).toBe(hash2);
      expect(hash1).toBe(
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
      );
    });

    it("computes deterministic plan hash regardless of input object key order", () => {
      const targetsA = {
        bucket: "target-bucket",
        olderThanDays: 7,
        uploads: [{ key: "data/file.csv", uploadId: "u-123" }],
        versionDeletions: [{ key: "data/old.bin", versionId: "v-456", type: "NONCURRENT_VERSION" }],
      };

      const targetsB = {
        uploads: [{ uploadId: "u-123", key: "data/file.csv" }],
        olderThanDays: 7,
        versionDeletions: [{ versionId: "v-456", type: "NONCURRENT_VERSION", key: "data/old.bin" }],
        bucket: "target-bucket",
      };

      const hashA = computePlanHash(targetsA);
      const hashB = computePlanHash(targetsB);
      expect(hashA).toBe(hashB);
      expect(typeof hashA).toBe("string");
      expect(hashA.length).toBe(64);
    });

    it("produces distinct hashes when targets differ", () => {
      const base = {
        bucket: "target-bucket",
        olderThanDays: 7,
        uploads: [{ key: "data/file.csv", uploadId: "u-123" }],
      };

      const differentBucket = { ...base, bucket: "other-bucket" };
      const differentDays = { ...base, olderThanDays: 14 };
      const differentKey = {
        ...base,
        uploads: [{ key: "data/other.csv", uploadId: "u-123" }],
      };
      const differentUploadId = {
        ...base,
        uploads: [{ key: "data/file.csv", uploadId: "u-999" }],
      };

      const baseHash = computePlanHash(base);
      expect(computePlanHash(differentBucket)).not.toBe(baseHash);
      expect(computePlanHash(differentDays)).not.toBe(baseHash);
      expect(computePlanHash(differentKey)).not.toBe(baseHash);
      expect(computePlanHash(differentUploadId)).not.toBe(baseHash);
    });
  });

  describe("verifyPlanIntegrity", () => {
    it("validates an untampered Schema 1.3 plan", () => {
      const plan = createPlan({
        bucket: "my-secure-bucket",
        olderThanDays: 7,
        uploads: [
          {
            key: "logs/2026/09/app.log",
            uploadId: "mpu-log-1",
            initiated: "2026-09-01T00:00:00.000Z",
            partsCount: 2,
            bytes: 2048,
            storageClass: "STANDARD",
            lifecycleStatus: "UNPROTECTED",
          },
        ],
        lifecycleAudit: {
          bucketHasLifecyclePolicy: false,
          hasCoveringRule: false,
          ghostRulesDetected: [],
        },
      });

      expect(plan.schemaVersion).toBe("1.3");
      expect(plan.planHash).toBeDefined();

      const verification = verifyPlanIntegrity(plan);
      expect(verification.valid).toBe(true);
      expect(verification.error).toBeUndefined();
    });

    it("rejects a Schema 1.3 plan if target key was tampered with", () => {
      const plan = createPlan({
        bucket: "my-secure-bucket",
        olderThanDays: 7,
        uploads: [
          {
            key: "logs/2026/09/app.log",
            uploadId: "mpu-log-1",
            initiated: "2026-09-01T00:00:00.000Z",
            partsCount: 2,
            bytes: 2048,
            storageClass: "STANDARD",
            lifecycleStatus: "UNPROTECTED",
          },
        ],
        lifecycleAudit: {
          bucketHasLifecyclePolicy: false,
          hasCoveringRule: false,
          ghostRulesDetected: [],
        },
      });

      // Tamper with key
      plan.uploads[0].key = "tampered/critical-system-file.db";

      const verification = verifyPlanIntegrity(plan);
      expect(verification.valid).toBe(false);
      expect(verification.error).toContain("Plan integrity verification failed");
      expect(verification.error).toContain("altered or corrupted");
    });

    it("rejects a Schema 1.3 plan if version deletion target was injected", () => {
      const plan = createPlan({
        bucket: "my-secure-bucket",
        olderThanDays: 7,
        uploads: [],
        versionDeletions: [
          {
            key: "valid-target.txt",
            versionId: "v-1",
            type: "NONCURRENT_VERSION",
            size: 100,
            lastModified: "2026-09-01T00:00:00.000Z",
          },
        ],
        lifecycleAudit: {
          bucketHasLifecyclePolicy: true,
          hasCoveringRule: true,
          ghostRulesDetected: [],
        },
      });

      // Tamper: inject another version target
      plan.versionDeletions!.push({
        key: "injected-target.txt",
        versionId: "v-injected",
        type: "NONCURRENT_VERSION",
        size: 500,
        lastModified: "2026-09-01T00:00:00.000Z",
      });

      const verification = verifyPlanIntegrity(plan);
      expect(verification.valid).toBe(false);
      expect(verification.error).toContain("Plan integrity verification failed");
    });

    it("rejects a Schema 1.3 plan missing planHash", () => {
      const plan = createPlan({
        bucket: "my-secure-bucket",
        olderThanDays: 7,
        uploads: [],
        lifecycleAudit: {
          bucketHasLifecyclePolicy: false,
          hasCoveringRule: false,
          ghostRulesDetected: [],
        },
      });

      delete (plan as any).planHash;
      const verification = verifyPlanIntegrity(plan);
      expect(verification.valid).toBe(false);
      expect(verification.error).toContain("requires a cryptographic planHash");
    });

    it("accepts legacy Schema 1.0/1.1/1.2 plans without planHash for backwards compatibility", () => {
      const legacy11: Plan = {
        schemaVersion: "1.1",
        generatedAt: new Date().toISOString(),
        bucket: "legacy-bucket",
        endpoint: null,
        olderThanDays: 7,
        totalZombieUploads: 1,
        totalStrandedBytes: 100,
        estimatedMonthlyWasteUSD: 0,
        lifecycleAudit: {
          bucketHasLifecyclePolicy: false,
          hasCoveringRule: false,
          ghostRulesDetected: [],
        },
        uploads: [
          {
            key: "old.bin",
            uploadId: "id",
            initiated: "2026-09-01T00:00:00.000Z",
            partsCount: 1,
            bytes: 100,
            storageClass: "STANDARD",
            lifecycleStatus: "UNPROTECTED",
          },
        ],
      };

      const verification = verifyPlanIntegrity(legacy11);
      expect(verification.valid).toBe(true);
    });
  });
});
