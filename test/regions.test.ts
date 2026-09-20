import { describe, it, expect } from "vitest";
import {
  normalizeBucketRegion,
  resolveBucketRegion,
  US_EAST_1,
  EU_WEST_1,
  LEGACY_EU_REGION,
} from "../src/discovery/regions.js";

describe("Region normalization", () => {
  describe("normalizeBucketRegion()", () => {
    it("normalizes null → us-east-1", () => {
      expect(normalizeBucketRegion(null)).toBe(US_EAST_1);
    });

    it("normalizes undefined → us-east-1", () => {
      expect(normalizeBucketRegion(undefined)).toBe(US_EAST_1);
    });

    it("normalizes empty string → us-east-1", () => {
      expect(normalizeBucketRegion("")).toBe(US_EAST_1);
    });

    it("normalizes whitespace-only string → us-east-1", () => {
      expect(normalizeBucketRegion("   ")).toBe(US_EAST_1);
    });

    it("normalizes legacy 'EU' → eu-west-1", () => {
      expect(normalizeBucketRegion(LEGACY_EU_REGION)).toBe(EU_WEST_1);
      expect(normalizeBucketRegion("EU")).toBe("eu-west-1");
    });

    it("passes through standard AWS region strings unchanged", () => {
      expect(normalizeBucketRegion("us-west-2")).toBe("us-west-2");
      expect(normalizeBucketRegion("eu-central-1")).toBe("eu-central-1");
      expect(normalizeBucketRegion("ap-southeast-1")).toBe("ap-southeast-1");
      expect(normalizeBucketRegion("sa-east-1")).toBe("sa-east-1");
      expect(normalizeBucketRegion("ca-central-1")).toBe("ca-central-1");
      expect(normalizeBucketRegion("us-east-1")).toBe("us-east-1");
    });

    it("does NOT normalize lowercase 'eu' (case-sensitive legacy check)", () => {
      // Only the exact string "EU" is the legacy constraint
      expect(normalizeBucketRegion("eu")).toBe("eu");
    });
  });

  describe("resolveBucketRegion()", () => {
    it("uses LocationConstraint when BucketRegion is absent", () => {
      expect(resolveBucketRegion({ LocationConstraint: null })).toBe(US_EAST_1);
      expect(resolveBucketRegion({ LocationConstraint: "" })).toBe(US_EAST_1);
      expect(resolveBucketRegion({ LocationConstraint: "EU" })).toBe(EU_WEST_1);
      expect(resolveBucketRegion({ LocationConstraint: "us-west-2" })).toBe("us-west-2");
    });

    it("prefers BucketRegion over LocationConstraint when both are present", () => {
      expect(
        resolveBucketRegion({
          LocationConstraint: null,
          BucketRegion: "eu-central-1",
        })
      ).toBe("eu-central-1");
    });

    it("falls back to LocationConstraint when BucketRegion is null or empty", () => {
      expect(
        resolveBucketRegion({
          LocationConstraint: "ap-southeast-1",
          BucketRegion: null,
        })
      ).toBe("ap-southeast-1");

      expect(
        resolveBucketRegion({
          LocationConstraint: "ap-southeast-1",
          BucketRegion: "",
        })
      ).toBe("ap-southeast-1");
    });

    it("normalizes BucketRegion through the same legacy rules", () => {
      expect(
        resolveBucketRegion({
          LocationConstraint: "us-west-2",
          BucketRegion: "EU",
        })
      ).toBe(EU_WEST_1);
    });

    it("handles response with no fields at all → us-east-1", () => {
      expect(resolveBucketRegion({})).toBe(US_EAST_1);
    });
  });
});
