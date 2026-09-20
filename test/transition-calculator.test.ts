import { describe, it, expect } from "vitest";
import {
  calculateTransitionCostDelta,
  normalizeStorageClass,
  getStorageClassConfig,
  BYTES_PER_KIB,
  BYTES_PER_GIB,
  S3_STANDARD_PRICE_PER_GIB_MONTH,
  MIN_BILLABLE_SIZE_128KIB,
  METADATA_OVERHEAD_STANDARD_BYTES,
  METADATA_OVERHEAD_GLACIER_BYTES,
  METADATA_OVERHEAD_TOTAL_BYTES,
  TRANSITION_FEE_PER_1K_IA,
  TRANSITION_FEE_PER_1K_GLACIER,
} from "../src/transitions/calculator.js";

describe("Transition Cost Delta Calculator", () => {
  describe("Mathematical Constants and Normalization", () => {
    it("defines exact byte constants", () => {
      expect(BYTES_PER_KIB).toBe(1024);
      expect(BYTES_PER_GIB).toBe(1073741824);
      expect(MIN_BILLABLE_SIZE_128KIB).toBe(131072);
      expect(METADATA_OVERHEAD_STANDARD_BYTES).toBe(8192);
      expect(METADATA_OVERHEAD_GLACIER_BYTES).toBe(32768);
      expect(METADATA_OVERHEAD_TOTAL_BYTES).toBe(40960);
      expect(S3_STANDARD_PRICE_PER_GIB_MONTH).toBe(0.023);
      expect(TRANSITION_FEE_PER_1K_IA).toBe(0.01);
      expect(TRANSITION_FEE_PER_1K_GLACIER).toBe(0.05);
    });

    it("normalizes storage class aliases correctly", () => {
      expect(normalizeStorageClass("standard_ia")).toBe("STANDARD_IA");
      expect(normalizeStorageClass("standard-ia")).toBe("STANDARD_IA");
      expect(normalizeStorageClass("STANDARDIA")).toBe("STANDARD_IA");
      expect(normalizeStorageClass("onezone-ia")).toBe("ONEZONE_IA");
      expect(normalizeStorageClass("gir")).toBe("GLACIER_IR");
      expect(normalizeStorageClass("glacier-instant-retrieval")).toBe("GLACIER_IR");
      expect(normalizeStorageClass("gfr")).toBe("GLACIER");
      expect(normalizeStorageClass("glacier-flexible-retrieval")).toBe("GLACIER");
      expect(normalizeStorageClass("gda")).toBe("DEEP_ARCHIVE");
      expect(normalizeStorageClass("glacier-deep-archive")).toBe("DEEP_ARCHIVE");
      expect(normalizeStorageClass("deep_archive")).toBe("DEEP_ARCHIVE");
      expect(normalizeStorageClass("intelligent-tiering")).toBe("INTELLIGENT_TIERING");
    });

    it("retrieves storage class configs with correct pricing and floors", () => {
      const ia = getStorageClassConfig("STANDARD_IA");
      expect(ia.storagePricePerGiBMonth).toBe(0.0125);
      expect(ia.minBillableSizeBytes).toBe(131072);
      expect(ia.hasMetadataOverhead).toBe(false);
      expect(ia.transitionFeePer1k).toBe(0.01);

      const gir = getStorageClassConfig("GLACIER_IR");
      expect(gir.storagePricePerGiBMonth).toBe(0.0040);
      expect(gir.minBillableSizeBytes).toBe(131072);
      expect(gir.hasMetadataOverhead).toBe(false);
      expect(gir.transitionFeePer1k).toBe(0.05);

      const gfr = getStorageClassConfig("GLACIER");
      expect(gfr.storagePricePerGiBMonth).toBe(0.0036);
      expect(gfr.minBillableSizeBytes).toBe(0);
      expect(gfr.hasMetadataOverhead).toBe(true);
      expect(gfr.transitionFeePer1k).toBe(0.05);

      const gda = getStorageClassConfig("DEEP_ARCHIVE");
      expect(gda.storagePricePerGiBMonth).toBe(0.00099);
      expect(gda.minBillableSizeBytes).toBe(0);
      expect(gda.hasMetadataOverhead).toBe(true);
      expect(gda.transitionFeePer1k).toBe(0.05);
    });
  });

  describe("S3 Standard-IA & One Zone-IA 128 KiB Floor Math", () => {
    it("enforces 128 KiB billable floor on small objects (1 KiB object)", () => {
      const objectCount = 1000;
      const averageSizeBytes = 1024; // 1 KiB
      const result = calculateTransitionCostDelta({
        objectCount,
        averageSizeBytes,
        targetStorageClass: "STANDARD_IA",
        durationDays: 30,
      });

      // Effective billable size must be 128 KiB = 131,072 bytes
      expect(result.effectiveBillableSizeBytes).toBe(131072);

      // Baseline standard cost: 1,000 * 1,024 bytes = 1,024,000 bytes at $0.023/GiB
      const expectedBaseline = (1000 * 1024 / BYTES_PER_GIB) * 0.023;
      expect(result.baselineStandardCost).toBeCloseTo(expectedBaseline, 8);

      // Target storage cost: 1,000 * 131,072 bytes = 131,072,000 bytes at $0.0125/GiB
      const expectedTargetStorage = (1000 * 131072 / BYTES_PER_GIB) * 0.0125;
      expect(result.targetStorageCost).toBeCloseTo(expectedTargetStorage, 8);

      // Transition fee: $0.01 / 1,000 objects
      expect(result.transitionRequestCost).toBe(0.01);
      expect(result.amortizedTransitionCostMonthly).toBe(0.01);

      // No metadata overhead in IA
      expect(result.metadataOverheadCosts.totalMonthly).toBe(0);

      // Target storage alone ($0.001525) is ~70x more expensive than Standard baseline ($0.0000219)
      expect(result.isPenalty).toBe(true);
      expect(result.netMonthlyDelta).toBeGreaterThan(0);
      // It can never break even
      expect(result.breakevenMonths).toBeNull();
    });

    it("does not artificially inflate objects >= 128 KiB in Standard-IA", () => {
      const objectCount = 1000;
      const averageSizeBytes = 1024 * 1024; // 1 MiB
      const result = calculateTransitionCostDelta({
        objectCount,
        averageSizeBytes,
        targetStorageClass: "STANDARD_IA",
        durationDays: 365,
      });

      expect(result.effectiveBillableSizeBytes).toBe(1024 * 1024);

      // Baseline: 1,000 MiB at $0.023/GiB
      const baseline = (1000 * 1024 * 1024 / BYTES_PER_GIB) * 0.023;
      expect(result.baselineStandardCost).toBeCloseTo(baseline, 6);

      // Target: 1,000 MiB at $0.0125/GiB
      const targetStorage = (1000 * 1024 * 1024 / BYTES_PER_GIB) * 0.0125;
      expect(result.targetStorageCost).toBeCloseTo(targetStorage, 6);

      // Net monthly delta is negative (savings!)
      expect(result.isPenalty).toBe(false);
      expect(result.netMonthlyDelta).toBeLessThan(0);
      expect(result.breakevenMonths).toBeGreaterThan(0);
    });

    it("enforces 128 KiB billable floor on ONEZONE_IA", () => {
      const result = calculateTransitionCostDelta({
        objectCount: 500,
        averageSizeBytes: 2048, // 2 KiB
        targetStorageClass: "ONEZONE_IA",
      });

      expect(result.effectiveBillableSizeBytes).toBe(131072);
      expect(result.isPenalty).toBe(true);
      expect(result.transitionRequestCost).toBe((500 / 1000) * 0.01);
    });
  });

  describe("Glacier Instant Retrieval (GIR) 128 KiB Floor Math", () => {
    it("enforces 128 KiB floor and $0.05/1k transition request fee on GIR", () => {
      const objectCount = 2000;
      const averageSizeBytes = 65536; // 64 KiB (< 128 KiB)
      const result = calculateTransitionCostDelta({
        objectCount,
        averageSizeBytes,
        targetStorageClass: "GLACIER_IR",
        durationDays: 30,
      });

      expect(result.effectiveBillableSizeBytes).toBe(131072);
      expect(result.targetStorageCost).toBeCloseTo((2000 * 131072 / BYTES_PER_GIB) * 0.0040, 8);
      expect(result.transitionRequestCost).toBe((2000 / 1000) * 0.05); // $0.10
      expect(result.metadataOverheadCosts.totalMonthly).toBe(0);
    });
  });

  describe("Glacier Flexible Retrieval (GFR) 40 KiB Metadata Split Math", () => {
    it("charges 8 KiB at Standard rate and 32 KiB at Glacier rate with NO 128 KiB floor", () => {
      const objectCount = 1000;
      const averageSizeBytes = 4096; // 4 KiB
      const result = calculateTransitionCostDelta({
        objectCount,
        averageSizeBytes,
        targetStorageClass: "GLACIER",
        durationDays: 30,
      });

      // GFR billable size is actual size (no 128 KiB floor)
      expect(result.effectiveBillableSizeBytes).toBe(4096);

      // Metadata split:
      // 8 KiB per object at Standard rate ($0.023/GiB)
      const expectedStandardMeta = (1000 * 8192 / BYTES_PER_GIB) * 0.023;
      expect(result.metadataOverheadCosts.standardCostMonthly).toBeCloseTo(expectedStandardMeta, 8);

      // 32 KiB per object at Glacier rate ($0.0036/GiB)
      const expectedGlacierMeta = (1000 * 32768 / BYTES_PER_GIB) * 0.0036;
      expect(result.metadataOverheadCosts.glacierCostMonthly).toBeCloseTo(expectedGlacierMeta, 8);

      expect(result.metadataOverheadCosts.totalMonthly).toBeCloseTo(
        expectedStandardMeta + expectedGlacierMeta,
        8
      );

      // Transition fee is $0.05 per 1,000 requests
      expect(result.transitionRequestCost).toBe(0.05);

      // Because metadata alone (40 KiB) is 10x larger than the 4 KiB file, ongoing cost in Glacier
      // exceeds Standard baseline, making it a penalty
      expect(result.isPenalty).toBe(true);
      expect(result.breakevenMonths).toBeNull();
    });

    it("calculates positive savings and breakeven threshold for large objects in GFR", () => {
      const objectCount = 100;
      const averageSizeBytes = 50 * 1024 * 1024; // 50 MiB
      const result = calculateTransitionCostDelta({
        objectCount,
        averageSizeBytes,
        targetStorageClass: "GLACIER",
        durationDays: 180,
      });

      expect(result.effectiveBillableSizeBytes).toBe(50 * 1024 * 1024);
      expect(result.isPenalty).toBe(false);
      expect(result.netMonthlyDelta).toBeLessThan(0);
      expect(result.breakevenMonths).toBeDefined();
      expect(result.breakevenMonths!).toBeGreaterThan(0);
      expect(result.breakevenMonths!).toBeLessThan(1); // Less than 1 month to break even on 50MB
    });
  });

  describe("Glacier Deep Archive (GDA) Math", () => {
    it("calculates 40 KiB metadata split using Deep Archive rate ($0.00099/GiB)", () => {
      const objectCount = 5000;
      const averageSizeBytes = 2048; // 2 KiB
      const result = calculateTransitionCostDelta({
        objectCount,
        averageSizeBytes,
        targetStorageClass: "DEEP_ARCHIVE",
      });

      expect(result.effectiveBillableSizeBytes).toBe(2048);

      // 8 KiB at Standard rate
      const expectedStandardMeta = (5000 * 8192 / BYTES_PER_GIB) * 0.023;
      expect(result.metadataOverheadCosts.standardCostMonthly).toBeCloseTo(expectedStandardMeta, 8);

      // 32 KiB at Deep Archive rate ($0.00099)
      const expectedGlacierMeta = (5000 * 32768 / BYTES_PER_GIB) * 0.00099;
      expect(result.metadataOverheadCosts.glacierCostMonthly).toBeCloseTo(expectedGlacierMeta, 8);

      // Transition fee is $0.05 / 1k: 5,000 * $0.05 / 1,000 = $0.25
      expect(result.transitionRequestCost).toBe(0.25);
    });
  });

  describe("Edge cases", () => {
    it("returns zero costs for 0 objects without throwing", () => {
      const result = calculateTransitionCostDelta({
        objectCount: 0,
        averageSizeBytes: 1024,
        targetStorageClass: "GLACIER",
      });

      expect(result.baselineStandardCost).toBe(0);
      expect(result.targetStorageCost).toBe(0);
      expect(result.transitionRequestCost).toBe(0);
      expect(result.metadataOverheadCosts.totalMonthly).toBe(0);
      expect(result.netMonthlyDelta).toBe(0);
      expect(result.isPenalty).toBe(false);
      expect(result.breakevenMonths).toBeNull();
    });

    it("handles 0 average size bytes gracefully", () => {
      const result = calculateTransitionCostDelta({
        objectCount: 100,
        averageSizeBytes: 0,
        targetStorageClass: "STANDARD_IA",
      });

      expect(result.effectiveBillableSizeBytes).toBe(131072);
      expect(result.baselineStandardCost).toBe(0);
      expect(result.targetStorageCost).toBeGreaterThan(0);
      expect(result.isPenalty).toBe(true);
    });
  });
});
