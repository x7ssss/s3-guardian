import { describe, it, expect } from "vitest";
import {
  computeWasteScore,
  rankStorageLensMetrics,
  StorageLensRawMetrics,
  StorageLensBucketMetrics,
} from "../src/lens/scorer.js";

describe("Storage Lens Scorer", () => {
  it("computes wasteBytes and wasteScore accurately", () => {
    const raw: StorageLensRawMetrics = {
      accountId: "111111111111",
      bucketName: "data-bucket",
      region: "us-east-1",
      storageBytes: 1_000_000,
      noncurrentBytes: 250_000,
      deleteMarkerCount: 10,
      incompleteMpuBytes: 100_000,
      incompleteMpuOlderThan7DaysBytes: 50_000,
    };

    const scored = computeWasteScore(raw);

    // wasteBytes = 250_000 + 50_000 = 300_000
    expect(scored.wasteBytes).toBe(300_000);
    // wasteScore = (300_000 / 1_000_000) * 100 = 30.0%
    expect(scored.wasteScore).toBeCloseTo(30.0, 4);
    // Size multiplier for 1 MB is ~1.0
    expect(scored.priority).toBeGreaterThanOrEqual(30.0);
  });

  it("handles zero storageBytes safely without division by zero", () => {
    const raw: StorageLensRawMetrics = {
      accountId: "111111111111",
      bucketName: "empty-bucket",
      region: "us-east-1",
      storageBytes: 0,
      noncurrentBytes: 50_000,
      deleteMarkerCount: 1,
      incompleteMpuBytes: 50_000,
      incompleteMpuOlderThan7DaysBytes: 50_000,
    };

    const scored = computeWasteScore(raw);
    expect(Number.isFinite(scored.wasteScore)).toBe(true);
    expect(Number.isFinite(scored.priority)).toBe(true);
    // (100_000 / 1) * 100 = 10_000_000
    expect(scored.wasteScore).toBe(100_000 * 100);
  });

  it("applies logarithmic TB size multiplier capped at 2.0", () => {
    const oneTB = 1024 ** 4; // 1 TiB
    const tenTB = 10 * oneTB; // 10 TiB

    const smallBucket = computeWasteScore({
      accountId: "111111111111",
      bucketName: "small",
      region: "us-east-1",
      storageBytes: 1000,
      noncurrentBytes: 500,
      deleteMarkerCount: 0,
      incompleteMpuBytes: 0,
      incompleteMpuOlderThan7DaysBytes: 0,
    });

    const tbBucket = computeWasteScore({
      accountId: "111111111111",
      bucketName: "one-tb",
      region: "us-east-1",
      storageBytes: oneTB,
      noncurrentBytes: oneTB / 2, // 50% waste
      deleteMarkerCount: 0,
      incompleteMpuBytes: 0,
      incompleteMpuOlderThan7DaysBytes: 0,
    });

    const hugeBucket = computeWasteScore({
      accountId: "111111111111",
      bucketName: "ten-tb",
      region: "us-east-1",
      storageBytes: tenTB,
      noncurrentBytes: tenTB / 2, // 50% waste
      deleteMarkerCount: 0,
      incompleteMpuBytes: 0,
      incompleteMpuOlderThan7DaysBytes: 0,
    });

    // Both tbBucket and hugeBucket have 50% wasteScore
    expect(tbBucket.wasteScore).toBeCloseTo(50.0, 2);
    expect(hugeBucket.wasteScore).toBeCloseTo(50.0, 2);

    // 1 TB multiplier: 1 + log10(1 + 1) = 1 + 0.30103 = 1.30103
    // priority: 50 * 1.30103 ≈ 65.05
    expect(tbBucket.priority).toBeGreaterThan(smallBucket.priority);
    expect(tbBucket.priority).toBeCloseTo(50 * (1 + Math.log10(2)), 1);

    // 10 TB multiplier: 1 + log10(1 + 10) = 1 + 1.04139 = 2.04139 capped at 2.0
    // priority: 50 * 2.0 = 100.0
    expect(hugeBucket.priority).toBe(100.0);
  });

  it("rankStorageLensMetrics sorts buckets descending by priority", () => {
    const list: StorageLensBucketMetrics[] = [
      {
        accountId: "111111111111",
        bucketName: "low-priority",
        region: "us-east-1",
        storageBytes: 1000,
        noncurrentBytes: 100,
        deleteMarkerCount: 0,
        incompleteMpuBytes: 0,
        incompleteMpuOlderThan7DaysBytes: 0,
        wasteBytes: 100,
        wasteScore: 10,
        priority: 10,
        estimatedMonthlyWasteUSD: 0,
      },
      {
        accountId: "222222222222",
        bucketName: "high-priority",
        region: "us-east-1",
        storageBytes: 1_000_000,
        noncurrentBytes: 800_000,
        deleteMarkerCount: 0,
        incompleteMpuBytes: 0,
        incompleteMpuOlderThan7DaysBytes: 0,
        wasteBytes: 800_000,
        wasteScore: 80,
        priority: 80,
        estimatedMonthlyWasteUSD: 0,
      },
      {
        accountId: "333333333333",
        bucketName: "medium-priority",
        region: "us-east-1",
        storageBytes: 500_000,
        noncurrentBytes: 250_000,
        deleteMarkerCount: 0,
        incompleteMpuBytes: 0,
        incompleteMpuOlderThan7DaysBytes: 0,
        wasteBytes: 250_000,
        wasteScore: 50,
        priority: 50,
        estimatedMonthlyWasteUSD: 0,
      },
    ];

    const ranked = rankStorageLensMetrics(list);
    expect(ranked.map((b) => b.bucketName)).toEqual([
      "high-priority",
      "medium-priority",
      "low-priority",
    ]);
  });
});
