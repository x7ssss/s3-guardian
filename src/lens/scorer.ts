import { calculateMonthlyCostUSD } from "../cost/estimator.js";

export interface StorageLensRawMetrics {
  accountId: string;
  bucketName: string;
  region: string;
  storageBytes: number;
  noncurrentBytes: number;
  deleteMarkerCount: number;
  incompleteMpuBytes: number;
  incompleteMpuOlderThan7DaysBytes: number;
}

export interface StorageLensBucketMetrics extends StorageLensRawMetrics {
  wasteBytes: number;
  wasteScore: number;
  priority: number;
  estimatedMonthlyWasteUSD: number;
}

const TB_BYTES = 1024 ** 4; // 1 TiB (1,099,511,627,776 bytes)

/**
 * Computes wasteScore, sizeMultiplier, and priority for a bucket's Storage Lens metrics.
 *
 * Invariant formulas:
 *  - Waste Bytes: noncurrentBytes + incompleteMpuOlderThan7DaysBytes
 *  - Waste Ratio (wasteScore): (wasteBytes / Math.max(storageBytes, 1)) * 100
 *  - Size Multiplier: Math.min(2.0, 1 + Math.log10(1 + storageBytes / (1024 ** 4)))
 *  - Priority: wasteScore * sizeMultiplier
 *  - Monthly Waste USD: calculateMonthlyCostUSD(wasteBytes)
 */
export function computeWasteScore(metrics: StorageLensRawMetrics): StorageLensBucketMetrics {
  const wasteBytes = metrics.noncurrentBytes + metrics.incompleteMpuOlderThan7DaysBytes;
  const wasteScore = (wasteBytes / Math.max(metrics.storageBytes, 1)) * 100;
  const sizeMultiplier = Math.min(2.0, 1 + Math.log10(1 + metrics.storageBytes / TB_BYTES));
  const priority = wasteScore * sizeMultiplier;
  const estimatedMonthlyWasteUSD = calculateMonthlyCostUSD(wasteBytes);

  return {
    ...metrics,
    wasteBytes,
    wasteScore,
    priority,
    estimatedMonthlyWasteUSD,
  };
}

/**
 * Ranks an array of Storage Lens bucket metrics descending by priority.
 * Secondary sort by wasteScore descending, then storageBytes descending.
 */
export function rankStorageLensMetrics(
  metricsList: StorageLensBucketMetrics[]
): StorageLensBucketMetrics[] {
  return [...metricsList].sort((a, b) => {
    if (b.priority !== a.priority) {
      return b.priority - a.priority;
    }
    if (b.wasteScore !== a.wasteScore) {
      return b.wasteScore - a.wasteScore;
    }
    return b.storageBytes - a.storageBytes;
  });
}
