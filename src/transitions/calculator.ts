/**
 * s3-guardian — Glacier & Storage Class Transition Cost Delta Calculator
 * 
 * Mathematical Precision Invariants:
 * - S3 Standard Baseline: $0.023 / GiB / month.
 * - S3 Standard-IA / One Zone-IA: 128 KiB (131,072 bytes) minimum billable size.
 * - S3 Glacier Instant Retrieval (GIR): 128 KiB (131,072 bytes) minimum billable size.
 * - S3 Glacier Flexible Retrieval (GFR) & Deep Archive (GDA): Fixed 40 KiB metadata overhead per object
 *   (8 KiB at Standard rate $0.023/GiB, 32 KiB at Glacier rate).
 * - Lifecycle Transition Request Fees: $0.01 / 1k for IA tiers, $0.05 / 1k for Glacier tiers.
 */

export const BYTES_PER_KIB = 1024;
export const BYTES_PER_GIB = 1024 * 1024 * 1024; // 1,073,741,824 bytes
export const S3_STANDARD_PRICE_PER_GIB_MONTH = 0.023; // $0.023 / GiB / month
export const MIN_BILLABLE_SIZE_128KIB = 128 * BYTES_PER_KIB; // 131,072 bytes

// Metadata overhead constants for GFR & GDA
export const METADATA_OVERHEAD_STANDARD_BYTES = 8 * BYTES_PER_KIB; // 8 KiB = 8,192 bytes
export const METADATA_OVERHEAD_GLACIER_BYTES = 32 * BYTES_PER_KIB; // 32 KiB = 32,768 bytes
export const METADATA_OVERHEAD_TOTAL_BYTES = 40 * BYTES_PER_KIB; // 40 KiB = 40,960 bytes

// Lifecycle transition request fees per 1,000 requests
export const TRANSITION_FEE_PER_1K_IA = 0.01; // $0.01 / 1,000
export const TRANSITION_FEE_PER_1K_GLACIER = 0.05; // $0.05 / 1,000

export interface StorageClassConfig {
  canonicalName: string;
  storagePricePerGiBMonth: number;
  minBillableSizeBytes: number;
  hasMetadataOverhead: boolean;
  transitionFeePer1k: number;
}

export const STORAGE_CLASS_CONFIGS: Record<string, StorageClassConfig> = {
  STANDARD: {
    canonicalName: "STANDARD",
    storagePricePerGiBMonth: 0.023,
    minBillableSizeBytes: 0,
    hasMetadataOverhead: false,
    transitionFeePer1k: 0,
  },
  STANDARD_IA: {
    canonicalName: "STANDARD_IA",
    storagePricePerGiBMonth: 0.0125,
    minBillableSizeBytes: MIN_BILLABLE_SIZE_128KIB,
    hasMetadataOverhead: false,
    transitionFeePer1k: TRANSITION_FEE_PER_1K_IA,
  },
  ONEZONE_IA: {
    canonicalName: "ONEZONE_IA",
    storagePricePerGiBMonth: 0.0100,
    minBillableSizeBytes: MIN_BILLABLE_SIZE_128KIB,
    hasMetadataOverhead: false,
    transitionFeePer1k: TRANSITION_FEE_PER_1K_IA,
  },
  GLACIER_IR: {
    canonicalName: "GLACIER_IR",
    storagePricePerGiBMonth: 0.0040,
    minBillableSizeBytes: MIN_BILLABLE_SIZE_128KIB,
    hasMetadataOverhead: false,
    transitionFeePer1k: TRANSITION_FEE_PER_1K_GLACIER,
  },
  GLACIER: {
    canonicalName: "GLACIER",
    storagePricePerGiBMonth: 0.0036,
    minBillableSizeBytes: 0,
    hasMetadataOverhead: true,
    transitionFeePer1k: TRANSITION_FEE_PER_1K_GLACIER,
  },
  DEEP_ARCHIVE: {
    canonicalName: "DEEP_ARCHIVE",
    storagePricePerGiBMonth: 0.00099,
    minBillableSizeBytes: 0,
    hasMetadataOverhead: true,
    transitionFeePer1k: TRANSITION_FEE_PER_1K_GLACIER,
  },
  INTELLIGENT_TIERING: {
    canonicalName: "INTELLIGENT_TIERING",
    storagePricePerGiBMonth: 0.0125, // Infrequent Access baseline
    minBillableSizeBytes: 0,
    hasMetadataOverhead: false,
    transitionFeePer1k: 0,
  },
};

/**
 * Normalizes user or AWS lifecycle storage class strings to standard enum key.
 */
export function normalizeStorageClass(rawClass: string): string {
  const upper = rawClass.trim().toUpperCase().replace(/-/g, "_");
  if (upper === "GIR" || upper === "GLACIER_INSTANT_RETRIEVAL") return "GLACIER_IR";
  if (upper === "GFR" || upper === "GLACIER_FLEXIBLE_RETRIEVAL") return "GLACIER";
  if (upper === "GDA" || upper === "GLACIER_DEEP_ARCHIVE") return "DEEP_ARCHIVE";
  if (upper === "INT" || upper === "INTELLIGENTTIERING") return "INTELLIGENT_TIERING";
  if (upper === "STANDARDIA") return "STANDARD_IA";
  if (upper === "ONEZONEIA") return "ONEZONE_IA";
  return upper;
}

/**
 * Returns configuration for a storage class, falling back to sensible heuristics if unknown.
 */
export function getStorageClassConfig(storageClass: string): StorageClassConfig {
  const normalized = normalizeStorageClass(storageClass);
  if (STORAGE_CLASS_CONFIGS[normalized]) {
    return STORAGE_CLASS_CONFIGS[normalized];
  }

  // Heuristics for non-standard or regional variants
  if (normalized.includes("DEEP")) {
    return {
      canonicalName: normalized,
      storagePricePerGiBMonth: 0.00099,
      minBillableSizeBytes: 0,
      hasMetadataOverhead: true,
      transitionFeePer1k: TRANSITION_FEE_PER_1K_GLACIER,
    };
  }
  if (normalized.includes("GLACIER_IR") || normalized.includes("GIR")) {
    return {
      canonicalName: normalized,
      storagePricePerGiBMonth: 0.0040,
      minBillableSizeBytes: MIN_BILLABLE_SIZE_128KIB,
      hasMetadataOverhead: false,
      transitionFeePer1k: TRANSITION_FEE_PER_1K_GLACIER,
    };
  }
  if (normalized.includes("GLACIER")) {
    return {
      canonicalName: normalized,
      storagePricePerGiBMonth: 0.0036,
      minBillableSizeBytes: 0,
      hasMetadataOverhead: true,
      transitionFeePer1k: TRANSITION_FEE_PER_1K_GLACIER,
    };
  }
  if (normalized.includes("IA")) {
    return {
      canonicalName: normalized,
      storagePricePerGiBMonth: 0.0125,
      minBillableSizeBytes: MIN_BILLABLE_SIZE_128KIB,
      hasMetadataOverhead: false,
      transitionFeePer1k: TRANSITION_FEE_PER_1K_IA,
    };
  }

  return {
    canonicalName: normalized,
    storagePricePerGiBMonth: 0.023,
    minBillableSizeBytes: 0,
    hasMetadataOverhead: false,
    transitionFeePer1k: 0,
  };
}

export interface TransitionCostParams {
  objectCount: number;
  averageSizeBytes: number;
  targetStorageClass: string;
  durationDays?: number;
}

export interface MetadataOverheadBreakdown {
  standardBytesPerObject: number;
  glacierBytesPerObject: number;
  standardCostMonthly: number;
  glacierCostMonthly: number;
  totalMonthly: number;
}

export interface TransitionCostResult {
  objectCount: number;
  averageSizeBytes: number;
  targetStorageClass: string;
  durationDays: number;
  baselineStandardCost: number;
  effectiveBillableSizeBytes: number;
  targetStorageCost: number;
  metadataOverheadCosts: MetadataOverheadBreakdown;
  transitionRequestCost: number;
  amortizedTransitionCostMonthly: number;
  targetMonthlyCost: number;
  netMonthlyDelta: number;
  isPenalty: boolean;
  breakevenMonths: number | null;
}

/**
 * Calculates exact cost comparison between staying in S3 Standard vs transitioning to target tier.
 * Accounts for:
 * - Baseline S3 Standard cost ($0.023/GiB/mo)
 * - 128 KiB minimum billable size floor for Standard-IA, One Zone-IA, and Glacier Instant Retrieval
 * - 40 KiB metadata overhead per object (8 KiB Standard rate + 32 KiB Glacier rate) for GFR and GDA
 * - Lifecycle transition request fees ($0.01/1k for IA, $0.05/1k for Glacier)
 * - Net monthly delta and penalty detection
 * - Breakeven threshold in months
 */
export function calculateTransitionCostDelta(params: TransitionCostParams): TransitionCostResult {
  const {
    objectCount,
    averageSizeBytes,
    targetStorageClass,
    durationDays = 30,
  } = params;

  const config = getStorageClassConfig(targetStorageClass);
  const safeCount = Math.max(0, objectCount);
  const safeAverageBytes = Math.max(0, averageSizeBytes);
  const safeDurationDays = Math.max(1, durationDays);

  // 1. Baseline Standard cost
  const totalRawBytes = safeCount * safeAverageBytes;
  const baselineStandardCost = (totalRawBytes / BYTES_PER_GIB) * S3_STANDARD_PRICE_PER_GIB_MONTH;

  // 2. Effective billable size per object in target tier
  const effectiveBillableSizeBytes =
    config.minBillableSizeBytes > 0
      ? Math.max(safeAverageBytes, config.minBillableSizeBytes)
      : safeAverageBytes;

  // 3. Target tier storage cost (excluding metadata overhead)
  const totalTargetStorageBytes = safeCount * effectiveBillableSizeBytes;
  const targetStorageCost = (totalTargetStorageBytes / BYTES_PER_GIB) * config.storagePricePerGiBMonth;

  // 4. Metadata overhead costs (8 KiB Standard + 32 KiB Glacier for GFR/GDA)
  let standardCostMonthly = 0;
  let glacierCostMonthly = 0;
  let standardBytesPerObject = 0;
  let glacierBytesPerObject = 0;

  if (config.hasMetadataOverhead && safeCount > 0) {
    standardBytesPerObject = METADATA_OVERHEAD_STANDARD_BYTES;
    glacierBytesPerObject = METADATA_OVERHEAD_GLACIER_BYTES;

    const totalStandardMetadataBytes = safeCount * METADATA_OVERHEAD_STANDARD_BYTES;
    const totalGlacierMetadataBytes = safeCount * METADATA_OVERHEAD_GLACIER_BYTES;

    standardCostMonthly = (totalStandardMetadataBytes / BYTES_PER_GIB) * S3_STANDARD_PRICE_PER_GIB_MONTH;
    glacierCostMonthly = (totalGlacierMetadataBytes / BYTES_PER_GIB) * config.storagePricePerGiBMonth;
  }

  const totalMetadataMonthly = standardCostMonthly + glacierCostMonthly;
  const metadataOverheadCosts: MetadataOverheadBreakdown = {
    standardBytesPerObject,
    glacierBytesPerObject,
    standardCostMonthly,
    glacierCostMonthly,
    totalMonthly: totalMetadataMonthly,
  };

  // 5. Transition request fees
  const transitionRequestCost = (safeCount / 1000) * config.transitionFeePer1k;
  const durationMonths = safeDurationDays / 30;
  const amortizedTransitionCostMonthly = transitionRequestCost / durationMonths;

  // 6. Target monthly cost and net monthly delta
  const targetMonthlyCost = targetStorageCost + totalMetadataMonthly + amortizedTransitionCostMonthly;
  const netMonthlyDelta = targetMonthlyCost - baselineStandardCost;
  const isPenalty = safeCount > 0 && netMonthlyDelta > 0;

  // 7. Breakeven threshold in months
  // Ongoing monthly savings = baseline standard cost - ongoing target monthly storage cost
  const ongoingTargetMonthlyCost = targetStorageCost + totalMetadataMonthly;
  const ongoingMonthlySavings = baselineStandardCost - ongoingTargetMonthlyCost;

  let breakevenMonths: number | null = null;
  if (safeCount > 0 && ongoingMonthlySavings > 0) {
    breakevenMonths = Math.round((transitionRequestCost / ongoingMonthlySavings) * 100) / 100;
  }

  return {
    objectCount: safeCount,
    averageSizeBytes: safeAverageBytes,
    targetStorageClass: config.canonicalName,
    durationDays: safeDurationDays,
    baselineStandardCost,
    effectiveBillableSizeBytes,
    targetStorageCost,
    metadataOverheadCosts,
    transitionRequestCost,
    amortizedTransitionCostMonthly,
    targetMonthlyCost,
    netMonthlyDelta,
    isPenalty,
    breakevenMonths,
  };
}
