export interface MutationCeilingOptions {
  /** Relative ceiling fraction of total bucket inventory, e.g. 0.05 for 5% (default: 0.05) */
  maxPercent?: number;
  /** Hard upper limit fallback when total bucket inventory is unknown (default: 1000) */
  maxAbsoluteFallback?: number;
  /** Explicit override flag (--bypass-mutation-ceiling) */
  bypass?: boolean;
}

export interface MutationCeilingResult {
  allowed: boolean;
  reason?: string;
  limit: number;
  percentage?: number;
  estimatedInventory?: number;
}

/**
 * Enforces the Relative Mutation Ceiling (Invariant 5):
 * Caps autonomous deletions to <= 5% of total bucket inventory
 * (or 1,000 objects hard cap if inventory is unknown).
 * Requires --bypass-mutation-ceiling to exceed.
 */
export function evaluateMutationCeiling(
  plannedCount: number,
  estimatedInventory?: number,
  options: MutationCeilingOptions = {}
): MutationCeilingResult {
  const maxPercent = options.maxPercent ?? 0.05;
  const maxAbsoluteFallback = options.maxAbsoluteFallback ?? 1000;
  const bypass = options.bypass === true;

  const count = Math.max(0, plannedCount);

  // If inventory is known and positive: calculate proportional limit
  if (typeof estimatedInventory === "number" && Number.isFinite(estimatedInventory) && estimatedInventory > 0) {
    const limit = Math.floor(estimatedInventory * maxPercent);
    const percentage = count / estimatedInventory;

    if (bypass) {
      return {
        allowed: true,
        limit,
        percentage,
        estimatedInventory,
        reason: "Bypassed via --bypass-mutation-ceiling",
      };
    }

    if (count <= limit) {
      return {
        allowed: true,
        limit,
        percentage,
        estimatedInventory,
      };
    }

    const pctDisplay = (maxPercent * 100).toFixed(1);
    return {
      allowed: false,
      limit,
      percentage,
      estimatedInventory,
      reason: `Planned mutations (${count}) exceed relative safety ceiling of ${pctDisplay}% (${limit} objects) of estimated inventory (${estimatedInventory}). Run with --bypass-mutation-ceiling to proceed.`,
    };
  }

  // Fallback: inventory is unknown or zero -> enforce absolute fallback ceiling (1,000 objects)
  const limit = maxAbsoluteFallback;

  if (bypass) {
    return {
      allowed: true,
      limit,
      reason: "Bypassed via --bypass-mutation-ceiling",
    };
  }

  if (count <= limit) {
    return {
      allowed: true,
      limit,
    };
  }

  return {
    allowed: false,
    limit,
    reason: `Planned mutations (${count}) exceed absolute safety fallback ceiling of ${limit} objects (bucket inventory unknown). Run with --bypass-mutation-ceiling to proceed.`,
  };
}
