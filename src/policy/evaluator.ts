import type { FleetScanResult } from "../fleet/scanner.js";

/** Exit codes enforced by the policy evaluator. */
export const EXIT_CODES = {
  /** Success, no policy violations. */
  SUCCESS: 0,
  /** Policy threshold breached (--max-waste-usd or --fail-on-unprotected). */
  POLICY_VIOLATION: 1,
  /** CLI argument / syntax error. */
  ARG_ERROR: 2,
  /** Account discovery / authentication failure. */
  DISCOVERY_AUTH_ERROR: 3,
} as const;

export type ExitCode = (typeof EXIT_CODES)[keyof typeof EXIT_CODES];

/** Options passed to the policy evaluator. */
export interface PolicyOptions {
  /** Fail if total estimated monthly waste exceeds this USD threshold. */
  maxWasteUSD?: number;
  /** Fail if any audited bucket lacks an active MPU lifecycle rule. */
  failOnUnprotected?: boolean;
}

/** A single policy violation entry. */
export interface PolicyViolation {
  rule: "MAX_WASTE_USD" | "FAIL_ON_UNPROTECTED";
  message: string;
}

/** Result of the policy evaluation. */
export interface PolicyEvaluationResult {
  violations: PolicyViolation[];
  exitCode: ExitCode;
}

/**
 * Evaluates fleet scan results against the configured policy flags.
 *
 * Rules:
 *  - `maxWasteUSD`: triggers POLICY_VIOLATION if total estimated monthly waste
 *    across all buckets exceeds the threshold.
 *  - `failOnUnprotected`: triggers POLICY_VIOLATION if any successfully audited
 *    bucket has no active MPU lifecycle rule (hasCoveringRule === false, and
 *    the lifecycle audit was not skipped due to provider quirks).
 *
 * Returns EXIT_CODES.SUCCESS (0) if no violations, POLICY_VIOLATION (1) otherwise.
 */
export function evaluatePolicy(
  result: FleetScanResult,
  options: PolicyOptions
): PolicyEvaluationResult {
  const violations: PolicyViolation[] = [];

  // Rule 1: max-waste-usd
  if (
    options.maxWasteUSD !== undefined &&
    result.totalEstimatedMonthlyWasteUSD > options.maxWasteUSD
  ) {
    violations.push({
      rule: "MAX_WASTE_USD",
      message:
        `Total estimated monthly waste $${result.totalEstimatedMonthlyWasteUSD.toFixed(2)}/mo ` +
        `exceeds threshold $${options.maxWasteUSD.toFixed(2)}/mo.`,
    });
  }

  // Rule 2: fail-on-unprotected
  if (options.failOnUnprotected) {
    const unprotectedBuckets = result.bucketResults.filter(
      (b) =>
        b.status === "AUDITED" &&
        b.lifecycleAudit !== undefined &&
        !b.lifecycleAudit.hasCoveringRule &&
        // Skip provider short-circuits (R2/MinIO) — they have native purge
        !b.lifecycleAudit.providerNotes
    );

    if (unprotectedBuckets.length > 0) {
      const names = unprotectedBuckets.map((b) => b.bucket).join(", ");
      violations.push({
        rule: "FAIL_ON_UNPROTECTED",
        message: `${unprotectedBuckets.length} bucket(s) have no active MPU lifecycle rule: ${names}`,
      });
    }
  }

  return {
    violations,
    exitCode:
      violations.length > 0 ? EXIT_CODES.POLICY_VIOLATION : EXIT_CODES.SUCCESS,
  };
}
