import { VolumetricRingBuffer } from "./ring-buffer.js";

export type CircuitBreakerState = "CLOSED" | "OPEN" | "HALF_OPEN";
export type CircuitOperation = "DeleteObjects" | "AbortMultipartUpload";

export interface CircuitBreakerOptions {
  windowSize?: number;
  baseCooldownMs?: number;
  initialConcurrency?: number;
  minConcurrency?: number;
  sustainedErrorThreshold?: number; // default 0.10 (10%)
  minSamplesForSustained?: number;  // default 5
}

export interface BatchErrorItem {
  Code?: string;
  Message?: string;
  name?: string;
  status?: number;
  $metadata?: { httpStatusCode?: number };
}

/**
 * Autonomous Circuit Breaker scoped by (bucket, operation).
 * Protects S3 buckets and execution pipelines against:
 *  - 403 AccessDenied permission cliffs (trips on 3 consecutive 403s)
 *  - 503 SlowDown / Throttling bursts (halves concurrency; trips on >= 3 in 5s or > 10% sustained error rate)
 *  - 400 BadDigest integrity corruption (immediate trip and quarantine)
 */
export class CircuitBreaker {
  public readonly bucket: string;
  public readonly operation: CircuitOperation;

  private state: CircuitBreakerState = "CLOSED";
  private readonly ringBuffer: VolumetricRingBuffer;
  private readonly baseCooldownMs: number;
  private readonly sustainedErrorThreshold: number;
  private readonly minSamplesForSustained: number;

  private initialConcurrency: number;
  private currentConcurrency: number;
  private minConcurrency: number;

  private consecutiveAccessDenied: number = 0;
  private throttleTimestamps: number[] = [];
  private tripCount: number = 0;
  private lastOpenedAt: number = 0;
  private currentCooldownMs: number = 0;
  private tripReason?: string;
  private quarantined: boolean = false;
  private halfOpenProbeInFlight: boolean = false;

  constructor(
    bucket: string,
    operation: CircuitOperation,
    options: CircuitBreakerOptions = {}
  ) {
    this.bucket = bucket;
    this.operation = operation;
    this.baseCooldownMs = options.baseCooldownMs ?? 5000;
    this.sustainedErrorThreshold = options.sustainedErrorThreshold ?? 0.1;
    this.minSamplesForSustained = options.minSamplesForSustained ?? 5;
    this.initialConcurrency = options.initialConcurrency ?? 10;
    this.currentConcurrency = this.initialConcurrency;
    this.minConcurrency = options.minConcurrency ?? 1;
    this.ringBuffer = new VolumetricRingBuffer(options.windowSize ?? 200);
  }

  // ─── Error Classification Helpers ──────────────────────────────────────────

  public static isAccessDenied(err: unknown): boolean {
    if (!err || typeof err !== "object") return false;
    const e = err as Record<string, unknown>;
    const code = String(e.Code || e.name || "");
    const status =
      (e.$metadata as Record<string, unknown> | undefined)?.httpStatusCode ??
      e.status ??
      e.statusCode;

    return (
      code === "AccessDenied" ||
      code === "AllAccessDisabled" ||
      code === "403" ||
      status === 403 ||
      /AccessDenied|Forbidden/i.test(String(e.Message || e.message || ""))
    );
  }

  public static isThrottle(err: unknown): boolean {
    if (!err || typeof err !== "object") return false;
    const e = err as Record<string, unknown>;
    const code = String(e.Code || e.name || "");
    const status =
      (e.$metadata as Record<string, unknown> | undefined)?.httpStatusCode ??
      e.status ??
      e.statusCode;

    return (
      code === "SlowDown" ||
      code === "Throttling" ||
      code === "ThrottlingException" ||
      code === "RequestTimeTooSkewed" ||
      code === "503" ||
      status === 503 ||
      /SlowDown|Throttling|Rate exceeded/i.test(String(e.Message || e.message || ""))
    );
  }

  public static isIntegrityError(err: unknown): boolean {
    if (!err || typeof err !== "object") return false;
    const e = err as Record<string, unknown>;
    const code = String(e.Code || e.name || "");
    const status =
      (e.$metadata as Record<string, unknown> | undefined)?.httpStatusCode ??
      e.status ??
      e.statusCode;

    return (
      code === "BadDigest" ||
      code === "ChecksumMismatch" ||
      code === "InvalidDigest" ||
      (status === 400 && /BadDigest|Checksum/i.test(String(e.Message || e.message || "")))
    );
  }

  // ─── State Machine & Transitions ───────────────────────────────────────────

  /**
   * Evaluates current state and checks whether execution is permitted.
   * Handles automatic transition from OPEN to HALF_OPEN when cooldown expires.
   */
  canExecute(): boolean {
    this.refreshState();

    if (this.state === "CLOSED") {
      return true;
    }

    if (this.state === "HALF_OPEN") {
      // In HALF_OPEN, allow a single canary/probe batch
      if (!this.halfOpenProbeInFlight) {
        this.halfOpenProbeInFlight = true;
        return true;
      }
      return false;
    }

    // OPEN state
    return false;
  }

  getState(): CircuitBreakerState {
    this.refreshState();
    return this.state;
  }

  getTripReason(): string | undefined {
    return this.tripReason;
  }

  isQuarantined(): boolean {
    return this.quarantined;
  }

  getErrorRate(): number {
    return this.ringBuffer.getErrorRate();
  }

  getErrorRatePercent(): number {
    return Math.round(this.getErrorRate() * 100);
  }

  getEffectiveConcurrency(): number {
    return this.currentConcurrency;
  }

  getConcurrency(): number {
    return this.currentConcurrency;
  }

  /**
   * Dynamically halves the current concurrency on throttling (503).
   */
  halveConcurrency(): number {
    this.currentConcurrency = Math.max(
      this.minConcurrency,
      Math.floor(this.currentConcurrency / 2)
    );
    return this.currentConcurrency;
  }

  /**
   * Restores concurrency gradually towards the initial limit after clean operations.
   */
  restoreConcurrency(): number {
    if (this.currentConcurrency < this.initialConcurrency) {
      this.currentConcurrency = Math.min(
        this.initialConcurrency,
        this.currentConcurrency + 1
      );
    }
    return this.currentConcurrency;
  }

  // ─── Outcome Recording ─────────────────────────────────────────────────────

  /**
   * Records a completely clean batch or single operation.
   */
  recordSuccess(count: number = 1): void {
    this.consecutiveAccessDenied = 0;
    this.ringBuffer.recordOutcome(0.0);
    this.restoreConcurrency();

    if (this.state === "HALF_OPEN") {
      // Probe in HALF_OPEN succeeded -> close circuit!
      this.state = "CLOSED";
      this.tripReason = undefined;
      this.halfOpenProbeInFlight = false;
      this.currentConcurrency = this.initialConcurrency;
    }
  }

  /**
   * Inspects batch execution results (such as DeleteObjects response.Errors).
   * Unconditionally inspects partial batch failures even when HTTP 200 was returned.
   */
  recordBatchResult(total: number, errors: BatchErrorItem[] = []): void {
    const errorCount = errors.length;
    const batchTotal = Math.max(total, errorCount);
    const errorRatio = batchTotal > 0 ? errorCount / batchTotal : 0;

    this.ringBuffer.recordOutcome(errorRatio);

    if (errorCount === 0) {
      this.recordSuccess(batchTotal);
      return;
    }

    // 1. Check for 400 BadDigest integrity error
    const hasBadDigest = errors.some((e) => CircuitBreaker.isIntegrityError(e));
    if (hasBadDigest) {
      this.quarantined = true;
      this.trip(
        "Immediate trip to OPEN: 400 BadDigest / ChecksumMismatch integrity error detected. Quarantining bucket operations."
      );
      return;
    }

    // 2. Check for 403 AccessDenied
    const hasAccessDenied = errors.some((e) => CircuitBreaker.isAccessDenied(e));
    if (hasAccessDenied) {
      this.consecutiveAccessDenied++;
      if (this.consecutiveAccessDenied >= 3) {
        this.trip(
          "Hard trip to OPEN: 3 consecutive 403 AccessDenied batch results. Aborting mutations to prevent permission cliff."
        );
        return;
      }
    } else {
      this.consecutiveAccessDenied = 0;
    }

    // 3. Check for 503 SlowDown / Throttling
    const hasThrottle = errors.some((e) => CircuitBreaker.isThrottle(e));
    if (hasThrottle) {
      this.halveConcurrency();
      const now = Date.now();
      // Keep throttle events within the last 5,000ms
      this.throttleTimestamps = this.throttleTimestamps.filter((t) => now - t < 5000);
      this.throttleTimestamps.push(now);

      if (this.throttleTimestamps.length >= 3) {
        this.trip(
          "Trip to OPEN: Throttling burst detected (>= 3 503 SlowDown responses within 5s)."
        );
        return;
      }
    }

    // 4. Check sustained moving error rate (> 10%)
    if (
      this.state === "CLOSED" &&
      this.ringBuffer.getCount() >= this.minSamplesForSustained &&
      this.ringBuffer.getErrorRate() > this.sustainedErrorThreshold
    ) {
      this.trip(
        `Trip to OPEN: Sustained error rate (${(this.ringBuffer.getErrorRate() * 100).toFixed(1)}%) exceeds ${(this.sustainedErrorThreshold * 100).toFixed(0)}% threshold.`
      );
      return;
    }

    // 5. If in HALF_OPEN and any errors occurred -> immediately re-trip to OPEN
    if (this.state === "HALF_OPEN") {
      this.trip(
        "Trip to OPEN: Probe in HALF_OPEN state encountered errors. Re-opening circuit."
      );
    }
  }

  /**
   * Records an unhandled exception thrown during execution (e.g. from AbortMultipartUploadCommand).
   */
  recordError(err: unknown): void {
    if (CircuitBreaker.isIntegrityError(err)) {
      this.quarantined = true;
      this.trip(
        "Immediate trip to OPEN: 400 BadDigest integrity error. Quarantining bucket operations."
      );
      return;
    }

    if (CircuitBreaker.isAccessDenied(err)) {
      this.consecutiveAccessDenied++;
      if (this.consecutiveAccessDenied >= 3) {
        this.trip(
          "Hard trip to OPEN: 3 consecutive 403 AccessDenied results. Aborting mutations."
        );
        return;
      }
    }

    if (CircuitBreaker.isThrottle(err)) {
      this.halveConcurrency();
      const now = Date.now();
      this.throttleTimestamps = this.throttleTimestamps.filter((t) => now - t < 5000);
      this.throttleTimestamps.push(now);

      if (this.throttleTimestamps.length >= 3) {
        this.trip(
          "Trip to OPEN: Throttling burst detected (>= 3 503 SlowDown responses within 5s)."
        );
        return;
      }
    }

    this.ringBuffer.recordOutcome(1.0);

    if (
      this.state === "CLOSED" &&
      this.ringBuffer.getCount() >= this.minSamplesForSustained &&
      this.ringBuffer.getErrorRate() > this.sustainedErrorThreshold
    ) {
      this.trip(
        `Trip to OPEN: Sustained error rate (${(this.ringBuffer.getErrorRate() * 100).toFixed(1)}%) exceeds ${(this.sustainedErrorThreshold * 100).toFixed(0)}% threshold.`
      );
      return;
    }

    if (this.state === "HALF_OPEN") {
      this.trip("Trip to OPEN: Probe in HALF_OPEN state failed. Re-opening circuit.");
    }
  }

  /**
   * Forcefully trips the circuit breaker to OPEN with a specific reason.
   */
  trip(reason: string): void {
    this.state = "OPEN";
    this.tripReason = reason;
    this.tripCount++;
    this.lastOpenedAt = Date.now();
    this.halfOpenProbeInFlight = false;

    // Exponential backoff: baseCooldown * 2^(tripCount - 1), capped at 2^5 (32x) + jitter (0..1000ms)
    const backoffFactor = Math.pow(2, Math.min(this.tripCount - 1, 5));
    const jitter = Math.floor(Math.random() * 1000);
    this.currentCooldownMs = this.baseCooldownMs * backoffFactor + jitter;
  }

  /**
   * Resets all internal metrics, buffer, and state back to CLOSED.
   */
  reset(): void {
    this.state = "CLOSED";
    this.ringBuffer.reset();
    this.consecutiveAccessDenied = 0;
    this.throttleTimestamps = [];
    this.tripCount = 0;
    this.lastOpenedAt = 0;
    this.currentCooldownMs = 0;
    this.tripReason = undefined;
    this.quarantined = false;
    this.halfOpenProbeInFlight = false;
    this.currentConcurrency = this.initialConcurrency;
  }

  // ─── Private Internal Helper ───────────────────────────────────────────────

  private refreshState(): void {
    if (this.state === "OPEN") {
      const elapsed = Date.now() - this.lastOpenedAt;
      if (elapsed >= this.currentCooldownMs) {
        this.state = "HALF_OPEN";
        this.halfOpenProbeInFlight = false;
      }
    }
  }
}
