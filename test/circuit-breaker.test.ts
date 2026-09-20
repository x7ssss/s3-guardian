import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { CircuitBreaker } from "../src/circuit/breaker.js";

describe("CircuitBreaker", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("initializes in CLOSED state with full concurrency", () => {
    const breaker = new CircuitBreaker("prod-bucket", "DeleteObjects", {
      initialConcurrency: 10,
    });

    expect(breaker.getState()).toBe("CLOSED");
    expect(breaker.canExecute()).toBe(true);
    expect(breaker.getEffectiveConcurrency()).toBe(10);
    expect(breaker.getErrorRate()).toBe(0);
    expect(breaker.isQuarantined()).toBe(false);
  });

  it("trips to OPEN on 3 consecutive 403 AccessDenied batches and resets on success", () => {
    const breaker = new CircuitBreaker("prod-bucket", "DeleteObjects");

    // Batch 1: AccessDenied
    breaker.recordBatchResult(100, [{ Code: "AccessDenied", Message: "Access Denied" }]);
    expect(breaker.getState()).toBe("CLOSED");
    expect(breaker.canExecute()).toBe(true);

    // Batch 2: AccessDenied
    breaker.recordBatchResult(100, [{ Code: "AccessDenied", Message: "Access Denied" }]);
    expect(breaker.getState()).toBe("CLOSED");

    // Clean batch: resets counter
    breaker.recordBatchResult(100, []);
    expect(breaker.getState()).toBe("CLOSED");

    // 2 more 403s
    breaker.recordBatchResult(100, [{ status: 403 }]);
    breaker.recordBatchResult(100, [{ status: 403 }]);
    expect(breaker.getState()).toBe("CLOSED");

    // 3rd consecutive 403 -> trips to OPEN!
    breaker.recordBatchResult(100, [{ status: 403 }]);
    expect(breaker.getState()).toBe("OPEN");
    expect(breaker.canExecute()).toBe(false);
    expect(breaker.getTripReason()).toContain("3 consecutive 403");
  });

  it("halves concurrency on 503 SlowDown and trips on burst (>= 3 in 5s)", () => {
    const breaker = new CircuitBreaker("prod-bucket", "DeleteObjects", {
      initialConcurrency: 10,
      minConcurrency: 1,
    });

    // 1st 503: halves concurrency 10 -> 5
    breaker.recordBatchResult(50, [{ Code: "SlowDown", Message: "Slow Down" }]);
    expect(breaker.getEffectiveConcurrency()).toBe(5);
    expect(breaker.getState()).toBe("CLOSED");

    // 2nd 503 after 1 second: halves concurrency 5 -> 2
    vi.advanceTimersByTime(1000);
    breaker.recordBatchResult(50, [{ Code: "SlowDown" }]);
    expect(breaker.getEffectiveConcurrency()).toBe(2);
    expect(breaker.getState()).toBe("CLOSED");

    // 3rd 503 within 5s: trips to OPEN!
    vi.advanceTimersByTime(1000);
    breaker.recordBatchResult(50, [{ Code: "SlowDown" }]);
    expect(breaker.getState()).toBe("OPEN");
    expect(breaker.getTripReason()).toContain("Throttling burst");
  });

  it("does not trip throttle burst if events are separated by > 5 seconds", () => {
    const breaker = new CircuitBreaker("prod-bucket", "DeleteObjects", {
      initialConcurrency: 10,
      minSamplesForSustained: 100, // prevent sustained trigger in this test
    });

    breaker.recordBatchResult(100, [{ Code: "SlowDown" }]);
    vi.advanceTimersByTime(6000);

    breaker.recordBatchResult(100, [{ Code: "SlowDown" }]);
    vi.advanceTimersByTime(6000);

    breaker.recordBatchResult(100, [{ Code: "SlowDown" }]);
    expect(breaker.getState()).toBe("CLOSED");
  });

  it("trips to OPEN immediately on 400 BadDigest and marks bucket as quarantined", () => {
    const breaker = new CircuitBreaker("prod-bucket", "DeleteObjects");

    breaker.recordBatchResult(10, [{ Code: "BadDigest", Message: "The specified Content-MD5 did not match" }]);

    expect(breaker.getState()).toBe("OPEN");
    expect(breaker.isQuarantined()).toBe(true);
    expect(breaker.getTripReason()).toContain("BadDigest");
  });

  it("trips to OPEN when sustained error rate exceeds 10%", () => {
    const breaker = new CircuitBreaker("prod-bucket", "DeleteObjects", {
      minSamplesForSustained: 5,
      sustainedErrorThreshold: 0.1,
    });

    // Record 5 batches with 20% error each
    for (let i = 0; i < 4; i++) {
      breaker.recordBatchResult(10, [{ Code: "InternalError" }, { Code: "InternalError" }]);
    }
    expect(breaker.getState()).toBe("CLOSED");

    // 5th batch pushes samples over minimum threshold with 20% error rate
    breaker.recordBatchResult(10, [{ Code: "InternalError" }, { Code: "InternalError" }]);
    expect(breaker.getState()).toBe("OPEN");
    expect(breaker.getTripReason()).toContain("Sustained error rate");
  });

  it("transitions to HALF_OPEN after cooldown and recovers to CLOSED on successful probe", () => {
    const breaker = new CircuitBreaker("prod-bucket", "DeleteObjects", {
      baseCooldownMs: 2000,
    });

    // Trip the breaker
    breaker.recordBatchResult(10, [{ Code: "BadDigest" }]);
    expect(breaker.getState()).toBe("OPEN");
    expect(breaker.canExecute()).toBe(false);

    // Advance timers by 4000ms (to surpass baseCooldown + jitter)
    vi.advanceTimersByTime(4000);

    // State transitions to HALF_OPEN
    expect(breaker.getState()).toBe("HALF_OPEN");
    expect(breaker.canExecute()).toBe(true);
    // While probe is in flight, second concurrent execution is blocked
    expect(breaker.canExecute()).toBe(false);

    // Probe succeeds with 0 errors
    breaker.recordSuccess(10);
    expect(breaker.getState()).toBe("CLOSED");
    expect(breaker.canExecute()).toBe(true);
  });

  it("re-trips to OPEN if HALF_OPEN probe encounters errors", () => {
    const breaker = new CircuitBreaker("prod-bucket", "DeleteObjects", {
      baseCooldownMs: 2000,
    });

    breaker.recordBatchResult(10, [{ Code: "BadDigest" }]);
    vi.advanceTimersByTime(4000);

    expect(breaker.getState()).toBe("HALF_OPEN");
    expect(breaker.canExecute()).toBe(true);

    // Probe fails with errors
    breaker.recordBatchResult(10, [{ Code: "InternalError" }]);
    expect(breaker.getState()).toBe("OPEN");
    expect(breaker.canExecute()).toBe(false);
  });

  it("handles recordError for thrown exceptions", () => {
    const breaker = new CircuitBreaker("prod-bucket", "AbortMultipartUpload");

    const err403 = new Error("Access Denied");
    (err403 as any).$metadata = { httpStatusCode: 403 };

    breaker.recordError(err403);
    breaker.recordError(err403);
    expect(breaker.getState()).toBe("CLOSED");

    breaker.recordError(err403);
    expect(breaker.getState()).toBe("OPEN");
    expect(breaker.getTripReason()).toContain("3 consecutive 403");
  });
});
