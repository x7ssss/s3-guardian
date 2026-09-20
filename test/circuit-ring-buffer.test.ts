import { describe, it, expect } from "vitest";
import { VolumetricRingBuffer } from "../src/circuit/ring-buffer.js";

describe("VolumetricRingBuffer", () => {
  it("initializes with default window size of 200 and zero error rate", () => {
    const ring = new VolumetricRingBuffer();
    expect(ring.getWindowSize()).toBe(200);
    expect(ring.getCount()).toBe(0);
    expect(ring.getErrorRate()).toBe(0);
  });

  it("calculates accurate moving average error rates in O(1)", () => {
    const ring = new VolumetricRingBuffer(4);

    ring.recordOutcome(0.0);
    expect(ring.getCount()).toBe(1);
    expect(ring.getErrorRate()).toBe(0.0);

    ring.recordOutcome(1.0);
    expect(ring.getCount()).toBe(2);
    expect(ring.getErrorRate()).toBe(0.5);

    ring.recordOutcome(0.5);
    expect(ring.getCount()).toBe(3);
    expect(ring.getErrorRate()).toBeCloseTo(0.5, 3);

    ring.recordOutcome(0.5);
    expect(ring.getCount()).toBe(4);
    // (0.0 + 1.0 + 0.5 + 0.5) / 4 = 2.0 / 4 = 0.5
    expect(ring.getErrorRate()).toBeCloseTo(0.5, 3);

    // Overwrite oldest item (0.0) with 1.0
    ring.recordOutcome(1.0);
    expect(ring.getCount()).toBe(4);
    // (1.0 + 0.5 + 0.5 + 1.0) / 4 = 3.0 / 4 = 0.75
    expect(ring.getErrorRate()).toBeCloseTo(0.75, 3);
  });

  it("clamps input error ratios outside [0, 1]", () => {
    const ring = new VolumetricRingBuffer(2);
    ring.recordOutcome(-0.5);
    expect(ring.getErrorRate()).toBe(0);

    ring.recordOutcome(2.5);
    // (0 + 1) / 2 = 0.5
    expect(ring.getErrorRate()).toBe(0.5);
  });

  it("resets state completely on reset()", () => {
    const ring = new VolumetricRingBuffer(5);
    ring.recordOutcome(1.0);
    ring.recordOutcome(0.8);
    expect(ring.getCount()).toBe(2);
    expect(ring.getErrorRate()).toBeGreaterThan(0);

    ring.reset();
    expect(ring.getCount()).toBe(0);
    expect(ring.getErrorRate()).toBe(0);
  });

  it("rejects non-positive window sizes", () => {
    expect(() => new VolumetricRingBuffer(0)).toThrow();
    expect(() => new VolumetricRingBuffer(-10)).toThrow();
    expect(() => new VolumetricRingBuffer(2.5)).toThrow();
  });
});
