import { describe, it, expect } from "vitest";
import { evaluateMutationCeiling } from "../src/safety/mutation-budget.js";

describe("evaluateMutationCeiling", () => {
  it("allows deletions within 5% of known inventory", () => {
    // Inventory = 10,000; 5% = 500
    const result = evaluateMutationCeiling(500, 10000);
    expect(result.allowed).toBe(true);
    expect(result.limit).toBe(500);
    expect(result.percentage).toBeCloseTo(0.05, 3);
  });

  it("blocks deletions exceeding 5% of known inventory", () => {
    // Inventory = 10,000; 5% = 500. Planned = 501
    const result = evaluateMutationCeiling(501, 10000);
    expect(result.allowed).toBe(false);
    expect(result.limit).toBe(500);
    expect(result.reason).toContain("exceed relative safety ceiling of 5.0% (500 objects)");
    expect(result.reason).toContain("--bypass-mutation-ceiling");
  });

  it("allows custom maxPercent override", () => {
    // Inventory = 10,000; 10% = 1000
    const result = evaluateMutationCeiling(800, 10000, { maxPercent: 0.1 });
    expect(result.allowed).toBe(true);
    expect(result.limit).toBe(1000);
  });

  it("enforces fallback limit of 1,000 objects when inventory is unknown", () => {
    const ok = evaluateMutationCeiling(1000);
    expect(ok.allowed).toBe(true);
    expect(ok.limit).toBe(1000);

    const blocked = evaluateMutationCeiling(1001);
    expect(blocked.allowed).toBe(false);
    expect(blocked.limit).toBe(1000);
    expect(blocked.reason).toContain("exceed absolute safety fallback ceiling of 1000 objects");
    expect(blocked.reason).toContain("--bypass-mutation-ceiling");
  });

  it("permits exceeding limits when bypass is true", () => {
    // Over known inventory limit
    const resKnown = evaluateMutationCeiling(5000, 10000, { bypass: true });
    expect(resKnown.allowed).toBe(true);
    expect(resKnown.reason).toContain("Bypassed");

    // Over unknown inventory limit
    const resUnknown = evaluateMutationCeiling(5000, undefined, { bypass: true });
    expect(resUnknown.allowed).toBe(true);
    expect(resUnknown.reason).toContain("Bypassed");
  });

  it("handles zero planned mutations", () => {
    const res = evaluateMutationCeiling(0, 5000);
    expect(res.allowed).toBe(true);
    expect(res.limit).toBe(250);
  });
});
