import { describe, it, expect } from "vitest";
import {
  calculateMonthlyCostUSD,
  formatMonthlyCost,
  formatBytes,
  BYTES_PER_GIB,
  S3_STANDARD_PRICE_PER_GIB_MONTH,
} from "../src/cost/estimator.js";

describe("Cost Estimator and Byte Formatter", () => {
  describe("formatBytes", () => {
    it("formats 0 bytes", () => {
      expect(formatBytes(0)).toBe("0 B");
      expect(formatBytes(-100)).toBe("0 B");
    });

    it("formats bytes below 1 KB", () => {
      expect(formatBytes(512)).toBe("512 B");
      expect(formatBytes(1023)).toBe("1023 B");
    });

    it("formats Kilobytes", () => {
      expect(formatBytes(1024)).toBe("1.00 KB");
      expect(formatBytes(1536)).toBe("1.50 KB");
    });

    it("formats Megabytes", () => {
      expect(formatBytes(1024 * 1024)).toBe("1.00 MB");
      expect(formatBytes(25 * 1024 * 1024)).toBe("25.00 MB");
    });

    it("formats Gigabytes", () => {
      expect(formatBytes(BYTES_PER_GIB)).toBe("1.00 GB");
      expect(formatBytes(2.5 * BYTES_PER_GIB)).toBe("2.50 GB");
    });

    it("formats Terabytes", () => {
      const tb = BYTES_PER_GIB * 1024;
      expect(formatBytes(tb)).toBe("1.00 TB");
      expect(formatBytes(3.75 * tb)).toBe("3.75 TB");
    });
  });

  describe("calculateMonthlyCostUSD", () => {
    it("returns 0 for 0 or negative bytes", () => {
      expect(calculateMonthlyCostUSD(0)).toBe(0);
      expect(calculateMonthlyCostUSD(-1024)).toBe(0);
    });

    it("calculates cost for 1 GiB using S3 Standard baseline ($0.023/GB/mo)", () => {
      // 1 GiB = 1024^3 bytes => 1 * 0.023 = 0.023 => rounds to $0.02
      expect(calculateMonthlyCostUSD(BYTES_PER_GIB)).toBe(0.02);
    });

    it("calculates cost for 100 GiB", () => {
      // 100 GiB * 0.023 = 2.30
      expect(calculateMonthlyCostUSD(100 * BYTES_PER_GIB)).toBe(2.3);
    });

    it("calculates cost for 1 TiB (1024 GiB)", () => {
      // 1024 GiB * 0.023 = 23.552 => rounds to 23.55
      expect(calculateMonthlyCostUSD(1024 * BYTES_PER_GIB)).toBe(23.55);
    });

    it("supports custom price per GiB", () => {
      expect(calculateMonthlyCostUSD(100 * BYTES_PER_GIB, 0.015)).toBe(1.5);
    });
  });

  describe("formatMonthlyCost", () => {
    it("formats 0 dollars", () => {
      expect(formatMonthlyCost(0)).toBe("$0.00/mo");
    });

    it("formats cents", () => {
      expect(formatMonthlyCost(0.02)).toBe("$0.02/mo");
      expect(formatMonthlyCost(2.3)).toBe("$2.30/mo");
      expect(formatMonthlyCost(1234.56)).toBe("$1234.56/mo");
    });
  });
});
