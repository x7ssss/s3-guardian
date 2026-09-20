import { describe, it, expect, vi } from "vitest";
import {
  parseHumanInterval,
  formatHumanInterval,
  startDaemon,
  DaemonHealthMetrics,
} from "../src/daemon/scheduler.js";
import { getLockFilePath } from "../src/daemon/lockfile.js";
import * as fs from "node:fs";

describe("Daemon Scheduler & Timing Engine", () => {
  describe("parseHumanInterval", () => {
    it("parses seconds shorthand", () => {
      expect(parseHumanInterval("45s")).toBe(45000);
      expect(parseHumanInterval("1s")).toBe(1000);
      expect(parseHumanInterval("0.5s")).toBe(500);
    });

    it("parses minutes shorthand", () => {
      expect(parseHumanInterval("30m")).toBe(1800000);
      expect(parseHumanInterval("1m")).toBe(60000);
    });

    it("parses hours shorthand", () => {
      expect(parseHumanInterval("1h")).toBe(3600000);
      expect(parseHumanInterval("12h")).toBe(43200000);
      expect(parseHumanInterval("24h")).toBe(86400000);
    });

    it("parses days shorthand", () => {
      expect(parseHumanInterval("1d")).toBe(86400000);
      expect(parseHumanInterval("7d")).toBe(604800000);
    });

    it("parses milliseconds shorthand", () => {
      expect(parseHumanInterval("500ms")).toBe(500);
      expect(parseHumanInterval("100ms")).toBe(100);
    });

    it("parses plain numeric string as milliseconds", () => {
      expect(parseHumanInterval("1500")).toBe(1500);
    });

    it("throws informative error on invalid format", () => {
      expect(() => parseHumanInterval("invalid")).toThrow(/Invalid interval format/);
      expect(() => parseHumanInterval("-5m")).toThrow(/Invalid interval format/);
      expect(() => parseHumanInterval("")).toThrow(/Invalid interval format/);
    });
  });

  describe("formatHumanInterval", () => {
    it("formats known round intervals", () => {
      expect(formatHumanInterval(86400000)).toBe("1d");
      expect(formatHumanInterval(3600000)).toBe("1h");
      expect(formatHumanInterval(43200000)).toBe("12h");
      expect(formatHumanInterval(60000)).toBe("1m");
      expect(formatHumanInterval(1000)).toBe("1s");
      expect(formatHumanInterval(500)).toBe("500ms");
    });
  });

  describe("startDaemon Execution Loop", () => {
    it("executes exactly maxRuns iterations and returns accurate summary", async () => {
      const lockName = "test-daemon-maxruns-" + Math.random().toString(36).slice(2, 8);
      const logs: string[] = [];
      const log = (msg: string) => logs.push(msg);

      let executions = 0;
      const progressList: DaemonHealthMetrics[] = [];

      const summary = await startDaemon({
        lockName,
        intervalMs: 10,
        maxRuns: 3,
        log,
        exitOnSignal: false,
        task: async (runIndex) => {
          executions++;
          return { wasteDetectedUSD: runIndex * 100 };
        },
        onProgress: (m) => {
          progressList.push(m);
        },
      });

      expect(executions).toBe(3);
      expect(summary.runCount).toBe(3);
      expect(summary.totalWasteDetectedUSD).toBe(300);
      expect(summary.isShuttingDown).toBe(false);
      expect(summary.memoryUsageMb).toBeGreaterThan(0);
      expect(progressList).toHaveLength(3);
      expect(progressList[0].runCount).toBe(1);
      expect(progressList[2].runCount).toBe(3);

      // Lock should be released
      const lockPath = getLockFilePath(lockName);
      expect(fs.existsSync(lockPath)).toBe(false);

      // Structured logs check
      expect(logs.some((l) => l.includes("[DAEMON] [STARTUP]"))).toBe(true);
      expect(logs.some((l) => l.includes("[DAEMON] [RUN #1]"))).toBe(true);
      expect(logs.some((l) => l.includes("[DAEMON] [RUN #3]"))).toBe(true);
    });

    it("aborts cleanly mid-interval when AbortSignal is fired", async () => {
      const lockName = "test-daemon-abort-" + Math.random().toString(36).slice(2, 8);
      const logs: string[] = [];
      const log = (msg: string) => logs.push(msg);

      const controller = new AbortController();
      let runs = 0;

      const daemonPromise = startDaemon({
        lockName,
        intervalMs: 5000, // 5 seconds interval
        signal: controller.signal,
        exitOnSignal: false,
        log,
        task: async () => {
          runs++;
          if (runs === 1) {
            // Abort after run 1 while it's about to sleep
            setTimeout(() => controller.abort(), 20);
          }
        },
      });

      const summary = await daemonPromise;
      expect(runs).toBe(1);
      expect(summary.runCount).toBe(1);

      // Lock released
      const lockPath = getLockFilePath(lockName);
      expect(fs.existsSync(lockPath)).toBe(false);
    });

    it("survives task errors without crashing the loop", async () => {
      const lockName = "test-daemon-errors-" + Math.random().toString(36).slice(2, 8);
      const logs: string[] = [];
      const errorLogs: string[] = [];

      let runs = 0;
      const summary = await startDaemon({
        lockName,
        intervalMs: 5,
        maxRuns: 2,
        log: (m) => logs.push(m),
        error: (m) => errorLogs.push(m),
        exitOnSignal: false,
        task: async (runIndex) => {
          runs++;
          if (runIndex === 1) {
            throw new Error("Simulated transient AWS error");
          }
          return { wasteDetectedUSD: 42.5 };
        },
      });

      expect(runs).toBe(2);
      expect(summary.runCount).toBe(2);
      expect(summary.totalWasteDetectedUSD).toBe(42.5);
      expect(errorLogs.some((e) => e.includes("Simulated transient AWS error"))).toBe(true);

      const lockPath = getLockFilePath(lockName);
      expect(fs.existsSync(lockPath)).toBe(false);
    });
  });
});
