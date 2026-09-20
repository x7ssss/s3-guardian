import { acquireDaemonLock, DaemonLock } from "./lockfile.js";
import { AuditLogWriter } from "../state/audit-writer.js";
import { Compactor } from "../state/compaction.js";
import { createAuditEvent, AuditEventType } from "../state/types.js";

export interface DaemonTaskResult {
  wasteDetectedUSD?: number;
  message?: string;
  data?: unknown;
  bucketName?: string;
  accountId?: string;
  eventType?: AuditEventType;
  bytesFreed?: number;
  targetCount?: number;
  planHash?: string;
  xAmzRequestIds?: string[];
  circuitBreakerTripped?: boolean;
}

export interface DaemonHealthMetrics {
  runCount: number;
  totalWasteDetectedUSD: number;
  lastRunDurationMs: number;
  memoryUsageMb: number;
  rssMb: number;
  lastRunTimestamp: string;
}

export interface DaemonOptions {
  lockName: string;
  intervalMs?: number;
  jitterMs?: number;
  maxRuns?: number;
  task: (runIndex: number, auditWriter?: AuditLogWriter) => Promise<DaemonTaskResult | void>;
  log?: (msg: string) => void;
  error?: (msg: string) => void;
  signal?: AbortSignal;
  targetDescription?: string;
  exitOnSignal?: boolean;
  onProgress?: (metrics: DaemonHealthMetrics) => void | Promise<void>;
  stateDir?: string;
  auditWriter?: AuditLogWriter;
  s3MirrorBucket?: string;
  autoCompactIntervalMs?: number;
}

export interface DaemonSummary {
  runCount: number;
  totalWasteDetectedUSD: number;
  lastRunDurationMs: number;
  memoryUsageMb: number;
  isShuttingDown: boolean;
}

/**
 * Parses human duration string into milliseconds.
 * Supports: '1h', '30m', '12h', '24h', '45s', '500ms', or raw milliseconds string.
 */
export function parseHumanInterval(val: string): number {
  const trimmed = val.trim().toLowerCase();
  const match = trimmed.match(/^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)?$/);
  if (!match) {
    throw new Error(
      `Invalid interval format: "${val}". Supported formats: 10s, 30m, 1h, 12h, 24h`
    );
  }

  const num = parseFloat(match[1]);
  if (isNaN(num) || num < 0) {
    throw new Error(`Interval must be a positive number, received: "${val}"`);
  }

  const unit = match[2] || "ms";
  switch (unit) {
    case "ms":
      return Math.round(num);
    case "s":
      return Math.round(num * 1000);
    case "m":
      return Math.round(num * 60 * 1000);
    case "h":
      return Math.round(num * 60 * 60 * 1000);
    case "d":
      return Math.round(num * 24 * 60 * 60 * 1000);
    default:
      return Math.round(num);
  }
}

/**
 * Formats milliseconds into human-readable duration shorthand.
 */
export function formatHumanInterval(ms: number): string {
  if (ms >= 86400000 && ms % 86400000 === 0) return `${ms / 86400000}d`;
  if (ms >= 3600000 && ms % 3600000 === 0) return `${ms / 3600000}h`;
  if (ms >= 60000 && ms % 60000 === 0) return `${ms / 60000}m`;
  if (ms >= 1000 && ms % 1000 === 0) return `${ms / 1000}s`;
  return `${ms}ms`;
}

/**
 * Interruptible sleep between daemon iterations.
 * Immediately resolves with false if abort signal fires.
 */
function interruptibleSleep(ms: number, signal?: AbortSignal): Promise<boolean> {
  return new Promise((resolve) => {
    if (signal?.aborted) {
      resolve(false);
      return;
    }

    const timer = setTimeout(() => {
      cleanup();
      resolve(true);
    }, ms);

    const onAbort = () => {
      cleanup();
      resolve(false);
    };

    const cleanup = () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    };

    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

/**
 * Starts continuous in-process daemon execution.
 *
 * Invariants:
 * - Single-instance PID lockfile via acquireDaemonLock.
 * - Monotonic delta timing using process.hrtime.bigint() to eliminate interval drift under system load.
 * - Memory monitoring via process.memoryUsage() to detect heap bloat.
 * - Signal-safe graceful shutdown: traps SIGINT/SIGTERM, allows in-flight execution to complete,
 *   releases lockfile, and cleanly terminates.
 */
export async function startDaemon(options: DaemonOptions): Promise<DaemonSummary> {
  const log = options.log ?? console.log;
  const error = options.error ?? console.error;
  const intervalMs = options.intervalMs ?? 3600000; // 1 hour default
  const jitterMs = options.jitterMs ?? 0;
  const maxRuns = options.maxRuns ?? Infinity;
  const exitOnSignal = options.exitOnSignal ?? true;
  const targetDesc = options.targetDescription ?? options.lockName;

  // 1. Acquire single-instance lockfile
  const lock: DaemonLock = acquireDaemonLock(options.lockName);

  // 1b. Initialize Audit Log Writer if stateDir or auditWriter is configured
  const effectiveStateDir = options.stateDir ?? (options.auditWriter ? options.auditWriter.stateDir : undefined);
  let writer: AuditLogWriter | null =
    options.auditWriter ?? (effectiveStateDir ? new AuditLogWriter({ stateDir: effectiveStateDir }) : null);
  const autoCompactIntervalMs = options.autoCompactIntervalMs ?? 86400000; // 24h default
  let lastCompactTime = Date.now();

  // 2. Setup lifecycle state and abort handling
  const internalAbort = new AbortController();
  const effectiveSignal = options.signal
    ? AbortSignal.any([options.signal, internalAbort.signal])
    : internalAbort.signal;

  let isShuttingDown = false;
  let isTaskExecuting = false;
  let currentTaskPromise: Promise<unknown> | null = null;
  let runCount = 0;
  let totalWasteDetectedUSD = 0;
  let lastRunDurationMs = 0;

  // 3. Graceful shutdown handler for SIGINT & SIGTERM
  const handleShutdownSignal = async (sig: string) => {
    if (isShuttingDown) return;
    isShuttingDown = true;
    const nowIso = new Date().toISOString();
    log(`\n[${nowIso}] [DAEMON] [SHUTDOWN] ${sig} received. Awaiting in-flight execution to complete...`);

    internalAbort.abort();

    if (isTaskExecuting && currentTaskPromise) {
      try {
        await currentTaskPromise;
      } catch {
        // Task errors are handled within loop
      }
    }

    if (writer) {
      await writer.close().catch(() => {});
    }

    lock.release();
    log(`[${new Date().toISOString()}] [DAEMON] [SHUTDOWN] Lockfile released. Daemon stopped cleanly.`);

    if (exitOnSignal) {
      process.exit(0);
    }
  };

  const sigintListener = () => {
    void handleShutdownSignal("SIGINT");
  };
  const sigtermListener = () => {
    void handleShutdownSignal("SIGTERM");
  };

  process.on("SIGINT", sigintListener);
  process.on("SIGTERM", sigtermListener);

  const cleanupListeners = () => {
    process.removeListener("SIGINT", sigintListener);
    process.removeListener("SIGTERM", sigtermListener);
  };

  // 4. Structured startup banner
  const startIso = new Date().toISOString();
  log(
    `[${startIso}] [DAEMON] [STARTUP] Target: ${targetDesc} | PID: ${process.pid} | Interval: ${intervalMs}ms (${formatHumanInterval(
      intervalMs
    )}) | Lock: ${lock.lockFilePath}`
  );

  try {
    while (runCount < maxRuns && !effectiveSignal.aborted && !isShuttingDown) {
      runCount++;

      // Monotonic timer start
      const startHr = process.hrtime.bigint();
      const runTimestamp = new Date().toISOString();

      isTaskExecuting = true;
      try {
        currentTaskPromise = options.task(runCount, writer ?? undefined);
        const taskResult = (await currentTaskPromise) as DaemonTaskResult | void;
        if (
          taskResult &&
          typeof taskResult === "object" &&
          "wasteDetectedUSD" in taskResult &&
          typeof taskResult.wasteDetectedUSD === "number"
        ) {
          totalWasteDetectedUSD = taskResult.wasteDetectedUSD;
        }

        if (writer && taskResult && typeof taskResult === "object") {
          const evtType: AuditEventType = taskResult.eventType ?? "DISCOVERY";
          await writer.append(
            createAuditEvent({
              eventType: evtType,
              accountId: taskResult.accountId ?? "ambient",
              bucketName: taskResult.bucketName ?? options.lockName,
              targetCount: taskResult.targetCount,
              bytesFreed: taskResult.bytesFreed,
              estimatedSavingsUSD: taskResult.wasteDetectedUSD,
              planHash: taskResult.planHash,
              xAmzRequestIds: taskResult.xAmzRequestIds,
            })
          ).catch((err) => {
            error(`[${new Date().toISOString()}] [DAEMON] [AUDIT-ERROR] Failed to write audit event: ${err}`);
          });

          if (taskResult.circuitBreakerTripped) {
            await writer.append(
              createAuditEvent({
                eventType: "CIRCUIT_BREAKER_TRIPPED",
                accountId: taskResult.accountId ?? "ambient",
                bucketName: taskResult.bucketName ?? options.lockName,
              })
            ).catch(() => {});
          }
        } else if (writer) {
          await writer.append(
            createAuditEvent({
              eventType: "DISCOVERY",
              accountId: "ambient",
              bucketName: options.lockName,
              estimatedSavingsUSD: totalWasteDetectedUSD,
            })
          ).catch(() => {});
        }
      } catch (err: unknown) {
        const errMsg = err instanceof Error ? err.message : String(err);
        error(`[${new Date().toISOString()}] [DAEMON] [ERROR] Run #${runCount} failed: ${errMsg}`);
      } finally {
        isTaskExecuting = false;
        currentTaskPromise = null;
      }

      // Monotonic duration calculation (drift-free delta)
      const endHr = process.hrtime.bigint();
      lastRunDurationMs = Number(endHr - startHr) / 1_000_000;

      // Periodic Compaction Check
      if (effectiveStateDir && Date.now() - lastCompactTime >= autoCompactIntervalMs) {
        try {
          log(`[${new Date().toISOString()}] [DAEMON] [COMPACTION] Triggering periodic audit log compaction...`);
          await Compactor.compactAuditLog(effectiveStateDir, {
            writer: writer ?? undefined,
            s3MirrorBucket: options.s3MirrorBucket,
          });
          lastCompactTime = Date.now();
          writer = new AuditLogWriter({ stateDir: effectiveStateDir });
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          error(`[${new Date().toISOString()}] [DAEMON] [COMPACTION-ERROR] Periodic compaction failed: ${msg}`);
        }
      }

      // Memory inspection
      const mem = process.memoryUsage();
      const memoryUsageMb = Math.round((mem.heapUsed / (1024 * 1024)) * 100) / 100;
      const rssMb = Math.round((mem.rss / (1024 * 1024)) * 100) / 100;

      const metrics: DaemonHealthMetrics = {
        runCount,
        totalWasteDetectedUSD,
        lastRunDurationMs: Math.round(lastRunDurationMs * 100) / 100,
        memoryUsageMb,
        rssMb,
        lastRunTimestamp: runTimestamp,
      };

      if (options.onProgress) {
        try {
          await options.onProgress(metrics);
        } catch {
          // Progress hooks must not crash daemon
        }
      }

      // Calculate next delay compensating for task execution time (drift prevention)
      let nextDelayMs = Math.max(0, intervalMs - lastRunDurationMs);
      if (jitterMs > 0) {
        nextDelayMs += Math.floor(Math.random() * jitterMs);
      }

      const completedIso = new Date().toISOString();
      log(
        `[${completedIso}] [DAEMON] [RUN #${runCount}] Completed in ${Math.round(
          lastRunDurationMs
        )}ms | Waste: $${totalWasteDetectedUSD.toFixed(2)}/mo | Memory: ${memoryUsageMb} MB heap (${rssMb} MB RSS) | Next run in ~${Math.round(
          nextDelayMs
        )}ms`
      );

      // If finished maxRuns or shutting down, exit loop
      if (runCount >= maxRuns || effectiveSignal.aborted || isShuttingDown) {
        break;
      }

      // Sleep until next scheduled iteration (interruptible by signal)
      const sleptFullDuration = await interruptibleSleep(nextDelayMs, effectiveSignal);
      if (!sleptFullDuration || isShuttingDown) {
        break;
      }
    }
  } finally {
    if (writer) {
      await writer.close().catch(() => {});
    }
    cleanupListeners();
    lock.release();
  }

  const finalMem = process.memoryUsage();
  return {
    runCount,
    totalWasteDetectedUSD,
    lastRunDurationMs: Math.round(lastRunDurationMs * 100) / 100,
    memoryUsageMb: Math.round((finalMem.heapUsed / (1024 * 1024)) * 100) / 100,
    isShuttingDown,
  };
}
