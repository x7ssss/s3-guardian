import { S3Client, AbortMultipartUploadCommand } from "@aws-sdk/client-s3";
import { Plan, ZombieUploadItem, validatePlan, readPlanFile } from "../planner/plan.js";
import { createConcurrencyLimiter } from "../utils/concurrency.js";
import { withRetry, RetryOptions } from "../utils/retry.js";
import { S3Provider } from "../providers/detector.js";
import { evaluateMutationCeiling } from "../safety/mutation-budget.js";
import { executeCanaryGate, CanaryVerificationError } from "../safety/canary.js";
import { CircuitBreaker } from "../circuit/breaker.js";

export type AbortItemStatus = "ABORTED" | "SKIPPED_ALREADY_ABORTED" | "FAILED";

export interface AbortErrorItem {
  key: string;
  uploadId: string;
  error: string;
}

export interface AbortResultItem {
  key: string;
  uploadId: string;
  status: AbortItemStatus;
  bytes: number;
  error?: string;
  requestId?: string;
  extendedRequestId?: string;
}

export interface AbortResult {
  total: number;
  aborted: number;
  skipped: number;
  failed: number;
  bytesFreed: number;
  errors: AbortErrorItem[];
  items?: AbortResultItem[];
  circuitBreaker?: CircuitBreaker;
}

export interface ExecuteOptions {
  confirm?: boolean;
  provider?: S3Provider;
  forceWasabiEarlyDelete?: boolean;
  concurrencyLimit?: number;
  retryOptions?: RetryOptions;
  now?: Date;
  estimatedInventory?: number;
  bypassMutationCeiling?: boolean;
  maxDeletionPercent?: number;
  skipCanary?: boolean;
  circuitBreaker?: CircuitBreaker;
  onProgress?: (
    completed: number,
    total: number,
    currentItem: ZombieUploadItem,
    status: AbortItemStatus,
    correlation?: { requestId?: string; extendedRequestId?: string }
  ) => void;
}

/**
 * Checks if an error indicates that the upload was already aborted or completed.
 */
export function isNoSuchUploadError(err: unknown): boolean {
  if (!err || typeof err !== "object") return false;
  const errorObj = err as Record<string, unknown>;
  const name = String(errorObj.name || errorObj.Code || "");
  const status =
    (errorObj.$metadata as Record<string, unknown> | undefined)?.httpStatusCode ??
    errorObj.statusCode ??
    errorObj.status;
  const message = String(errorObj.message || "");

  return (
    name === "NoSuchUpload" ||
    name === "NotFound" ||
    status === 404 ||
    /NoSuchUpload|specified upload does not exist/i.test(message)
  );
}

/**
 * Consumes a Plan (or path to plan.json), validates the schema,
 * checks the --confirm flag, and executes AbortMultipartUploadCommand
 * with bounded concurrency (max 10) and exponential backoff retry.
 *
 * Gracefully handles NoSuchUpload / 404 errors as SKIPPED_ALREADY_ABORTED
 * instead of throwing or failing the batch.
 */
export async function executeAbortPlan(
  client: S3Client,
  planOrPath: Plan | string,
  options: ExecuteOptions = {}
): Promise<AbortResult> {
  // Safety Invariant: --confirm is strictly mandatory
  if (options.confirm !== true) {
    throw new Error(
      "Safety check failed: The '--confirm' flag is strictly required to execute abort operations. No changes were made."
    );
  }

  const plan: Plan =
    typeof planOrPath === "string"
      ? await readPlanFile(planOrPath)
      : validatePlan(planOrPath);

  // Wasabi 90-Day Retention Guard
  if (options.provider === "wasabi" && !options.forceWasabiEarlyDelete) {
    const now = options.now ?? new Date();
    const nowTime = now.getTime();
    const WASABI_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;
    const youngUploads = plan.uploads.filter((u) => {
      if (!u.initiated) return false;
      const ts = new Date(u.initiated).getTime();
      return !isNaN(ts) && nowTime - ts < WASABI_RETENTION_MS;
    });

    if (youngUploads.length > 0) {
      throw new Error(
        "⚠️ Wasabi charges 90 days minimum retention. Deleting objects < 90 days old triggers Timed Deleted Storage fees."
      );
    }
  }

  // 1. Relative Mutation Ceiling (Invariant 5)
  const ceiling = evaluateMutationCeiling(
    plan.uploads.length,
    options.estimatedInventory ?? (plan as any).estimatedInventory,
    {
      maxPercent: options.maxDeletionPercent,
      bypass: options.bypassMutationCeiling,
    }
  );
  if (!ceiling.allowed) {
    throw new Error(`Safety check failed: ${ceiling.reason}`);
  }

  // 2. Circuit Breaker initialization
  const breaker =
    options.circuitBreaker ??
    new CircuitBreaker(plan.bucket, "AbortMultipartUpload", {
      initialConcurrency: options.concurrencyLimit ?? 10,
    });

  let aborted = 0;
  let skipped = 0;
  let failed = 0;
  let bytesFreed = 0;
  let completed = 0;
  const errors: AbortErrorItem[] = [];
  const items: AbortResultItem[] = [];
  const total = plan.uploads.length;
  let targetsToProcess = plan.uploads;

  // 3. Canary Gate (Invariant 6)
  if (!options.skipCanary && plan.uploads.length > 0) {
    try {
      const canaryResult = await executeCanaryGate(client, plan.bucket, plan.uploads, breaker, {
        retryOptions: options.retryOptions,
      });

      for (const outcome of canaryResult.outcomes) {
        completed++;
        if (outcome.status === "ABORTED") {
          aborted++;
          bytesFreed += outcome.bytes ?? 0;
          items.push({
            key: outcome.key,
            uploadId: outcome.uploadId ?? "",
            status: "ABORTED",
            bytes: outcome.bytes ?? 0,
            requestId: outcome.requestId,
          });
          const target = canaryResult.canaryTargets.find((c: any) => c.uploadId === outcome.uploadId);
          if (target) {
            options.onProgress?.(completed, total, target, "ABORTED", { requestId: outcome.requestId });
          }
        } else if (outcome.status === "SKIPPED_ALREADY_ABORTED") {
          skipped++;
          items.push({
            key: outcome.key,
            uploadId: outcome.uploadId ?? "",
            status: "SKIPPED_ALREADY_ABORTED",
            bytes: 0,
          });
          const target = canaryResult.canaryTargets.find((c: any) => c.uploadId === outcome.uploadId);
          if (target) {
            options.onProgress?.(completed, total, target, "SKIPPED_ALREADY_ABORTED");
          }
        }
      }

      targetsToProcess = canaryResult.remainingTargets;
    } catch (err: unknown) {
      if (err instanceof CanaryVerificationError) {
        const processedUploadIds = new Set<string>();

        if (err.outcomes && err.outcomes.length > 0) {
          for (const outcome of err.outcomes) {
            if (outcome.uploadId) processedUploadIds.add(outcome.uploadId);
            completed++;
            if (outcome.status === "ABORTED") {
              aborted++;
              bytesFreed += outcome.bytes ?? 0;
              items.push({
                key: outcome.key,
                uploadId: outcome.uploadId ?? "",
                status: "ABORTED",
                bytes: outcome.bytes ?? 0,
                requestId: outcome.requestId,
              });
            } else if (outcome.status === "SKIPPED_ALREADY_ABORTED") {
              skipped++;
              items.push({
                key: outcome.key,
                uploadId: outcome.uploadId ?? "",
                status: "SKIPPED_ALREADY_ABORTED",
                bytes: 0,
              });
            } else if (outcome.status === "FAILED") {
              failed++;
              const errorMsg = outcome.error ?? err.message;
              errors.push({
                key: outcome.key,
                uploadId: outcome.uploadId ?? "",
                error: errorMsg,
              });
              items.push({
                key: outcome.key,
                uploadId: outcome.uploadId ?? "",
                status: "FAILED",
                bytes: 0,
                error: errorMsg,
              });
            }
          }
        }

        if (err.outcomes.length === 0 && err.errors && err.errors.length > 0) {
          for (const e of err.errors) {
            failed++;
            completed++;
            errors.push({
              key: e.key,
              uploadId: e.uploadId,
              error: e.error,
            });
            items.push({
              key: e.key,
              uploadId: e.uploadId,
              status: "FAILED",
              bytes: 0,
              error: e.error,
            });
          }
        }

        // Account for any remaining uploads not processed due to early canary halt
        for (const item of plan.uploads) {
          if (!processedUploadIds.has(item.uploadId) && !items.some((i) => i.uploadId === item.uploadId)) {
            failed++;
            completed++;
            const reason = `Aborted due to canary failure: ${err.message}`;
            errors.push({
              key: item.key,
              uploadId: item.uploadId,
              error: reason,
            });
            items.push({
              key: item.key,
              uploadId: item.uploadId,
              status: "FAILED",
              bytes: 0,
              error: reason,
            });
          }
        }

        return {
          total,
          aborted,
          skipped,
          failed,
          bytesFreed,
          errors,
          items,
          circuitBreaker: breaker,
        };
      }
      throw err;
    }
  }

  // 4. Batch loop with Circuit Breaker & dynamic concurrency
  const initialLimit = Math.min(options.concurrencyLimit ?? 10, 10);
  const limiter = createConcurrencyLimiter(initialLimit);
  let breakerTripped = false;

  await Promise.all(
    targetsToProcess.map((item) =>
      limiter(async () => {
        if (breakerTripped || !breaker.canExecute()) {
          breakerTripped = true;
          failed++;
          const status: AbortItemStatus = "FAILED";
          const errorMessage = `Circuit breaker tripped to OPEN: ${breaker.getTripReason()}`;
          errors.push({
            key: item.key,
            uploadId: item.uploadId,
            error: errorMessage,
          });
          items.push({
            key: item.key,
            uploadId: item.uploadId,
            status,
            bytes: item.bytes,
            error: errorMessage,
          });
          completed++;
          return;
        }

        let status: AbortItemStatus = "ABORTED";
        let errorMessage: string | undefined = undefined;
        let requestId: string | undefined = undefined;
        let extendedRequestId: string | undefined = undefined;

        try {
          const res = await withRetry(
            () =>
              client.send(
                new AbortMultipartUploadCommand({
                  Bucket: plan.bucket,
                  Key: item.key,
                  UploadId: item.uploadId,
                })
              ),
            options.retryOptions
          );

          requestId = res?.$metadata?.requestId;
          extendedRequestId = res?.$metadata?.extendedRequestId;
          aborted++;
          bytesFreed += item.bytes;
          breaker.recordSuccess();
        } catch (err: unknown) {
          if (isNoSuchUploadError(err)) {
            // Upload was completed or aborted externally since plan creation:
            // catch gracefully, mark as SKIPPED_ALREADY_ABORTED, do not fail batch.
            skipped++;
            status = "SKIPPED_ALREADY_ABORTED";
          } else {
            failed++;
            status = "FAILED";
            errorMessage =
              err instanceof Error ? err.message : String(err);
            errors.push({
              key: item.key,
              uploadId: item.uploadId,
              error: errorMessage,
            });
            breaker.recordError(err);
            if (breaker.getState() === "OPEN") {
              breakerTripped = true;
            }
          }
        } finally {
          completed++;
          items.push({
            key: item.key,
            uploadId: item.uploadId,
            status,
            bytes: item.bytes,
            error: errorMessage,
            requestId,
            extendedRequestId,
          });
          options.onProgress?.(completed, total, item, status, {
            requestId,
            extendedRequestId,
          });
        }
      })
    )
  );

  return {
    total,
    aborted,
    skipped,
    failed,
    bytesFreed,
    errors,
    items,
    circuitBreaker: breaker,
  };
}
