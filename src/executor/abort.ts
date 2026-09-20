import { S3Client, AbortMultipartUploadCommand } from "@aws-sdk/client-s3";
import { Plan, ZombieUploadItem, validatePlan, readPlanFile } from "../planner/plan.js";
import { createConcurrencyLimiter } from "../utils/concurrency.js";
import { withRetry, RetryOptions } from "../utils/retry.js";
import { S3Provider } from "../providers/detector.js";

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
}

export interface ExecuteOptions {
  confirm?: boolean;
  provider?: S3Provider;
  forceWasabiEarlyDelete?: boolean;
  concurrencyLimit?: number;
  retryOptions?: RetryOptions;
  now?: Date;
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

  const concurrencyLimit = Math.min(options.concurrencyLimit ?? 10, 10);
  const limiter = createConcurrencyLimiter(concurrencyLimit);

  let aborted = 0;
  let skipped = 0;
  let failed = 0;
  let bytesFreed = 0;
  let completed = 0;
  const errors: AbortErrorItem[] = [];
  const items: AbortResultItem[] = [];
  const total = plan.uploads.length;

  await Promise.all(
    plan.uploads.map((item) =>
      limiter(async () => {
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
  };
}
