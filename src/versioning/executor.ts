import {
  S3Client,
  DeleteObjectsCommand,
  DeleteObjectsCommandOutput,
  ObjectIdentifier,
} from "@aws-sdk/client-s3";
import { withRetry, isSlowDownError, RetryOptions } from "../utils/retry.js";
import { S3Provider } from "../providers/detector.js";

export interface TargetVersionIdentifier {
  Key: string;
  VersionId: string;
  LastModified?: string | Date;
}

export interface CloudTrailCorrelationBatch {
  requestId?: string;
  extendedRequestId?: string;
  batchSize: number;
  timestamp: string;
}

export interface VersionExecutorOptions {
  confirm: boolean;
  bypassGovernance?: boolean;
  provider?: S3Provider;
  forceWasabiEarlyDelete?: boolean;
  now?: Date;
  batchSize?: number;
  retryOptions?: RetryOptions;
  onProgress?: (
    deleted: number,
    total: number,
    correlation?: { requestId?: string; extendedRequestId?: string }
  ) => void;
}

export interface VersionDeletionFailure {
  Key: string;
  VersionId: string;
  Code?: string;
  Message?: string;
}

export interface VersionExecutionResult {
  total: number;
  deleted: number;
  failed: number;
  errors: VersionDeletionFailure[];
  correlations?: CloudTrailCorrelationBatch[];
}

const MAX_BATCH_SIZE = 1000;

function isTransientError(code?: string): boolean {
  if (!code) return false;
  return (
    code === "SlowDown" ||
    code === "Throttling" ||
    code === "InternalError" ||
    code === "ServiceUnavailable" ||
    code === "503"
  );
}

/**
 * Executes bulk deletion of specific object versions using DeleteObjectsCommand.
 *
 * Invariant 3: Quiet Bulk Deletion Safety:
 *  - Uses `Quiet: true` in batches of max 1,000 items.
 *  - UNCONDITIONALLY inspects `response.Errors` for partial batch failures.
 *  - Retries transient batch failures with full jitter backoff.
 *  - Strictly requires `options.confirm === true`.
 */
export async function executeVersionDeletion(
  client: S3Client,
  bucket: string,
  entries: TargetVersionIdentifier[],
  options: VersionExecutorOptions
): Promise<VersionExecutionResult> {
  if (options.confirm !== true) {
    throw new Error(
      "Safety check failed: The '--confirm' flag is strictly required to execute version deletions. No objects were deleted."
    );
  }

  // Wasabi 90-Day Retention Guard
  if (options.provider === "wasabi" && !options.forceWasabiEarlyDelete) {
    const now = options.now ?? new Date();
    const nowTime = now.getTime();
    const WASABI_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;
    const youngVersions = entries.filter((e) => {
      if (!e.LastModified) return false;
      const ts =
        e.LastModified instanceof Date
          ? e.LastModified.getTime()
          : new Date(e.LastModified).getTime();
      return !isNaN(ts) && nowTime - ts < WASABI_RETENTION_MS;
    });

    if (youngVersions.length > 0) {
      throw new Error(
        "⚠️ Wasabi charges 90 days minimum retention. Deleting objects < 90 days old triggers Timed Deleted Storage fees."
      );
    }
  }

  const batchSize = Math.min(
    MAX_BATCH_SIZE,
    Math.max(1, options.batchSize ?? MAX_BATCH_SIZE)
  );

  let totalDeleted = 0;
  const allErrors: VersionDeletionFailure[] = [];
  const correlations: CloudTrailCorrelationBatch[] = [];

  for (let i = 0; i < entries.length; i += batchSize) {
    const chunk = entries.slice(i, i + batchSize);
    let itemsToProcess: TargetVersionIdentifier[] = [...chunk];
    let attempt = 0;
    const maxRetries = options.retryOptions?.maxRetries ?? 3;

    while (itemsToProcess.length > 0) {
      attempt++;
      const s3Objects: ObjectIdentifier[] = itemsToProcess.map((e) => ({
        Key: e.Key,
        VersionId: e.VersionId === "null" ? "null" : e.VersionId,
      }));

      const deleteParams = {
        Bucket: bucket,
        Delete: {
          Objects: s3Objects,
          Quiet: true,
        },
        ...(options.bypassGovernance === true ? { BypassGovernanceRetention: true } : {}),
      };

      const response: DeleteObjectsCommandOutput = await withRetry(
        () => client.send(new DeleteObjectsCommand(deleteParams)),
        options.retryOptions
      );

      const requestId = response.$metadata?.requestId;
      const extendedRequestId = response.$metadata?.extendedRequestId;
      correlations.push({
        requestId,
        extendedRequestId,
        batchSize: s3Objects.length,
        timestamp: new Date().toISOString(),
      });

      const batchErrors = response.Errors ?? [];

      if (batchErrors.length === 0) {
        // Entire sub-batch succeeded
        totalDeleted += itemsToProcess.length;
        options.onProgress?.(totalDeleted, entries.length, {
          requestId,
          extendedRequestId,
        });
        break;
      }

      // Invariant 3: Inspect response.Errors and separate transient from permanent
      const transientItems: TargetVersionIdentifier[] = [];

      for (const err of batchErrors) {
        const key = err.Key ?? "";
        const versionId = err.VersionId ?? "";

        if (isTransientError(err.Code) && attempt <= maxRetries) {
          transientItems.push({ Key: key, VersionId: versionId });
        } else {
          allErrors.push({
            Key: key,
            VersionId: versionId,
            Code: err.Code,
            Message: err.Message,
          });
        }
      }

      const succeededThisPass = itemsToProcess.length - batchErrors.length;
      totalDeleted += Math.max(0, succeededThisPass);
      options.onProgress?.(totalDeleted, entries.length, {
        requestId,
        extendedRequestId,
      });

      if (transientItems.length > 0 && attempt <= maxRetries) {
        itemsToProcess = transientItems;
        // Jittered backoff before retrying transient items
        const delay = Math.floor(Math.random() * (100 * Math.pow(2, attempt)));
        await new Promise((res) => setTimeout(res, delay));
      } else {
        break;
      }
    }
  }

  return {
    total: entries.length,
    deleted: totalDeleted,
    failed: allErrors.length,
    errors: allErrors,
    correlations,
  };
}
