import {
  S3Client,
  DeleteObjectsCommand,
  DeleteObjectsCommandOutput,
  ObjectIdentifier,
} from "@aws-sdk/client-s3";
import { withRetry, isSlowDownError, RetryOptions } from "../utils/retry.js";

export interface TargetVersionIdentifier {
  Key: string;
  VersionId: string;
}

export interface VersionExecutorOptions {
  confirm: boolean;
  batchSize?: number;
  retryOptions?: RetryOptions;
  onProgress?: (deleted: number, total: number) => void;
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

  const batchSize = Math.min(
    MAX_BATCH_SIZE,
    Math.max(1, options.batchSize ?? MAX_BATCH_SIZE)
  );

  let totalDeleted = 0;
  const allErrors: VersionDeletionFailure[] = [];

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

      const response: DeleteObjectsCommandOutput = await withRetry(
        () =>
          client.send(
            new DeleteObjectsCommand({
              Bucket: bucket,
              Delete: {
                Objects: s3Objects,
                Quiet: true,
              },
            })
          ),
        options.retryOptions
      );

      const batchErrors = response.Errors ?? [];

      if (batchErrors.length === 0) {
        // Entire sub-batch succeeded
        totalDeleted += itemsToProcess.length;
        options.onProgress?.(totalDeleted, entries.length);
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
      options.onProgress?.(totalDeleted, entries.length);

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
  };
}
