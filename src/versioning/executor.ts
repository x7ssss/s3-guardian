import {
  S3Client,
  DeleteObjectsCommand,
  DeleteObjectsCommandOutput,
  ObjectIdentifier,
} from "@aws-sdk/client-s3";
import { withRetry, isSlowDownError, RetryOptions } from "../utils/retry.js";
import { S3Provider } from "../providers/detector.js";
import { evaluateMutationCeiling } from "../safety/mutation-budget.js";
import { executeCanaryGate, CanaryVerificationError } from "../safety/canary.js";
import { CircuitBreaker } from "../circuit/breaker.js";
import { createDeletionCertificate } from "../rollback/manifest-generator.js";
import { DeletionCertificate } from "../rollback/types.js";
import { computeSha256Hex, canonicalizeJson } from "../planner/jcs.js";

export interface TargetVersionIdentifier {
  Key: string;
  VersionId: string;
  LastModified?: string | Date;
  sizeBytes?: number;
  size?: number;
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
  estimatedInventory?: number;
  bypassMutationCeiling?: boolean;
  maxDeletionPercent?: number;
  skipCanary?: boolean;
  circuitBreaker?: CircuitBreaker;
  stateDir?: string;
  planHash?: string;
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
  circuitBreaker?: CircuitBreaker;
  deletionCertificate?: DeletionCertificate;
  certificatePath?: string;
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

  // 1. Relative Mutation Ceiling (Invariant 5)
  const ceiling = evaluateMutationCeiling(
    entries.length,
    options.estimatedInventory,
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
    new CircuitBreaker(bucket, "DeleteObjects");

  // 3. Wasabi 90-Day Retention Guard
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

  let totalDeleted = 0;
  const allErrors: VersionDeletionFailure[] = [];
  const correlations: CloudTrailCorrelationBatch[] = [];
  let itemsToExecute = entries;

  // 4. Canary Gate Verification (Invariant 6)
  if (!options.skipCanary && entries.length > 0) {
    try {
      const canaryResult = await executeCanaryGate(client, bucket, entries, breaker, {
        bypassGovernance: options.bypassGovernance,
        retryOptions: options.retryOptions,
      });
      totalDeleted += canaryResult.deletedCount;
      if (canaryResult.requestIds.length > 0) {
        correlations.push({
          requestId: canaryResult.requestIds[0],
          batchSize: canaryResult.canaryTargetCount,
          timestamp: new Date().toISOString(),
        });
      }
      options.onProgress?.(totalDeleted, entries.length, {
        requestId: canaryResult.requestIds[0],
      });
      itemsToExecute = canaryResult.remainingTargets;
    } catch (err: unknown) {
      if (err instanceof CanaryVerificationError) {
        if (err.outcomes && err.outcomes.length > 0) {
          for (const outcome of err.outcomes) {
            if (outcome.status === "DELETED") {
              totalDeleted++;
            }
          }
        }
        if (err.errors && err.errors.length > 0) {
          allErrors.push(...err.errors);
        } else {
          allErrors.push({
            Key: entries[0]?.Key ?? "",
            VersionId: entries[0]?.VersionId ?? "",
            Code: "CanaryVerificationFailed",
            Message: err.message,
          });
        }
        // Account for any remaining targets if not all targets were in canary
        const processedIdentifiers = new Set(
          (err.outcomes ?? []).map((o) => `${o.key}::${o.versionId}`)
        );
        for (const item of entries) {
          const id = `${item.Key}::${item.VersionId}`;
          if (!processedIdentifiers.has(id)) {
            allErrors.push({
              Key: item.Key,
              VersionId: item.VersionId,
              Code: "CanaryVerificationFailed",
              Message: `Aborted due to canary failure: ${err.message}`,
            });
          }
        }
        let deletionCert: DeletionCertificate | undefined;
        let certPath: string | undefined;
        if (totalDeleted > 0) {
          try {
            const failedSet = new Set(allErrors.map((e) => `${e.Key}::${e.VersionId}`));
            const deletedEntries = entries
              .filter((e) => !failedSet.has(`${e.Key}::${e.VersionId}`))
              .slice(0, totalDeleted);
            const totalBytes = deletedEntries.reduce(
              (sum, e) => sum + (e.sizeBytes ?? e.size ?? 0),
              0
            );
            const planHash =
              options.planHash ??
              computeSha256Hex(
                canonicalizeJson({
                  bucket,
                  entries: entries.map((e) => ({ key: e.Key, versionId: e.VersionId })),
                })
              );
            const certRes = await createDeletionCertificate({
              stateDir: options.stateDir,
              bucketName: bucket,
              operation: "PERMANENT_VERSION_DELETE",
              targetCount: totalDeleted,
              totalBytesReclaimed: totalBytes,
              planHash,
              requestIds: correlations.map((c) => c.requestId).filter(Boolean) as string[],
              itemLedger: deletedEntries.map((e) => ({
                key: e.Key,
                versionId: e.VersionId,
                sizeBytes: e.sizeBytes ?? e.size ?? 0,
              })),
            });
            deletionCert = certRes.certificate;
            certPath = certRes.certificatePath;
          } catch (cErr) {
            console.error("[s3-guardian:certificate] Failed to write deletion certificate:", cErr);
          }
        }

        return {
          total: entries.length,
          deleted: totalDeleted,
          failed: allErrors.length,
          errors: allErrors,
          correlations,
          circuitBreaker: breaker,
          deletionCertificate: deletionCert,
          certificatePath: certPath,
        };
      }
      throw err;
    }
  }

  const batchSize = Math.min(
    MAX_BATCH_SIZE,
    Math.max(1, options.batchSize ?? MAX_BATCH_SIZE)
  );

  for (let i = 0; i < itemsToExecute.length; i += batchSize) {
    if (!breaker.canExecute()) {
      allErrors.push({
        Key: itemsToExecute[i]?.Key ?? "",
        VersionId: itemsToExecute[i]?.VersionId ?? "",
        Code: "CircuitBreakerOpen",
        Message: `Circuit breaker tripped to OPEN: ${breaker.getTripReason()}`,
      });
      break;
    }

    const chunk = itemsToExecute.slice(i, i + batchSize);
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
      breaker.recordBatchResult(s3Objects.length, batchErrors);

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

      if (breaker.getState() === "OPEN") {
        break;
      }

      if (transientItems.length > 0 && attempt <= maxRetries) {
        itemsToProcess = transientItems;
        // Jittered backoff before retrying transient items
        const delay = Math.floor(Math.random() * (100 * Math.pow(2, attempt)));
        await new Promise((res) => setTimeout(res, delay));
      } else {
        break;
      }
    }

    if (breaker.getState() === "OPEN") {
      break;
    }
  }

  let deletionCertificate: DeletionCertificate | undefined;
  let certificatePath: string | undefined;
  if (totalDeleted > 0) {
    try {
      const failedSet = new Set(allErrors.map((e) => `${e.Key}::${e.VersionId}`));
      const deletedEntries = entries
        .filter((e) => !failedSet.has(`${e.Key}::${e.VersionId}`))
        .slice(0, totalDeleted);
      const totalBytes = deletedEntries.reduce(
        (sum, e) => sum + (e.sizeBytes ?? e.size ?? 0),
        0
      );
      const planHash =
        options.planHash ??
        computeSha256Hex(
          canonicalizeJson({
            bucket,
            entries: entries.map((e) => ({ key: e.Key, versionId: e.VersionId })),
          })
        );
      const certRes = await createDeletionCertificate({
        stateDir: options.stateDir,
        bucketName: bucket,
        operation: "PERMANENT_VERSION_DELETE",
        targetCount: totalDeleted,
        totalBytesReclaimed: totalBytes,
        planHash,
        requestIds: correlations.map((c) => c.requestId).filter(Boolean) as string[],
        itemLedger: deletedEntries.map((e) => ({
          key: e.Key,
          versionId: e.VersionId,
          sizeBytes: e.sizeBytes ?? e.size ?? 0,
        })),
      });
      deletionCertificate = certRes.certificate;
      certificatePath = certRes.certificatePath;
    } catch (cErr) {
      console.error("[s3-guardian:certificate] Failed to write deletion certificate:", cErr);
    }
  }

  return {
    total: entries.length,
    deleted: totalDeleted,
    failed: allErrors.length,
    errors: allErrors,
    correlations,
    circuitBreaker: breaker,
    deletionCertificate,
    certificatePath,
  };
}
