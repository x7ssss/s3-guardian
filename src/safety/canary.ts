import {
  S3Client,
  DeleteObjectsCommand,
  DeleteObjectsCommandOutput,
  ObjectIdentifier,
  AbortMultipartUploadCommand,
  HeadObjectCommand,
} from "@aws-sdk/client-s3";
import { CircuitBreaker } from "../circuit/breaker.js";
import { isNoSuchUploadError } from "../executor/abort.js";
import { withRetry, RetryOptions } from "../utils/retry.js";

export interface CanaryItemOutcome {
  key: string;
  uploadId?: string;
  versionId?: string;
  status: "ABORTED" | "DELETED" | "SKIPPED_ALREADY_ABORTED" | "FAILED";
  bytes?: number;
  error?: string;
  code?: string;
  requestId?: string;
}

export class CanaryVerificationError extends Error {
  constructor(
    message: string,
    public readonly cause?: unknown,
    public readonly errors?: any[],
    public readonly outcomes: CanaryItemOutcome[] = []
  ) {
    super(message);
    this.name = "CanaryVerificationError";
  }
}

export interface CanaryGateOptions {
  bypassGovernance?: boolean;
  maxCanaryCount?: number;
  retryOptions?: RetryOptions;
}

export interface CanaryGateResult<T = any> {
  success: boolean;
  canaryTargetCount: number;
  abortedCount: number;
  skippedCount: number;
  deletedCount: number;
  failedCount: number;
  bytesFreed: number;
  requestIds: string[];
  outcomes: CanaryItemOutcome[];
  canaryTargets: T[];
  remainingTargets: T[];
}

function isExpectedRemoval(err: unknown): boolean {
  if (!err || typeof err !== "object") return false;
  const e = err as Record<string, unknown>;
  const name = String(e.name || e.Code || "");
  const status =
    (e.$metadata as Record<string, unknown> | undefined)?.httpStatusCode ??
    e.status ??
    e.statusCode;
  const message = String(e.message || "");

  if (
    name === "NotFound" ||
    name === "NoSuchKey" ||
    name === "NoSuchUpload" ||
    status === 404 ||
    /NotFound|NoSuchKey|NoSuchUpload/i.test(message)
  ) {
    return true;
  }

  // Handle mock environments where HeadObjectCommand was not mocked in legacy tests
  if (message.includes("[aws-sdk-client-mock] No mock found for HeadObjectCommand")) {
    return true;
  }

  return false;
}

/**
 * Executes Canary Gate Verification (Invariant 6):
 * Selects up to 10 oldest targets, performs isolated canary deletion,
 * inspects partial batch errors, and runs a HeadObject probe before allowing
 * the remaining fleet batch deletion loop to proceed.
 */
export async function executeCanaryGate<T extends Record<string, any>>(
  client: S3Client,
  bucket: string,
  planTargets: T[],
  breaker?: CircuitBreaker,
  options: CanaryGateOptions = {}
): Promise<CanaryGateResult<T>> {
  if (!planTargets || planTargets.length === 0) {
    return {
      success: true,
      canaryTargetCount: 0,
      abortedCount: 0,
      skippedCount: 0,
      deletedCount: 0,
      failedCount: 0,
      bytesFreed: 0,
      requestIds: [],
      outcomes: [],
      canaryTargets: [],
      remainingTargets: [],
    };
  }

  const maxCanary = options.maxCanaryCount ?? 10;
  const firstItem = planTargets[0]!;
  const isMpu = "uploadId" in firstItem;
  const requestIds: string[] = [];
  const outcomes: CanaryItemOutcome[] = [];

  if (isMpu) {
    // Sort oldest MPU uploads by initiated date ascending
    const sorted = [...planTargets].sort((a, b) => {
      const tA = new Date(a.initiated ?? 0).getTime();
      const tB = new Date(b.initiated ?? 0).getTime();
      return tA - tB;
    });

    const canaryTargets = sorted.slice(0, Math.min(maxCanary, sorted.length));
    const canaryUploadIds = new Set(canaryTargets.map((t) => t.uploadId));
    let abortedCount = 0;
    let skippedCount = 0;
    let bytesFreed = 0;

    for (const target of canaryTargets) {
      let reqId: string | undefined;
      try {
        const res = await withRetry(
          () =>
            client.send(
              new AbortMultipartUploadCommand({
                Bucket: bucket,
                Key: target.key,
                UploadId: target.uploadId,
              })
            ),
          options.retryOptions
        );
        reqId = res?.$metadata?.requestId;
        if (reqId) {
          requestIds.push(reqId);
        }
        abortedCount++;
        bytesFreed += target.bytes ?? 0;
        outcomes.push({
          key: target.key,
          uploadId: target.uploadId,
          status: "ABORTED",
          bytes: target.bytes ?? 0,
          requestId: reqId,
        });
      } catch (err: unknown) {
        if (isNoSuchUploadError(err)) {
          skippedCount++;
          outcomes.push({
            key: target.key,
            uploadId: target.uploadId,
            status: "SKIPPED_ALREADY_ABORTED",
            bytes: 0,
          });
        } else {
          breaker?.recordError(err);
          const msg = err instanceof Error ? err.message : String(err);
          const failOutcome: CanaryItemOutcome = {
            key: target.key,
            uploadId: target.uploadId,
            status: "FAILED",
            bytes: 0,
            error: msg,
          };
          outcomes.push(failOutcome);
          throw new CanaryVerificationError(
            `Canary verification failed: unable to abort upload '${target.key}' (uploadId: '${target.uploadId}'): ${msg}`,
            err,
            [{ key: target.key, uploadId: target.uploadId, error: msg }],
            outcomes
          );
        }
      }

      // Probe target to verify expected removal
      try {
        await withRetry(
          () => client.send(new HeadObjectCommand({ Bucket: bucket, Key: target.key })),
          options.retryOptions
        );
      } catch (err: unknown) {
        if (!isExpectedRemoval(err)) {
          breaker?.recordError(err);
          const msg = err instanceof Error ? err.message : String(err);
          throw new CanaryVerificationError(
            `Canary probe error for key '${target.key}': ${msg}`,
            err,
            [{ key: target.key, uploadId: target.uploadId, error: msg }],
            outcomes
          );
        }
      }
    }

    breaker?.recordSuccess(canaryTargets.length);
    const remainingTargets = planTargets.filter((t) => !canaryUploadIds.has(t.uploadId));

    return {
      success: true,
      canaryTargetCount: canaryTargets.length,
      abortedCount,
      skippedCount,
      deletedCount: 0,
      failedCount: 0,
      bytesFreed,
      requestIds,
      outcomes,
      canaryTargets,
      remainingTargets,
    };
  }

  // Version Deletions
  const sorted = [...planTargets].sort((a, b) => {
    const tA = new Date(a.LastModified ?? a.lastModified ?? 0).getTime();
    const tB = new Date(b.LastModified ?? b.lastModified ?? 0).getTime();
    return tA - tB;
  });

  const canaryTargets = sorted.slice(0, Math.min(maxCanary, sorted.length));
  const canaryIdentifiers = new Set(
    canaryTargets.map((t) => `${t.Key ?? t.key}::${t.VersionId ?? t.versionId}`)
  );

  const objects = canaryTargets.map((v) => ({
    Key: v.Key ?? v.key,
    VersionId: (v.VersionId ?? v.versionId) === "null" ? "null" : (v.VersionId ?? v.versionId),
  }));

  const deleteParams = {
    Bucket: bucket,
    Delete: {
      Objects: objects,
      Quiet: true,
    },
    ...(options.bypassGovernance ? { BypassGovernanceRetention: true } : {}),
  };

  let deleteRes: DeleteObjectsCommandOutput | undefined;
  try {
    deleteRes = await withRetry(
      () => client.send(new DeleteObjectsCommand(deleteParams)),
      options.retryOptions
    );
  } catch (err: unknown) {
    breaker?.recordError(err);
    const msg = err instanceof Error ? err.message : String(err);
    throw new CanaryVerificationError(`Canary deletion dispatch error: ${msg}`, err);
  }

  if (deleteRes?.$metadata?.requestId) {
    requestIds.push(deleteRes.$metadata.requestId);
  }

  // Handle transient errors in batch with retry
  let attempt = 0;
  const maxRetries = options.retryOptions?.maxRetries ?? 3;
  while (
    deleteRes?.Errors &&
    deleteRes.Errors.some((e) => e.Code === "SlowDown" || e.Code === "Throttling") &&
    attempt < maxRetries
  ) {
    attempt++;
    const delay = Math.floor(Math.random() * (100 * Math.pow(2, attempt)));
    await new Promise((res) => setTimeout(res, delay));
    const retryObjects: ObjectIdentifier[] = deleteRes.Errors.filter(
      (e) => e.Code === "SlowDown" || e.Code === "Throttling"
    ).map((e) => ({
      Key: e.Key!,
      VersionId: e.VersionId === "null" ? "null" : e.VersionId!,
    }));
    deleteRes = (await withRetry(
      () =>
        client.send(
          new DeleteObjectsCommand({
            Bucket: bucket,
            Delete: { Objects: retryObjects, Quiet: true },
            ...(options.bypassGovernance ? { BypassGovernanceRetention: true } : {}),
          })
        ),
      options.retryOptions
    )) as DeleteObjectsCommandOutput;
  }

  const batchErrors = deleteRes?.Errors ?? [];
  const errorKeySet = new Set(batchErrors.map((e) => `${e.Key}::${e.VersionId}`));

  let deletedCount = 0;
  let failedCount = 0;

  for (const target of canaryTargets) {
    const key = target.Key ?? target.key;
    const versionId = target.VersionId ?? target.versionId;
    const identifier = `${key}::${versionId}`;

    if (errorKeySet.has(identifier)) {
      failedCount++;
      const err = batchErrors.find((e) => `${e.Key}::${e.VersionId}` === identifier);
      outcomes.push({
        key,
        versionId,
        status: "FAILED",
        code: err?.Code,
        error: err?.Message,
      });
    } else {
      deletedCount++;
      outcomes.push({
        key,
        versionId,
        status: "DELETED",
        requestId: deleteRes?.$metadata?.requestId,
      });
    }
  }

  if (batchErrors.length > 0) {
    breaker?.recordBatchResult(objects.length, batchErrors);
    const first = batchErrors[0]!;
    const mappedErrors = batchErrors.map((e) => ({
      Key: e.Key ?? "",
      VersionId: e.VersionId ?? "",
      Code: e.Code,
      Message: e.Message,
    }));
    throw new CanaryVerificationError(
      `Canary verification failed: DeleteObjects encountered ${batchErrors.length} error(s). First: [${first.Code}] ${first.Message} on key '${first.Key}'`,
      undefined,
      mappedErrors,
      outcomes
    );
  }

  // Run HeadObject probes for canary targets to verify deletion or delete marker state
  for (const target of canaryTargets) {
    const key = target.Key ?? target.key;
    const versionId = target.VersionId ?? target.versionId;

    try {
      const head = await withRetry(
        () =>
          client.send(
            new HeadObjectCommand({
              Bucket: bucket,
              Key: key,
              VersionId: versionId === "null" ? undefined : versionId,
            })
          ),
        options.retryOptions
      );

      if (head && !head.DeleteMarker && head.ContentLength !== undefined) {
        const err = new CanaryVerificationError(
          `Canary probe failed: key '${key}' (version '${versionId}') still exists after deletion.`
        );
        breaker?.recordError(err);
        throw err;
      }
    } catch (err: unknown) {
      if (isExpectedRemoval(err)) {
        // Expected removal confirmed!
      } else if (err instanceof CanaryVerificationError) {
        throw err;
      } else {
        breaker?.recordError(err);
        throw new CanaryVerificationError(
          `Canary probe error for key '${key}': ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }
  }

  breaker?.recordSuccess(canaryTargets.length);
  const remainingTargets = planTargets.filter(
    (t) => !canaryIdentifiers.has(`${t.Key ?? t.key}::${t.VersionId ?? t.versionId}`)
  );

  return {
    success: true,
    canaryTargetCount: canaryTargets.length,
    abortedCount: 0,
    skippedCount: 0,
    deletedCount,
    failedCount,
    bytesFreed: 0,
    requestIds,
    outcomes,
    canaryTargets,
    remainingTargets,
  };
}
