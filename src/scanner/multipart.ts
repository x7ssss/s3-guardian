import {
  S3Client,
  ListMultipartUploadsCommand,
  ListMultipartUploadsCommandOutput,
  ListPartsCommand,
  ListPartsCommandOutput,
  MultipartUpload,
  Part,
} from "@aws-sdk/client-s3";
import { createConcurrencyLimiter } from "../utils/concurrency.js";
import { withRetry, RetryOptions } from "../utils/retry.js";
import { calculateMonthlyCostUSD } from "../cost/estimator.js";
import { ZombieUploadItem } from "../planner/plan.js";

export type LifecycleStatus = "UNPROTECTED" | "COVERED" | "COVERED_LAGGING" | "GHOST_RULE";

export interface ScanOptions {
  olderThanDays?: number;
  prefix?: string;
  concurrencyLimit?: number;
  endpoint?: string | null;
  now?: Date;
  retryOptions?: RetryOptions;
  onProgress?: (completed: number, total: number) => void;
}

export interface PartsAggregation {
  partsCount: number;
  bytes: number;
}

export interface ScanResult {
  bucket: string;
  endpoint: string | null;
  olderThanDays: number;
  totalZombieUploads: number;
  totalStrandedBytes: number;
  estimatedMonthlyWasteUSD: number;
  uploads: ZombieUploadItem[];
}

// ─── Page-level stream item yielded by scanMultipartUploadsStream ─────────────

export interface UploadPageItem {
  key: string;
  uploadId: string;
  initiated: Date;
  storageClass: string;
}

/**
 * Retrieves all parts for a single multipart upload, paginating with PartNumberMarker
 * and retrying on 503 Slow Down with jitter.
 */
export async function getUploadPartsInfo(
  client: S3Client,
  bucket: string,
  key: string,
  uploadId: string,
  retryOptions?: RetryOptions
): Promise<PartsAggregation> {
  let partsCount = 0;
  let totalBytes = 0;
  let partNumberMarker: string | undefined = undefined;

  while (true) {
    const currentMarker: string | undefined = partNumberMarker;

    let response: ListPartsCommandOutput;
    try {
      response = await withRetry(
        () =>
          client.send(
            new ListPartsCommand({
              Bucket: bucket,
              Key: key,
              UploadId: uploadId,
              PartNumberMarker: currentMarker,
            })
          ),
        retryOptions
      );
    } catch (err: unknown) {
      // If the upload was aborted or completed concurrently, handle gracefully
      const errorObj = err as Record<string, unknown>;
      if (
        errorObj?.name === "NoSuchUpload" ||
        (errorObj?.$metadata as Record<string, unknown> | undefined)
          ?.httpStatusCode === 404
      ) {
        return { partsCount: 0, bytes: 0 };
      }
      throw err;
    }

    const parts: Part[] = response.Parts ?? [];
    for (const part of parts) {
      partsCount++;
      totalBytes += part.Size ?? 0;
    }

    if (!response.IsTruncated) {
      break;
    }

    // Pagination marker: use NextPartNumberMarker or fallback to last part's PartNumber
    const lastPart = parts.length > 0 ? parts[parts.length - 1] : undefined;
    const hasNextPartMarker =
      typeof response.NextPartNumberMarker === "string" &&
      response.NextPartNumberMarker.trim().length > 0;

    const nextMarker: string | undefined = hasNextPartMarker
      ? response.NextPartNumberMarker
      : lastPart?.PartNumber != null
      ? String(lastPart.PartNumber)
      : undefined;

    if (!nextMarker || nextMarker === currentMarker) {
      break;
    }

    partNumberMarker = nextMarker;
  }

  return { partsCount, bytes: totalBytes };
}

/**
 * Streaming async generator that yields candidate uploads page-by-page from
 * ListMultipartUploads without accumulating them in memory.
 *
 * Each yielded item has the raw S3 upload fields plus a resolved StorageClass.
 * This ensures scanning 100,000+ uploads does not exhaust the V8 heap.
 *
 * Paginates using BOTH KeyMarker AND UploadIdMarker per the S3 spec,
 * with robust fallback to the last upload's Key/UploadId when Next markers are absent.
 */
export async function* scanMultipartUploadsStream(
  client: S3Client,
  bucket: string,
  options: ScanOptions = {}
): AsyncGenerator<UploadPageItem> {
  const olderThanDays = options.olderThanDays ?? 7;
  const now = options.now ?? new Date();
  const cutoffTime = now.getTime() - olderThanDays * 24 * 60 * 60 * 1000;

  let keyMarker: string | undefined = undefined;
  let uploadIdMarker: string | undefined = undefined;

  while (true) {
    const currentKeyMarker: string | undefined = keyMarker;
    const currentUploadIdMarker: string | undefined = uploadIdMarker;

    const response: ListMultipartUploadsCommandOutput = await withRetry(
      () =>
        client.send(
          new ListMultipartUploadsCommand({
            Bucket: bucket,
            KeyMarker: currentKeyMarker,
            UploadIdMarker: currentUploadIdMarker,
            Prefix: options.prefix,
          })
        ),
      options.retryOptions
    );

    const uploads: MultipartUpload[] = response.Uploads ?? [];

    for (const upload of uploads) {
      if (
        upload.Key &&
        upload.UploadId &&
        upload.Initiated &&
        upload.Initiated.getTime() < cutoffTime
      ) {
        yield {
          key: upload.Key,
          uploadId: upload.UploadId,
          initiated: upload.Initiated,
          storageClass: upload.StorageClass ?? "STANDARD",
        };
      }
    }

    if (!response.IsTruncated) {
      break;
    }

    const lastUpload =
      uploads.length > 0 ? uploads[uploads.length - 1] : undefined;

    // Real-world S3 edge case: when IsTruncated is true but NextKeyMarker is
    // missing/null/empty, fall back to the Key and UploadId of the last Uploads item.
    const hasNextKeyMarker =
      typeof response.NextKeyMarker === "string" &&
      response.NextKeyMarker.trim().length > 0;
    const hasNextUploadIdMarker =
      typeof response.NextUploadIdMarker === "string" &&
      response.NextUploadIdMarker.trim().length > 0;

    const nextKeyMarker: string | undefined = hasNextKeyMarker
      ? response.NextKeyMarker
      : lastUpload?.Key;
    const nextUploadIdMarker: string | undefined = hasNextUploadIdMarker
      ? response.NextUploadIdMarker
      : lastUpload?.UploadId;

    // Prevent infinite loops: if markers didn't advance or can't be resolved, stop.
    if (
      !nextKeyMarker ||
      (nextKeyMarker === currentKeyMarker &&
        nextUploadIdMarker === currentUploadIdMarker)
    ) {
      break;
    }

    keyMarker = nextKeyMarker;
    uploadIdMarker = nextUploadIdMarker;
  }
}

/**
 * Scans a bucket for abandoned multipart uploads older than olderThanDays.
 * Uses the streaming generator internally then resolves parts with bounded concurrency.
 *
 * Retains the original eager API (returns a full ScanResult) for backwards compatibility
 * with the plan and apply commands.
 */
export async function scanMultipartUploads(
  client: S3Client,
  bucket: string,
  options: ScanOptions = {}
): Promise<ScanResult> {
  const olderThanDays = options.olderThanDays ?? 7;
  const concurrencyLimit = options.concurrencyLimit ?? 10;

  // Drain the streaming generator into a candidate list.
  // For very large buckets callers should use scanMultipartUploadsStream directly.
  const candidateUploads: UploadPageItem[] = [];
  for await (const item of scanMultipartUploadsStream(client, bucket, options)) {
    candidateUploads.push(item);
  }

  // Concurrently fetch parts with concurrency capped to 10
  const limiter = createConcurrencyLimiter(concurrencyLimit);
  let completed = 0;
  const total = candidateUploads.length;

  const zombieItems = await Promise.all(
    candidateUploads.map((item) =>
      limiter(async (): Promise<ZombieUploadItem> => {
        const partsInfo = await getUploadPartsInfo(
          client,
          bucket,
          item.key,
          item.uploadId,
          options.retryOptions
        );

        completed++;
        options.onProgress?.(completed, total);

        return {
          key: item.key,
          uploadId: item.uploadId,
          initiated: item.initiated.toISOString(),
          partsCount: partsInfo.partsCount,
          bytes: partsInfo.bytes,
          storageClass: item.storageClass,
          lifecycleStatus: "UNPROTECTED", // Default; enriched by lifecycle audit in CLI
        };
      })
    )
  );

  // Deterministic sorting: by key, then by uploadId
  zombieItems.sort((a, b) => {
    const keyComp = a.key.localeCompare(b.key);
    if (keyComp !== 0) return keyComp;
    return a.uploadId.localeCompare(b.uploadId);
  });

  const totalStrandedBytes = zombieItems.reduce(
    (sum, item) => sum + item.bytes,
    0
  );
  const estimatedMonthlyWasteUSD = calculateMonthlyCostUSD(totalStrandedBytes);

  return {
    bucket,
    endpoint: options.endpoint ?? null,
    olderThanDays,
    totalZombieUploads: zombieItems.length,
    totalStrandedBytes,
    estimatedMonthlyWasteUSD,
    uploads: zombieItems,
  };
}
