import {
  S3Client,
  ListObjectVersionsCommand,
  ListObjectVersionsCommandOutput,
  ObjectVersion,
  DeleteMarkerEntry,
} from "@aws-sdk/client-s3";
import { withRetry, RetryOptions } from "../utils/retry.js";
import { calculateMonthlyCostUSD } from "../cost/estimator.js";

export interface VersionPage {
  versions: ObjectVersion[];
  deleteMarkers: DeleteMarkerEntry[];
}

export interface VersionScanOptions {
  prefix?: string;
  olderThanDays?: number;
  now?: Date;
  retryOptions?: RetryOptions;
}

export interface NoncurrentVersionItem {
  key: string;
  versionId: string;
  size: number;
  lastModified: string;
  storageClass: string;
}

export interface ExpiredDeleteMarkerItem {
  key: string;
  versionId: string;
  lastModified: string;
}

export interface VersionScanResult {
  bucket: string;
  totalVersionsScanned: number;
  totalDeleteMarkersScanned: number;
  noncurrentVersionsCount: number;
  noncurrentBytes: number;
  estimatedMonthlyWasteUSD: number;
  expiredDeleteMarkersCount: number;
  noncurrentVersions: NoncurrentVersionItem[];
  expiredDeleteMarkers: ExpiredDeleteMarkerItem[];
}

/**
 * Async generator that paginates ListObjectVersions using dual compound markers
 * (KeyMarker + VersionIdMarker).
 *
 * Invariant 2: Dual-Marker Pagination:
 *  - MUST paginate using BOTH KeyMarker and VersionIdMarker from NextKeyMarker and NextVersionIdMarker.
 *  - Never terminates if Versions is empty while IsTruncated is true (DeleteMarkers may hold the payload).
 */
export async function* scanObjectVersionsStream(
  client: S3Client,
  bucket: string,
  options: VersionScanOptions = {}
): AsyncGenerator<VersionPage> {
  let keyMarker: string | undefined = undefined;
  let versionIdMarker: string | undefined = undefined;

  while (true) {
    const currentKeyMarker: string | undefined = keyMarker;
    const currentVersionIdMarker: string | undefined = versionIdMarker;

    const response: ListObjectVersionsCommandOutput = await withRetry(
      () =>
        client.send(
          new ListObjectVersionsCommand({
            Bucket: bucket,
            KeyMarker: currentKeyMarker,
            VersionIdMarker: currentVersionIdMarker,
            Prefix: options.prefix,
          })
        ),
      options.retryOptions
    );

    const versions: ObjectVersion[] = response.Versions ?? [];
    const deleteMarkers: DeleteMarkerEntry[] = response.DeleteMarkers ?? [];

    yield { versions, deleteMarkers };

    if (!response.IsTruncated) {
      break;
    }

    // Determine next markers
    const hasNextKey =
      typeof response.NextKeyMarker === "string" &&
      response.NextKeyMarker.trim().length > 0;
    const hasNextVersionId =
      typeof response.NextVersionIdMarker === "string" &&
      response.NextVersionIdMarker.trim().length > 0;

    let nextKeyMarker: string | undefined = hasNextKey
      ? response.NextKeyMarker
      : undefined;
    let nextVersionIdMarker: string | undefined = hasNextVersionId
      ? response.NextVersionIdMarker
      : undefined;

    // Fallback if NextKeyMarker is omitted despite IsTruncated being true
    if (!nextKeyMarker) {
      const lastV =
        versions.length > 0 ? versions[versions.length - 1] : undefined;
      const lastDM =
        deleteMarkers.length > 0
          ? deleteMarkers[deleteMarkers.length - 1]
          : undefined;

      if (lastV && lastDM) {
        const comp = (lastV.Key ?? "").localeCompare(lastDM.Key ?? "");
        if (comp > 0) {
          nextKeyMarker = lastV.Key;
          nextVersionIdMarker = lastV.VersionId;
        } else {
          nextKeyMarker = lastDM.Key;
          nextVersionIdMarker = lastDM.VersionId;
        }
      } else if (lastV) {
        nextKeyMarker = lastV.Key;
        nextVersionIdMarker = lastV.VersionId;
      } else if (lastDM) {
        nextKeyMarker = lastDM.Key;
        nextVersionIdMarker = lastDM.VersionId;
      }
    }

    // Guard against infinite loop if markers do not advance
    if (
      !nextKeyMarker ||
      (nextKeyMarker === currentKeyMarker &&
        nextVersionIdMarker === currentVersionIdMarker)
    ) {
      break;
    }

    keyMarker = nextKeyMarker;
    versionIdMarker = nextVersionIdMarker;
  }
}

/**
 * Scans all object versions and delete markers in a bucket.
 * Quantifies noncurrent data versions and Expired Object Delete Markers (EODMs).
 */
export async function scanObjectVersions(
  client: S3Client,
  bucket: string,
  options: VersionScanOptions = {}
): Promise<VersionScanResult> {
  const olderThanDays = options.olderThanDays ?? 0;
  const now = options.now ?? new Date();
  const cutoffTime = now.getTime() - olderThanDays * 24 * 60 * 60 * 1000;

  let totalVersionsScanned = 0;
  let totalDeleteMarkersScanned = 0;
  let noncurrentBytes = 0;

  const noncurrentVersions: NoncurrentVersionItem[] = [];
  const candidateDeleteMarkers: Array<{
    key: string;
    versionId: string;
    lastModified: string;
  }> = [];

  // Track keys that have at least one data version (current or noncurrent)
  const keysWithDataVersions = new Set<string>();

  for await (const page of scanObjectVersionsStream(client, bucket, options)) {
    totalVersionsScanned += page.versions.length;
    totalDeleteMarkersScanned += page.deleteMarkers.length;

    for (const v of page.versions) {
      if (!v.Key) continue;
      keysWithDataVersions.add(v.Key);

      // Noncurrent version check
      if (v.IsLatest === false || (!v.IsLatest && v.VersionId)) {
        const lastMod = v.LastModified ? v.LastModified.getTime() : 0;
        if (olderThanDays === 0 || lastMod <= cutoffTime) {
          const size = v.Size ?? 0;
          noncurrentBytes += size;
          noncurrentVersions.push({
            key: v.Key,
            versionId: v.VersionId ?? "null",
            size,
            lastModified: v.LastModified?.toISOString() ?? new Date(0).toISOString(),
            storageClass: v.StorageClass ?? "STANDARD",
          });
        }
      }
    }

    for (const dm of page.deleteMarkers) {
      if (!dm.Key) continue;
      // An expired delete marker candidate must be IsLatest === true
      if (dm.IsLatest === true) {
        candidateDeleteMarkers.push({
          key: dm.Key,
          versionId: dm.VersionId ?? "null",
          lastModified: dm.LastModified?.toISOString() ?? new Date(0).toISOString(),
        });
      }
    }
  }

  // Expired Object Delete Marker (EODM): delete marker where dm.IsLatest is true (object is deleted)
  const expiredDeleteMarkers: ExpiredDeleteMarkerItem[] = candidateDeleteMarkers;

  const estimatedMonthlyWasteUSD = calculateMonthlyCostUSD(noncurrentBytes);

  return {
    bucket,
    totalVersionsScanned,
    totalDeleteMarkersScanned,
    noncurrentVersionsCount: noncurrentVersions.length,
    noncurrentBytes,
    estimatedMonthlyWasteUSD,
    expiredDeleteMarkersCount: expiredDeleteMarkers.length,
    noncurrentVersions,
    expiredDeleteMarkers,
  };
}
