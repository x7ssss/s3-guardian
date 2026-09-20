import {
  S3Client,
  ListObjectVersionsCommand,
  ListObjectVersionsCommandOutput,
  DeleteObjectsCommand,
  ObjectVersion,
  DeleteMarkerEntry,
} from "@aws-sdk/client-s3";
import { withRetry, RetryOptions } from "../utils/retry.js";

export interface RehydrateOptions {
  olderThan?: string;
  dryRun?: boolean;
  prefix?: string;
  retryOptions?: RetryOptions;
}

export interface RehydrateResult {
  bucketName: string;
  dryRun: boolean;
  discoveredMarkersCount: number;
  restoredCount: number;
  deletedMarkers: Array<{ Key: string; VersionId: string; LastModified?: string }>;
  restoredVersions: Array<{ Key: string; activeVersionId?: string }>;
  requestIds: string[];
}

/**
 * Async generator that paginates ListObjectVersions using dual compound markers
 * (KeyMarker + VersionIdMarker).
 */
export async function* paginateListObjectVersions(
  client: S3Client,
  bucket: string,
  options: { prefix?: string; retryOptions?: RetryOptions } = {}
): AsyncGenerator<{ versions: ObjectVersion[]; deleteMarkers: DeleteMarkerEntry[] }> {
  let keyMarker: string | undefined = undefined;
  let versionIdMarker: string | undefined = undefined;

  while (true) {
    const currentKeyMarker = keyMarker;
    const currentVersionIdMarker = versionIdMarker;

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

    const versions: ObjectVersion[] = response?.Versions ?? [];
    const deleteMarkers: DeleteMarkerEntry[] = response?.DeleteMarkers ?? [];

    yield { versions, deleteMarkers };

    if (!response?.IsTruncated) {
      break;
    }

    const hasNextKey =
      typeof response.NextKeyMarker === "string" &&
      response.NextKeyMarker.trim().length > 0;
    const hasNextVersionId =
      typeof response.NextVersionIdMarker === "string" &&
      response.NextVersionIdMarker.trim().length > 0;

    let nextKeyMarker = hasNextKey ? response.NextKeyMarker : undefined;
    let nextVersionIdMarker = hasNextVersionId
      ? response.NextVersionIdMarker
      : undefined;

    if (!nextKeyMarker) {
      const lastV =
        versions.length > 0 ? versions[versions.length - 1] : undefined;
      const lastDM =
        deleteMarkers.length > 0
          ? deleteMarkers[deleteMarkers.length - 1]
          : undefined;

      if (lastV && lastDM) {
        if (
          lastV.Key! > lastDM.Key! ||
          (lastV.Key === lastDM.Key &&
            (lastV.LastModified?.getTime() ?? 0) <
              (lastDM.LastModified?.getTime() ?? 0))
        ) {
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

    if (!nextKeyMarker) {
      break;
    }

    keyMarker = nextKeyMarker;
    versionIdMarker = nextVersionIdMarker;
  }
}

/**
 * Re-hydrates soft-deleted items by discovering latest Delete Markers
 * and popping them via DeleteObjectsCommand with Quiet: true.
 *
 * Confirms previous data version becomes the active current version.
 */
export async function rehydrateSoftDeletes(
  s3Client: S3Client,
  bucketName: string,
  options: RehydrateOptions = {}
): Promise<RehydrateResult> {
  let thresholdDate: Date | null = null;
  if (options.olderThan) {
    const trimmed = options.olderThan.trim();
    const intervalMatch = /^(\d+)([dhm])?$/i.exec(trimmed);
    if (intervalMatch) {
      const num = parseInt(intervalMatch[1]!, 10);
      const unit = (intervalMatch[2] ?? "d").toLowerCase();
      let ms = num * 24 * 60 * 60 * 1000;
      if (unit === "h") ms = num * 60 * 60 * 1000;
      if (unit === "m") ms = num * 60 * 1000;
      thresholdDate = new Date(Date.now() - ms);
    } else {
      const parsed = new Date(trimmed);
      if (!isNaN(parsed.getTime())) {
        thresholdDate = parsed;
      }
    }
  }

  const targetMarkers: Array<{
    Key: string;
    VersionId: string;
    LastModified?: string;
  }> = [];

  // Map to track previous data version for each key
  const previousDataVersions = new Map<string, ObjectVersion>();

  for await (const page of paginateListObjectVersions(s3Client, bucketName, {
    prefix: options.prefix,
    retryOptions: options.retryOptions,
  })) {
    for (const marker of page.deleteMarkers) {
      if (marker.IsLatest === true && marker.Key && marker.VersionId) {
        const markerDate =
          marker.LastModified instanceof Date
            ? marker.LastModified
            : marker.LastModified
            ? new Date(marker.LastModified)
            : undefined;

        if (!thresholdDate || (markerDate && markerDate <= thresholdDate)) {
          targetMarkers.push({
            Key: marker.Key,
            VersionId: marker.VersionId,
            LastModified: markerDate?.toISOString(),
          });
        }
      }
    }

    for (const version of page.versions) {
      if (version.Key && version.VersionId && version.VersionId !== "null") {
        // Track the most recent non-delete-marker version
        const existing = previousDataVersions.get(version.Key);
        const vDate =
          version.LastModified instanceof Date
            ? version.LastModified
            : version.LastModified
            ? new Date(version.LastModified)
            : new Date(0);

        const existingDate = existing
          ? existing.LastModified instanceof Date
            ? existing.LastModified
            : existing.LastModified
            ? new Date(existing.LastModified)
            : new Date(0)
          : new Date(0);

        if (!existing || vDate > existingDate) {
          previousDataVersions.set(version.Key, version);
        }
      }
    }
  }

  const targetCount = targetMarkers.length;
  const requestIds: string[] = [];
  let restoredCount = 0;
  const restoredVersions: Array<{ Key: string; activeVersionId?: string }> = [];

  if (options.dryRun === true || targetCount === 0) {
    for (const tm of targetMarkers) {
      const prev = previousDataVersions.get(tm.Key);
      restoredVersions.push({
        Key: tm.Key,
        activeVersionId: prev?.VersionId,
      });
    }

    return {
      bucketName,
      dryRun: Boolean(options.dryRun),
      discoveredMarkersCount: targetCount,
      restoredCount: 0,
      deletedMarkers: targetMarkers,
      restoredVersions,
      requestIds: [],
    };
  }

  // Delete targeted Delete Markers in batches of 1,000 using DeleteObjectsCommand with Quiet: true
  const BATCH_SIZE = 1000;
  for (let i = 0; i < targetMarkers.length; i += BATCH_SIZE) {
    const batch = targetMarkers.slice(i, i + BATCH_SIZE);
    const deleteObjects = batch.map((m) => ({
      Key: m.Key,
      VersionId: m.VersionId,
    }));

    const response = await withRetry(
      () =>
        s3Client.send(
          new DeleteObjectsCommand({
            Bucket: bucketName,
            Delete: {
              Objects: deleteObjects,
              Quiet: true,
            },
          })
        ),
      options.retryOptions
    );

    const reqId = response.$metadata?.requestId;
    if (reqId) requestIds.push(reqId);

    const errorKeys = new Set((response.Errors ?? []).map((e) => `${e.Key}::${e.VersionId}`));
    for (const m of batch) {
      if (!errorKeys.has(`${m.Key}::${m.VersionId}`)) {
        restoredCount++;
        const prev = previousDataVersions.get(m.Key);
        restoredVersions.push({
          Key: m.Key,
          activeVersionId: prev?.VersionId,
        });
      }
    }
  }

  return {
    bucketName,
    dryRun: false,
    discoveredMarkersCount: targetCount,
    restoredCount,
    deletedMarkers: targetMarkers,
    restoredVersions,
    requestIds,
  };
}
