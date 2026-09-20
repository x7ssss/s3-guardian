import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { createReadStream } from "node:fs";
import { resolve as pathResolve } from "node:path";
import { parseS3Uri } from "../checkpoint/s3-checkpoint.js";
import { parseStorageLensCsvStream } from "./parser.js";
import {
  StorageLensBucketMetrics,
  rankStorageLensMetrics,
} from "./scorer.js";

export interface ReadStorageLensOptions {
  top?: number;
  minWasteUSD?: number;
}

/**
 * Reads Storage Lens metrics from either a local CSV file or an S3 CSV object,
 * scores each bucket, and optionally filters and ranks the top offenders.
 *
 * Invariants:
 *  - Zero data-plane overhead: Reads only macroscopic daily CSV exports.
 *  - No ListObjects / ListObjectVersions / ListMultipartUploads calls are made.
 *  - Observational separation: Read-only triage and ranking.
 */
export async function readStorageLensMetrics(
  s3Client: S3Client,
  source: string,
  options: ReadStorageLensOptions = {}
): Promise<StorageLensBucketMetrics[]> {
  let stream: NodeJS.ReadableStream;

  if (source.startsWith("s3://")) {
    const { bucket, key } = parseS3Uri(source);
    const response = await s3Client.send(
      new GetObjectCommand({
        Bucket: bucket,
        Key: key,
      })
    );

    if (!response.Body) {
      throw new Error(`S3 GetObject returned empty body for ${source}`);
    }

    stream = response.Body as NodeJS.ReadableStream;
  } else {
    const fullPath = pathResolve(source);
    stream = createReadStream(fullPath);
  }

  let metrics = await parseStorageLensCsvStream(stream);

  // Filter by minimum waste threshold if configured
  if (options.minWasteUSD !== undefined && options.minWasteUSD > 0) {
    metrics = metrics.filter((m) => m.estimatedMonthlyWasteUSD >= options.minWasteUSD!);
  }

  // Sort descending by priority
  const ranked = rankStorageLensMetrics(metrics);

  // Slice to top N if specified
  if (options.top !== undefined && options.top > 0) {
    return ranked.slice(0, options.top);
  }

  return ranked;
}
