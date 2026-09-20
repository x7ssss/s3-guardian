import * as fs from "node:fs/promises";
import * as fsSync from "node:fs";
import * as path from "node:path";
import * as readline from "node:readline";
import { createGzip, gunzip } from "node:zlib";
import { promisify } from "node:util";
import { pipeline } from "node:stream/promises";
import { Readable } from "node:stream";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { AuditEvent, BucketAggregate, CompactionSnapshot } from "./types.js";
import { AuditLogWriter } from "./audit-writer.js";

const gunzipAsync = promisify(gunzip);

export interface CompactionOptions {
  s3MirrorBucket?: string;
  s3Client?: S3Client;
  writer?: AuditLogWriter;
  mergePreviousSnapshot?: boolean;
  /** Internal test injection hooks */
  _fs?: {
    rename?: (src: string, dest: string) => Promise<void>;
  };
}

export interface CompactionResult {
  snapshotPath: string;
  compactedCount: number;
}

/**
 * Reads the latest compressed compaction snapshot from ${stateDir}/snapshots/
 */
export async function readLatestSnapshot(
  stateDir: string
): Promise<CompactionSnapshot | null> {
  const snapshotsDir = path.join(stateDir, "snapshots");
  let files: string[];
  try {
    files = await fs.readdir(snapshotsDir);
  } catch {
    return null;
  }

  const snapshotFiles = files
    .filter((f) => f.startsWith("snapshot-") && f.endsWith(".json.gz"))
    .sort()
    .reverse();

  if (snapshotFiles.length === 0) {
    return null;
  }

  const latestFile = path.join(snapshotsDir, snapshotFiles[0]!);
  try {
    const compressed = await fs.readFile(latestFile);
    const decompressed = await gunzipAsync(compressed);
    return JSON.parse(decompressed.toString("utf8")) as CompactionSnapshot;
  } catch (err) {
    console.error(`[s3-guardian:compaction] Failed to read snapshot ${latestFile}:`, err);
    return null;
  }
}

/**
 * Reads aggregated history for a specific bucket, merging the latest snapshot
 * with uncompacted events in audit.jsonl.
 */
export async function getBucketHistory(
  stateDir: string,
  bucketName: string
): Promise<BucketAggregate | null> {
  let aggregate: BucketAggregate | null = null;

  // 1. Load baseline from latest snapshot
  const latestSnapshot = await readLatestSnapshot(stateDir);
  if (latestSnapshot && latestSnapshot.buckets) {
    for (const [key, b] of Object.entries(latestSnapshot.buckets)) {
      if (b.bucketName === bucketName || key.endsWith(`:${bucketName}`)) {
        aggregate = { ...b };
        break;
      }
    }
  }

  // 2. Stream uncompacted audit.jsonl events
  const logPath = path.join(stateDir, "audit.jsonl");
  try {
    await fs.access(logPath);
  } catch {
    return aggregate;
  }

  const fileStream = fsSync.createReadStream(logPath, { encoding: "utf8" });
  const rl = readline.createInterface({
    input: fileStream,
    crlfDelay: Infinity,
  });

  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    let event: AuditEvent;
    try {
      event = JSON.parse(trimmed);
    } catch {
      continue;
    }

    if (event.bucketName !== bucketName) continue;

    if (!aggregate) {
      aggregate = {
        accountId: event.accountId,
        bucketName: event.bucketName,
        totalBytesFreed: 0,
        totalEstimatedSavingsUSD: 0,
        eventCount: 0,
        lastEventTimestamp: event.timestamp,
        circuitBreakerTrips: 0,
      };
    }

    aggregate.eventCount++;
    if (typeof event.bytesFreed === "number") {
      aggregate.totalBytesFreed += event.bytesFreed;
    }
    if (typeof event.estimatedSavingsUSD === "number") {
      aggregate.totalEstimatedSavingsUSD += event.estimatedSavingsUSD;
    }
    if (event.eventType === "CIRCUIT_BREAKER_TRIPPED") {
      aggregate.circuitBreakerTrips++;
    }
    if (event.planHash) {
      aggregate.lastSeenPlanHash = event.planHash;
    }
    if (!aggregate.lastEventTimestamp || event.timestamp > aggregate.lastEventTimestamp) {
      aggregate.lastEventTimestamp = event.timestamp;
    }
    if (event.details) {
      aggregate.details = { ...(aggregate.details ?? {}), ...event.details };
    }
  }

  return aggregate;
}

/**
 * Compactor: executes streaming compaction of audit.jsonl with < 50MB RSS memory footprint.
 */
export class Compactor {
  /**
   * Compacts audit.jsonl into a gzip-compressed snapshot and rotates the log.
   */
  static async compactAuditLog(
    stateDir: string,
    options: CompactionOptions = {}
  ): Promise<CompactionResult> {
    const logPath = path.join(stateDir, "audit.jsonl");
    const snapshotsDir = path.join(stateDir, "snapshots");
    await fs.mkdir(snapshotsDir, { recursive: true });

    if (options.writer) {
      await options.writer.close();
    }

    // Check if audit.jsonl exists and has content
    try {
      const stat = await fs.stat(logPath);
      if (stat.size === 0) {
        return { snapshotPath: "", compactedCount: 0 };
      }
    } catch {
      return { snapshotPath: "", compactedCount: 0 };
    }

    // 1. Atomically rotate audit.jsonl to rotating file
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const rotatingPath = path.join(stateDir, `audit.jsonl.rotating.${Date.now()}`);

    // Bounded retry for Windows NTFS file lock safety during rotation rename
    const startTime = Date.now();
    let attempt = 0;
    const renameFn = options._fs?.rename ?? fs.rename;
    while (true) {
      try {
        await renameFn(logPath, rotatingPath);
        break;
      } catch (err: unknown) {
        const code =
          err && typeof err === "object" && "code" in err
            ? (err as { code: unknown }).code
            : undefined;
        const isLock = code === "EPERM" || code === "EBUSY" || code === "EACCES";
        if (!isLock || Date.now() - startTime >= 3000) {
          throw err;
        }
        attempt++;
        const delay = Math.floor(Math.random() * Math.min(300, 20 * Math.pow(2, attempt))) + 10;
        await new Promise((res) => setTimeout(res, delay));
      }
    }

    // Re-create a clean, empty audit.jsonl
    await fs.writeFile(logPath, "", "utf8");

    // 2. Initialize aggregated map (optionally seeding with previous snapshot)
    const aggregates = new Map<string, BucketAggregate>();

    if (options.mergePreviousSnapshot !== false) {
      const prev = await readLatestSnapshot(stateDir);
      if (prev && prev.buckets) {
        for (const [key, val] of Object.entries(prev.buckets)) {
          aggregates.set(key, { ...val });
        }
      }
    }

    // 3. Stream rotating file line-by-line (< 50MB RSS)
    let compactedCount = 0;
    const fileStream = fsSync.createReadStream(rotatingPath, { encoding: "utf8" });
    const rl = readline.createInterface({
      input: fileStream,
      crlfDelay: Infinity,
    });

    for await (const line of rl) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      compactedCount++;
      let event: AuditEvent;
      try {
        event = JSON.parse(trimmed);
      } catch {
        continue;
      }

      const key = `${event.accountId}:${event.bucketName}`;
      let agg = aggregates.get(key);
      if (!agg) {
        agg = {
          accountId: event.accountId,
          bucketName: event.bucketName,
          totalBytesFreed: 0,
          totalEstimatedSavingsUSD: 0,
          eventCount: 0,
          lastEventTimestamp: event.timestamp,
          circuitBreakerTrips: 0,
        };
        aggregates.set(key, agg);
      }

      agg.eventCount++;
      if (typeof event.bytesFreed === "number") {
        agg.totalBytesFreed += event.bytesFreed;
      }
      if (typeof event.estimatedSavingsUSD === "number") {
        agg.totalEstimatedSavingsUSD += event.estimatedSavingsUSD;
      }
      if (event.eventType === "CIRCUIT_BREAKER_TRIPPED") {
        agg.circuitBreakerTrips++;
      }
      if (event.planHash) {
        agg.lastSeenPlanHash = event.planHash;
      }
      if (!agg.lastEventTimestamp || event.timestamp > agg.lastEventTimestamp) {
        agg.lastEventTimestamp = event.timestamp;
      }
      if (event.details) {
        agg.details = { ...(agg.details ?? {}), ...event.details };
      }
    }

    // 4. Compress aggregated snapshot directly to snapshots/snapshot-<timestamp>.json.gz
    const snapshotPath = path.join(snapshotsDir, `snapshot-${timestamp}.json.gz`);
    const snapshotPayload: CompactionSnapshot = {
      snapshotVersion: "1.0",
      compactedAt: new Date().toISOString(),
      sourceEventsCount: compactedCount,
      buckets: Object.fromEntries(aggregates.entries()),
    };

    const jsonBuffer = Buffer.from(JSON.stringify(snapshotPayload, null, 2), "utf8");
    const sourceStream = Readable.from(jsonBuffer);
    const gzipStream = createGzip({ level: 9 });
    const outStream = fsSync.createWriteStream(snapshotPath);

    await pipeline(sourceStream, gzipStream, outStream);

    // 5. Unlink the rotating log file
    await fs.unlink(rotatingPath).catch(() => {});

    // 6. S3 Mirror Upload if configured
    if (options.s3MirrorBucket) {
      const s3Client = options.s3Client ?? new S3Client({});
      const fileName = path.basename(snapshotPath);
      const s3Key = `guardian-state/${fileName}`;
      const fileData = await fs.readFile(snapshotPath);

      await s3Client.send(
        new PutObjectCommand({
          Bucket: options.s3MirrorBucket,
          Key: s3Key,
          Body: fileData,
          ContentType: "application/gzip",
        })
      );
    }

    return {
      snapshotPath,
      compactedCount,
    };
  }
}
