import * as readline from "node:readline";
import {
  computeWasteScore,
  StorageLensBucketMetrics,
  StorageLensRawMetrics,
} from "./scorer.js";

export interface ColumnIndices {
  recordType: number;
  accountId: number;
  bucketName: number;
  region: number;
  storageBytes: number;
  noncurrentBytes: number;
  deleteMarkerCount: number;
  incompleteMpuBytes: number;
  incompleteMpuOlderThan7DaysBytes: number;
}

export const DEFAULT_COLUMN_INDICES: ColumnIndices = {
  recordType: 0,
  accountId: 1,
  bucketName: 2,
  region: 3,
  storageBytes: 4,
  noncurrentBytes: 5,
  deleteMarkerCount: 6,
  incompleteMpuBytes: 7,
  incompleteMpuOlderThan7DaysBytes: 8,
};

/**
 * Parses a single CSV line honoring double quotes and escaped quotes.
 */
export function parseCsvLine(line: string): string[] {
  const values: string[] = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (char === "," && !inQuotes) {
      values.push(current.trim());
      current = "";
    } else {
      current += char;
    }
  }

  values.push(current.trim());
  return values;
}

function normalizeHeader(header: string): string {
  return header.trim().toLowerCase().replace(/[^a-z0-9]/g, "");
}

/**
 * Attempts to map column names to ColumnIndices dynamically based on the header row.
 * Returns null if the row does not look like a header row.
 */
export function detectHeaderIndices(headers: string[]): ColumnIndices | null {
  const normalized = headers.map(normalizeHeader);
  const findIndex = (...patterns: string[]): number => {
    return normalized.findIndex((h) => patterns.some((p) => h === p || h.includes(p)));
  };

  const recordTypeIdx = findIndex("recordtype");
  if (recordTypeIdx === -1) {
    // Not a recognizable header row
    return null;
  }

  return {
    recordType: recordTypeIdx,
    accountId: findIndex("awsaccountid", "accountid", "account"),
    bucketName: findIndex("bucketname", "bucket"),
    region: findIndex("awsregion", "region"),
    storageBytes: findIndex("totalstoragebytes", "storagebytes", "bytes"),
    noncurrentBytes: findIndex("noncurrentversionstoragebytes", "noncurrentbytes", "noncurrent"),
    deleteMarkerCount: findIndex("deletemarkerobjectcount", "deletemarkercount", "deletemarkers"),
    incompleteMpuBytes: findIndex("incompletempustoragebytes", "incompletempubytes"),
    incompleteMpuOlderThan7DaysBytes: findIndex(
      "incompletempustorageolderthan7daysbytes",
      "incompletempuolderthan7daysbytes",
      "incompletempu7daysbytes"
    ),
  };
}

function parseNumber(value: string | undefined): number {
  if (!value) return 0;
  const num = parseFloat(value);
  return isNaN(num) || num < 0 ? 0 : num;
}

/**
 * Parses an AWS Storage Lens CSV export stream using native readline.
 *
 * Invariants:
 *  - Zero data-plane API overhead (reads macroscopic export metrics only).
 *  - Dynamically maps headers or falls back to standard Storage Lens schema.
 *  - Filters strictly for record_type === 'BUCKET' (skips ACCOUNT and PREFIX rollups).
 *  - Calculates waste score and priority for all bucket entries.
 */
export async function parseStorageLensCsvStream(
  readableStream: NodeJS.ReadableStream
): Promise<StorageLensBucketMetrics[]> {
  const rl = readline.createInterface({
    input: readableStream,
    crlfDelay: Infinity,
  });

  const results: StorageLensBucketMetrics[] = [];
  let columnIndices: ColumnIndices = DEFAULT_COLUMN_INDICES;
  let isFirstLine = true;

  for await (const rawLine of rl) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    const values = parseCsvLine(line);
    if (values.length === 0 || (values.length === 1 && !values[0])) {
      continue;
    }

    if (isFirstLine) {
      isFirstLine = false;
      const detected = detectHeaderIndices(values);
      if (detected) {
        columnIndices = detected;
        continue; // Skip the header row itself
      }
      // If first row is not a header, fall through and parse it as data using DEFAULT_COLUMN_INDICES
    }

    const recordType = (values[columnIndices.recordType] || "").toUpperCase();
    if (recordType !== "BUCKET") {
      continue;
    }

    const accountId = values[columnIndices.accountId] || "unknown";
    const bucketName = values[columnIndices.bucketName] || "unknown";
    const region = values[columnIndices.region] || "unknown";

    const storageBytes = parseNumber(values[columnIndices.storageBytes]);
    const noncurrentBytes = parseNumber(values[columnIndices.noncurrentBytes]);
    const deleteMarkerCount = Math.round(parseNumber(values[columnIndices.deleteMarkerCount]));
    const incompleteMpuBytes = parseNumber(values[columnIndices.incompleteMpuBytes]);
    const incompleteMpuOlderThan7DaysBytes = parseNumber(
      values[columnIndices.incompleteMpuOlderThan7DaysBytes]
    );

    const rawMetrics: StorageLensRawMetrics = {
      accountId,
      bucketName,
      region,
      storageBytes,
      noncurrentBytes,
      deleteMarkerCount,
      incompleteMpuBytes,
      incompleteMpuOlderThan7DaysBytes,
    };

    results.push(computeWasteScore(rawMetrics));
  }

  return results;
}
