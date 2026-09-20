import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";
import { mockClient } from "aws-sdk-client-mock";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import {
  Compactor,
  readLatestSnapshot,
  getBucketHistory,
} from "../src/state/compaction.js";
import { AuditLogWriter } from "../src/state/audit-writer.js";
import { createAuditEvent, AuditEvent } from "../src/state/types.js";

const s3Mock = mockClient(S3Client);

describe("Audit Compactor & History (Compactor)", () => {
  let tempDir: string;

  beforeEach(async () => {
    s3Mock.reset();
    tempDir = path.join(os.tmpdir(), "s3-guardian-compactor-test-" + Math.random().toString(36).slice(2));
    await fs.mkdir(tempDir, { recursive: true });
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
  });

  it("returns empty result if audit.jsonl does not exist or is empty", async () => {
    const res1 = await Compactor.compactAuditLog(tempDir);
    expect(res1.compactedCount).toBe(0);
    expect(res1.snapshotPath).toBe("");

    // Empty file
    await fs.writeFile(path.join(tempDir, "audit.jsonl"), "", "utf8");
    const res2 = await Compactor.compactAuditLog(tempDir);
    expect(res2.compactedCount).toBe(0);
    expect(res2.snapshotPath).toBe("");
  });

  it("compacts >1,000 streaming events into a compressed .json.gz snapshot and rotates log", async () => {
    const writer = new AuditLogWriter({ stateDir: tempDir });
    const count = 1200;

    let expectedBytesFreedBucketA = 0;
    let expectedSavingsBucketA = 0;
    let expectedTripsBucketB = 0;

    for (let i = 0; i < count; i++) {
      if (i % 3 === 0) {
        // Bucket A remediation
        const bytes = 1000 + i;
        const savings = (1000 + i) * 0.000023;
        expectedBytesFreedBucketA += bytes;
        expectedSavingsBucketA += savings;
        await writer.append(
          createAuditEvent({
            eventType: "REMEDIATION_EXECUTED",
            accountId: "111111111111",
            bucketName: "bucket-alpha",
            bytesFreed: bytes,
            estimatedSavingsUSD: savings,
            planHash: `hash-${i}`,
          })
        );
      } else if (i % 3 === 1) {
        // Bucket B circuit breaker trip
        expectedTripsBucketB++;
        await writer.append(
          createAuditEvent({
            eventType: "CIRCUIT_BREAKER_TRIPPED",
            accountId: "222222222222",
            bucketName: "bucket-beta",
            details: { reason: "403 AccessDenied limit exceeded" },
          })
        );
      } else {
        // Bucket A discovery
        await writer.append(
          createAuditEvent({
            eventType: "DISCOVERY",
            accountId: "111111111111",
            bucketName: "bucket-alpha",
            targetCount: 50,
          })
        );
      }
    }

    await writer.close();

    // Compact the audit log
    const result = await Compactor.compactAuditLog(tempDir);
    expect(result.compactedCount).toBe(count);
    expect(result.snapshotPath).toBeTruthy();
    expect(result.snapshotPath.endsWith(".json.gz")).toBe(true);

    // Verify audit.jsonl was emptied and no rotating file remains
    const remainingLog = await fs.readFile(path.join(tempDir, "audit.jsonl"), "utf8");
    expect(remainingLog).toBe("");

    const dirFiles = await fs.readdir(tempDir);
    expect(dirFiles.some((f) => f.includes("rotating"))).toBe(false);

    // Read and verify the snapshot contents
    const snapshot = await readLatestSnapshot(tempDir);
    expect(snapshot).not.toBeNull();
    expect(snapshot?.snapshotVersion).toBe("1.0");
    expect(snapshot?.sourceEventsCount).toBe(count);

    const bucketAlpha = snapshot?.buckets["111111111111:bucket-alpha"];
    expect(bucketAlpha).toBeDefined();
    expect(bucketAlpha?.bucketName).toBe("bucket-alpha");
    expect(bucketAlpha?.accountId).toBe("111111111111");
    expect(bucketAlpha?.totalBytesFreed).toBe(expectedBytesFreedBucketA);
    expect(bucketAlpha?.totalEstimatedSavingsUSD).toBeCloseTo(expectedSavingsBucketA, 4);

    const bucketBeta = snapshot?.buckets["222222222222:bucket-beta"];
    expect(bucketBeta).toBeDefined();
    expect(bucketBeta?.bucketName).toBe("bucket-beta");
    expect(bucketBeta?.circuitBreakerTrips).toBe(expectedTripsBucketB);
  });

  it("merges previous snapshot aggregates on incremental compactions", async () => {
    const writer = new AuditLogWriter({ stateDir: tempDir });

    // Step 1: Write first event batch and compact
    await writer.append(
      createAuditEvent({
        eventType: "REMEDIATION_EXECUTED",
        accountId: "1001",
        bucketName: "shared-bucket",
        bytesFreed: 500,
        estimatedSavingsUSD: 0.1,
      })
    );
    await writer.close();

    const firstResult = await Compactor.compactAuditLog(tempDir);
    expect(firstResult.compactedCount).toBe(1);

    // Step 2: Write second event batch and compact again
    const writer2 = new AuditLogWriter({ stateDir: tempDir });
    await writer2.append(
      createAuditEvent({
        eventType: "REMEDIATION_EXECUTED",
        accountId: "1001",
        bucketName: "shared-bucket",
        bytesFreed: 300,
        estimatedSavingsUSD: 0.06,
      })
    );
    await writer2.close();

    const secondResult = await Compactor.compactAuditLog(tempDir);
    expect(secondResult.compactedCount).toBe(1);

    // Step 3: Read latest snapshot and verify merged totals: 500 + 300 = 800
    const snapshot = await readLatestSnapshot(tempDir);
    const agg = snapshot?.buckets["1001:shared-bucket"];
    expect(agg?.totalBytesFreed).toBe(800);
    expect(agg?.totalEstimatedSavingsUSD).toBeCloseTo(0.16, 4);
    expect(agg?.eventCount).toBe(2);
  });

  it("getBucketHistory combines snapshot baseline and live uncompacted audit.jsonl events", async () => {
    // 1. Initially unknown bucket returns null
    const initialHist = await getBucketHistory(tempDir, "analytics-bucket");
    expect(initialHist).toBeNull();

    // 2. Compact some events into snapshot
    const writer1 = new AuditLogWriter({ stateDir: tempDir });
    await writer1.append(
      createAuditEvent({
        eventType: "REMEDIATION_EXECUTED",
        accountId: "777788889999",
        bucketName: "analytics-bucket",
        bytesFreed: 10000,
        estimatedSavingsUSD: 1.5,
      })
    );
    await writer1.close();
    await Compactor.compactAuditLog(tempDir);

    // 3. Write live uncompacted events to audit.jsonl
    const writer2 = new AuditLogWriter({ stateDir: tempDir });
    await writer2.append(
      createAuditEvent({
        eventType: "REMEDIATION_EXECUTED",
        accountId: "777788889999",
        bucketName: "analytics-bucket",
        bytesFreed: 5000,
        estimatedSavingsUSD: 0.75,
      })
    );
    await writer2.append(
      createAuditEvent({
        eventType: "CIRCUIT_BREAKER_TRIPPED",
        accountId: "777788889999",
        bucketName: "analytics-bucket",
      })
    );
    await writer2.close();

    // 4. Query history for analytics-bucket
    const history = await getBucketHistory(tempDir, "analytics-bucket");
    expect(history).not.toBeNull();
    expect(history?.bucketName).toBe("analytics-bucket");
    expect(history?.accountId).toBe("777788889999");
    expect(history?.totalBytesFreed).toBe(15000);
    expect(history?.totalEstimatedSavingsUSD).toBeCloseTo(2.25, 4);
    expect(history?.circuitBreakerTrips).toBe(1);
    expect(history?.eventCount).toBe(3);
  });

  it("uploads snapshot to S3 mirror bucket when s3MirrorBucket is specified", async () => {
    s3Mock.on(PutObjectCommand).resolves({});

    const writer = new AuditLogWriter({ stateDir: tempDir });
    await writer.append(
      createAuditEvent({
        eventType: "REMEDIATION_EXECUTED",
        accountId: "123456789012",
        bucketName: "mirror-test-bucket",
        bytesFreed: 4096,
      })
    );
    await writer.close();

    const mockS3 = new S3Client({});
    const result = await Compactor.compactAuditLog(tempDir, {
      s3MirrorBucket: "my-audit-mirror-bucket",
      s3Client: mockS3,
    });

    expect(result.compactedCount).toBe(1);

    const calls = s3Mock.commandCalls(PutObjectCommand);
    expect(calls).toHaveLength(1);
    const putInput = calls[0]!.args[0].input;
    expect(putInput.Bucket).toBe("my-audit-mirror-bucket");
    expect(putInput.Key).toMatch(/^guardian-state\/snapshot-.*\.json\.gz$/);
    expect(putInput.ContentType).toBe("application/gzip");
  });

  it("retries on Windows EPERM during rotation rename", async () => {
    const writer = new AuditLogWriter({ stateDir: tempDir });
    await writer.append(
      createAuditEvent({
        eventType: "DISCOVERY",
        accountId: "123",
        bucketName: "retry-bucket",
      })
    );
    await writer.close();

    let renameAttempts = 0;
    const result = await Compactor.compactAuditLog(tempDir, {
      _fs: {
        rename: async (src, dest) => {
          renameAttempts++;
          if (renameAttempts === 1) {
            const err = new Error("File locked by process") as any;
            err.code = "EPERM";
            throw err;
          }
          return fs.rename(src, dest);
        },
      },
    });
    expect(renameAttempts).toBeGreaterThanOrEqual(2);
    expect(result.compactedCount).toBe(1);
  });
});
