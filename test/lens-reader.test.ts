import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { readStorageLensMetrics } from "../src/lens/reader.js";
import { writeFile, unlink } from "node:fs/promises";
import { resolve as pathResolve } from "node:path";
import { tmpdir } from "node:os";
import { Readable } from "node:stream";

const s3Mock = mockClient(S3Client);

describe("Storage Lens Reader", () => {
  beforeEach(() => {
    s3Mock.reset();
  });

  const sampleCsv = [
    "record_type,aws_account_id,bucket_name,aws_region,storage_bytes,non_current_version_storage_bytes,delete_marker_object_count,incomplete_mpu_storage_bytes,incomplete_mpu_storage_older_than_7_days_bytes",
    "BUCKET,111111111111,bucket-wasteful,us-east-1,1000000000000,500000000000,10,100000000000,50000000000",
    "BUCKET,111111111111,bucket-clean,us-east-1,1000000000000,1000,0,0,0",
    "BUCKET,111111111111,bucket-moderate,us-east-1,1000000000000,200000000000,5,50000000000,20000000000",
  ].join("\n");

  it("reads from a local file and ranks by priority", async () => {
    const tempFile = pathResolve(tmpdir(), `lens-test-${Date.now()}.csv`);
    await writeFile(tempFile, sampleCsv, "utf8");

    try {
      const client = new S3Client({});
      const metrics = await readStorageLensMetrics(client, tempFile);

      expect(metrics).toHaveLength(3);
      // bucket-wasteful has highest waste, so should be rank 1
      expect(metrics[0].bucketName).toBe("bucket-wasteful");
      expect(metrics[1].bucketName).toBe("bucket-moderate");
      expect(metrics[2].bucketName).toBe("bucket-clean");
    } finally {
      await unlink(tempFile).catch(() => {});
    }
  });

  it("reads from S3 URI via GetObjectCommand", async () => {
    s3Mock.on(GetObjectCommand).resolves({
      Body: Readable.from(sampleCsv) as any,
    });

    const client = new S3Client({});
    const metrics = await readStorageLensMetrics(
      client,
      "s3://my-inventory-bucket/lens/daily-export.csv"
    );

    expect(metrics).toHaveLength(3);
    expect(metrics[0].bucketName).toBe("bucket-wasteful");

    const calls = s3Mock.commandCalls(GetObjectCommand);
    expect(calls).toHaveLength(1);
    expect(calls[0].args[0].input.Bucket).toBe("my-inventory-bucket");
    expect(calls[0].args[0].input.Key).toBe("lens/daily-export.csv");
  });

  it("slices results to top N", async () => {
    s3Mock.on(GetObjectCommand).resolves({
      Body: Readable.from(sampleCsv) as any,
    });

    const client = new S3Client({});
    const metrics = await readStorageLensMetrics(
      client,
      "s3://my-bucket/lens.csv",
      { top: 2 }
    );

    expect(metrics).toHaveLength(2);
    expect(metrics[0].bucketName).toBe("bucket-wasteful");
    expect(metrics[1].bucketName).toBe("bucket-moderate");
  });

  it("filters buckets below min-waste-usd threshold", async () => {
    s3Mock.on(GetObjectCommand).resolves({
      Body: Readable.from(sampleCsv) as any,
    });

    const client = new S3Client({});
    // bucket-clean has ~0 waste, bucket-wasteful has 550 GB waste ($11.78/mo)
    const metrics = await readStorageLensMetrics(
      client,
      "s3://my-bucket/lens.csv",
      { minWasteUSD: 5.0 }
    );

    expect(metrics.length).toBeGreaterThan(0);
    expect(metrics.every((m) => m.estimatedMonthlyWasteUSD >= 5.0)).toBe(true);
    expect(metrics.some((m) => m.bucketName === "bucket-clean")).toBe(false);
  });
});
