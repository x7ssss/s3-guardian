import { describe, it, expect } from "vitest";
import { Readable } from "node:stream";
import {
  parseCsvLine,
  parseStorageLensCsvStream,
  detectHeaderIndices,
} from "../src/lens/parser.js";

describe("Storage Lens CSV Parser", () => {
  describe("parseCsvLine", () => {
    it("parses unquoted comma-separated values", () => {
      const line = "BUCKET,111111111111,my-bucket,us-east-1,1000,200,5,100,50";
      expect(parseCsvLine(line)).toEqual([
        "BUCKET",
        "111111111111",
        "my-bucket",
        "us-east-1",
        "1000",
        "200",
        "5",
        "100",
        "50",
      ]);
    });

    it("handles quoted values containing commas and escaped quotes", () => {
      const line = '"BUCKET","111111111111","my,bucket,with,commas","us-east-1","1000"';
      expect(parseCsvLine(line)).toEqual([
        "BUCKET",
        "111111111111",
        "my,bucket,with,commas",
        "us-east-1",
        "1000",
      ]);
    });
  });

  describe("detectHeaderIndices", () => {
    it("detects standard snake_case headers", () => {
      const headers = [
        "record_type",
        "aws_account_id",
        "bucket_name",
        "aws_region",
        "storage_bytes",
        "non_current_version_storage_bytes",
        "delete_marker_object_count",
        "incomplete_mpu_storage_bytes",
        "incomplete_mpu_storage_older_than_7_days_bytes",
      ];
      const indices = detectHeaderIndices(headers);
      expect(indices).not.toBeNull();
      expect(indices!.recordType).toBe(0);
      expect(indices!.accountId).toBe(1);
      expect(indices!.bucketName).toBe(2);
      expect(indices!.region).toBe(3);
      expect(indices!.storageBytes).toBe(4);
      expect(indices!.noncurrentBytes).toBe(5);
    });

    it("detects PascalCase and alternative header variations", () => {
      const headers = [
        "RecordType",
        "AccountId",
        "BucketName",
        "Region",
        "TotalStorageBytes",
        "NonCurrentVersionStorageBytes",
        "DeleteMarkerObjectCount",
        "IncompleteMPUStorageBytes",
        "IncompleteMPUStorageOlderThan7DaysBytes",
      ];
      const indices = detectHeaderIndices(headers);
      expect(indices).not.toBeNull();
      expect(indices!.recordType).toBe(0);
      expect(indices!.accountId).toBe(1);
      expect(indices!.bucketName).toBe(2);
      expect(indices!.region).toBe(3);
    });

    it("returns null if row is not a header row", () => {
      const dataRow = ["BUCKET", "111111111111", "bucket-name", "us-east-1"];
      expect(detectHeaderIndices(dataRow)).toBeNull();
    });
  });

  describe("parseStorageLensCsvStream", () => {
    it("parses CSV stream, filters for BUCKET, and ignores ACCOUNT/PREFIX rollups", async () => {
      const csvData = [
        "record_type,aws_account_id,bucket_name,aws_region,storage_bytes,non_current_version_storage_bytes,delete_marker_object_count,incomplete_mpu_storage_bytes,incomplete_mpu_storage_older_than_7_days_bytes",
        "ACCOUNT,111111111111,ALL_BUCKETS,ALL_REGIONS,50000000,10000000,50,5000000,2000000",
        "BUCKET,111111111111,alpha-bucket,us-east-1,1000000,400000,10,200000,100000",
        "PREFIX,111111111111,alpha-bucket,us-east-1,500000,200000,5,100000,50000",
        "BUCKET,111111111111,beta-bucket,us-west-2,2000000,100000,0,50000,0",
      ].join("\n");

      const stream = Readable.from(csvData);
      const metrics = await parseStorageLensCsvStream(stream);

      // Only the 2 BUCKET rows should be returned
      expect(metrics).toHaveLength(2);
      expect(metrics[0].bucketName).toBe("alpha-bucket");
      expect(metrics[0].region).toBe("us-east-1");
      expect(metrics[0].storageBytes).toBe(1_000_000);
      expect(metrics[0].noncurrentBytes).toBe(400_000);
      expect(metrics[0].deleteMarkerCount).toBe(10);
      expect(metrics[0].incompleteMpuBytes).toBe(200_000);
      expect(metrics[0].incompleteMpuOlderThan7DaysBytes).toBe(100_000);
      expect(metrics[0].wasteBytes).toBe(500_000); // 400k + 100k
      expect(metrics[0].wasteScore).toBe(50.0); // 500k / 1M * 100

      expect(metrics[1].bucketName).toBe("beta-bucket");
      expect(metrics[1].region).toBe("us-west-2");
    });

    it("parses headerless CSV using default column indices", async () => {
      const csvData = [
        "BUCKET,222222222222,headerless-bucket,eu-west-1,5000000,1000000,25,500000,250000",
      ].join("\n");

      const stream = Readable.from(csvData);
      const metrics = await parseStorageLensCsvStream(stream);

      expect(metrics).toHaveLength(1);
      expect(metrics[0].bucketName).toBe("headerless-bucket");
      expect(metrics[0].accountId).toBe("222222222222");
      expect(metrics[0].region).toBe("eu-west-1");
      expect(metrics[0].storageBytes).toBe(5_000_000);
    });

    it("handles empty lines and whitespace lines safely", async () => {
      const csvData = [
        "record_type,aws_account_id,bucket_name,aws_region,storage_bytes,non_current_version_storage_bytes,delete_marker_object_count,incomplete_mpu_storage_bytes,incomplete_mpu_storage_older_than_7_days_bytes",
        "",
        "   ",
        "# Comment line",
        "BUCKET,111111111111,clean-bucket,us-east-1,1000,0,0,0,0",
        "",
      ].join("\n");

      const stream = Readable.from(csvData);
      const metrics = await parseStorageLensCsvStream(stream);

      expect(metrics).toHaveLength(1);
      expect(metrics[0].bucketName).toBe("clean-bucket");
    });
  });
});
