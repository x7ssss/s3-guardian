import { describe, it, expect, beforeEach, vi } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  S3Client,
  ListMultipartUploadsCommand,
  ListPartsCommand,
} from "@aws-sdk/client-s3";
import {
  scanMultipartUploads,
  scanMultipartUploadsStream,
  getUploadPartsInfo,
} from "../src/scanner/multipart.js";

const s3Mock = mockClient(S3Client);

describe("Scanner: multipart uploads & parts pagination", () => {
  beforeEach(() => {
    s3Mock.reset();
  });

  it("paginates ListMultipartUploads using BOTH KeyMarker AND UploadIdMarker", async () => {
    const s3Client = new S3Client({});
    const now = new Date("2026-09-20T12:00:00.000Z");
    const oldDate = new Date("2026-09-01T00:00:00.000Z");

    // Page 1
    s3Mock
      .on(ListMultipartUploadsCommand, {
        Bucket: "my-bucket",
        KeyMarker: undefined,
        UploadIdMarker: undefined,
      })
      .resolvesOnce({
        IsTruncated: true,
        NextKeyMarker: "page1-key.bin",
        NextUploadIdMarker: "page1-upload-id",
        Uploads: [
          {
            Key: "page1-key.bin",
            UploadId: "page1-upload-id",
            Initiated: oldDate,
          },
        ],
      });

    // Page 2
    s3Mock
      .on(ListMultipartUploadsCommand, {
        Bucket: "my-bucket",
        KeyMarker: "page1-key.bin",
        UploadIdMarker: "page1-upload-id",
      })
      .resolvesOnce({
        IsTruncated: false,
        Uploads: [
          {
            Key: "page2-key.bin",
            UploadId: "page2-upload-id",
            Initiated: oldDate,
          },
        ],
      });

    // Mock parts for both uploads
    s3Mock
      .on(ListPartsCommand, {
        Bucket: "my-bucket",
        Key: "page1-key.bin",
        UploadId: "page1-upload-id",
      })
      .resolves({
        IsTruncated: false,
        Parts: [{ PartNumber: 1, Size: 1000 }],
      });

    s3Mock
      .on(ListPartsCommand, {
        Bucket: "my-bucket",
        Key: "page2-key.bin",
        UploadId: "page2-upload-id",
      })
      .resolves({
        IsTruncated: false,
        Parts: [{ PartNumber: 1, Size: 2000 }],
      });

    const result = await scanMultipartUploads(s3Client, "my-bucket", {
      now,
      olderThanDays: 7,
      retryOptions: { initialDelayMs: 1 },
    });

    expect(result.totalZombieUploads).toBe(2);
    expect(result.totalStrandedBytes).toBe(3000);
    expect(result.uploads.map((u) => u.key)).toEqual([
      "page1-key.bin",
      "page2-key.bin",
    ]);
  });

  it("handles fallback to last upload's Key and UploadId when Next markers are omitted", async () => {
    const s3Client = new S3Client({});
    const now = new Date("2026-09-20T12:00:00.000Z");
    const oldDate = new Date("2026-09-01T00:00:00.000Z");

    // Page 1: IsTruncated is true, but NextKeyMarker/NextUploadIdMarker are not provided
    s3Mock
      .on(ListMultipartUploadsCommand, {
        Bucket: "my-bucket",
        KeyMarker: undefined,
        UploadIdMarker: undefined,
      })
      .resolvesOnce({
        IsTruncated: true,
        Uploads: [
          {
            Key: "fallback-key.bin",
            UploadId: "fallback-uid",
            Initiated: oldDate,
          },
        ],
      });

    // Page 2: Called with the fallback Key and UploadId
    s3Mock
      .on(ListMultipartUploadsCommand, {
        Bucket: "my-bucket",
        KeyMarker: "fallback-key.bin",
        UploadIdMarker: "fallback-uid",
      })
      .resolvesOnce({
        IsTruncated: false,
        Uploads: [],
      });

    s3Mock.on(ListPartsCommand).resolves({
      IsTruncated: false,
      Parts: [{ PartNumber: 1, Size: 500 }],
    });

    const result = await scanMultipartUploads(s3Client, "my-bucket", {
      now,
      olderThanDays: 7,
      retryOptions: { initialDelayMs: 1 },
    });

    expect(result.totalZombieUploads).toBe(1);
    expect(result.uploads[0].key).toBe("fallback-key.bin");
    expect(result.uploads[0].bytes).toBe(500);
  });

  it("prevents infinite loops when response is truncated but no markers or uploads exist", async () => {
    const s3Client = new S3Client({});
    const now = new Date("2026-09-20T12:00:00.000Z");

    // Broken server response: IsTruncated=true, but Uploads=[] and NextKeyMarker is undefined
    s3Mock.on(ListMultipartUploadsCommand).resolvesOnce({
      IsTruncated: true,
      Uploads: [],
    });

    const result = await scanMultipartUploads(s3Client, "my-bucket", {
      now,
      olderThanDays: 7,
      retryOptions: { initialDelayMs: 1 },
    });

    expect(result.totalZombieUploads).toBe(0);
    expect(s3Mock.commandCalls(ListMultipartUploadsCommand).length).toBe(1);
  });

  it("filters out uploads younger than olderThanDays", async () => {
    const s3Client = new S3Client({});
    const now = new Date("2026-09-20T12:00:00.000Z");
    const zombieDate = new Date("2026-09-10T00:00:00.000Z"); // 10 days old
    const freshDate = new Date("2026-09-18T00:00:00.000Z"); // 2 days old

    s3Mock.on(ListMultipartUploadsCommand).resolvesOnce({
      IsTruncated: false,
      Uploads: [
        { Key: "old-zombie.bin", UploadId: "id-old", Initiated: zombieDate },
        { Key: "fresh-active.bin", UploadId: "id-fresh", Initiated: freshDate },
      ],
    });

    s3Mock
      .on(ListPartsCommand, {
        Bucket: "my-bucket",
        Key: "old-zombie.bin",
        UploadId: "id-old",
      })
      .resolves({
        IsTruncated: false,
        Parts: [{ PartNumber: 1, Size: 1048576 }],
      });

    const result = await scanMultipartUploads(s3Client, "my-bucket", {
      now,
      olderThanDays: 7,
      retryOptions: { initialDelayMs: 1 },
    });

    expect(result.totalZombieUploads).toBe(1);
    expect(result.uploads[0].key).toBe("old-zombie.bin");
    expect(result.totalStrandedBytes).toBe(1048576);
  });

  it("paginates ListParts using PartNumberMarker and sums stranded bytes", async () => {
    const s3Client = new S3Client({});

    // Page 1: parts 1 and 2
    s3Mock
      .on(ListPartsCommand, {
        Bucket: "my-bucket",
        Key: "multi-part.iso",
        UploadId: "up-multi",
        PartNumberMarker: undefined,
      })
      .resolvesOnce({
        IsTruncated: true,
        NextPartNumberMarker: "2",
        Parts: [
          { PartNumber: 1, Size: 5242880 }, // 5 MB
          { PartNumber: 2, Size: 5242880 }, // 5 MB
        ],
      });

    // Page 2: parts 3
    s3Mock
      .on(ListPartsCommand, {
        Bucket: "my-bucket",
        Key: "multi-part.iso",
        UploadId: "up-multi",
        PartNumberMarker: "2",
      })
      .resolvesOnce({
        IsTruncated: false,
        Parts: [
          { PartNumber: 3, Size: 2097152 }, // 2 MB
        ],
      });

    const partsInfo = await getUploadPartsInfo(
      s3Client,
      "my-bucket",
      "multi-part.iso",
      "up-multi",
      { initialDelayMs: 1 }
    );

    expect(partsInfo.partsCount).toBe(3);
    expect(partsInfo.bytes).toBe(5242880 + 5242880 + 2097152);
  });

  it("handles fallback to last part number when NextPartNumberMarker is omitted", async () => {
    const s3Client = new S3Client({});

    // Page 1: IsTruncated true, but NextPartNumberMarker is omitted
    s3Mock
      .on(ListPartsCommand, {
        Bucket: "my-bucket",
        Key: "test.bin",
        UploadId: "uid-1",
        PartNumberMarker: undefined,
      })
      .resolvesOnce({
        IsTruncated: true,
        Parts: [{ PartNumber: 1, Size: 100 }],
      });

    // Page 2: Requested with PartNumberMarker="1"
    s3Mock
      .on(ListPartsCommand, {
        Bucket: "my-bucket",
        Key: "test.bin",
        UploadId: "uid-1",
        PartNumberMarker: "1",
      })
      .resolvesOnce({
        IsTruncated: false,
        Parts: [{ PartNumber: 2, Size: 200 }],
      });

    const partsInfo = await getUploadPartsInfo(
      s3Client,
      "my-bucket",
      "test.bin",
      "uid-1",
      { initialDelayMs: 1 }
    );

    expect(partsInfo.partsCount).toBe(2);
    expect(partsInfo.bytes).toBe(300);
  });

  it("retries on 503 Slow Down and eventually succeeds", async () => {
    const s3Client = new S3Client({});

    const slowDownError = new Error("Slow Down");
    (slowDownError as any).$metadata = { httpStatusCode: 503 };
    slowDownError.name = "SlowDown";

    // Reject first with 503 SlowDown, then resolve
    s3Mock
      .on(ListPartsCommand)
      .rejectsOnce(slowDownError)
      .resolvesOnce({
        IsTruncated: false,
        Parts: [{ PartNumber: 1, Size: 1024 }],
      });

    const partsInfo = await getUploadPartsInfo(
      s3Client,
      "my-bucket",
      "retry-file.bin",
      "uid-retry",
      { initialDelayMs: 1, maxRetries: 3 }
    );

    expect(partsInfo.partsCount).toBe(1);
    expect(partsInfo.bytes).toBe(1024);
  });

  it("handles NoSuchUpload (404) gracefully if upload disappears during scan", async () => {
    const s3Client = new S3Client({});

    const noSuchUploadError = new Error("The specified upload does not exist");
    noSuchUploadError.name = "NoSuchUpload";
    (noSuchUploadError as any).$metadata = { httpStatusCode: 404 };

    s3Mock.on(ListPartsCommand).rejectsOnce(noSuchUploadError);

    const partsInfo = await getUploadPartsInfo(
      s3Client,
      "my-bucket",
      "deleted.bin",
      "uid-gone",
      { initialDelayMs: 1 }
    );

    expect(partsInfo.partsCount).toBe(0);
    expect(partsInfo.bytes).toBe(0);
  });

  it("respects concurrency limit when querying multiple zombie uploads", async () => {
    const s3Client = new S3Client({});
    const now = new Date("2026-09-20T12:00:00.000Z");
    const oldDate = new Date("2026-09-01T00:00:00.000Z");

    // 15 zombie uploads
    const uploads = Array.from({ length: 15 }, (_, i) => ({
      Key: `file-${i}.bin`,
      UploadId: `uid-${i}`,
      Initiated: oldDate,
    }));

    s3Mock.on(ListMultipartUploadsCommand).resolvesOnce({
      IsTruncated: false,
      Uploads: uploads,
    });

    let currentConcurrency = 0;
    let maxObservedConcurrency = 0;

    s3Mock.on(ListPartsCommand).callsFake(async () => {
      currentConcurrency++;
      if (currentConcurrency > maxObservedConcurrency) {
        maxObservedConcurrency = currentConcurrency;
      }
      // Small artificial delay to verify concurrency
      await new Promise((res) => setTimeout(res, 10));
      currentConcurrency--;
      return {
        IsTruncated: false,
        Parts: [{ PartNumber: 1, Size: 100 }],
      };
    });

    const result = await scanMultipartUploads(s3Client, "my-bucket", {
      now,
      olderThanDays: 7,
      concurrencyLimit: 10,
      retryOptions: { initialDelayMs: 1 },
    });

    expect(result.totalZombieUploads).toBe(15);
    expect(maxObservedConcurrency).toBeLessThanOrEqual(10);
  });

  it("scanMultipartUploads exposes storageClass from ListMultipartUploads", async () => {
    const s3Client = new S3Client({});
    const now = new Date("2026-09-20T12:00:00.000Z");
    const oldDate = new Date("2026-09-01T00:00:00.000Z");

    s3Mock.on(ListMultipartUploadsCommand).resolvesOnce({
      IsTruncated: false,
      Uploads: [
        {
          Key: "glacier-file.bin",
          UploadId: "uid-glacier",
          Initiated: oldDate,
          StorageClass: "GLACIER",
        },
        {
          Key: "standard-file.bin",
          UploadId: "uid-std",
          Initiated: oldDate,
          // StorageClass omitted → should default to "STANDARD"
        },
      ],
    });

    s3Mock.on(ListPartsCommand).resolves({
      IsTruncated: false,
      Parts: [{ PartNumber: 1, Size: 500 }],
    });

    const result = await scanMultipartUploads(s3Client, "my-bucket", {
      now,
      olderThanDays: 7,
      retryOptions: { initialDelayMs: 1 },
    });

    expect(result.totalZombieUploads).toBe(2);
    const glacierItem = result.uploads.find((u) => u.key === "glacier-file.bin");
    const standardItem = result.uploads.find((u) => u.key === "standard-file.bin");
    expect(glacierItem?.storageClass).toBe("GLACIER");
    expect(standardItem?.storageClass).toBe("STANDARD");
  });
});

describe("Scanner: scanMultipartUploadsStream async generator", () => {
  beforeEach(() => {
    s3Mock.reset();
  });

  it("yields uploads page-by-page without accumulating all in memory", async () => {
    const s3Client = new S3Client({});
    const now = new Date("2026-09-20T12:00:00.000Z");
    const oldDate = new Date("2026-09-01T00:00:00.000Z");

    // Page 1
    s3Mock
      .on(ListMultipartUploadsCommand, {
        Bucket: "stream-bucket",
        KeyMarker: undefined,
        UploadIdMarker: undefined,
      })
      .resolvesOnce({
        IsTruncated: true,
        NextKeyMarker: "page1.bin",
        NextUploadIdMarker: "uid-page1",
        Uploads: [
          { Key: "page1.bin", UploadId: "uid-page1", Initiated: oldDate },
        ],
      });

    // Page 2
    s3Mock
      .on(ListMultipartUploadsCommand, {
        Bucket: "stream-bucket",
        KeyMarker: "page1.bin",
        UploadIdMarker: "uid-page1",
      })
      .resolvesOnce({
        IsTruncated: false,
        Uploads: [
          { Key: "page2.bin", UploadId: "uid-page2", Initiated: oldDate },
        ],
      });

    const yielded: string[] = [];
    for await (const item of scanMultipartUploadsStream(s3Client, "stream-bucket", {
      now,
      olderThanDays: 7,
    })) {
      yielded.push(item.key);
    }

    expect(yielded).toEqual(["page1.bin", "page2.bin"]);
    expect(s3Mock.commandCalls(ListMultipartUploadsCommand).length).toBe(2);
  });

  it("yields only uploads older than olderThanDays, skipping fresh ones", async () => {
    const s3Client = new S3Client({});
    const now = new Date("2026-09-20T12:00:00.000Z");

    s3Mock.on(ListMultipartUploadsCommand).resolvesOnce({
      IsTruncated: false,
      Uploads: [
        {
          Key: "old.bin",
          UploadId: "uid-old",
          Initiated: new Date("2026-09-01T00:00:00.000Z"), // 19 days old
        },
        {
          Key: "fresh.bin",
          UploadId: "uid-fresh",
          Initiated: new Date("2026-09-19T00:00:00.000Z"), // 1 day old
        },
      ],
    });

    const yielded: string[] = [];
    for await (const item of scanMultipartUploadsStream(s3Client, "stream-bucket", {
      now,
      olderThanDays: 7,
    })) {
      yielded.push(item.key);
    }

    expect(yielded).toEqual(["old.bin"]);
  });

  it("yields the StorageClass field correctly from ListMultipartUploads", async () => {
    const s3Client = new S3Client({});
    const now = new Date("2026-09-20T12:00:00.000Z");
    const oldDate = new Date("2026-09-01T00:00:00.000Z");

    s3Mock.on(ListMultipartUploadsCommand).resolvesOnce({
      IsTruncated: false,
      Uploads: [
        {
          Key: "cold.bin",
          UploadId: "uid-cold",
          Initiated: oldDate,
          StorageClass: "GLACIER",
        },
        {
          Key: "standard.bin",
          UploadId: "uid-std",
          Initiated: oldDate,
          // StorageClass omitted → should default to "STANDARD"
        },
      ],
    });

    const items: Array<{ key: string; storageClass: string }> = [];
    for await (const item of scanMultipartUploadsStream(s3Client, "stream-bucket", {
      now,
      olderThanDays: 7,
    })) {
      items.push({ key: item.key, storageClass: item.storageClass });
    }

    expect(items).toHaveLength(2);
    expect(items.find((i) => i.key === "cold.bin")?.storageClass).toBe("GLACIER");
    expect(items.find((i) => i.key === "standard.bin")?.storageClass).toBe("STANDARD");
  });

  it("stops immediately on empty page (not truncated)", async () => {
    const s3Client = new S3Client({});
    const now = new Date("2026-09-20T12:00:00.000Z");

    s3Mock.on(ListMultipartUploadsCommand).resolvesOnce({
      IsTruncated: false,
      Uploads: [],
    });

    const items = [];
    for await (const item of scanMultipartUploadsStream(s3Client, "empty-bucket", { now })) {
      items.push(item);
    }

    expect(items).toHaveLength(0);
    expect(s3Mock.commandCalls(ListMultipartUploadsCommand).length).toBe(1);
  });

  it("applies prefix filter option to ListMultipartUploads", async () => {
    const s3Client = new S3Client({});
    const now = new Date("2026-09-20T12:00:00.000Z");
    const oldDate = new Date("2026-09-01T00:00:00.000Z");

    s3Mock
      .on(ListMultipartUploadsCommand, {
        Bucket: "prefix-bucket",
        Prefix: "uploads/",
      })
      .resolvesOnce({
        IsTruncated: false,
        Uploads: [
          { Key: "uploads/file.bin", UploadId: "uid-1", Initiated: oldDate },
        ],
      });

    const items = [];
    for await (const item of scanMultipartUploadsStream(s3Client, "prefix-bucket", {
      now,
      olderThanDays: 7,
      prefix: "uploads/",
    })) {
      items.push(item);
    }

    expect(items).toHaveLength(1);
    expect(items[0].key).toBe("uploads/file.bin");
    // Verify the mock was called with correct prefix
    const calls = s3Mock.commandCalls(ListMultipartUploadsCommand);
    expect(calls.length).toBeGreaterThan(0);
    // The first call should have the prefix in its input
    const firstCallInput = calls[0].args[0].input;
    expect(firstCallInput.Prefix).toBe("uploads/");
  });
});
