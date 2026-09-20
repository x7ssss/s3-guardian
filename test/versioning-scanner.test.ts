import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  S3Client,
  ListObjectVersionsCommand,
} from "@aws-sdk/client-s3";
import {
  scanObjectVersionsStream,
  scanObjectVersions,
} from "../src/versioning/scanner.js";

const s3Mock = mockClient(S3Client);

describe("Versioning Scanner", () => {
  beforeEach(() => {
    s3Mock.reset();
  });

  describe("Dual-Marker Pagination (scanObjectVersionsStream)", () => {
    it("paginates using both KeyMarker and VersionIdMarker", async () => {
      const client = new S3Client({});

      // Page 1: returns IsTruncated with NextKeyMarker and NextVersionIdMarker
      s3Mock
        .on(ListObjectVersionsCommand, {
          Bucket: "test-bucket",
          KeyMarker: undefined,
          VersionIdMarker: undefined,
        })
        .resolvesOnce({
          IsTruncated: true,
          NextKeyMarker: "photo.jpg",
          NextVersionIdMarker: "v1",
          Versions: [
            {
              Key: "photo.jpg",
              VersionId: "v2",
              IsLatest: true,
              Size: 5000,
            },
          ],
          DeleteMarkers: [],
        });

      // Page 2: must receive KeyMarker="photo.jpg" AND VersionIdMarker="v1"
      s3Mock
        .on(ListObjectVersionsCommand, {
          Bucket: "test-bucket",
          KeyMarker: "photo.jpg",
          VersionIdMarker: "v1",
        })
        .resolvesOnce({
          IsTruncated: false,
          Versions: [
            {
              Key: "photo.jpg",
              VersionId: "v1",
              IsLatest: false,
              Size: 4500,
            },
          ],
          DeleteMarkers: [],
        });

      const pages = [];
      for await (const page of scanObjectVersionsStream(client, "test-bucket")) {
        pages.push(page);
      }

      expect(pages).toHaveLength(2);
      expect(pages[0].versions[0].VersionId).toBe("v2");
      expect(pages[1].versions[0].VersionId).toBe("v1");
    });

    it("does not terminate pagination when Versions is empty while IsTruncated is true", async () => {
      const client = new S3Client({});

      // Page 1 has empty Versions, but populated DeleteMarkers and IsTruncated: true
      s3Mock
        .on(ListObjectVersionsCommand, {
          Bucket: "test-bucket",
          KeyMarker: undefined,
          VersionIdMarker: undefined,
        })
        .resolvesOnce({
          IsTruncated: true,
          NextKeyMarker: "deleted-file.txt",
          NextVersionIdMarker: "dm1",
          Versions: [],
          DeleteMarkers: [
            {
              Key: "deleted-file.txt",
              VersionId: "dm1",
              IsLatest: true,
            },
          ],
        });

      // Page 2
      s3Mock
        .on(ListObjectVersionsCommand, {
          Bucket: "test-bucket",
          KeyMarker: "deleted-file.txt",
          VersionIdMarker: "dm1",
        })
        .resolvesOnce({
          IsTruncated: false,
          Versions: [
            {
              Key: "second-file.txt",
              VersionId: "v1",
              IsLatest: true,
              Size: 100,
            },
          ],
          DeleteMarkers: [],
        });

      const pages = [];
      for await (const page of scanObjectVersionsStream(client, "test-bucket")) {
        pages.push(page);
      }

      // Must have continued to page 2 despite page 1 having empty Versions
      expect(pages).toHaveLength(2);
      expect(pages[0].deleteMarkers).toHaveLength(1);
      expect(pages[1].versions).toHaveLength(1);
    });

    it("handles multiple versions of the same key across pagination boundaries", async () => {
      const client = new S3Client({});

      s3Mock
        .on(ListObjectVersionsCommand, {
          Bucket: "test-bucket",
          KeyMarker: undefined,
          VersionIdMarker: undefined,
        })
        .resolvesOnce({
          IsTruncated: true,
          NextKeyMarker: "data.csv",
          NextVersionIdMarker: "vid-2",
          Versions: [
            { Key: "data.csv", VersionId: "vid-3", IsLatest: true, Size: 100 },
          ],
        });

      s3Mock
        .on(ListObjectVersionsCommand, {
          Bucket: "test-bucket",
          KeyMarker: "data.csv",
          VersionIdMarker: "vid-2",
        })
        .resolvesOnce({
          IsTruncated: false,
          Versions: [
            { Key: "data.csv", VersionId: "vid-2", IsLatest: false, Size: 90 },
            { Key: "data.csv", VersionId: "vid-1", IsLatest: false, Size: 80 },
          ],
        });

      const pages = [];
      for await (const page of scanObjectVersionsStream(client, "test-bucket")) {
        pages.push(page);
      }

      expect(pages).toHaveLength(2);
      const allVersions = pages.flatMap((p) => p.versions);
      expect(allVersions).toHaveLength(3);
    });
  });

  describe("Quantification (scanObjectVersions)", () => {
    it("sums noncurrent version bytes and identifies Expired Object Delete Markers (EODMs)", async () => {
      const client = new S3Client({});

      // Setup:
      // 1. "file1.txt" has current (100b) and noncurrent (200b)
      // 2. "file2.txt" was deleted, has DeleteMarker (IsLatest: true) and an old noncurrent version (300b) -> DM is NOT expired
      // 3. "file3.txt" has ONLY a DeleteMarker (IsLatest: true) and NO data versions -> EODM!
      // 4. "file4.txt" has current (500b) only
      s3Mock.on(ListObjectVersionsCommand).resolvesOnce({
        IsTruncated: false,
        Versions: [
          { Key: "file1.txt", VersionId: "v1-latest", IsLatest: true, Size: 100 },
          { Key: "file1.txt", VersionId: "v1-old", IsLatest: false, Size: 200 },
          { Key: "file2.txt", VersionId: "v2-old", IsLatest: false, Size: 300 },
          { Key: "file4.txt", VersionId: "v4-latest", IsLatest: true, Size: 500 },
        ],
        DeleteMarkers: [
          { Key: "file2.txt", VersionId: "dm2", IsLatest: true },
          { Key: "file3.txt", VersionId: "dm3", IsLatest: true }, // Expired Object Delete Marker!
        ],
      });

      const result = await scanObjectVersions(client, "my-bucket");

      expect(result.bucket).toBe("my-bucket");
      expect(result.totalVersionsScanned).toBe(4);
      expect(result.totalDeleteMarkersScanned).toBe(2);

      // Noncurrent versions: file1.txt:v1-old (200b) + file2.txt:v2-old (300b) = 500b
      expect(result.noncurrentVersionsCount).toBe(2);
      expect(result.noncurrentBytes).toBe(500);
      expect(result.noncurrentVersions.map((v) => v.versionId)).toEqual(["v1-old", "v2-old"]);

      // Expired Object Delete Markers: only file3.txt (has no data versions)
      expect(result.expiredDeleteMarkersCount).toBe(1);
      expect(result.expiredDeleteMarkers[0].key).toBe("file3.txt");
      expect(result.expiredDeleteMarkers[0].versionId).toBe("dm3");

      // Cost estimation at S3 baseline ($0.023/GiB/month)
      expect(result.estimatedMonthlyWasteUSD).toBeGreaterThanOrEqual(0);
    });

    it("respects olderThanDays cutoff when filtering noncurrent versions", async () => {
      const client = new S3Client({});
      const now = new Date("2026-09-20T12:00:00.000Z");
      const recentDate = new Date("2026-09-18T00:00:00.000Z"); // 2 days old
      const oldDate = new Date("2026-09-01T00:00:00.000Z");    // 19 days old

      s3Mock.on(ListObjectVersionsCommand).resolvesOnce({
        IsTruncated: false,
        Versions: [
          { Key: "doc.pdf", VersionId: "v3", IsLatest: true, Size: 1000, LastModified: recentDate },
          { Key: "doc.pdf", VersionId: "v2", IsLatest: false, Size: 2000, LastModified: recentDate },
          { Key: "doc.pdf", VersionId: "v1", IsLatest: false, Size: 3000, LastModified: oldDate },
        ],
        DeleteMarkers: [],
      });

      const result = await scanObjectVersions(client, "my-bucket", {
        olderThanDays: 7,
        now,
      });

      // Only v1 is older than 7 days
      expect(result.noncurrentVersionsCount).toBe(1);
      expect(result.noncurrentBytes).toBe(3000);
      expect(result.noncurrentVersions[0].versionId).toBe("v1");
    });
  });
});
