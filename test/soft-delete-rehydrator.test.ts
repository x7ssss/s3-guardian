import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  S3Client,
  ListObjectVersionsCommand,
  DeleteObjectsCommand,
} from "@aws-sdk/client-s3";
import { rehydrateSoftDeletes } from "../src/rollback/rehydrator.js";

const s3Mock = mockClient(S3Client);

describe("Soft Delete Rehydrator (rehydrateSoftDeletes)", () => {
  beforeEach(() => {
    s3Mock.reset();
  });

  it("discovers latest Delete Markers and un-deletes by popping tombstones via DeleteObjects", async () => {
    const client = new S3Client({});

    // S3 state:
    // doc.pdf:
    //   - Delete Marker (VersionId: "dm-1", IsLatest: true, LastModified: 2026-08-01)
    //   - Data Version  (VersionId: "v-data-1", IsLatest: false, LastModified: 2026-07-01)
    // image.png:
    //   - Delete Marker (VersionId: "dm-2", IsLatest: false, LastModified: 2026-07-15) -> NOT latest, should NOT be popped
    //   - Data Version  (VersionId: "v-data-2", IsLatest: true, LastModified: 2026-08-05)

    s3Mock.on(ListObjectVersionsCommand, { Bucket: "docs-bucket" }).resolvesOnce({
      DeleteMarkers: [
        {
          Key: "doc.pdf",
          VersionId: "dm-1",
          IsLatest: true,
          LastModified: new Date("2026-08-01T12:00:00Z"),
        },
        {
          Key: "image.png",
          VersionId: "dm-2",
          IsLatest: false,
          LastModified: new Date("2026-07-15T12:00:00Z"),
        },
      ],
      Versions: [
        {
          Key: "doc.pdf",
          VersionId: "v-data-1",
          IsLatest: false,
          LastModified: new Date("2026-07-01T12:00:00Z"),
        },
        {
          Key: "image.png",
          VersionId: "v-data-2",
          IsLatest: true,
          LastModified: new Date("2026-08-05T12:00:00Z"),
        },
      ],
      IsTruncated: false,
    });

    s3Mock.on(DeleteObjectsCommand, { Bucket: "docs-bucket" }).resolvesOnce({
      $metadata: { requestId: "aws-req-pop-1" },
      Deleted: [{ Key: "doc.pdf", VersionId: "dm-1" }],
    });

    const result = await rehydrateSoftDeletes(client, "docs-bucket");

    expect(result.dryRun).toBe(false);
    expect(result.discoveredMarkersCount).toBe(1);
    expect(result.restoredCount).toBe(1);
    expect(result.deletedMarkers).toEqual([
      {
        Key: "doc.pdf",
        VersionId: "dm-1",
        LastModified: "2026-08-01T12:00:00.000Z",
      },
    ]);
    expect(result.restoredVersions).toEqual([
      {
        Key: "doc.pdf",
        activeVersionId: "v-data-1",
      },
    ]);
    expect(result.requestIds).toContain("aws-req-pop-1");

    // Invariant 5: Verify DeleteObjectsCommand Quiet: true and exact Key + VersionId
    const delCalls = s3Mock.commandCalls(DeleteObjectsCommand);
    expect(delCalls.length).toBe(1);
    const input = delCalls[0]?.args[0].input;
    expect(input.Bucket).toBe("docs-bucket");
    expect(input.Delete?.Quiet).toBe(true);
    expect(input.Delete?.Objects).toEqual([
      { Key: "doc.pdf", VersionId: "dm-1" },
    ]);
  });

  it("supports dryRun mode: identifies target markers without calling DeleteObjectsCommand", async () => {
    const client = new S3Client({});

    s3Mock.on(ListObjectVersionsCommand, { Bucket: "dry-run-bucket" }).resolvesOnce({
      DeleteMarkers: [
        {
          Key: "contract.pdf",
          VersionId: "dm-contract",
          IsLatest: true,
          LastModified: new Date("2026-08-10T10:00:00Z"),
        },
      ],
      Versions: [
        {
          Key: "contract.pdf",
          VersionId: "v-contract-prev",
          IsLatest: false,
          LastModified: new Date("2026-08-01T10:00:00Z"),
        },
      ],
      IsTruncated: false,
    });

    const result = await rehydrateSoftDeletes(client, "dry-run-bucket", {
      dryRun: true,
    });

    expect(result.dryRun).toBe(true);
    expect(result.discoveredMarkersCount).toBe(1);
    expect(result.restoredCount).toBe(0);
    expect(result.restoredVersions[0]?.activeVersionId).toBe("v-contract-prev");

    // Zero DeleteObjectsCommand calls
    expect(s3Mock.commandCalls(DeleteObjectsCommand).length).toBe(0);
  });

  it("filters markers matching olderThan threshold", async () => {
    const client = new S3Client({});

    s3Mock.on(ListObjectVersionsCommand, { Bucket: "time-bucket" }).resolvesOnce({
      DeleteMarkers: [
        {
          Key: "old-doc.pdf",
          VersionId: "dm-old",
          IsLatest: true,
          LastModified: new Date("2026-07-01T00:00:00Z"),
        },
        {
          Key: "recent-doc.pdf",
          VersionId: "dm-recent",
          IsLatest: true,
          LastModified: new Date("2026-09-15T00:00:00Z"),
        },
      ],
      Versions: [
        { Key: "old-doc.pdf", VersionId: "v-old", IsLatest: false },
        { Key: "recent-doc.pdf", VersionId: "v-recent", IsLatest: false },
      ],
      IsTruncated: false,
    });

    s3Mock.on(DeleteObjectsCommand).resolvesOnce({
      $metadata: { requestId: "req-time" },
    });

    // Rehydrate only markers older than August 1, 2026
    const result = await rehydrateSoftDeletes(client, "time-bucket", {
      olderThan: "2026-08-01T00:00:00.000Z",
    });

    expect(result.discoveredMarkersCount).toBe(1);
    expect(result.deletedMarkers[0]?.Key).toBe("old-doc.pdf");
    expect(result.restoredCount).toBe(1);

    const delCalls = s3Mock.commandCalls(DeleteObjectsCommand);
    expect(delCalls.length).toBe(1);
    expect(delCalls[0]?.args[0].input.Delete?.Objects).toEqual([
      { Key: "old-doc.pdf", VersionId: "dm-old" },
    ]);
  });
});
