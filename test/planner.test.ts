import { describe, it, expect, afterEach } from "vitest";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";
import {
  createPlan,
  validatePlan,
  writePlanFile,
  readPlanFile,
  Plan,
} from "../src/planner/plan.js";

describe("Planner and Plan Schema", () => {
  const tempDir = path.join(os.tmpdir(), `s3-guardian-test-${Date.now()}`);

  afterEach(async () => {
    try {
      await fs.rm(tempDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it("creates a deterministic plan with sorted uploads", () => {
    const rawUploads = [
      {
        key: "videos/b.mp4",
        uploadId: "id-2",
        initiated: "2026-09-01T00:00:00.000Z",
        partsCount: 2,
        bytes: 2000,
      },
      {
        key: "archives/a.tar",
        uploadId: "id-1",
        initiated: "2026-09-01T00:00:00.000Z",
        partsCount: 5,
        bytes: 5000,
      },
      {
        key: "videos/b.mp4",
        uploadId: "id-1",
        initiated: "2026-09-01T00:00:00.000Z",
        partsCount: 1,
        bytes: 1000,
      },
    ];

    const plan = createPlan({
      bucket: "test-bucket",
      olderThanDays: 7,
      uploads: rawUploads,
      generatedAt: "2026-09-20T12:00:00.000Z",
    });

    expect(plan.schemaVersion).toBe("1.0");
    expect(plan.bucket).toBe("test-bucket");
    expect(plan.olderThanDays).toBe(7);
    expect(plan.totalZombieUploads).toBe(3);
    expect(plan.totalStrandedBytes).toBe(8000);
    expect(plan.estimatedMonthlyWasteUSD).toBe(0);

    // Verify deterministic order: archives/a.tar first, then videos/b.mp4 id-1, then videos/b.mp4 id-2
    expect(plan.uploads[0].key).toBe("archives/a.tar");
    expect(plan.uploads[1].key).toBe("videos/b.mp4");
    expect(plan.uploads[1].uploadId).toBe("id-1");
    expect(plan.uploads[2].key).toBe("videos/b.mp4");
    expect(plan.uploads[2].uploadId).toBe("id-2");
  });

  it("validates a valid plan successfully", () => {
    const validData = {
      schemaVersion: "1.0",
      generatedAt: "2026-09-20T12:00:00.000Z",
      bucket: "prod-bucket",
      endpoint: null,
      olderThanDays: 14,
      totalZombieUploads: 1,
      totalStrandedBytes: 1073741824,
      estimatedMonthlyWasteUSD: 0.02,
      uploads: [
        {
          key: "backup.iso",
          uploadId: "upl-123",
          initiated: "2026-09-01T00:00:00.000Z",
          partsCount: 10,
          bytes: 1073741824,
        },
      ],
    };

    const validated = validatePlan(validData);
    expect(validated.schemaVersion).toBe("1.0");
    expect(validated.bucket).toBe("prod-bucket");
    expect(validated.uploads.length).toBe(1);
    expect(validated.uploads[0].key).toBe("backup.iso");
  });

  it("rejects unsupported schemaVersion", () => {
    expect(() =>
      validatePlan({
        schemaVersion: "2.0",
        bucket: "bucket",
        olderThanDays: 7,
        uploads: [],
      })
    ).toThrow(/Unsupported plan schemaVersion/);
  });

  it("rejects plan with missing bucket or invalid uploads", () => {
    expect(() =>
      validatePlan({
        schemaVersion: "1.0",
        bucket: "",
        olderThanDays: 7,
        uploads: [],
      })
    ).toThrow(/missing or invalid 'bucket'/);

    expect(() =>
      validatePlan({
        schemaVersion: "1.0",
        bucket: "b",
        olderThanDays: -1,
        uploads: [],
      })
    ).toThrow(/invalid 'olderThanDays'/);

    expect(() =>
      validatePlan({
        schemaVersion: "1.0",
        bucket: "b",
        olderThanDays: 7,
        uploads: "not-an-array",
      })
    ).toThrow(/'uploads' must be an array/);
  });

  it("persists and reads plan from disk", async () => {
    const planPath = path.join(tempDir, "sub", "plan.json");
    const plan = createPlan({
      bucket: "persist-bucket",
      olderThanDays: 7,
      uploads: [
        {
          key: "file.bin",
          uploadId: "up-99",
          initiated: "2026-09-01T00:00:00.000Z",
          partsCount: 3,
          bytes: 3000,
        },
      ],
    });

    await writePlanFile(planPath, plan);
    const loaded = await readPlanFile(planPath);

    expect(loaded.bucket).toBe("persist-bucket");
    expect(loaded.uploads.length).toBe(1);
    expect(loaded.uploads[0].key).toBe("file.bin");
    expect(loaded.uploads[0].bytes).toBe(3000);
  });
});
