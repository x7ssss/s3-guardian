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

// Shared no-op lifecycle audit for tests that don't care about lifecycle
const emptyLifecycleAudit = {
  bucketHasLifecyclePolicy: false,
  hasCoveringRule: false,
  mpuRules: [],
  ghostRulesDetected: [],
  providerNotes: undefined,
};

describe("Planner and Plan Schema", () => {
  const tempDir = path.join(os.tmpdir(), `s3-guardian-test-${Date.now()}`);

  afterEach(async () => {
    try {
      await fs.rm(tempDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it("creates a deterministic plan with sorted uploads (schemaVersion 1.1)", () => {
    const rawUploads = [
      {
        key: "videos/b.mp4",
        uploadId: "id-2",
        initiated: "2026-09-01T00:00:00.000Z",
        partsCount: 2,
        bytes: 2000,
        storageClass: "STANDARD",
        lifecycleStatus: "UNPROTECTED" as const,
      },
      {
        key: "archives/a.tar",
        uploadId: "id-1",
        initiated: "2026-09-01T00:00:00.000Z",
        partsCount: 5,
        bytes: 5000,
        storageClass: "STANDARD",
        lifecycleStatus: "UNPROTECTED" as const,
      },
      {
        key: "videos/b.mp4",
        uploadId: "id-1",
        initiated: "2026-09-01T00:00:00.000Z",
        partsCount: 1,
        bytes: 1000,
        storageClass: "GLACIER",
        lifecycleStatus: "UNPROTECTED" as const,
      },
    ];

    const plan = createPlan({
      bucket: "test-bucket",
      olderThanDays: 7,
      uploads: rawUploads,
      lifecycleAudit: emptyLifecycleAudit,
      generatedAt: "2026-09-20T12:00:00.000Z",
    });

    expect(plan.schemaVersion).toBe("1.1");
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

  it("includes lifecycleAudit in the plan", () => {
    const plan = createPlan({
      bucket: "test-bucket",
      olderThanDays: 7,
      uploads: [],
      lifecycleAudit: {
        bucketHasLifecyclePolicy: true,
        hasCoveringRule: false,
        mpuRules: [],
        ghostRulesDetected: ["Rule 'ghost' uses a Tag filter which is ignored for MPU aborts."],
      },
    });

    expect(plan.lifecycleAudit.bucketHasLifecyclePolicy).toBe(true);
    expect(plan.lifecycleAudit.hasCoveringRule).toBe(false);
    expect(plan.lifecycleAudit.ghostRulesDetected).toHaveLength(1);
  });

  it("adds highVolumeWarning when uploads exceed 10,000", () => {
    const manyUploads = Array.from({ length: 10_001 }, (_, i) => ({
      key: `file-${i}.bin`,
      uploadId: `uid-${i}`,
      initiated: "2026-09-01T00:00:00.000Z",
      partsCount: 1,
      bytes: 100,
      storageClass: "STANDARD",
      lifecycleStatus: "UNPROTECTED" as const,
    }));

    const plan = createPlan({
      bucket: "big-bucket",
      olderThanDays: 7,
      uploads: manyUploads,
      lifecycleAudit: emptyLifecycleAudit,
    });

    expect(plan.highVolumeWarning).toContain("CloudTrail Data Events");
    expect(plan.highVolumeWarning).toContain(">10k uploads");
  });

  it("does NOT add highVolumeWarning when uploads are <= 10,000", () => {
    const plan = createPlan({
      bucket: "small-bucket",
      olderThanDays: 7,
      uploads: [],
      lifecycleAudit: emptyLifecycleAudit,
    });
    expect(plan.highVolumeWarning).toBeUndefined();
  });

  it("validates a valid schema 1.1 plan successfully", () => {
    const validData = {
      schemaVersion: "1.1",
      generatedAt: "2026-09-20T12:00:00.000Z",
      bucket: "prod-bucket",
      endpoint: null,
      olderThanDays: 14,
      totalZombieUploads: 1,
      totalStrandedBytes: 1073741824,
      estimatedMonthlyWasteUSD: 0.02,
      lifecycleAudit: {
        bucketHasLifecyclePolicy: true,
        hasCoveringRule: true,
        ghostRulesDetected: [],
      },
      uploads: [
        {
          key: "backup.iso",
          uploadId: "upl-123",
          initiated: "2026-09-01T00:00:00.000Z",
          partsCount: 10,
          bytes: 1073741824,
          storageClass: "STANDARD",
          lifecycleStatus: "COVERED",
        },
      ],
    };

    const validated = validatePlan(validData);
    expect(validated.schemaVersion).toBe("1.1");
    expect(validated.bucket).toBe("prod-bucket");
    expect(validated.uploads.length).toBe(1);
    expect(validated.uploads[0].key).toBe("backup.iso");
    expect(validated.uploads[0].storageClass).toBe("STANDARD");
    expect(validated.uploads[0].lifecycleStatus).toBe("COVERED");
  });

  it("validates a schema 1.0 plan and up-converts it to 1.1 with safe defaults", () => {
    const legacyData = {
      schemaVersion: "1.0",
      generatedAt: "2026-09-20T12:00:00.000Z",
      bucket: "legacy-bucket",
      endpoint: null,
      olderThanDays: 7,
      totalZombieUploads: 1,
      totalStrandedBytes: 1000,
      estimatedMonthlyWasteUSD: 0,
      uploads: [
        {
          key: "legacy.bin",
          uploadId: "uid-1",
          initiated: "2026-09-01T00:00:00.000Z",
          partsCount: 1,
          bytes: 1000,
          // No storageClass, no lifecycleStatus → should default
        },
      ],
    };

    const validated = validatePlan(legacyData);
    // Up-converted to 1.1
    expect(validated.schemaVersion).toBe("1.1");
    // Safe defaults
    expect(validated.uploads[0].storageClass).toBe("STANDARD");
    expect(validated.uploads[0].lifecycleStatus).toBe("UNPROTECTED");
    expect(validated.lifecycleAudit.bucketHasLifecyclePolicy).toBe(false);
    expect(validated.lifecycleAudit.hasCoveringRule).toBe(false);
    expect(validated.lifecycleAudit.ghostRulesDetected).toEqual([]);
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
        schemaVersion: "1.1",
        bucket: "",
        olderThanDays: 7,
        uploads: [],
      })
    ).toThrow(/missing or invalid 'bucket'/);

    expect(() =>
      validatePlan({
        schemaVersion: "1.1",
        bucket: "b",
        olderThanDays: -1,
        uploads: [],
      })
    ).toThrow(/invalid 'olderThanDays'/);

    expect(() =>
      validatePlan({
        schemaVersion: "1.1",
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
          storageClass: "STANDARD",
          lifecycleStatus: "UNPROTECTED",
        },
      ],
      lifecycleAudit: emptyLifecycleAudit,
    });

    await writePlanFile(planPath, plan);
    const loaded = await readPlanFile(planPath);

    expect(loaded.bucket).toBe("persist-bucket");
    expect(loaded.uploads.length).toBe(1);
    expect(loaded.uploads[0].key).toBe("file.bin");
    expect(loaded.uploads[0].bytes).toBe(3000);
    expect(loaded.uploads[0].storageClass).toBe("STANDARD");
    expect(loaded.lifecycleAudit).toBeDefined();
  });

  it("plan storageClass and lifecycleStatus are preserved through write/read cycle", async () => {
    const planPath = path.join(tempDir, "storageclass-plan.json");
    const plan = createPlan({
      bucket: "sc-bucket",
      olderThanDays: 7,
      uploads: [
        {
          key: "glacier.bin",
          uploadId: "uid-g",
          initiated: "2026-09-01T00:00:00.000Z",
          partsCount: 1,
          bytes: 1000,
          storageClass: "GLACIER",
          lifecycleStatus: "GHOST_RULE",
        },
      ],
      lifecycleAudit: {
        ...emptyLifecycleAudit,
        ghostRulesDetected: ["Rule 'my-rule' uses a Tag filter."],
      },
    });

    await writePlanFile(planPath, plan);
    const loaded = await readPlanFile(planPath);

    expect(loaded.uploads[0].storageClass).toBe("GLACIER");
    expect(loaded.uploads[0].lifecycleStatus).toBe("GHOST_RULE");
    expect(loaded.lifecycleAudit.ghostRulesDetected).toHaveLength(1);
  });
});
