import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  S3Client,
  ListBucketsCommand,
  GetBucketLocationCommand,
  ListMultipartUploadsCommand,
  ListPartsCommand,
  GetBucketLifecycleConfigurationCommand,
} from "@aws-sdk/client-s3";
import {
  scanFleet,
  DiscoveryAuthError,
  matchesExcludePattern,
} from "../src/fleet/scanner.js";
import { evaluatePolicy, EXIT_CODES } from "../src/policy/evaluator.js";
import { S3ClientPool } from "../src/discovery/client-pool.js";

const s3Mock = mockClient(S3Client);

// Helper: stub GetBucketLocation to return us-east-1 for all buckets
function stubAllBucketsInUsEast1(bucketNames: string[]) {
  for (const name of bucketNames) {
    s3Mock
      .on(GetBucketLocationCommand, { Bucket: name })
      .resolves({ LocationConstraint: null }); // null = us-east-1
  }
}

// Helper: stub lifecycle as NoSuchLifecycleConfiguration
function stubNoLifecycle() {
  const err = new Error("NoSuchLifecycleConfiguration");
  err.name = "NoSuchLifecycleConfiguration";
  (err as any).$metadata = { httpStatusCode: 404 };
  s3Mock.on(GetBucketLifecycleConfigurationCommand).rejects(err);
}

// Helper: stub clean bucket (no uploads)
function stubCleanBucket() {
  s3Mock.on(ListMultipartUploadsCommand).resolves({
    IsTruncated: false,
    Uploads: [],
  });
}

describe("matchesExcludePattern()", () => {
  it("matches plain substring (case-insensitive)", () => {
    expect(matchesExcludePattern("my-temp-bucket", ["temp"])).toBe(true);
    expect(matchesExcludePattern("MY-TEMP-BUCKET", ["temp"])).toBe(true);
    expect(matchesExcludePattern("production-bucket", ["temp"])).toBe(false);
  });

  it("matches glob prefix pattern", () => {
    expect(matchesExcludePattern("dev-logs-bucket", ["dev-*"])).toBe(true);
    expect(matchesExcludePattern("prod-logs-bucket", ["dev-*"])).toBe(false);
  });

  it("matches glob suffix pattern", () => {
    expect(matchesExcludePattern("bucket-backup", ["*-backup"])).toBe(true);
    expect(matchesExcludePattern("bucket-primary", ["*-backup"])).toBe(false);
  });

  it("matches wildcard anywhere pattern", () => {
    expect(matchesExcludePattern("my-archive-bucket-2026", ["*archive*"])).toBe(true);
    expect(matchesExcludePattern("my-primary-bucket", ["*archive*"])).toBe(false);
  });

  it("matches against multiple patterns (any match wins)", () => {
    expect(matchesExcludePattern("dev-temp", ["prod", "temp"])).toBe(true);
    expect(matchesExcludePattern("dev-primary", ["prod", "temp"])).toBe(false);
  });

  it("returns false for empty pattern list", () => {
    expect(matchesExcludePattern("any-bucket", [])).toBe(false);
  });
});

describe("Fleet scanner: scanFleet()", () => {
  beforeEach(() => {
    s3Mock.reset();
  });

  // ── Discovery auth failure ──────────────────────────────────────────────────

  it("throws DiscoveryAuthError when ListBuckets is denied (exit code 3)", async () => {
    const discoveryClient = new S3Client({});
    const err = new Error("Access Denied");
    err.name = "AccessDenied";
    (err as any).$metadata = { httpStatusCode: 403 };

    s3Mock.on(ListBucketsCommand).rejectsOnce(err);

    await expect(
      scanFleet({ discoveryClient })
    ).rejects.toThrow(DiscoveryAuthError);

    await expect(
      scanFleet({ discoveryClient: new S3Client({}) })
    ).rejects.toThrow(/ListBuckets failed/);
  });

  it("DiscoveryAuthError is an instance of Error", async () => {
    const discoveryClient = new S3Client({});
    const err = new Error("Forbidden");
    err.name = "AccessDenied";
    (err as any).$metadata = { httpStatusCode: 403 };

    s3Mock.on(ListBucketsCommand).rejects(err);

    try {
      await scanFleet({ discoveryClient });
      expect.fail("Should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(DiscoveryAuthError);
      expect(e).toBeInstanceOf(Error);
      expect((e as DiscoveryAuthError).name).toBe("DiscoveryAuthError");
    }
  });

  // ── Empty fleet ────────────────────────────────────────────────────────────

  it("handles empty account (no buckets) gracefully", async () => {
    const pool = new S3ClientPool();
    const discoveryClient = new S3Client({});

    s3Mock.on(ListBucketsCommand).resolves({ Buckets: [] });

    const result = await scanFleet({ discoveryClient, clientPool: pool });
    await pool.destroy();

    expect(result.bucketsDiscovered).toBe(0);
    expect(result.bucketsAudited).toBe(0);
    expect(result.bucketsSkipped).toBe(0);
    expect(result.totalZombieUploads).toBe(0);
    expect(result.bucketResults).toHaveLength(0);
  });

  // ── 403 isolation per bucket ───────────────────────────────────────────────

  it("isolates 403 AccessDenied on one bucket without terminating the fleet", async () => {
    const pool = new S3ClientPool();
    const discoveryClient = new S3Client({});
    const now = new Date("2026-09-20T12:00:00.000Z");
    const oldDate = new Date("2026-09-01T00:00:00.000Z");

    s3Mock.on(ListBucketsCommand).resolves({
      Buckets: [
        { Name: "accessible-bucket" },
        { Name: "denied-bucket" },
      ],
    });

    stubAllBucketsInUsEast1(["accessible-bucket", "denied-bucket"]);
    stubNoLifecycle();

    // accessible-bucket: clean
    s3Mock
      .on(ListMultipartUploadsCommand, { Bucket: "accessible-bucket" })
      .resolves({ IsTruncated: false, Uploads: [] });

    // denied-bucket: 403 on ListMultipartUploads
    const accessErr = new Error("Access Denied");
    accessErr.name = "AccessDenied";
    (accessErr as any).$metadata = { httpStatusCode: 403 };
    s3Mock
      .on(ListMultipartUploadsCommand, { Bucket: "denied-bucket" })
      .rejects(accessErr);

    const result = await scanFleet({ discoveryClient, clientPool: pool, now });
    await pool.destroy();

    expect(result.bucketsDiscovered).toBe(2);
    expect(result.bucketsAudited).toBe(1);
    expect(result.bucketsSkipped).toBe(1);

    const accessible = result.bucketResults.find((r) => r.bucket === "accessible-bucket");
    const denied = result.bucketResults.find((r) => r.bucket === "denied-bucket");

    expect(accessible?.status).toBe("AUDITED");
    expect(denied?.status).toBe("SKIPPED_ACCESS_DENIED");
    expect(denied?.errorMessage).toMatch(/access denied/i);
  });

  it("classifies Requester-Pays bucket as SKIPPED_REQUESTER_PAYS", async () => {
    const pool = new S3ClientPool();
    const discoveryClient = new S3Client({});
    const now = new Date("2026-09-20T12:00:00.000Z");

    s3Mock.on(ListBucketsCommand).resolves({
      Buckets: [{ Name: "requester-pays-bucket" }],
    });
    stubAllBucketsInUsEast1(["requester-pays-bucket"]);
    stubNoLifecycle();

    const rpErr = new Error("BucketIsRequesterPays: Access to this bucket requires requester pays");
    rpErr.name = "BucketIsRequesterPays";
    (rpErr as any).$metadata = { httpStatusCode: 403 };
    s3Mock.on(ListMultipartUploadsCommand).rejects(rpErr);

    const result = await scanFleet({ discoveryClient, clientPool: pool, now });
    await pool.destroy();

    expect(result.bucketsSkipped).toBe(1);
    const rp = result.bucketResults.find((r) => r.bucket === "requester-pays-bucket");
    expect(rp?.status).toBe("SKIPPED_REQUESTER_PAYS");
  });

  it("classifies 404 NoSuchBucket as SKIPPED_NOT_FOUND", async () => {
    const pool = new S3ClientPool();
    const discoveryClient = new S3Client({});
    const now = new Date("2026-09-20T12:00:00.000Z");

    s3Mock.on(ListBucketsCommand).resolves({
      Buckets: [{ Name: "ghost-bucket" }],
    });
    stubAllBucketsInUsEast1(["ghost-bucket"]);
    stubNoLifecycle();

    const notFoundErr = new Error("NoSuchBucket");
    notFoundErr.name = "NoSuchBucket";
    (notFoundErr as any).$metadata = { httpStatusCode: 404 };
    s3Mock.on(ListMultipartUploadsCommand).rejects(notFoundErr);

    const result = await scanFleet({ discoveryClient, clientPool: pool, now });
    await pool.destroy();

    const ghost = result.bucketResults.find((r) => r.bucket === "ghost-bucket");
    expect(ghost?.status).toBe("SKIPPED_NOT_FOUND");
  });

  // ── Multiple buckets with errors: fleet continues ──────────────────────────

  it("continues auditing remaining buckets when multiple individual buckets fail", async () => {
    const pool = new S3ClientPool();
    const discoveryClient = new S3Client({});
    const now = new Date("2026-09-20T12:00:00.000Z");
    const oldDate = new Date("2026-09-01T00:00:00.000Z");

    s3Mock.on(ListBucketsCommand).resolves({
      Buckets: [
        { Name: "ok-bucket-1" },
        { Name: "denied-bucket" },
        { Name: "ok-bucket-2" },
      ],
    });

    stubAllBucketsInUsEast1(["ok-bucket-1", "denied-bucket", "ok-bucket-2"]);
    stubNoLifecycle();

    s3Mock
      .on(ListMultipartUploadsCommand, { Bucket: "ok-bucket-1" })
      .resolves({ IsTruncated: false, Uploads: [
        { Key: "file.bin", UploadId: "uid-1", Initiated: oldDate },
      ]});

    s3Mock
      .on(ListPartsCommand, { Bucket: "ok-bucket-1" })
      .resolves({ IsTruncated: false, Parts: [{ PartNumber: 1, Size: 1000 }] });

    const err = new Error("Access Denied");
    err.name = "AccessDenied";
    (err as any).$metadata = { httpStatusCode: 403 };
    s3Mock
      .on(ListMultipartUploadsCommand, { Bucket: "denied-bucket" })
      .rejects(err);

    s3Mock
      .on(ListMultipartUploadsCommand, { Bucket: "ok-bucket-2" })
      .resolves({ IsTruncated: false, Uploads: [] });

    const result = await scanFleet({
      discoveryClient,
      clientPool: pool,
      now,
      olderThanDays: 7,
      retryOptions: { initialDelayMs: 1 },
    });
    await pool.destroy();

    expect(result.bucketsDiscovered).toBe(3);
    expect(result.bucketsAudited).toBe(2);
    expect(result.bucketsSkipped).toBe(1);
    expect(result.totalZombieUploads).toBe(1);

    const ok1 = result.bucketResults.find((r) => r.bucket === "ok-bucket-1");
    expect(ok1?.status).toBe("AUDITED");
    expect(ok1?.totalZombieUploads).toBe(1);

    const denied = result.bucketResults.find((r) => r.bucket === "denied-bucket");
    expect(denied?.status).toBe("SKIPPED_ACCESS_DENIED");

    const ok2 = result.bucketResults.find((r) => r.bucket === "ok-bucket-2");
    expect(ok2?.status).toBe("AUDITED");
    expect(ok2?.totalZombieUploads).toBe(0);
  });

  // ── Exclusion filters ─────────────────────────────────────────────────────

  it("excludes buckets matching --exclude-bucket patterns", async () => {
    const pool = new S3ClientPool();
    const discoveryClient = new S3Client({});
    const now = new Date("2026-09-20T12:00:00.000Z");

    s3Mock.on(ListBucketsCommand).resolves({
      Buckets: [
        { Name: "prod-data-bucket" },
        { Name: "dev-temp-bucket" },
        { Name: "archive-2024-bucket" },
      ],
    });

    // Only prod-data-bucket needs location + scan; others are filtered before resolution
    stubAllBucketsInUsEast1(["prod-data-bucket"]);
    s3Mock.on(GetBucketLocationCommand, { Bucket: "prod-data-bucket" }).resolves({ LocationConstraint: null });
    stubNoLifecycle();

    s3Mock
      .on(ListMultipartUploadsCommand, { Bucket: "prod-data-bucket" })
      .resolves({ IsTruncated: false, Uploads: [] });

    const result = await scanFleet({
      discoveryClient,
      clientPool: pool,
      now,
      excludeBuckets: ["dev-*", "archive"],
    });
    await pool.destroy();

    expect(result.bucketsDiscovered).toBe(3);
    expect(result.bucketsAudited).toBe(1);
    expect(result.bucketsSkipped).toBe(2);

    const excluded = result.bucketResults.filter((r) => r.status === "SKIPPED_EXCLUDED");
    expect(excluded).toHaveLength(2);
    expect(excluded.map((r) => r.bucket).sort()).toEqual([
      "archive-2024-bucket",
      "dev-temp-bucket",
    ]);
  });

  it("excludes buckets in excluded regions", async () => {
    const pool = new S3ClientPool();
    const discoveryClient = new S3Client({});
    const now = new Date("2026-09-20T12:00:00.000Z");

    s3Mock.on(ListBucketsCommand).resolves({
      Buckets: [
        { Name: "us-bucket" },
        { Name: "eu-bucket" },
      ],
    });

    s3Mock.on(GetBucketLocationCommand, { Bucket: "us-bucket" }).resolves({ LocationConstraint: null }); // us-east-1
    s3Mock.on(GetBucketLocationCommand, { Bucket: "eu-bucket" }).resolves({ LocationConstraint: "eu-central-1" });

    stubNoLifecycle();
    s3Mock
      .on(ListMultipartUploadsCommand, { Bucket: "us-bucket" })
      .resolves({ IsTruncated: false, Uploads: [] });

    const result = await scanFleet({
      discoveryClient,
      clientPool: pool,
      now,
      excludeRegions: ["eu-central-1"],
    });
    await pool.destroy();

    const eu = result.bucketResults.find((r) => r.bucket === "eu-bucket");
    expect(eu?.status).toBe("SKIPPED_EXCLUDED_REGION");
    expect(result.bucketsAudited).toBe(1);
  });

  // ── Aggregated totals ──────────────────────────────────────────────────────

  it("aggregates totalStrandedBytes and totalZombieUploads across all audited buckets", async () => {
    const pool = new S3ClientPool();
    const discoveryClient = new S3Client({});
    const now = new Date("2026-09-20T12:00:00.000Z");
    const oldDate = new Date("2026-09-01T00:00:00.000Z");

    s3Mock.on(ListBucketsCommand).resolves({
      Buckets: [
        { Name: "bucket-a" },
        { Name: "bucket-b" },
      ],
    });

    stubAllBucketsInUsEast1(["bucket-a", "bucket-b"]);
    stubNoLifecycle();

    // bucket-a: 2 uploads × 5MB each
    s3Mock
      .on(ListMultipartUploadsCommand, { Bucket: "bucket-a" })
      .resolves({
        IsTruncated: false,
        Uploads: [
          { Key: "file-a1.bin", UploadId: "uid-a1", Initiated: oldDate },
          { Key: "file-a2.bin", UploadId: "uid-a2", Initiated: oldDate },
        ],
      });
    s3Mock
      .on(ListPartsCommand, { Bucket: "bucket-a", Key: "file-a1.bin" })
      .resolves({ IsTruncated: false, Parts: [{ PartNumber: 1, Size: 5_242_880 }] });
    s3Mock
      .on(ListPartsCommand, { Bucket: "bucket-a", Key: "file-a2.bin" })
      .resolves({ IsTruncated: false, Parts: [{ PartNumber: 1, Size: 5_242_880 }] });

    // bucket-b: 1 upload × 10MB
    s3Mock
      .on(ListMultipartUploadsCommand, { Bucket: "bucket-b" })
      .resolves({
        IsTruncated: false,
        Uploads: [
          { Key: "file-b1.bin", UploadId: "uid-b1", Initiated: oldDate },
        ],
      });
    s3Mock
      .on(ListPartsCommand, { Bucket: "bucket-b", Key: "file-b1.bin" })
      .resolves({ IsTruncated: false, Parts: [{ PartNumber: 1, Size: 10_485_760 }] });

    const result = await scanFleet({
      discoveryClient,
      clientPool: pool,
      now,
      olderThanDays: 7,
      retryOptions: { initialDelayMs: 1 },
    });
    await pool.destroy();

    expect(result.bucketsAudited).toBe(2);
    expect(result.totalZombieUploads).toBe(3);
    expect(result.totalStrandedBytes).toBe(5_242_880 * 2 + 10_485_760);
  });

  // ── Legacy EU region ───────────────────────────────────────────────────────

  it("normalizes legacy 'EU' region from GetBucketLocation to eu-west-1", async () => {
    const pool = new S3ClientPool();
    const discoveryClient = new S3Client({});
    const now = new Date("2026-09-20T12:00:00.000Z");

    s3Mock.on(ListBucketsCommand).resolves({
      Buckets: [{ Name: "legacy-eu-bucket" }],
    });

    s3Mock
      .on(GetBucketLocationCommand, { Bucket: "legacy-eu-bucket" })
      .resolves({ LocationConstraint: "EU" });

    stubNoLifecycle();
    s3Mock
      .on(ListMultipartUploadsCommand, { Bucket: "legacy-eu-bucket" })
      .resolves({ IsTruncated: false, Uploads: [] });

    const result = await scanFleet({ discoveryClient, clientPool: pool, now });
    await pool.destroy();

    const bucket = result.bucketResults.find((r) => r.bucket === "legacy-eu-bucket");
    expect(bucket?.region).toBe("eu-west-1");
    expect(bucket?.status).toBe("AUDITED");
  });
});

// ─── Policy evaluator tests ───────────────────────────────────────────────────

describe("Policy evaluator: evaluatePolicy()", () => {
  const baseResult = {
    bucketsDiscovered: 2,
    bucketsAudited: 2,
    bucketsSkipped: 0,
    totalZombieUploads: 5,
    totalStrandedBytes: 100_000_000,
    totalEstimatedMonthlyWasteUSD: 0,
    bucketResults: [] as any[],
  };

  it("returns exit code 0 (SUCCESS) with no policy options", () => {
    const result = evaluatePolicy({ ...baseResult }, {});
    expect(result.exitCode).toBe(EXIT_CODES.SUCCESS);
    expect(result.violations).toHaveLength(0);
  });

  it("returns exit code 1 (POLICY_VIOLATION) when waste exceeds --max-waste-usd", () => {
    const result = evaluatePolicy(
      { ...baseResult, totalEstimatedMonthlyWasteUSD: 25.50 },
      { maxWasteUSD: 10 }
    );
    expect(result.exitCode).toBe(EXIT_CODES.POLICY_VIOLATION);
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0].rule).toBe("MAX_WASTE_USD");
    expect(result.violations[0].message).toContain("25.50");
    expect(result.violations[0].message).toContain("10.00");
  });

  it("returns exit code 0 when waste is exactly at the --max-waste-usd threshold", () => {
    const result = evaluatePolicy(
      { ...baseResult, totalEstimatedMonthlyWasteUSD: 10.00 },
      { maxWasteUSD: 10.00 }
    );
    // Threshold is "exceeds", so exactly equal is NOT a violation
    expect(result.exitCode).toBe(EXIT_CODES.SUCCESS);
    expect(result.violations).toHaveLength(0);
  });

  it("returns exit code 0 when waste is below threshold", () => {
    const result = evaluatePolicy(
      { ...baseResult, totalEstimatedMonthlyWasteUSD: 5.00 },
      { maxWasteUSD: 10.00 }
    );
    expect(result.exitCode).toBe(EXIT_CODES.SUCCESS);
  });

  it("returns exit code 1 when --fail-on-unprotected and bucket has no lifecycle rule", () => {
    const fleetResult = {
      ...baseResult,
      totalEstimatedMonthlyWasteUSD: 0,
      bucketResults: [
        {
          bucket: "unprotected-bucket",
          region: "us-east-1",
          status: "AUDITED" as const,
          lifecycleAudit: {
            bucketHasLifecyclePolicy: false,
            hasCoveringRule: false,
            ghostRulesDetected: [],
            providerNotes: undefined,
          },
        },
      ],
    };

    const result = evaluatePolicy(fleetResult, { failOnUnprotected: true });
    expect(result.exitCode).toBe(EXIT_CODES.POLICY_VIOLATION);
    expect(result.violations[0].rule).toBe("FAIL_ON_UNPROTECTED");
    expect(result.violations[0].message).toContain("unprotected-bucket");
  });

  it("does NOT flag provider short-circuits (R2/MinIO) as unprotected", () => {
    const fleetResult = {
      ...baseResult,
      totalEstimatedMonthlyWasteUSD: 0,
      bucketResults: [
        {
          bucket: "r2-bucket",
          region: "auto",
          status: "AUDITED" as const,
          lifecycleAudit: {
            bucketHasLifecyclePolicy: true,
            hasCoveringRule: true,
            ghostRulesDetected: [],
            providerNotes: "Cloudflare R2 detected. R2 automatically purges incomplete multipart uploads after 7 days by default.",
          },
        },
      ],
    };

    const result = evaluatePolicy(fleetResult, { failOnUnprotected: true });
    expect(result.exitCode).toBe(EXIT_CODES.SUCCESS);
  });

  it("returns exit code 0 when bucket has a covering rule and --fail-on-unprotected is set", () => {
    const fleetResult = {
      ...baseResult,
      totalEstimatedMonthlyWasteUSD: 0,
      bucketResults: [
        {
          bucket: "protected-bucket",
          region: "us-east-1",
          status: "AUDITED" as const,
          lifecycleAudit: {
            bucketHasLifecyclePolicy: true,
            hasCoveringRule: true,
            ghostRulesDetected: [],
            providerNotes: undefined,
          },
        },
      ],
    };

    const result = evaluatePolicy(fleetResult, { failOnUnprotected: true });
    expect(result.exitCode).toBe(EXIT_CODES.SUCCESS);
  });

  it("reports multiple violations simultaneously", () => {
    const fleetResult = {
      ...baseResult,
      totalEstimatedMonthlyWasteUSD: 999.99,
      bucketResults: [
        {
          bucket: "bad-bucket",
          region: "us-east-1",
          status: "AUDITED" as const,
          lifecycleAudit: {
            bucketHasLifecyclePolicy: false,
            hasCoveringRule: false,
            ghostRulesDetected: [],
            providerNotes: undefined,
          },
        },
      ],
    };

    const result = evaluatePolicy(fleetResult, {
      maxWasteUSD: 10,
      failOnUnprotected: true,
    });

    expect(result.exitCode).toBe(EXIT_CODES.POLICY_VIOLATION);
    expect(result.violations).toHaveLength(2);
    expect(result.violations.map((v) => v.rule).sort()).toEqual([
      "FAIL_ON_UNPROTECTED",
      "MAX_WASTE_USD",
    ]);
  });

  it("skipped buckets do NOT trigger --fail-on-unprotected", () => {
    const fleetResult = {
      ...baseResult,
      totalEstimatedMonthlyWasteUSD: 0,
      bucketResults: [
        {
          bucket: "denied-bucket",
          region: "us-east-1",
          status: "SKIPPED_ACCESS_DENIED" as const,
          // No lifecycleAudit — was never scanned
        },
      ],
    };

    const result = evaluatePolicy(fleetResult, { failOnUnprotected: true });
    expect(result.exitCode).toBe(EXIT_CODES.SUCCESS);
  });
});

// ─── CLI integration: fleet exit codes ───────────────────────────────────────

describe("CLI fleet exit codes", () => {
  beforeEach(() => {
    s3Mock.reset();
  });

  it("returns exit code 3 when ListBuckets is denied", async () => {
    const { main } = await import("../src/cli.js");

    const err = new Error("Access Denied");
    err.name = "AccessDenied";
    (err as any).$metadata = { httpStatusCode: 403 };
    s3Mock.on(ListBucketsCommand).rejects(err);

    const logs: string[] = [];
    const errors: string[] = [];
    const code = await main(["scan", "--all-buckets"], {
      stdout: (m) => logs.push(m),
      stderr: (m) => errors.push(m),
    });

    expect(code).toBe(EXIT_CODES.DISCOVERY_AUTH_ERROR); // 3
    expect(errors.join(" ")).toContain("Discovery failed");
  });

  it("returns exit code 1 when --max-waste-usd threshold is exceeded", async () => {
    const { main } = await import("../src/cli.js");
    const now = new Date("2026-09-20T12:00:00.000Z");
    const oldDate = new Date("2026-09-01T00:00:00.000Z");

    s3Mock.on(ListBucketsCommand).resolves({ Buckets: [{ Name: "wasteful-bucket" }] });
    s3Mock.on(GetBucketLocationCommand).resolves({ LocationConstraint: null });

    const lifecycleErr = new Error("NoSuchLifecycleConfiguration");
    lifecycleErr.name = "NoSuchLifecycleConfiguration";
    (lifecycleErr as any).$metadata = { httpStatusCode: 404 };
    s3Mock.on(GetBucketLifecycleConfigurationCommand).rejects(lifecycleErr);

    // 100 GiB worth of stranded data → ~$2.30/mo at S3 Standard
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: Array.from({ length: 10 }, (_, i) => ({
        Key: `file-${i}.bin`,
        UploadId: `uid-${i}`,
        Initiated: oldDate,
      })),
    });
    // Each upload has 1 part of 10 GiB = 10 * 10 GiB * 10 = 100 GiB total
    s3Mock.on(ListPartsCommand).resolves({
      IsTruncated: false,
      Parts: [{ PartNumber: 1, Size: 10 * 1024 * 1024 * 1024 }], // 10 GiB
    });

    const logs: string[] = [];
    const errors: string[] = [];
    const code = await main(
      ["scan", "--all-buckets", "--max-waste-usd", "1"],
      {
        stdout: (m) => logs.push(m),
        stderr: (m) => errors.push(m),
      }
    );

    expect(code).toBe(EXIT_CODES.POLICY_VIOLATION); // 1
    expect(logs.join("\n")).toContain("MAX_WASTE_USD");
  });

  it("returns exit code 0 when no policy violations", async () => {
    const { main } = await import("../src/cli.js");

    s3Mock.on(ListBucketsCommand).resolves({ Buckets: [{ Name: "clean-bucket" }] });
    s3Mock.on(GetBucketLocationCommand).resolves({ LocationConstraint: null });

    const lifecycleErr = new Error("NoSuchLifecycleConfiguration");
    lifecycleErr.name = "NoSuchLifecycleConfiguration";
    (lifecycleErr as any).$metadata = { httpStatusCode: 404 };
    s3Mock.on(GetBucketLifecycleConfigurationCommand).rejects(lifecycleErr);

    s3Mock.on(ListMultipartUploadsCommand).resolves({ IsTruncated: false, Uploads: [] });

    const logs: string[] = [];
    const code = await main(
      ["scan", "--all-buckets", "--max-waste-usd", "100"],
      { stdout: (m) => logs.push(m), stderr: () => {} }
    );

    expect(code).toBe(EXIT_CODES.SUCCESS); // 0
  });

  it("returns exit code 1 with --fail-on-unprotected and unprotected bucket", async () => {
    const { main } = await import("../src/cli.js");

    s3Mock.on(ListBucketsCommand).resolves({ Buckets: [{ Name: "no-lc-bucket" }] });
    s3Mock.on(GetBucketLocationCommand).resolves({ LocationConstraint: null });

    const lifecycleErr = new Error("NoSuchLifecycleConfiguration");
    lifecycleErr.name = "NoSuchLifecycleConfiguration";
    (lifecycleErr as any).$metadata = { httpStatusCode: 404 };
    s3Mock.on(GetBucketLifecycleConfigurationCommand).rejects(lifecycleErr);

    s3Mock.on(ListMultipartUploadsCommand).resolves({ IsTruncated: false, Uploads: [] });

    const logs: string[] = [];
    const code = await main(
      ["scan", "--all-buckets", "--fail-on-unprotected"],
      { stdout: (m) => logs.push(m), stderr: () => {} }
    );

    expect(code).toBe(EXIT_CODES.POLICY_VIOLATION); // 1
    expect(logs.join("\n")).toContain("FAIL_ON_UNPROTECTED");
  });
});
