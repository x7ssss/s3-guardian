import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  S3Client,
  ListBucketsCommand,
  ListMultipartUploadsCommand,
  ListPartsCommand,
  AbortMultipartUploadCommand,
  GetBucketLifecycleConfigurationCommand,
  PutBucketLifecycleConfigurationCommand,
  ListObjectVersionsCommand,
  DeleteObjectsCommand,
} from "@aws-sdk/client-s3";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";
import { main } from "../src/cli.js";
import { Plan, writePlanFile } from "../src/planner/plan.js";

const s3Mock = mockClient(S3Client);

// Helper: stub lifecycle to return "no policy" (NoSuchLifecycleConfiguration)
function stubNoLifecycle() {
  const err = new Error("NoSuchLifecycleConfiguration");
  err.name = "NoSuchLifecycleConfiguration";
  (err as any).$metadata = { httpStatusCode: 404 };
  s3Mock.on(GetBucketLifecycleConfigurationCommand).rejects(err);
}

// Helper: stub lifecycle to return a valid covering rule
function stubCoveringLifecycle() {
  s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
    Rules: [
      {
        ID: "cleanup-rule",
        Status: "Enabled",
        Filter: { Prefix: "" },
        AbortIncompleteMultipartUpload: { DaysAfterInitiation: 7 },
      },
    ],
  });
}

describe("CLI entrypoint and subcommand flow", () => {
  let stdoutLogs: string[] = [];
  let stderrLogs: string[] = [];

  const captureIO = {
    stdout: (msg: string) => stdoutLogs.push(msg),
    stderr: (msg: string) => stderrLogs.push(msg),
  };

  beforeEach(() => {
    s3Mock.reset();
    stdoutLogs = [];
    stderrLogs = [];
  });

  it("prints version on --version", async () => {
    const code = await main(["--version"], captureIO);
    expect(code).toBe(0);
    expect(stdoutLogs.join(" ")).toContain("s3-guardian v0.6.0");
  });

  it("prints help on --help or no args", async () => {
    const code1 = await main(["--help"], captureIO);
    expect(code1).toBe(0);
    expect(stdoutLogs.join(" ")).toContain("USAGE:");

    stdoutLogs = [];
    const code2 = await main([], captureIO);
    expect(code2).toBe(0);
    expect(stdoutLogs.join(" ")).toContain("USAGE:");
  });

  it("returns 2 for unknown command", async () => {
    const code = await main(["foobar"], captureIO);
    expect(code).toBe(2);
    expect(stderrLogs.join(" ")).toContain("Unknown command 'foobar'");
  });

  it("scan returns 2 if bucket is omitted", async () => {
    const code = await main(["scan"], captureIO);
    expect(code).toBe(2);
    expect(stderrLogs.join(" ")).toContain("Bucket name is required for 'scan'");
  });

  it("scan outputs clean message when no zombie uploads found", async () => {
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [],
    });
    stubNoLifecycle();

    const code = await main(["scan", "clean-bucket"], captureIO);
    expect(code).toBe(0);
    expect(stdoutLogs.join(" ")).toContain("Clean! No multipart uploads older than 7 days found");
  });

  it("scan outputs lifecycle banner when bucket has no lifecycle rule", async () => {
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [],
    });
    stubNoLifecycle();

    const code = await main(["scan", "unprotected-bucket"], captureIO);
    expect(code).toBe(0);
    const output = stdoutLogs.join("\n");
    expect(output).toContain("Bucket has NO lifecycle rule covering multipart uploads");
  });

  it("scan does not show no-lifecycle banner when a covering rule exists", async () => {
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [],
    });
    stubCoveringLifecycle();

    const code = await main(["scan", "protected-bucket"], captureIO);
    expect(code).toBe(0);
    const output = stdoutLogs.join("\n");
    expect(output).not.toContain("Bucket has NO lifecycle rule");
  });

  it("scan outputs formatted table with Storage Class and Coverage columns when zombies found", async () => {
    const oldDate = new Date(Date.now() - 10 * 86400000);
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [
        {
          Key: "uploads/data.zip",
          UploadId: "upload-abc",
          Initiated: oldDate,
          StorageClass: "STANDARD",
        },
      ],
    });

    s3Mock.on(ListPartsCommand).resolves({
      IsTruncated: false,
      Parts: [
        { PartNumber: 1, Size: 10485760 }, // 10 MB
      ],
    });
    stubNoLifecycle();

    const code = await main(["scan", "zombie-bucket"], captureIO);
    expect(code).toBe(0);
    const output = stdoutLogs.join("\n");
    expect(output).toContain("Found 1 zombie multipart upload(s)");
    expect(output).toContain("uploads/data.zip");
    expect(output).toContain("10.00 MB");
    expect(output).toContain("Storage Class");
    expect(output).toContain("Coverage");
    expect(output).toContain("UNPROTECTED");
    expect(output).toContain("s3-guardian plan zombie-bucket --out plan.json");
  });

  it("scan flags non-standard storage class (Glacier Staging Trap)", async () => {
    const oldDate = new Date(Date.now() - 10 * 86400000);
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [
        {
          Key: "cold/data.zip",
          UploadId: "upload-glacier",
          Initiated: oldDate,
          StorageClass: "GLACIER",
        },
      ],
    });

    s3Mock.on(ListPartsCommand).resolves({
      IsTruncated: false,
      Parts: [{ PartNumber: 1, Size: 1048576 }],
    });
    stubNoLifecycle();

    const code = await main(["scan", "glacier-bucket"], captureIO);
    expect(code).toBe(0);
    const output = stdoutLogs.join("\n");
    expect(output).toContain("⚠ GLACIER");
  });

  it("scan shows ghost rule banner when ghost rule is detected", async () => {
    const oldDate = new Date(Date.now() - 10 * 86400000);
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [
        { Key: "file.bin", UploadId: "uid-1", Initiated: oldDate },
      ],
    });
    s3Mock.on(ListPartsCommand).resolves({
      IsTruncated: false,
      Parts: [{ PartNumber: 1, Size: 1000 }],
    });
    // Ghost rule: Tag filter on MPU abort rule
    s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
      Rules: [
        {
          ID: "ghost-rule",
          Status: "Enabled",
          Filter: { Tag: { Key: "env", Value: "dev" } },
          AbortIncompleteMultipartUpload: { DaysAfterInitiation: 7 },
        },
      ],
    });

    const code = await main(["scan", "ghost-bucket"], captureIO);
    expect(code).toBe(0);
    const output = stdoutLogs.join("\n");
    expect(output).toContain("Ghost rule detected");
    expect(output).toContain("ghost-rule");
    expect(output).toContain("GHOST_RULE");
  });

  it("scan --json outputs machine-readable JSON with lifecycle audit", async () => {
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [],
    });
    stubNoLifecycle();

    const code = await main(["scan", "clean-bucket", "--json"], captureIO);
    expect(code).toBe(0);
    const parsed = JSON.parse(stdoutLogs[0]);
    expect(parsed.bucket).toBe("clean-bucket");
    expect(parsed.totalZombieUploads).toBe(0);
    expect(parsed.lifecycleAudit).toBeDefined();
    expect(parsed.lifecycleAudit.bucketHasLifecyclePolicy).toBe(false);
  });

  it("plan generates plan file on disk with schema 1.1 and lifecycle audit", async () => {
    const tempFile = path.join(os.tmpdir(), `test-plan-${Date.now()}.json`);
    const oldDate = new Date(Date.now() - 10 * 86400000);

    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [
        { Key: "file.bin", UploadId: "uid-xyz", Initiated: oldDate },
      ],
    });

    s3Mock.on(ListPartsCommand).resolves({
      IsTruncated: false,
      Parts: [{ PartNumber: 1, Size: 5000 }],
    });
    stubNoLifecycle();

    try {
      const code = await main(["plan", "my-bucket", "--out", tempFile], captureIO);
      expect(code).toBe(0);
      expect(stdoutLogs.join(" ")).toContain("Plan generated successfully");

      const fileContent = await fs.readFile(tempFile, "utf8");
      const parsed: Plan = JSON.parse(fileContent);
      expect(parsed.schemaVersion).toBe("1.1");
      expect(parsed.bucket).toBe("my-bucket");
      expect(parsed.uploads.length).toBe(1);
      expect(parsed.uploads[0].key).toBe("file.bin");
      expect(parsed.uploads[0].storageClass).toBe("STANDARD");
      expect(parsed.uploads[0].lifecycleStatus).toBe("UNPROTECTED");
      expect(parsed.lifecycleAudit).toBeDefined();
      expect(parsed.lifecycleAudit.bucketHasLifecyclePolicy).toBe(false);
      expect(parsed.lifecycleAudit.hasCoveringRule).toBe(false);
    } finally {
      await fs.unlink(tempFile).catch(() => {});
    }
  });

  it("plan shows lifecycle audit summary in output", async () => {
    const tempFile = path.join(os.tmpdir(), `test-plan-lifecycle-${Date.now()}.json`);
    const oldDate = new Date(Date.now() - 10 * 86400000);

    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [
        { Key: "file.bin", UploadId: "uid-1", Initiated: oldDate },
      ],
    });
    s3Mock.on(ListPartsCommand).resolves({
      IsTruncated: false,
      Parts: [{ PartNumber: 1, Size: 1000 }],
    });
    stubNoLifecycle();

    try {
      const code = await main(["plan", "my-bucket", "--out", tempFile], captureIO);
      expect(code).toBe(0);
      const output = stdoutLogs.join("\n");
      expect(output).toContain("Lifecycle Audit: Bucket has NO lifecycle rule covering multipart uploads");
    } finally {
      await fs.unlink(tempFile).catch(() => {});
    }
  });

  it("apply strictly enforces --confirm flag and rejects without it", async () => {
    const tempFile = path.join(os.tmpdir(), `test-plan-reject-${Date.now()}.json`);
    const plan: Plan = {
      schemaVersion: "1.1",
      generatedAt: new Date().toISOString(),
      bucket: "apply-bucket",
      endpoint: null,
      olderThanDays: 7,
      totalZombieUploads: 1,
      totalStrandedBytes: 1000,
      estimatedMonthlyWasteUSD: 0,
      lifecycleAudit: {
        bucketHasLifecyclePolicy: false,
        hasCoveringRule: false,
        ghostRulesDetected: [],
      },
      uploads: [
        {
          key: "file.bin",
          uploadId: "uid-1",
          initiated: new Date().toISOString(),
          partsCount: 1,
          bytes: 1000,
          storageClass: "STANDARD",
          lifecycleStatus: "UNPROTECTED",
        },
      ],
    };

    await writePlanFile(tempFile, plan);

    try {
      // Without --confirm
      const code = await main(["apply", "--plan", tempFile], captureIO);
      expect(code).toBe(2);
      expect(stderrLogs.join(" ")).toContain("Safety check failed: The '--confirm' flag is strictly required");
      expect(s3Mock.calls().length).toBe(0);
    } finally {
      await fs.unlink(tempFile).catch(() => {});
    }
  });

  it("apply executes deletions when --confirm is present", async () => {
    const tempFile = path.join(os.tmpdir(), `test-plan-confirm-${Date.now()}.json`);
    const plan: Plan = {
      schemaVersion: "1.1",
      generatedAt: new Date().toISOString(),
      bucket: "apply-bucket",
      endpoint: null,
      olderThanDays: 7,
      totalZombieUploads: 1,
      totalStrandedBytes: 1000,
      estimatedMonthlyWasteUSD: 0,
      lifecycleAudit: {
        bucketHasLifecyclePolicy: false,
        hasCoveringRule: false,
        ghostRulesDetected: [],
      },
      uploads: [
        {
          key: "file.bin",
          uploadId: "uid-1",
          initiated: new Date().toISOString(),
          partsCount: 1,
          bytes: 1000,
          storageClass: "STANDARD",
          lifecycleStatus: "UNPROTECTED",
        },
      ],
    };

    await writePlanFile(tempFile, plan);
    s3Mock.on(AbortMultipartUploadCommand).resolves({});

    try {
      const code = await main(
        ["apply", "--plan", tempFile, "--confirm"],
        captureIO
      );
      expect(code).toBe(0);
      expect(stdoutLogs.join(" ")).toContain("Successfully aborted: 1");
      expect(stdoutLogs.join(" ")).toContain("Cleanup completed successfully");
      expect(s3Mock.commandCalls(AbortMultipartUploadCommand).length).toBe(1);
    } finally {
      await fs.unlink(tempFile).catch(() => {});
    }
  });

  it("apply is backwards compatible with schema 1.0 plan files (auto-upconverts)", async () => {
    const tempFile = path.join(os.tmpdir(), `test-plan-v10-${Date.now()}.json`);

    // Write a raw schema 1.0 plan (no storageClass, no lifecycleStatus, no lifecycleAudit)
    const legacyPlan = {
      schemaVersion: "1.0",
      generatedAt: new Date().toISOString(),
      bucket: "legacy-bucket",
      endpoint: null,
      olderThanDays: 7,
      totalZombieUploads: 1,
      totalStrandedBytes: 500,
      estimatedMonthlyWasteUSD: 0,
      uploads: [
        {
          key: "legacy.bin",
          uploadId: "uid-legacy",
          initiated: new Date().toISOString(),
          partsCount: 1,
          bytes: 500,
        },
      ],
    };
    await fs.writeFile(tempFile, JSON.stringify(legacyPlan, null, 2), "utf8");
    s3Mock.on(AbortMultipartUploadCommand).resolves({});

    try {
      const code = await main(
        ["apply", "--plan", tempFile, "--confirm"],
        captureIO
      );
      expect(code).toBe(0);
      expect(stdoutLogs.join(" ")).toContain("Successfully aborted: 1");
    } finally {
      await fs.unlink(tempFile).catch(() => {});
    }
  });

  it("scan outputs MinIO provider note for local endpoint", async () => {
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [],
    });
    // No lifecycle mock needed — MinIO short-circuits without API call

    const code = await main(
      ["scan", "my-bucket", "--endpoint", "http://localhost:9000"],
      captureIO
    );
    expect(code).toBe(0);
    const output = stdoutLogs.join("\n");
    expect(output).toContain("MinIO detected");
  });

  it("scan outputs R2 provider note for Cloudflare R2 endpoint", async () => {
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [],
    });

    const code = await main(
      ["scan", "my-bucket", "--endpoint", "https://acct.r2.cloudflarestorage.com"],
      captureIO
    );
    expect(code).toBe(0);
    const output = stdoutLogs.join("\n");
    expect(output).toContain("Cloudflare R2 detected");
  });

  it("scan outputs remediation tip when bucket has no lifecycle rule", async () => {
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [],
    });
    stubNoLifecycle();

    const code = await main(["scan", "unprotected-bucket"], captureIO);
    expect(code).toBe(0);
    const output = stdoutLogs.join("\n");
    expect(output).toContain("Run `s3-guardian remediate unprotected-bucket`");
  });

  it("plan outputs remediation tip when bucket has no lifecycle rule", async () => {
    const tempFile = path.join(os.tmpdir(), `test-plan-tip-${Date.now()}.json`);
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [],
    });
    stubNoLifecycle();

    try {
      const code = await main(["plan", "tip-bucket", "--out", tempFile], captureIO);
      expect(code).toBe(0);
      const output = stdoutLogs.join("\n");
      expect(output).toContain("Run `s3-guardian remediate tip-bucket`");
    } finally {
      await fs.unlink(tempFile).catch(() => {});
    }
  });

  it("remediate outputs Terraform snippet by default", async () => {
    const code = await main(["remediate", "my-bucket"], captureIO);
    expect(code).toBe(0);
    const output = stdoutLogs.join("\n");
    expect(output).toContain('resource "aws_s3_bucket_lifecycle_configuration"');
    expect(output).toContain('bucket = "my-bucket"');
    expect(output).toContain("s3-guardian-abort-mpu");
    expect(output).toContain("days_after_initiation = 7");
  });

  it("remediate outputs CloudFormation YAML with --format cloudformation", async () => {
    const code = await main(
      ["remediate", "my-bucket", "--format", "cloudformation", "--days", "14"],
      captureIO
    );
    expect(code).toBe(0);
    const output = stdoutLogs.join("\n");
    expect(output).toContain("Type: AWS::S3::Bucket");
    expect(output).toContain('BucketName: "my-bucket"');
    expect(output).toContain("Id: s3-guardian-abort-mpu");
    expect(output).toContain("DaysAfterInitiation: 14");
  });

  it("remediate saves IaC snippet to file with --out-iac", async () => {
    const tempIacFile = path.join(os.tmpdir(), `remediate-${Date.now()}.tf`);
    try {
      const code = await main(
        ["remediate", "my-bucket", "--out-iac", tempIacFile],
        captureIO
      );
      expect(code).toBe(0);
      expect(stdoutLogs.join(" ")).toContain(`saved to: ${tempIacFile}`);
      const content = await fs.readFile(tempIacFile, "utf8");
      expect(content).toContain('resource "aws_s3_bucket_lifecycle_configuration"');
    } finally {
      await fs.unlink(tempIacFile).catch(() => {});
    }
  });

  it("remediate returns 2 if bucket is omitted and not --all-buckets", async () => {
    const code = await main(["remediate"], captureIO);
    expect(code).toBe(2);
    expect(stderrLogs.join(" ")).toContain("Bucket name is required for 'remediate'");
  });

  it("remediate executes direct API apply with --danger-direct-api-apply", async () => {
    s3Mock
      .on(GetBucketLifecycleConfigurationCommand, { Bucket: "api-remediate-bucket" })
      .resolvesOnce({ Rules: [] });

    s3Mock
      .on(PutBucketLifecycleConfigurationCommand, { Bucket: "api-remediate-bucket" })
      .resolvesOnce({});

    const code = await main(
      ["remediate", "api-remediate-bucket", "--danger-direct-api-apply", "--days", "5"],
      captureIO
    );

    expect(code).toBe(0);
    const output = stdoutLogs.join("\n");
    expect(output).toContain("Direct API remediation complete for 'api-remediate-bucket'");
    expect(output).toContain("DaysAfterInitiation: 5");

    const putCalls = s3Mock.commandCalls(PutBucketLifecycleConfigurationCommand);
    expect(putCalls.length).toBe(1);
    expect(putCalls[0].args[0].input.Bucket).toBe("api-remediate-bucket");
  });

  it("scan dispatches webhook when --webhook-url and --notify-always are provided", async () => {
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [],
    });
    stubNoLifecycle();

    const mockFetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    const originalFetch = globalThis.fetch;
    globalThis.fetch = mockFetch as any;

    try {
      const code = await main(
        [
          "scan",
          "webhook-bucket",
          "--webhook-url",
          "https://hooks.slack.com/services/T/B/X",
          "--notify-always",
        ],
        captureIO
      );
      expect(code).toBe(0);
      expect(mockFetch).toHaveBeenCalledTimes(1);
      const requestBody = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(requestBody.text).toContain("webhook-bucket");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("scan --all-buckets passes --checkpoint to scanFleet", async () => {
    s3Mock.on(ListBucketsCommand).resolves({ Buckets: [] });

    const code = await main(
      ["scan", "--all-buckets", "--checkpoint", "s3://my-ops-bucket/chk.json"],
      captureIO
    );
    expect(code).toBe(0);
  });

  it("scan --include-versions displays versioning waste table", async () => {
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [],
    });
    stubNoLifecycle();

    s3Mock.on(ListObjectVersionsCommand).resolves({
      IsTruncated: false,
      Versions: [
        { Key: "old-doc.pdf", VersionId: "v1", IsLatest: false, Size: 1048576 },
      ],
      DeleteMarkers: [
        { Key: "deleted-doc.pdf", VersionId: "dm1", IsLatest: true },
      ],
    });

    const code = await main(
      ["scan", "versioned-bucket", "--include-versions"],
      captureIO
    );

    expect(code).toBe(0);
    const output = stdoutLogs.join("\n");
    expect(output).toContain("Noncurrent Versions");
    expect(output).toContain("Stranded Size");
    expect(output).toContain("Monthly Cost");
    expect(output).toContain("Expired Delete Markers");
  });

  it("plan --include-versions generates plan schema 1.2 with versionDeletions", async () => {
    const tempFile = path.join(os.tmpdir(), `test-plan-ver-${Date.now()}.json`);
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [],
    });
    stubNoLifecycle();

    s3Mock.on(ListObjectVersionsCommand).resolves({
      IsTruncated: false,
      Versions: [
        { Key: "noncurrent.bin", VersionId: "v-old", IsLatest: false, Size: 2048 },
      ],
      DeleteMarkers: [],
    });

    try {
      const code = await main(
        ["plan", "versioned-bucket", "--include-versions", "--out", tempFile],
        captureIO
      );
      expect(code).toBe(0);

      const raw = await fs.readFile(tempFile, "utf8");
      const plan = JSON.parse(raw);
      expect(plan.schemaVersion).toBe("1.2");
      expect(plan.versionDeletions).toHaveLength(1);
      expect(plan.versionDeletions[0].key).toBe("noncurrent.bin");
      expect(plan.versionDeletions[0].versionId).toBe("v-old");
      expect(plan.totalNoncurrentVersions).toBe(1);
    } finally {
      await fs.unlink(tempFile).catch(() => {});
    }
  });

  it("apply executes version deletions when plan has versionDeletions", async () => {
    const tempFile = path.join(os.tmpdir(), `test-plan-apply-ver-${Date.now()}.json`);
    const plan: Plan = {
      schemaVersion: "1.2",
      generatedAt: new Date().toISOString(),
      bucket: "apply-ver-bucket",
      endpoint: null,
      olderThanDays: 7,
      totalZombieUploads: 0,
      totalStrandedBytes: 0,
      estimatedMonthlyWasteUSD: 0,
      lifecycleAudit: {
        bucketHasLifecyclePolicy: true,
        hasCoveringRule: true,
        ghostRulesDetected: [],
      },
      uploads: [],
      versionDeletions: [
        {
          key: "file-to-delete.txt",
          versionId: "v-del",
          type: "NONCURRENT_VERSION",
          size: 512,
          lastModified: new Date().toISOString(),
        },
      ],
      totalNoncurrentVersions: 1,
      totalExpiredDeleteMarkers: 0,
    };

    await writePlanFile(tempFile, plan);

    s3Mock.on(DeleteObjectsCommand).resolvesOnce({
      Deleted: [],
      Errors: [],
    });

    try {
      const code = await main(
        ["apply", "--plan", tempFile, "--confirm"],
        captureIO
      );
      expect(code).toBe(0);
      expect(stdoutLogs.join(" ")).toContain("Successfully deleted: 1");

      const delCalls = s3Mock.commandCalls(DeleteObjectsCommand);
      expect(delCalls.length).toBe(1);
      expect(delCalls[0].args[0].input.Bucket).toBe("apply-ver-bucket");
      expect(delCalls[0].args[0].input.Delete?.Objects?.[0].Key).toBe("file-to-delete.txt");
    } finally {
      await fs.unlink(tempFile).catch(() => {});
    }
  });
});
