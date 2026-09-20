import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  S3Client,
  ListBucketsCommand,
  GetBucketLocationCommand,
  ListMultipartUploadsCommand,
  ListPartsCommand,
  AbortMultipartUploadCommand,
  GetBucketLifecycleConfigurationCommand,
  PutBucketLifecycleConfigurationCommand,
  ListObjectVersionsCommand,
  DeleteObjectsCommand,
  ListObjectsV2Command,
} from "@aws-sdk/client-s3";
import { STSClient, AssumeRoleCommand } from "@aws-sdk/client-sts";
import { OrganizationsClient, ListAccountsCommand } from "@aws-sdk/client-organizations";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";
import { main } from "../src/cli.js";
import { Plan, writePlanFile } from "../src/planner/plan.js";

const s3Mock = mockClient(S3Client);
const stsMock = mockClient(STSClient);
const orgMock = mockClient(OrganizationsClient);

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
    stsMock.reset();
    orgMock.reset();
    stdoutLogs = [];
    stderrLogs = [];
  });

  it("prints version on --version", async () => {
    const code = await main(["--version"], captureIO);
    expect(code).toBe(0);
    expect(stdoutLogs.join(" ")).toContain("s3-guardian v1.5.0");
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
      expect(parsed.schemaVersion).toBe("1.3");
      expect(parsed.planHash).toBeDefined();
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
          initiated: new Date(Date.now() - 10 * 86400000).toISOString(),
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
      generatedAt: new Date(Date.now() - 10 * 86400000).toISOString(),
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
          initiated: new Date(Date.now() - 10 * 86400000).toISOString(),
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
      expect(plan.schemaVersion).toBe("1.3");
      expect(plan.planHash).toBeDefined();
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
      generatedAt: new Date(Date.now() - 10 * 86400000).toISOString(),
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
          lastModified: new Date(Date.now() - 10 * 86400000).toISOString(),
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

  it("scan --accounts executes multi-account sweep and renders executive summary table", async () => {
    stsMock.on(AssumeRoleCommand).resolves({
      Credentials: {
        AccessKeyId: "ASIA_CLI_TEST",
        SecretAccessKey: "SECRET",
        SessionToken: "TOKEN",
        Expiration: new Date(Date.now() + 3600_000),
      },
    });

    s3Mock.on(ListBucketsCommand).resolves({
      Buckets: [{ Name: "acct-bucket-1" }],
    });
    s3Mock.on(GetBucketLocationCommand).resolves({
      LocationConstraint: "us-east-1",
    });
    s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({ Rules: [] });
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      Uploads: [
        {
          Key: "large-video.mp4",
          UploadId: "mp4-123",
          Initiated: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000),
        },
      ],
      IsTruncated: false,
    });
    s3Mock.on(ListPartsCommand).resolves({
      Parts: [{ PartNumber: 1, Size: 500 * 1024 * 1024 * 1024 }],
      IsTruncated: false,
    });

    const code = await main(
      ["scan", "--accounts", "111111111111,222222222222", "--role-name", "TestRole"],
      captureIO
    );

    expect(code).toBe(0);
    const output = stdoutLogs.join("\n");
    expect(output).toContain("Multi-Account Sweep Summary");
    expect(output).toContain("111111111111");
    expect(output).toContain("222222222222");
    expect(output).toContain("Total Accounts:        2");
  });

  it("scan --accounts --json outputs machine-readable multi-account sweep results", async () => {
    stsMock.on(AssumeRoleCommand).resolves({
      Credentials: {
        AccessKeyId: "ASIA_CLI_JSON",
        SecretAccessKey: "SECRET",
        SessionToken: "TOKEN",
        Expiration: new Date(Date.now() + 3600_000),
      },
    });

    s3Mock.on(ListBucketsCommand).resolves({ Buckets: [] });

    const code = await main(
      ["scan", "--accounts", "111111111111", "--json"],
      captureIO
    );

    expect(code).toBe(0);
    const parsed = JSON.parse(stdoutLogs.join(""));
    expect(parsed.totalAccounts).toBe(1);
    expect(parsed.accountResults).toHaveLength(1);
    expect(parsed.accountResults[0].accountId).toBe("111111111111");
    expect(parsed.accountResults[0].status).toBe("SUCCESS");
  });

  it("scan --org discovers accounts via AWS Organizations and sweeps them", async () => {
    orgMock.on(ListAccountsCommand).resolves({
      Accounts: [
        { Id: "123456789012", Name: "Prod-Account", Status: "ACTIVE" },
      ],
    });

    stsMock.on(AssumeRoleCommand).resolves({
      Credentials: {
        AccessKeyId: "ASIA_CLI_ORG",
        SecretAccessKey: "SECRET",
        SessionToken: "TOKEN",
        Expiration: new Date(Date.now() + 3600_000),
      },
    });

    s3Mock.on(ListBucketsCommand).resolves({ Buckets: [] });

    const code = await main(
      ["scan", "--org", "--role-name", "OrganizationAccountAccessRole"],
      captureIO
    );

    expect(code).toBe(0);
    expect(stdoutLogs.join("\n")).toContain("Prod-Account");
    expect(orgMock.commandCalls(ListAccountsCommand)).toHaveLength(1);
  });

  it("plan --accounts generates multi-account plan file on disk", async () => {
    const tempPlanFile = path.resolve(os.tmpdir(), `multi-plan-${Date.now()}.json`);

    stsMock.on(AssumeRoleCommand).resolves({
      Credentials: {
        AccessKeyId: "ASIA_PLAN",
        SecretAccessKey: "SECRET",
        SessionToken: "TOKEN",
        Expiration: new Date(Date.now() + 3600_000),
      },
    });

    s3Mock.on(ListBucketsCommand).resolves({ Buckets: [] });

    try {
      const code = await main(
        ["plan", "--accounts", "111111111111", "--out", tempPlanFile],
        captureIO
      );

      expect(code).toBe(0);
      expect(stdoutLogs.join("\n")).toContain("Multi-account plan generated");

      const fileContent = await fs.readFile(tempPlanFile, "utf8");
      const parsedPlan = JSON.parse(fileContent);
      expect(parsedPlan.totalAccounts).toBe(1);
      expect(parsedPlan.accountResults[0].accountId).toBe("111111111111");
    } finally {
      await fs.unlink(tempPlanFile).catch(() => {});
    }
  });

  it("scan --accounts enforces --max-waste-usd policy threshold", async () => {
    stsMock.on(AssumeRoleCommand).resolves({
      Credentials: {
        AccessKeyId: "ASIA_POLICY",
        SecretAccessKey: "SECRET",
        SessionToken: "TOKEN",
        Expiration: new Date(Date.now() + 3600_000),
      },
    });

    s3Mock.on(ListBucketsCommand).resolves({
      Buckets: [{ Name: "costly-bucket" }],
    });
    s3Mock.on(GetBucketLocationCommand).resolves({
      LocationConstraint: "us-east-1",
    });
    s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({ Rules: [] });
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      Uploads: [
        {
          Key: "big.tar",
          UploadId: "tar-1",
          Initiated: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000),
        },
      ],
    });
    s3Mock.on(ListPartsCommand).resolves({
      Parts: [{ PartNumber: 1, Size: 1000 * 1024 * 1024 * 1024 }], // 1000 GiB ($23/mo)
    });

    const code = await main(
      ["scan", "--accounts", "111111111111", "--max-waste-usd", "5.00"],
      captureIO
    );

    expect(code).toBe(1); // POLICY_VIOLATION
    expect(stdoutLogs.join("\n")).toContain("Policy violations detected");
  });

  it("lens returns 2 if source argument is missing", async () => {
    const code = await main(["lens"], captureIO);
    expect(code).toBe(2);
    expect(stderrLogs.join("\n")).toContain("<source> is required for 'lens'");
  });

  it("lens renders high-density ranking table and actionable tip", async () => {
    const tempCsv = path.resolve(os.tmpdir(), `cli-lens-${Date.now()}.csv`);
    const csvContent = [
      "record_type,aws_account_id,bucket_name,aws_region,storage_bytes,non_current_version_storage_bytes,delete_marker_object_count,incomplete_mpu_storage_bytes,incomplete_mpu_storage_older_than_7_days_bytes",
      "BUCKET,111111111111,cli-waste-bucket,us-east-1,1000000000000,500000000000,5,100000000000,50000000000",
      "BUCKET,222222222222,cli-clean-bucket,eu-west-1,500000000000,0,0,0,0",
    ].join("\n");
    await fs.writeFile(tempCsv, csvContent, "utf8");

    try {
      const code = await main(["lens", tempCsv], captureIO);
      expect(code).toBe(0);
      const output = stdoutLogs.join("\n");
      expect(output).toContain("Storage Lens Triage & Ranking");
      expect(output).toContain("cli-waste-bucket");
      expect(output).toContain("cli-clean-bucket");
      expect(output).toContain("💡 Tip: Run 's3-guardian scan cli-waste-bucket --include-versions'");
    } finally {
      await fs.unlink(tempCsv).catch(() => {});
    }
  });

  it("lens --json outputs machine-readable JSON array", async () => {
    const tempCsv = path.resolve(os.tmpdir(), `cli-lens-json-${Date.now()}.csv`);
    const csvContent = [
      "record_type,aws_account_id,bucket_name,aws_region,storage_bytes,non_current_version_storage_bytes,delete_marker_object_count,incomplete_mpu_storage_bytes,incomplete_mpu_storage_older_than_7_days_bytes",
      "BUCKET,111111111111,json-bucket,us-east-1,1000000,500000,0,0,0",
    ].join("\n");
    await fs.writeFile(tempCsv, csvContent, "utf8");

    try {
      const code = await main(["lens", tempCsv, "--json"], captureIO);
      expect(code).toBe(0);
      const parsed = JSON.parse(stdoutLogs.join(""));
      expect(Array.isArray(parsed)).toBe(true);
      expect(parsed).toHaveLength(1);
      expect(parsed[0].bucketName).toBe("json-bucket");
      expect(parsed[0].wasteScore).toBe(50);
    } finally {
      await fs.unlink(tempCsv).catch(() => {});
    }
  });

  it("lens --top limits output count", async () => {
    const tempCsv = path.resolve(os.tmpdir(), `cli-lens-top-${Date.now()}.csv`);
    const csvContent = [
      "record_type,aws_account_id,bucket_name,aws_region,storage_bytes,non_current_version_storage_bytes,delete_marker_object_count,incomplete_mpu_storage_bytes,incomplete_mpu_storage_older_than_7_days_bytes",
      "BUCKET,111111111111,top-b1,us-east-1,1000000,500000,0,0,0",
      "BUCKET,111111111111,top-b2,us-east-1,1000000,400000,0,0,0",
    ].join("\n");
    await fs.writeFile(tempCsv, csvContent, "utf8");

    try {
      const code = await main(["lens", tempCsv, "--top", "1", "--json"], captureIO);
      expect(code).toBe(0);
      const parsed = JSON.parse(stdoutLogs.join(""));
      expect(parsed).toHaveLength(1);
      expect(parsed[0].bucketName).toBe("top-b1");
    } finally {
      await fs.unlink(tempCsv).catch(() => {});
    }
  });

  // ─── Transition Auditor CLI Tests ──────────────────────────────────────────

  it("audit-transitions returns 2 if bucket is omitted and not --all-buckets", async () => {
    const code = await main(["audit-transitions"], captureIO);
    expect(code).toBe(2);
    expect(stderrLogs.join(" ")).toContain("Bucket name is required for 'audit-transitions'");
  });

  it("audit-transitions <bucket> renders terminal output table with columns and actionable tip", async () => {
    s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
      Rules: [
        {
          ID: "glacier-trap-rule",
          Status: "Enabled",
          Filter: {},
          Transitions: [
            {
              Days: 30,
              StorageClass: "GLACIER",
            },
          ],
        },
      ],
    });

    s3Mock.on(ListObjectsV2Command).resolves({
      Contents: Array.from({ length: 1000 }, (_, i) => ({
        Key: `small-${i}.txt`,
        Size: 1024,
      })),
    });

    const code = await main(["audit-transitions", "test-bucket"], captureIO);
    expect(code).toBe(0);

    const output = stdoutLogs.join("\n");
    expect(output).toContain("Auditing lifecycle transitions in bucket 'test-bucket'");
    expect(output).toContain("Rule ID");
    expect(output).toContain("Target Tier");
    expect(output).toContain("Days");
    expect(output).toContain("Min Size Filter");
    expect(output).toContain("Small-Object Risk");
    expect(output).toContain("Est. Penalty/Mo");
    expect(output).toContain("Status");
    expect(output).toContain("glacier-trap-rule");
    expect(output).toContain("GLACIER");
    expect(output).toContain("HIGH (< 128 KiB)");
    expect(output).toContain("TRAP DETECTED");
    expect(output).toContain("Actionable Tip: Small-object transition traps detected!");
    expect(output).toContain("object_size_greater_than = 131072");
  });

  it("audit-transitions <bucket> --json outputs machine-readable JSON", async () => {
    s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
      Rules: [
        {
          ID: "unconstrained-ia",
          Status: "Enabled",
          Filter: {},
          Transitions: [
            {
              Days: 60,
              StorageClass: "STANDARD_IA",
            },
          ],
        },
      ],
    });

    s3Mock.on(ListObjectsV2Command).resolves({
      Contents: [],
    });

    const code = await main(["audit-transitions", "json-test-bucket", "--json"], captureIO);
    expect(code).toBe(0);

    const parsed = JSON.parse(stdoutLogs.join(""));
    expect(parsed.bucketName).toBe("json-test-bucket");
    expect(parsed.hasLifecyclePolicy).toBe(true);
    expect(parsed.dangerousRules).toHaveLength(1);
    expect(parsed.dangerousRules[0].ruleId).toBe("unconstrained-ia");
    expect(parsed.dangerousRules[0].targetStorageClass).toBe("STANDARD_IA");
    expect(parsed.dangerousRules[0].recommendedMinSize).toBe(131072);
  });

  it("audit-transitions --all-buckets scans all buckets and outputs fleet summary", async () => {
    s3Mock.on(ListBucketsCommand).resolves({
      Buckets: [{ Name: "fleet-bucket-1" }, { Name: "fleet-bucket-2" }],
    });
    s3Mock.on(GetBucketLocationCommand).resolves({
      LocationConstraint: "us-east-1",
    });
    s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
      Rules: [
        {
          ID: "trap-rule",
          Status: "Enabled",
          Filter: {},
          Transitions: [
            {
              Days: 30,
              StorageClass: "GLACIER",
            },
          ],
        },
      ],
    });
    s3Mock.on(ListObjectsV2Command).resolves({
      Contents: [],
    });

    const code = await main(["audit-transitions", "--all-buckets", "--json"], captureIO);
    expect(code).toBe(0);

    const parsed = JSON.parse(stdoutLogs.join(""));
    expect(parsed.bucketsAudited).toBe(2);
    expect(parsed.dangerousBucketsCount).toBe(2);
    expect(Array.isArray(parsed.buckets)).toBe(true);
  });

  it("scan <bucket> --audit-transitions includes transition audit in table and JSON output", async () => {
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      Uploads: [],
    });
    s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
      Rules: [
        {
          ID: "scan-transition-rule",
          Status: "Enabled",
          Filter: {},
          Transitions: [
            {
              Days: 30,
              StorageClass: "GLACIER",
            },
          ],
        },
      ],
    });
    s3Mock.on(ListObjectsV2Command).resolves({
      Contents: [],
    });

    // Test JSON mode
    stdoutLogs = [];
    const codeJson = await main(["scan", "scan-bucket", "--audit-transitions", "--json"], captureIO);
    expect(codeJson).toBe(0);
    const parsed = JSON.parse(stdoutLogs.join(""));
    expect(parsed.transitionAudit).toBeDefined();
    expect(parsed.transitionAudit.dangerousRules).toHaveLength(1);
    expect(parsed.transitionAudit.dangerousRules[0].ruleId).toBe("scan-transition-rule");

    // Test table mode
    stdoutLogs = [];
    const codeTable = await main(["scan", "scan-bucket", "--audit-transitions"], captureIO);
    expect(codeTable).toBe(0);
    const tableOutput = stdoutLogs.join("\n");
    expect(tableOutput).toContain("Rule ID");
    expect(tableOutput).toContain("Target Tier");
    expect(tableOutput).toContain("scan-transition-rule");
    expect(tableOutput).toContain("Actionable Tip: Small-object transition traps detected!");
  });

  it("rejects invalid --interval format with exit code 2", async () => {
    const code = await main(["scan", "test-bucket", "--interval", "invalid-time"], captureIO);
    expect(code).toBe(2);
    expect(stderrLogs.join(" ")).toContain("Invalid interval format");
  });

  it("executes single-bucket scan in daemon mode with --once", async () => {
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      Uploads: [],
    });
    stubCoveringLifecycle();

    const code = await main(["scan", "daemon-bucket", "--daemon", "--once"], captureIO);
    expect(code).toBe(0);
    const output = stdoutLogs.join("\n");
    expect(output).toContain("[DAEMON] [STARTUP]");
    expect(output).toContain("Target: Bucket scan (daemon-bucket)");
    expect(output).toContain("[DAEMON] [RUN #1]");
    expect(output).toContain("Clean! No multipart uploads");
  });

  it("reports daemon lock conflict with exit code 2 when lock already held", async () => {
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      Uploads: [],
    });
    stubCoveringLifecycle();

    const lockPath = path.join(os.tmpdir(), "s3-guardian-scan-conflict_bucket.lock");
    await fs.writeFile(lockPath, `${process.pid}\n`, { flag: "w" });

    try {
      const code = await main(["scan", "conflict_bucket", "--daemon", "--once"], captureIO);
      expect(code).toBe(2);
      expect(stderrLogs.join(" ")).toContain("Daemon lock conflict");
    } finally {
      try {
        await fs.unlink(lockPath);
      } catch {
        // ignore
      }
    }
  });

  it("executes audit-transitions in daemon mode with --once", async () => {
    s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
      Rules: [],
    });

    const code = await main(["audit-transitions", "trans-bucket", "--daemon", "--once"], captureIO);
    expect(code).toBe(0);
    const output = stdoutLogs.join("\n");
    expect(output).toContain("[DAEMON] [STARTUP]");
    expect(output).toContain("Target: Bucket transition audit (trans-bucket)");
    expect(output).toContain("[DAEMON] [RUN #1]");
  });

  describe("drift command", () => {
    const tmpDir = os.tmpdir();
    const testTfFile = path.join(tmpDir, `test-drift-${Math.random().toString(36).slice(2, 8)}.tf`);
    const testTfStateFile = path.join(tmpDir, `test-drift-${Math.random().toString(36).slice(2, 8)}.tfstate`);

    afterEach(async () => {
      try {
        await fs.unlink(testTfFile);
      } catch {}
      try {
        await fs.unlink(testTfStateFile);
      } catch {}
    });

    it("returns 2 if bucket name is missing", async () => {
      const code = await main(["drift"], captureIO);
      expect(code).toBe(2);
      expect(stderrLogs.join(" ")).toContain("Bucket name is required for 'drift'");
    });

    it("returns 2 if neither --tf-file nor --tfstate is provided", async () => {
      const code = await main(["drift", "my-bucket"], captureIO);
      expect(code).toBe(2);
      expect(stderrLogs.join(" ")).toContain("Either --tf-file <path> or --tfstate <path> must be provided");
    });

    it("returns 2 if --tf-file does not exist", async () => {
      const code = await main(["drift", "my-bucket", "--tf-file", "nonexistent-file.tf"], captureIO);
      expect(code).toBe(2);
      expect(stderrLogs.join(" ")).toContain("Target Terraform file not found");
    });

    it("evaluates drift using --tfstate and returns code 0 when IN_SYNC", async () => {
      s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
        Rules: [
          {
            ID: "s3-guardian-abort-mpu",
            Status: "Enabled",
            Filter: {},
            AbortIncompleteMultipartUpload: { DaysAfterInitiation: 7 },
          },
        ],
      });

      const tfstate = JSON.stringify({
        version: 4,
        resources: [
          {
            mode: "managed",
            type: "aws_s3_bucket_lifecycle_configuration",
            name: "test",
            instances: [
              {
                attributes: {
                  bucket: "sync-bucket",
                  rule: [
                    {
                      id: "s3-guardian-abort-mpu",
                      status: "Enabled",
                      abort_incomplete_multipart_upload: [{ days_after_initiation: 7 }],
                    },
                  ],
                },
              },
            ],
          },
        ],
      });
      await fs.writeFile(testTfStateFile, tfstate, "utf8");

      const code = await main(["drift", "sync-bucket", "--tfstate", testTfStateFile, "--json"], captureIO);
      expect(code).toBe(0);

      const parsed = JSON.parse(stdoutLogs.join(""));
      expect(parsed.status).toBe("IN_SYNC");
      expect(parsed.isDrifted).toBe(false);
      expect(parsed.bucketName).toBe("sync-bucket");
    });

    it("outputs unified diff when --patch is passed", async () => {
      s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
        Rules: [],
      });

      const initialTf = `
resource "aws_s3_bucket_lifecycle_configuration" "lifecycle_patch_bucket" {
  bucket = "patch-bucket"
}
`.trim();
      await fs.writeFile(testTfFile, initialTf, "utf8");

      const code = await main(["drift", "patch-bucket", "--tf-file", testTfFile, "--patch"], captureIO);
      expect(code).toBe(0);

      const patchOutput = stdoutLogs.join("\n");
      expect(patchOutput).toContain("--- a/");
      expect(patchOutput).toContain("+++ b/");
      expect(patchOutput).toContain("+    id     = \"s3-guardian-abort-mpu\"");
    });

    it("applies patch to file when --write is passed and renders drift table", async () => {
      s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
        Rules: [],
      });

      const initialTf = `
resource "aws_s3_bucket_lifecycle_configuration" "lifecycle_write_bucket" {
  bucket = "write-bucket"
}
`.trim();
      await fs.writeFile(testTfFile, initialTf, "utf8");

      const code = await main(["drift", "write-bucket", "--tf-file", testTfFile, "--write"], captureIO);
      // Returns 1 because drift was detected (before write)
      expect(code).toBe(1);

      const tableOutput = stdoutLogs.join("\n");
      expect(tableOutput).toContain("Resource Type");
      expect(tableOutput).toContain("Drift Status");
      expect(tableOutput).toContain("DRIFT_DETECTED");
      expect(tableOutput).toContain("Successfully applied drift remediation patch");

      // Verify file was mutated on disk
      const updatedContent = await fs.readFile(testTfFile, "utf8");
      expect(updatedContent).toContain("s3-guardian-abort-mpu");
    });
  });

  describe("Multi-Cloud Provider CLI Flags & Wasabi Guard", () => {
    const tmpDir = os.tmpdir();

    it("displays [Provider: Cloudflare R2] banner when --provider r2 is active", async () => {
      s3Mock.on(ListMultipartUploadsCommand).resolves({
        Uploads: [],
      });
      s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
        Rules: [],
      });

      const code = await main(["scan", "my-r2-bucket", "--provider", "r2"], captureIO);
      expect(code).toBe(0);
      expect(stdoutLogs.join("\n")).toContain("[Provider: Cloudflare R2]");
    });

    it("displays [Provider: Wasabi] banner when Wasabi endpoint is passed", async () => {
      s3Mock.on(ListMultipartUploadsCommand).resolves({
        Uploads: [],
      });
      s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
        Rules: [],
      });

      const code = await main(
        ["scan", "wasabi-bucket", "--endpoint", "https://s3.wasabisys.com"],
        captureIO
      );
      expect(code).toBe(0);
      expect(stdoutLogs.join("\n")).toContain("[Provider: Wasabi]");
    });

    it("displays [Provider: MinIO] banner when MinIO localhost:9000 endpoint is passed", async () => {
      s3Mock.on(ListMultipartUploadsCommand).resolves({
        Uploads: [],
      });
      s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
        Rules: [],
      });

      const code = await main(
        ["scan", "minio-bucket", "--endpoint", "http://localhost:9000"],
        captureIO
      );
      expect(code).toBe(0);
      expect(stdoutLogs.join("\n")).toContain("[Provider: MinIO]");
    });

    it("enforces Wasabi 90-day retention guard on apply and permits bypass with --force-wasabi-early-delete", async () => {
      s3Mock.on(ListMultipartUploadsCommand).resolves({
        Uploads: [],
      });
      s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
        Rules: [],
      });

      const planFilePath = path.join(tmpDir, "wasabi-plan.json");
      const recentInitiated = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(); // 10 days old

      // Create a plan file targeting Wasabi
      const planCode = await main(
        [
          "plan",
          "wasabi-test-bucket",
          "--out",
          planFilePath,
          "--provider",
          "wasabi",
          "--endpoint",
          "https://s3.wasabisys.com",
        ],
        captureIO
      );
      expect(planCode).toBe(0);

      // Now inject a recent upload into the plan file and recompute hash
      const planRaw = JSON.parse(await fs.readFile(planFilePath, "utf8"));
      planRaw.uploads = [
        {
          key: "wasabi/active-churn.bin",
          uploadId: "upl-wasabi-1",
          initiated: recentInitiated,
          partsCount: 1,
          bytes: 1048576,
          storageClass: "STANDARD",
          lifecycleStatus: "UNPROTECTED",
        },
      ];
      planRaw.totalZombieUploads = 1;
      planRaw.totalStrandedBytes = 1048576;
      planRaw.estimatedMonthlyWasteUSD = 0.023;

      // Recompute integrity hash using canonical JCS
      const { computePlanHash } = await import("../src/planner/jcs.js");
      planRaw.planHash = computePlanHash({
        schemaVersion: planRaw.schemaVersion,
        bucket: planRaw.bucket,
        endpoint: planRaw.endpoint,
        olderThanDays: planRaw.olderThanDays,
        uploads: planRaw.uploads,
        versionDeletions: planRaw.versionDeletions,
      });

      await fs.writeFile(planFilePath, JSON.stringify(planRaw, null, 2), "utf8");

      // Attempt apply without --force-wasabi-early-delete -> should be blocked with exit code 1
      stderrLogs.length = 0;
      stdoutLogs.length = 0;
      const blockedCode = await main(
        [
          "apply",
          "--plan",
          planFilePath,
          "--confirm",
          "--provider",
          "wasabi",
          "--endpoint",
          "https://s3.wasabisys.com",
        ],
        captureIO
      );
      expect(blockedCode).toBe(1);
      expect(stderrLogs.join("\n")).toContain("Wasabi charges 90 days minimum retention");

      // Now attempt apply WITH --force-wasabi-early-delete -> should succeed with exit code 0
      s3Mock.on(AbortMultipartUploadCommand).resolves({});
      stderrLogs.length = 0;
      stdoutLogs.length = 0;
      const successCode = await main(
        [
          "apply",
          "--plan",
          planFilePath,
          "--confirm",
          "--provider",
          "wasabi",
          "--endpoint",
          "https://s3.wasabisys.com",
          "--force-wasabi-early-delete",
        ],
        captureIO
      );
      expect(successCode).toBe(0);
      expect(stdoutLogs.join("\n")).toContain("Multipart Upload cleanup summary:");
    });
  });

  describe("Interactive Dashboard / TUI subcommand", () => {
    it("dashboard rejects non-interactive terminal (non-TTY) with code 2", async () => {
      const code = await main(["dashboard"], { ...captureIO, isTTY: false });
      expect(code).toBe(2);
      expect(stderrLogs.join("\n")).toContain("Interactive dashboard requires an interactive terminal (TTY)");
      expect(stderrLogs.join("\n")).toContain("s3-guardian scan --all-buckets");
    });

    it("tui alias rejects non-interactive terminal (non-TTY) with code 2", async () => {
      const code = await main(["tui"], { ...captureIO, isTTY: false });
      expect(code).toBe(2);
      expect(stderrLogs.join("\n")).toContain("Interactive dashboard requires an interactive terminal (TTY)");
    });

    it("dashboard launches and exits cleanly when TTY is true and abort signal is provided", async () => {
      const ac = new AbortController();
      ac.abort(); // already aborted signal exits dashboard immediately
      const code = await main(["dashboard"], {
        ...captureIO,
        isTTY: true,
        signal: ac.signal,
      });
      expect(code).toBe(0);
    });

    it("tui alias launches with --lens and exits cleanly with abort signal", async () => {
      const ac = new AbortController();
      ac.abort();
      const code = await main(["tui", "--lens", "export.csv"], {
        ...captureIO,
        isTTY: true,
        signal: ac.signal,
      });
      expect(code).toBe(0);
    });
  });
});

