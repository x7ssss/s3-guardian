import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  S3Client,
  ListMultipartUploadsCommand,
  ListPartsCommand,
  AbortMultipartUploadCommand,
} from "@aws-sdk/client-s3";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";
import { main } from "../src/cli.js";
import { Plan, writePlanFile } from "../src/planner/plan.js";

const s3Mock = mockClient(S3Client);

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
    expect(stdoutLogs.join(" ")).toContain("s3-guardian v0.1.0");
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

  it("returns 1 for unknown command", async () => {
    const code = await main(["foobar"], captureIO);
    expect(code).toBe(1);
    expect(stderrLogs.join(" ")).toContain("Unknown command 'foobar'");
  });

  it("scan returns 1 if bucket is omitted", async () => {
    const code = await main(["scan"], captureIO);
    expect(code).toBe(1);
    expect(stderrLogs.join(" ")).toContain("Bucket name is required for 'scan'");
  });

  it("scan outputs clean message when no zombie uploads found", async () => {
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [],
    });

    const code = await main(["scan", "clean-bucket"], captureIO);
    expect(code).toBe(0);
    expect(stdoutLogs.join(" ")).toContain("Clean! No multipart uploads older than 7 days found");
  });

  it("scan outputs formatted table and summary when zombies found", async () => {
    const oldDate = new Date(Date.now() - 10 * 86400000);
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [
        { Key: "uploads/data.zip", UploadId: "upload-abc", Initiated: oldDate },
      ],
    });

    s3Mock.on(ListPartsCommand).resolves({
      IsTruncated: false,
      Parts: [
        { PartNumber: 1, Size: 10485760 }, // 10 MB
      ],
    });

    const code = await main(["scan", "zombie-bucket"], captureIO);
    expect(code).toBe(0);
    const output = stdoutLogs.join("\n");
    expect(output).toContain("Found 1 zombie multipart upload(s)");
    expect(output).toContain("uploads/data.zip");
    expect(output).toContain("10.00 MB");
    expect(output).toContain("s3-guardian plan zombie-bucket --out plan.json");
  });

  it("scan --json outputs machine-readable JSON", async () => {
    s3Mock.on(ListMultipartUploadsCommand).resolves({
      IsTruncated: false,
      Uploads: [],
    });

    const code = await main(["scan", "clean-bucket", "--json"], captureIO);
    expect(code).toBe(0);
    const parsed = JSON.parse(stdoutLogs[0]);
    expect(parsed.bucket).toBe("clean-bucket");
    expect(parsed.totalZombieUploads).toBe(0);
  });

  it("plan generates plan file on disk", async () => {
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

    try {
      const code = await main(["plan", "my-bucket", "--out", tempFile], captureIO);
      expect(code).toBe(0);
      expect(stdoutLogs.join(" ")).toContain("Plan generated successfully");

      const fileContent = await fs.readFile(tempFile, "utf8");
      const parsed: Plan = JSON.parse(fileContent);
      expect(parsed.schemaVersion).toBe("1.0");
      expect(parsed.bucket).toBe("my-bucket");
      expect(parsed.uploads.length).toBe(1);
      expect(parsed.uploads[0].key).toBe("file.bin");
    } finally {
      await fs.unlink(tempFile).catch(() => {});
    }
  });

  it("apply strictly enforces --confirm flag and rejects without it", async () => {
    const tempFile = path.join(os.tmpdir(), `test-plan-reject-${Date.now()}.json`);
    const plan: Plan = {
      schemaVersion: "1.0",
      generatedAt: new Date().toISOString(),
      bucket: "apply-bucket",
      endpoint: null,
      olderThanDays: 7,
      totalZombieUploads: 1,
      totalStrandedBytes: 1000,
      estimatedMonthlyWasteUSD: 0,
      uploads: [
        {
          key: "file.bin",
          uploadId: "uid-1",
          initiated: new Date().toISOString(),
          partsCount: 1,
          bytes: 1000,
        },
      ],
    };

    await writePlanFile(tempFile, plan);

    try {
      // Without --confirm
      const code = await main(["apply", "--plan", tempFile], captureIO);
      expect(code).toBe(1);
      expect(stderrLogs.join(" ")).toContain("Safety check failed: The '--confirm' flag is strictly required");
      expect(s3Mock.calls().length).toBe(0);
    } finally {
      await fs.unlink(tempFile).catch(() => {});
    }
  });

  it("apply executes deletions when --confirm is present", async () => {
    const tempFile = path.join(os.tmpdir(), `test-plan-confirm-${Date.now()}.json`);
    const plan: Plan = {
      schemaVersion: "1.0",
      generatedAt: new Date().toISOString(),
      bucket: "apply-bucket",
      endpoint: null,
      olderThanDays: 7,
      totalZombieUploads: 1,
      totalStrandedBytes: 1000,
      estimatedMonthlyWasteUSD: 0,
      uploads: [
        {
          key: "file.bin",
          uploadId: "uid-1",
          initiated: new Date().toISOString(),
          partsCount: 1,
          bytes: 1000,
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
});
