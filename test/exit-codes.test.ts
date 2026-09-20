import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";
import {
  S3Client,
  ListBucketsCommand,
  GetBucketLocationCommand,
  ListMultipartUploadsCommand,
  ListPartsCommand,
  AbortMultipartUploadCommand,
  GetObjectLockConfigurationCommand,
  GetBucketLifecycleConfigurationCommand,
  GetBucketTaggingCommand,
} from "@aws-sdk/client-s3";
import { main } from "../src/cli.js";
import { EXIT_CODES } from "../src/policy/evaluator.js";
import { Plan, writePlanFile } from "../src/planner/plan.js";

const s3Mock = mockClient(S3Client);

describe("SemVer 2.0 Exit Code Contract (exit-codes.test.ts)", () => {
  let stdoutLogs: string[] = [];
  let stderrLogs: string[] = [];
  let tempDir: string;

  const captureIO = {
    stdout: (msg: string) => stdoutLogs.push(msg),
    stderr: (msg: string) => stderrLogs.push(msg),
  };

  beforeEach(async () => {
    s3Mock.reset();
    stdoutLogs = [];
    stderrLogs = [];
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "s3-guardian-exit-codes-"));
  });

  afterEach(async () => {
    try {
      await fs.rm(tempDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  // ── Exit Code 0: SUCCESS ──────────────────────────────────────────────────
  describe("Exit Code 0: SUCCESS", () => {
    it("returns 0 on --version", async () => {
      const code = await main(["--version"], captureIO);
      expect(code).toBe(EXIT_CODES.SUCCESS);
      expect(code).toBe(0);
      expect(stdoutLogs.join(" ")).toContain("s3-guardian v2.0.0");
    });

    it("returns 0 on --help", async () => {
      const code = await main(["--help"], captureIO);
      expect(code).toBe(EXIT_CODES.SUCCESS);
      expect(code).toBe(0);
      expect(stdoutLogs.join(" ")).toContain("USAGE:");
    });

    it("returns 0 on clean scan with no zombie uploads", async () => {
      s3Mock.on(GetBucketLocationCommand).resolves({ LocationConstraint: "us-east-1" });
      s3Mock.on(ListMultipartUploadsCommand).resolves({ Uploads: [] });
      s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({
        Rules: [
          {
            ID: "cleanup-rule",
            Status: "Enabled",
            Filter: {},
            AbortIncompleteMultipartUpload: { DaysAfterInitiation: 7 },
          },
        ],
      });

      const code = await main(["scan", "clean-bucket"], captureIO);
      expect(code).toBe(EXIT_CODES.SUCCESS);
      expect(code).toBe(0);
      expect(stdoutLogs.join(" ")).toContain("Clean!");
    });
  });

  // ── Exit Code 1: CONFIG_ARG_ERROR ─────────────────────────────────────────
  describe("Exit Code 1: CONFIG_ARG_ERROR", () => {
    it("returns 1 when an unknown command is supplied", async () => {
      const code = await main(["non-existent-subcommand"], captureIO);
      expect(code).toBe(EXIT_CODES.CONFIG_ARG_ERROR);
      expect(code).toBe(1);
      expect(stderrLogs.join(" ")).toContain("Unknown command 'non-existent-subcommand'");
    });

    it("returns 1 when a required bucket argument is omitted in scan", async () => {
      const code = await main(["scan"], captureIO);
      expect(code).toBe(EXIT_CODES.CONFIG_ARG_ERROR);
      expect(code).toBe(1);
      expect(stderrLogs.join(" ")).toContain("Bucket name is required for 'scan'");
    });

    it("returns 1 when an invalid --interval format is specified", async () => {
      const code = await main(["operate", "my-bucket", "--interval", "100lightyears"], captureIO);
      expect(code).toBe(EXIT_CODES.CONFIG_ARG_ERROR);
      expect(code).toBe(1);
      expect(stderrLogs.join(" ")).toContain("Invalid interval format");
    });

    it("returns 1 when --max-blast-radius is negative", async () => {
      const code = await main(["operate", "my-bucket", "--max-blast-radius", "-5"], captureIO);
      expect(code).toBe(EXIT_CODES.CONFIG_ARG_ERROR);
      expect(code).toBe(1);
      expect(stderrLogs.join(" ")).toContain("--max-blast-radius must be a non-negative number");
    });

    it("returns 1 when apply is missing mandatory --confirm", async () => {
      const tempPlan = path.join(tempDir, "plan.json");
      const plan: Plan = {
        schemaVersion: "1.2",
        generatedAt: new Date().toISOString(),
        bucket: "unconfirmed-bucket",
        endpoint: null,
        olderThanDays: 7,
        totalZombieUploads: 0,
        totalStrandedBytes: 0,
        estimatedMonthlyWasteUSD: 0,
        uploads: [],
      };
      await writePlanFile(tempPlan, plan);

      const code = await main(["apply", "--plan", tempPlan], captureIO);
      expect(code).toBe(EXIT_CODES.CONFIG_ARG_ERROR);
      expect(code).toBe(1);
      expect(stderrLogs.join(" ")).toContain("'--confirm' flag is strictly required");
    });
  });

  // ── Exit Code 2: AUTH_IAM_ERROR ───────────────────────────────────────────
  describe("Exit Code 2: AUTH_IAM_ERROR", () => {
    it("returns 2 when S3 ListBuckets fails with AccessDenied", async () => {
      const deniedErr = new Error("Access Denied: User is not authorized to perform: s3:ListAllMyBuckets");
      deniedErr.name = "AccessDenied";
      s3Mock.on(ListBucketsCommand).rejects(deniedErr);

      const code = await main(["scan", "--all-buckets"], captureIO);
      expect(code).toBe(EXIT_CODES.AUTH_IAM_ERROR);
      expect(code).toBe(2);
      expect(stderrLogs.join(" ")).toContain("Access Denied");
    });

    it("returns 2 when S3 returns UnauthorizedOperation", async () => {
      const unauthErr = new Error("You are not authorized to perform this operation.");
      unauthErr.name = "UnauthorizedOperation";
      s3Mock.on(ListMultipartUploadsCommand).rejects(unauthErr);

      const code = await main(["scan", "unauth-bucket"], captureIO);
      expect(code).toBe(EXIT_CODES.AUTH_IAM_ERROR);
      expect(code).toBe(2);
    });
  });

  // ── Exit Code 3: POLICY_VIOLATION ─────────────────────────────────────────
  describe("Exit Code 3: POLICY_VIOLATION", () => {
    it("returns 3 when declarative policy fails static validation invariant", async () => {
      const badPolicyPath = path.join(tempDir, "invalid-policy.yaml");
      await fs.writeFile(
        badPolicyPath,
        `
schemaVersion: "1"
policyId: invalid-guard
scope:
  level: GLOBAL
rules:
  - id: bad-mpu-cleanup
    match: {}
    mpuAbortDays: 3d # < 7 days invariant breach
`,
        "utf8"
      );

      const code = await main(["policy", "validate", badPolicyPath], captureIO);
      expect(code).toBe(EXIT_CODES.POLICY_VIOLATION);
      expect(code).toBe(3);
      expect(stderrLogs.join(" ")).toContain("Policy validation failed");
    });

    it("returns 3 when scan --all-buckets detects non-compliant buckets against --policy", async () => {
      const policyPath = path.join(tempDir, "compliance-policy.yaml");
      await fs.writeFile(
        policyPath,
        `
schemaVersion: "1"
policyId: comp-policy
scope:
  level: GLOBAL
rules:
  - id: global-cleanup
    match: {}
    mpuAbortDays: 7d
`,
        "utf8"
      );

      s3Mock.on(ListBucketsCommand).resolves({
        Buckets: [{ Name: "unprotected-policy-bucket" }],
      });
      s3Mock.on(GetBucketLocationCommand).resolves({ LocationConstraint: "us-east-1" });
      s3Mock.on(ListMultipartUploadsCommand).resolves({ Uploads: [] });
      const noLifecycleErr = new Error("NoSuchLifecycleConfiguration");
      noLifecycleErr.name = "NoSuchLifecycleConfiguration";
      (noLifecycleErr as any).$metadata = { httpStatusCode: 404 };
      s3Mock.on(GetBucketLifecycleConfigurationCommand).rejects(noLifecycleErr);

      const code = await main(["scan", "--all-buckets", "--policy", policyPath], captureIO);
      expect(code).toBe(EXIT_CODES.POLICY_VIOLATION);
      expect(code).toBe(3);
      expect(stdoutLogs.join(" ")).toContain("Non-Compliant Buckets");
    });
  });

  // ── Exit Code 4: CIRCUIT_CANARY_BLAST_RADIUS ──────────────────────────────
  describe("Exit Code 4: CIRCUIT_CANARY_BLAST_RADIUS", () => {
    it("returns 4 when Sovereign Operator relative blast radius ceiling is breached", async () => {
      const oldDate = new Date(Date.now() - 15 * 24 * 60 * 60 * 1000);
      s3Mock.on(GetBucketLocationCommand).resolves({ LocationConstraint: "us-east-1" });
      s3Mock.on(GetBucketTaggingCommand).rejects(new Error("NoSuchTagSet"));
      s3Mock.on(GetObjectLockConfigurationCommand).rejects(new Error("ObjectLockConfigurationNotFoundError"));
      s3Mock.on(ListMultipartUploadsCommand).resolves({
        IsTruncated: false,
        Uploads: Array.from({ length: 10 }, (_, i) => ({
          Key: `waste-${i}.bin`,
          UploadId: `uid-${i}`,
          Initiated: oldDate,
        })),
      });
      s3Mock.on(ListPartsCommand).resolves({
        IsTruncated: false,
        Parts: [{ PartNumber: 1, Size: 1000 }],
      });

      const code = await main(
        [
          "operate",
          "breach-bucket",
          "--once",
          "--max-blast-radius",
          "5", // 5% of 10 items = ceiling of 0 items
          "--state-dir",
          tempDir,
        ],
        captureIO
      );

      expect(code).toBe(EXIT_CODES.CIRCUIT_CANARY_BLAST_RADIUS);
      expect(code).toBe(4);
      expect(stderrLogs.join(" ")).toContain("Sovereign Operator halted");
      expect(stderrLogs.join(" ")).toContain("exceed relative safety ceiling");
    });

    it("returns 4 when Wasabi minimum retention guard prevents premature deletion", async () => {
      const tempPlan = path.join(tempDir, "wasabi-plan.json");
      const plan: Plan = {
        schemaVersion: "1.2",
        generatedAt: new Date().toISOString(),
        bucket: "wasabi-test-bucket",
        endpoint: "https://s3.wasabisys.com",
        olderThanDays: 7,
        totalZombieUploads: 1,
        totalStrandedBytes: 5000000,
        estimatedMonthlyWasteUSD: 0.1,
        uploads: [
          {
            key: "wasabi-recent.bin",
            uploadId: "wasabi-uid-1",
            initiated: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(), // 10 days old (< 90 days)
            partsCount: 1,
            bytes: 5000000,
            storageClass: "STANDARD",
            lifecycleStatus: "UNPROTECTED",
          },
        ],
      };
      await writePlanFile(tempPlan, plan);

      const code = await main(
        [
          "apply",
          "--plan",
          tempPlan,
          "--confirm",
          "--provider",
          "wasabi",
          "--endpoint",
          "https://s3.wasabisys.com",
        ],
        captureIO
      );

      expect(code).toBe(EXIT_CODES.CIRCUIT_CANARY_BLAST_RADIUS);
      expect(code).toBe(4);
      expect(stderrLogs.join(" ")).toContain("Wasabi charges 90 days minimum retention");
    });
  });

  // ── Exit Code 5: FS_STATE_ERROR ───────────────────────────────────────────
  describe("Exit Code 5: FS_STATE_ERROR", () => {
    it("returns 5 when encountering filesystem corruption or unreadable state file", async () => {
      const fsErr = new Error("ENOENT: no such file or directory, open corrupt-manifest.json");
      (fsErr as any).code = "ENOENT";

      s3Mock.on(ListMultipartUploadsCommand).rejects(fsErr);

      const code = await main(["scan", "fs-err-bucket"], captureIO);
      expect(code).toBe(EXIT_CODES.FS_STATE_ERROR);
      expect(code).toBe(5);
      expect(stderrLogs.join(" ")).toContain("ENOENT");
    });
  });

  // ── Exit Code 6: NETWORK_TIMEOUT ──────────────────────────────────────────
  describe("Exit Code 6: NETWORK_TIMEOUT", () => {
    it("returns 6 when AWS SDK connection times out with ETIMEDOUT", async () => {
      const netErr = new Error("connect ETIMEDOUT 52.216.0.1:443");
      (netErr as any).code = "ETIMEDOUT";

      s3Mock.on(ListMultipartUploadsCommand).rejects(netErr);

      const code = await main(["scan", "timeout-bucket"], captureIO);
      expect(code).toBe(EXIT_CODES.NETWORK_TIMEOUT);
      expect(code).toBe(6);
      expect(stderrLogs.join(" ")).toContain("ETIMEDOUT");
    });

    it("returns 6 when request fails with TimeoutError", async () => {
      const timeoutErr = new Error("Socket timeout reading from s3.amazonaws.com");
      timeoutErr.name = "TimeoutError";

      s3Mock.on(ListMultipartUploadsCommand).rejects(timeoutErr);

      const code = await main(["scan", "timeout-bucket-2"], captureIO);
      expect(code).toBe(EXIT_CODES.NETWORK_TIMEOUT);
      expect(code).toBe(6);
      expect(stderrLogs.join(" ")).toContain("Socket timeout");
    });
  });
});
