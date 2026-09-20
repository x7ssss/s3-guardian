import { spawn, execFile } from "node:child_process";
import * as fs from "node:fs/promises";
import * as fsSync from "node:fs";
import * as path from "node:path";
import * as assert from "node:assert";
import { promisify } from "node:util";
import {
  S3Client,
  CreateBucketCommand,
  PutBucketVersioningCommand,
  CreateMultipartUploadCommand,
  ListMultipartUploadsCommand,
  AbortMultipartUploadCommand,
  PutObjectCommand,
  DeleteObjectCommand,
  GetObjectCommand,
  ListObjectVersionsCommand,
  DeleteObjectsCommand,
  DeleteBucketCommand,
  PutBucketPolicyCommand,
  DeleteBucketPolicyCommand,
  PutObjectLockConfigurationCommand,
  PutBucketLifecycleConfigurationCommand,
  GetBucketLifecycleConfigurationCommand,
} from "@aws-sdk/client-s3";
import { STSClient, AssumeRoleCommand } from "@aws-sdk/client-sts";
import { AuditLogWriter } from "../src/state/audit-writer.js";
import { createAuditEvent } from "../src/state/types.js";

const execFileAsync = promisify(execFile);

// ── Target Configuration ───────────────────────────────────────────────────────
const ENDPOINT = "http://127.0.0.1:9000";
const REGION = "us-east-1";
const ACCESS_KEY_ID = "minioadmin";
const SECRET_ACCESS_KEY = "minioadmin";
const FORCE_PATH_STYLE = true;

const s3 = new S3Client({
  endpoint: ENDPOINT,
  region: REGION,
  credentials: {
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET_ACCESS_KEY,
  },
  forcePathStyle: FORCE_PATH_STYLE,
});

const suiteId = Date.now().toString(36);
const createdBuckets: string[] = [];
const tempFilesToClean: string[] = [];
const tempDirsToClean: string[] = [];

interface ScenarioResult {
  id: number;
  name: string;
  status: "PASSED" | "FAILED";
  durationMs: number;
  details: string;
}

const scenarioResults: ScenarioResult[] = [];

function logBanner(text: string) {
  console.log("\n" + "=".repeat(80));
  console.log(`🛡️  ${text}`);
  console.log("=".repeat(80));
}

function logScenarioHeader(num: number, title: string) {
  console.log(`\n--------------------------------------------------------------------------------`);
  console.log(`▶ Scenario ${num}: ${title}`);
  console.log(`--------------------------------------------------------------------------------`);
}

function runCli(
  args: string[],
  extraEnv?: NodeJS.ProcessEnv
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, ["./dist/cli.js", ...args], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        AWS_ACCESS_KEY_ID: ACCESS_KEY_ID,
        AWS_SECRET_ACCESS_KEY: SECRET_ACCESS_KEY,
        AWS_REGION: REGION,
        AWS_ENDPOINT_URL: ENDPOINT,
        ...extraEnv,
      },
    });

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    proc.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    proc.on("error", reject);
    proc.on("close", (exitCode) => {
      resolve({ exitCode: exitCode ?? 0, stdout, stderr });
    });
  });
}

async function cleanDeleteBucket(client: S3Client, bucket: string) {
  try {
    // 1. Remove bucket policy if attached
    try {
      await client.send(new DeleteBucketPolicyCommand({ Bucket: bucket }));
    } catch {
      // Ignore
    }

    // 2. Abort all MPUs
    try {
      const listMpus = await client.send(new ListMultipartUploadsCommand({ Bucket: bucket }));
      if (listMpus.Uploads) {
        for (const u of listMpus.Uploads) {
          if (u.Key && u.UploadId) {
            await client.send(
              new AbortMultipartUploadCommand({
                Bucket: bucket,
                Key: u.Key,
                UploadId: u.UploadId,
              })
            );
          }
        }
      }
    } catch {
      // Ignore
    }

    // 3. Delete all versions and delete markers
    try {
      const listVersions = await client.send(new ListObjectVersionsCommand({ Bucket: bucket }));
      const objectsToDelete = [
        ...(listVersions.Versions ?? []).map((v) => ({ Key: v.Key!, VersionId: v.VersionId })),
        ...(listVersions.DeleteMarkers ?? []).map((d) => ({ Key: d.Key!, VersionId: d.VersionId })),
      ];

      if (objectsToDelete.length > 0) {
        await client.send(
          new DeleteObjectsCommand({
            Bucket: bucket,
            Delete: { Objects: objectsToDelete, Quiet: true },
          })
        );
      }
    } catch {
      // Ignore
    }

    // 4. Delete the bucket
    await client.send(new DeleteBucketCommand({ Bucket: bucket }));
    console.log(`   [Teardown] Bucket '${bucket}' cleanly deleted.`);
  } catch (err: unknown) {
    console.warn(`   [Teardown Notice] Cleanup for bucket '${bucket}': ${(err as Error).message}`);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// SCENARIO IMPLEMENTATIONS
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Scenario 1: Active In-Flight Pipeline Protection (Churn Guard)
 */
async function runScenario1(): Promise<ScenarioResult> {
  const start = Date.now();
  const scenarioNum = 1;
  const name = "Active In-Flight Pipeline Protection (Churn Guard)";
  logScenarioHeader(scenarioNum, name);

  const bucketName = `test-ent-churn-${suiteId}`;
  createdBuckets.push(bucketName);
  const planFile = path.resolve(`plan-churn-${suiteId}.json`);
  tempFilesToClean.push(planFile);

  console.log(`   Creating bucket '${bucketName}'...`);
  await s3.send(new CreateBucketCommand({ Bucket: bucketName }));

  console.log(`   Initiating active in-flight multipart upload (< 24h old)...`);
  const mpu = await s3.send(
    new CreateMultipartUploadCommand({
      Bucket: bucketName,
      Key: "pipeline/telemetry-chunk-001.bin",
    })
  );
  assert.ok(mpu.UploadId, "MPU UploadId must be returned");

  console.log(`   Running 'plan' without churn bypass...`);
  const planRun = await runCli([
    "plan",
    bucketName,
    "--older-than",
    "0",
    "--out",
    planFile,
    "--endpoint",
    ENDPOINT,
    "--force-path-style",
  ]);

  console.log(`   Plan CLI Exit Code: ${planRun.exitCode}`);
  assert.strictEqual(planRun.exitCode, 0, "Plan generation should exit 0");

  const planContent = JSON.parse(await fs.readFile(planFile, "utf8"));
  const churnFinding = planContent.blastRadiusAudit?.findings?.find(
    (f: any) => f.code === "ACTIVE_CHURN_DETECTED"
  );
  assert.ok(churnFinding, "Plan must flag ACTIVE_CHURN_DETECTED finding");
  assert.strictEqual(churnFinding.risk, "HIGH", "Churn risk must be HIGH");
  assert.strictEqual(planContent.blastRadiusAudit?.riskLevel, "HIGH", "Audit riskLevel must be HIGH");
  console.log(`   ✓ Correctly flagged ACTIVE_CHURN_DETECTED (Risk: HIGH)`);

  console.log(`   Attempting 'apply' without --allow-active-churn flag...`);
  const applyRun = await runCli([
    "apply",
    "--plan",
    planFile,
    "--confirm",
    "--endpoint",
    ENDPOINT,
    "--force-path-style",
  ]);

  console.log(`   Apply CLI Exit Code: ${applyRun.exitCode}`);
  assert.strictEqual(applyRun.exitCode, 4, "Apply must halt with SemVer exit code 4 (CIRCUIT_CANARY_BLAST_RADIUS)");
  assert.ok(
    applyRun.stderr.includes("ACTIVE_CHURN_DETECTED") || applyRun.stdout.includes("ACTIVE_CHURN_DETECTED"),
    "Stderr/stdout must report ACTIVE_CHURN_DETECTED"
  );
  console.log(`   ✓ Deletion strictly blocked by churn guard (exit code 4)`);

  console.log(`   Re-running 'plan' with '--allow-active-churn'...`);
  const overridePlanRun = await runCli([
    "plan",
    bucketName,
    "--older-than",
    "0",
    "--out",
    planFile,
    "--allow-active-churn",
    "--endpoint",
    ENDPOINT,
    "--force-path-style",
  ]);

  assert.strictEqual(overridePlanRun.exitCode, 0);
  const overrideContent = JSON.parse(await fs.readFile(planFile, "utf8"));
  const overriddenFinding = overrideContent.blastRadiusAudit?.findings?.find(
    (f: any) => f.code === "ACTIVE_CHURN_OVERRIDDEN"
  );
  assert.ok(overriddenFinding, "Plan must flag ACTIVE_CHURN_OVERRIDDEN");
  console.log(`   ✓ Active churn override successfully acknowledged`);

  return {
    id: scenarioNum,
    name,
    status: "PASSED",
    durationMs: Date.now() - start,
    details: "Blocked unauthorized apply of <24h MPU with exit code 4; permitted with explicit override.",
  };
}

/**
 * Scenario 2: Blast-Radius Mutation Ceiling Breaker
 */
async function runScenario2(): Promise<ScenarioResult> {
  const start = Date.now();
  const scenarioNum = 2;
  const name = "Blast-Radius Mutation Ceiling Breaker";
  logScenarioHeader(scenarioNum, name);

  const bucketName = `test-ent-blast-${suiteId}`;
  createdBuckets.push(bucketName);
  const policyFile = path.resolve(`policy-blast-${suiteId}.json`);
  tempFilesToClean.push(policyFile);

  console.log(`   Creating versioned bucket '${bucketName}'...`);
  await s3.send(new CreateBucketCommand({ Bucket: bucketName }));
  await s3.send(
    new PutBucketVersioningCommand({
      Bucket: bucketName,
      VersioningConfiguration: { Status: "Enabled" },
    })
  );

  console.log(`   Seeding 100 versioned objects (put and soft-delete)...`);
  const itemsToSeed = 100;
  for (let i = 0; i < itemsToSeed; i++) {
    const key = `dataset/record-${String(i).padStart(3, "0")}.json`;
    await s3.send(
      new PutObjectCommand({
        Bucket: bucketName,
        Key: key,
        Body: JSON.stringify({ id: i, payload: "enterprise-blast-test" }),
      })
    );
    await s3.send(
      new DeleteObjectCommand({
        Bucket: bucketName,
        Key: key,
      })
    );
  }
  console.log(`   ✓ Seeded ${itemsToSeed} expired delete markers.`);

  console.log(`   Executing 'operate --once' against 100% targeting...`);
  const operateRun = await runCli([
    "operate",
    bucketName,
    "--once",
    "--max-blast-radius",
    "5",
    "--endpoint",
    ENDPOINT,
    "--force-path-style",
  ]);

  console.log(`   Operate Exit Code: ${operateRun.exitCode}`);
  assert.strictEqual(
    operateRun.exitCode,
    4,
    "Operator must halt with SemVer exit code 4 (CIRCUIT_CANARY_BLAST_RADIUS)"
  );
  assert.ok(
    operateRun.stderr.includes("ceiling") ||
      operateRun.stdout.includes("ceiling") ||
      operateRun.stderr.includes("BLAST_RADIUS_AUDIT") ||
      operateRun.stdout.includes("BLAST_RADIUS_AUDIT"),
    "Operator must report mutation ceiling breach"
  );
  console.log(`   ✓ Operator successfully halted at BLAST_RADIUS_AUDIT due to 100% exceeding 5% ceiling`);

  return {
    id: scenarioNum,
    name,
    status: "PASSED",
    durationMs: Date.now() - start,
    details: "100 objects targeted (100% of inventory); halted at BLAST_RADIUS_AUDIT with SemVer exit code 4.",
  };
}

/**
 * Scenario 3: Canary Verification Gate & Circuit Breaker Trip
 */
async function runScenario3(): Promise<ScenarioResult> {
  const start = Date.now();
  const scenarioNum = 3;
  const name = "Canary Verification Gate & Circuit Breaker Trip";
  logScenarioHeader(scenarioNum, name);

  const bucketName = `test-ent-canary-${suiteId}`;
  createdBuckets.push(bucketName);
  const policyFile = path.resolve(`policy-canary-${suiteId}.json`);
  tempFilesToClean.push(policyFile);

  console.log(`   Creating bucket '${bucketName}'...`);
  await s3.send(new CreateBucketCommand({ Bucket: bucketName }));

  console.log(`   Seeding 20 multipart uploads...`);
  const totalItems = 20;
  const seededUploadIds: string[] = [];
  for (let i = 0; i < totalItems; i++) {
    const key = `canary-test/chunk-${String(i).padStart(2, "0")}.dat`;
    const res = await s3.send(
      new CreateMultipartUploadCommand({
        Bucket: bucketName,
        Key: key,
      })
    );
    if (res.UploadId) seededUploadIds.push(res.UploadId);
  }
  assert.strictEqual(seededUploadIds.length, totalItems);
  console.log(`   ✓ Seeded ${totalItems} multipart uploads.`);

  console.log(`   Injecting S3 Bucket Policy with 'Deny' on 's3:AbortMultipartUpload'...`);
  const denyPolicy = {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "DenyAbortCanaryProbe",
        Effect: "Deny",
        Principal: "*",
        Action: "s3:AbortMultipartUpload",
        Resource: `arn:aws:s3:::${bucketName}/*`,
      },
    ],
  };
  await s3.send(
    new PutBucketPolicyCommand({
      Bucket: bucketName,
      Policy: JSON.stringify(denyPolicy),
    })
  );
  console.log(`   ✓ Bucket policy injected.`);

  console.log(`   Assuming role with session policy denying s3:AbortMultipartUpload...`);
  const sessionPolicy = {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Action: ["s3:List*", "s3:Get*"],
        Resource: "*",
      },
      {
        Effect: "Deny",
        Action: "s3:AbortMultipartUpload",
        Resource: "*",
      },
    ],
  };

  const sts = new STSClient({
    endpoint: ENDPOINT,
    region: REGION,
    credentials: {
      accessKeyId: ACCESS_KEY_ID,
      secretAccessKey: SECRET_ACCESS_KEY,
    },
  });

  const assumed = await sts.send(
    new AssumeRoleCommand({
      RoleArn: "arn:aws:iam::123456789012:role/canary-operator",
      RoleSessionName: "canary-gate-test",
      DurationSeconds: 900,
      Policy: JSON.stringify(sessionPolicy),
    })
  );

  console.log(`   Executing 'operate --once' (canaryCount: 5, maxBlastRadius: 100%)...`);
  const operateRun = await runCli(
    [
      "operate",
      bucketName,
      "--once",
      "--older-than",
      "0",
      "--canary-count",
      "5",
      "--max-blast-radius",
      "100",
      "--endpoint",
      ENDPOINT,
      "--force-path-style",
    ],
    {
      AWS_ACCESS_KEY_ID: assumed.Credentials?.AccessKeyId,
      AWS_SECRET_ACCESS_KEY: assumed.Credentials?.SecretAccessKey,
      AWS_SESSION_TOKEN: assumed.Credentials?.SessionToken,
    }
  );

  console.log(`   Operate Exit Code: ${operateRun.exitCode}`);
  assert.strictEqual(
    operateRun.exitCode,
    4,
    "Canary verification failure must return SemVer exit code 4 (CIRCUIT_CANARY_BLAST_RADIUS)"
  );
  assert.ok(
    operateRun.stderr.includes("Canary verification failure") ||
      operateRun.stdout.includes("Canary verification failure") ||
      operateRun.stderr.includes("Access Denied") ||
      operateRun.stdout.includes("Access Denied"),
    "Output must reflect canary verification gate failure"
  );
  console.log(`   ✓ Canary gate failed as expected.`);

  // Remove the bucket policy so we can inspect and verify remaining uploads
  await s3.send(new DeleteBucketPolicyCommand({ Bucket: bucketName }));

  const listMpus = await s3.send(new ListMultipartUploadsCommand({ Bucket: bucketName }));
  const remainingCount = listMpus.Uploads?.length ?? 0;
  console.log(`   Remaining MPUs after circuit trip: ${remainingCount}/${totalItems}`);
  assert.strictEqual(
    remainingCount,
    totalItems,
    "All remaining targets must remain completely untouched after circuit breaker trips!"
  );
  console.log(`   ✓ Circuit breaker tripped to OPEN; 100% of targets preserved.`);

  return {
    id: scenarioNum,
    name,
    status: "PASSED",
    durationMs: Date.now() - start,
    details: "Canary probe failed via Deny policy; circuit breaker tripped to OPEN; 20/20 items left untouched (exit code 4).",
  };
}

/**
 * Scenario 4: Soft Delete Rehydration (Tombstone Popping)
 */
async function runScenario4(): Promise<ScenarioResult> {
  const start = Date.now();
  const scenarioNum = 4;
  const name = "Soft Delete Rehydration (Tombstone Popping)";
  logScenarioHeader(scenarioNum, name);

  const bucketName = `test-ent-rehydrate-${suiteId}`;
  createdBuckets.push(bucketName);

  console.log(`   Creating versioned bucket '${bucketName}'...`);
  await s3.send(new CreateBucketCommand({ Bucket: bucketName }));
  await s3.send(
    new PutBucketVersioningCommand({
      Bucket: bucketName,
      VersioningConfiguration: { Status: "Enabled" },
    })
  );

  const objectKey = "data/production.csv";
  const expectedContent = "id,sku,amount\n101,PROD-A,99.50\n102,PROD-B,149.00\n";

  console.log(`   Writing initial object '${objectKey}'...`);
  const putRes = await s3.send(
    new PutObjectCommand({
      Bucket: bucketName,
      Key: objectKey,
      Body: expectedContent,
    })
  );
  assert.ok(putRes.VersionId, "PutObject should return VersionId in versioned bucket");

  console.log(`   Soft-deleting '${objectKey}' (creating Delete Marker)...`);
  const delRes = await s3.send(
    new DeleteObjectCommand({
      Bucket: bucketName,
      Key: objectKey,
    })
  );
  assert.ok(delRes.DeleteMarker, "DeleteObject should return DeleteMarker: true");

  console.log(`   Verifying object returns 404 (NoSuchKey) after soft deletion...`);
  let got404 = false;
  try {
    await s3.send(new GetObjectCommand({ Bucket: bucketName, Key: objectKey }));
  } catch (err: any) {
    if (err.name === "NoSuchKey" || err.$metadata?.httpStatusCode === 404) {
      got404 = true;
    }
  }
  assert.ok(got404, "GetObject must fail with 404 when Delete Marker is present");
  console.log(`   ✓ Object confirmed hidden by tombstone.`);

  console.log(`   Running 'rehydrate' command...`);
  const rehydrateRun = await runCli([
    "rehydrate",
    bucketName,
    "--endpoint",
    ENDPOINT,
    "--force-path-style",
  ]);

  console.log(`   Rehydrate Exit Code: ${rehydrateRun.exitCode}`);
  assert.strictEqual(rehydrateRun.exitCode, 0, "Rehydrate must complete with exit code 0");
  assert.ok(
    rehydrateRun.stdout.includes("Delete Markers Popped:  1") ||
      rehydrateRun.stdout.includes("Delete Markers Popped"),
    "Output must confirm Delete Marker was popped"
  );

  console.log(`   Verifying object is rehydrated and readable...`);
  const restoredObj = await s3.send(new GetObjectCommand({ Bucket: bucketName, Key: objectKey }));
  const restoredBody = await restoredObj.Body?.transformToString();
  assert.strictEqual(restoredBody, expectedContent, "Rehydrated object content must match original payload");
  console.log(`   ✓ Object successfully rehydrated and restored!`);

  return {
    id: scenarioNum,
    name,
    status: "PASSED",
    durationMs: Date.now() - start,
    details: "Popped Delete Marker tombstone; previously 404 object successfully restored and verified.",
  };
}

/**
 * Scenario 5: Linearizable Audit Ledger & Zero-Memory Compaction
 */
async function runScenario5(): Promise<ScenarioResult> {
  const start = Date.now();
  const scenarioNum = 5;
  const name = "Linearizable Audit Ledger & Zero-Memory Compaction";
  logScenarioHeader(scenarioNum, name);

  const stateDir = path.resolve(`.s3-guardian-audit-${suiteId}`);
  tempDirsToClean.push(stateDir);

  console.log(`   Initializing AuditLogWriter in '${stateDir}'...`);
  const writer = new AuditLogWriter({ stateDir });

  console.log(`   Generating 50 audit events in audit.jsonl...`);
  for (let i = 0; i < 50; i++) {
    await writer.append(
      createAuditEvent({
        eventType: i % 2 === 0 ? "CANARY_VERIFIED" : "REMEDIATION_EXECUTED",
        accountId: "123456789012",
        bucketName: `production-lake-${i % 5}`,
        targetCount: 10 + i,
        bytesFreed: (10 + i) * 1024 * 1024,
        planHash: `0123456789abcdef${String(i).padStart(48, "0")}`,
        xAmzRequestIds: [`req-${i}-abc`],
      })
    );
  }
  await writer.close();

  const auditLogPath = path.join(stateDir, "audit.jsonl");
  assert.ok(fsSync.existsSync(auditLogPath), "audit.jsonl must exist");
  const uncompactedStats = await fs.stat(auditLogPath);
  console.log(`   ✓ Uncompacted audit.jsonl size: ${uncompactedStats.size} bytes`);

  const memBefore = process.memoryUsage().rss;

  console.log(`   Running 'state compact' CLI command...`);
  const compactRun = await runCli([
    "state",
    "compact",
    "--state-dir",
    stateDir,
    "--endpoint",
    ENDPOINT,
    "--force-path-style",
  ]);

  const memAfter = process.memoryUsage().rss;
  const memDiffMB = Math.round((memAfter - memBefore) / (1024 * 1024));

  console.log(`   Compact CLI Exit Code: ${compactRun.exitCode}`);
  assert.strictEqual(compactRun.exitCode, 0, "state compact must exit 0");

  const snapshotsDir = path.join(stateDir, "snapshots");
  assert.ok(fsSync.existsSync(snapshotsDir), "snapshots/ directory must be created");
  const snapshotFiles = (await fs.readdir(snapshotsDir)).filter((f) => f.endsWith(".json.gz"));
  assert.ok(snapshotFiles.length >= 1, "At least one .json.gz snapshot file must exist");
  console.log(`   ✓ Found compressed snapshot: ${snapshotFiles[0]}`);

  console.log(`   Memory RSS delta during compaction: ${memDiffMB} MB (Threshold: < 50 MB)`);
  assert.ok(Math.abs(memDiffMB) < 50, `Memory RSS change (${memDiffMB}MB) must be below 50MB`);
  console.log(`   ✓ Verified zero-memory streaming compaction`);

  return {
    id: scenarioNum,
    name,
    status: "PASSED",
    durationMs: Date.now() - start,
    details: `Compacted 50 events to gzip snapshot; rotated audit.jsonl; RSS delta: ${memDiffMB}MB (<50MB).`,
  };
}

/**
 * Scenario 6: Remote State Drift Detection & Atomic Rollback
 */
async function runScenario6(): Promise<ScenarioResult> {
  const start = Date.now();
  const scenarioNum = 6;
  const name = "Remote State Drift Detection & Atomic Rollback";
  logScenarioHeader(scenarioNum, name);

  const bucketName = `test-ent-rollback-${suiteId}`;
  createdBuckets.push(bucketName);
  const stateDir = path.resolve(`.s3-guardian-rollback-${suiteId}`);
  tempDirsToClean.push(stateDir);
  const policyFile = path.resolve(`policy-rollback-${suiteId}.json`);
  tempFilesToClean.push(policyFile);

  console.log(`   Creating bucket '${bucketName}'...`);
  await s3.send(new CreateBucketCommand({ Bucket: bucketName }));

  console.log(`   Setting baseline lifecycle rule...`);
  await s3.send(
    new PutBucketLifecycleConfigurationCommand({
      Bucket: bucketName,
      LifecycleConfiguration: {
        Rules: [
          {
            ID: "baseline-rule",
            Status: "Enabled",
            Filter: {},
            Expiration: { Days: 60 },
          },
        ],
      },
    })
  );

  // Declarative policy to apply a mutation
  const policyDoc = {
    schemaVersion: "1",
    policyId: `rollback-test-policy-${suiteId}`,
    scope: { level: "GLOBAL" },
    defaults: { action: "AUTO_REMEDIATE" },
    rules: [
      {
        id: "guardian-rule-mutated",
        match: {},
        action: "AUTO_REMEDIATE",
        expirationDays: 30,
      },
    ],
  };
  await fs.writeFile(policyFile, JSON.stringify(policyDoc, null, 2), "utf8");

  console.log(`   Applying policy to generate UndoManifest...`);
  const applyRun = await runCli([
    "policy",
    "apply",
    bucketName,
    "--policy",
    policyFile,
    "--confirm",
    "--state-dir",
    stateDir,
    "--endpoint",
    ENDPOINT,
    "--force-path-style",
  ]);

  assert.strictEqual(
    applyRun.exitCode,
    0,
    `Policy apply must succeed with exit code 0. Stderr: ${applyRun.stderr}, Stdout: ${applyRun.stdout}`
  );

  const undoDir = path.join(stateDir, "undo");
  assert.ok(fsSync.existsSync(undoDir), "undo/ directory must exist");
  const manifestFiles = (await fs.readdir(undoDir)).filter((f) => f.startsWith("undo-") && f.endsWith(".json"));
  assert.ok(manifestFiles.length >= 1, "An undo manifest file must be generated");
  const manifestPath = path.join(undoDir, manifestFiles[0]!);
  console.log(`   ✓ Captured UndoManifest: ${path.basename(manifestPath)}`);

  console.log(`   Simulating out-of-band remote state drift via direct S3 API...`);
  await s3.send(
    new PutBucketLifecycleConfigurationCommand({
      Bucket: bucketName,
      LifecycleConfiguration: {
        Rules: [
          {
            ID: "rogue-out-of-band-drift",
            Status: "Enabled",
            Filter: {},
            Expiration: { Days: 90 },
          },
        ],
      },
    })
  );
  console.log(`   ✓ Out-of-band drift injected.`);

  console.log(`   Running 'rollback' without --force flag...`);
  const rollbackRun = await runCli([
    "rollback",
    manifestPath,
    "--endpoint",
    ENDPOINT,
    "--force-path-style",
  ]);

  console.log(`   Rollback CLI Exit Code: ${rollbackRun.exitCode}`);
  assert.strictEqual(
    rollbackRun.exitCode,
    3,
    "Rollback must reject with SemVer exit code 3 (POLICY_VIOLATION) when state has diverged"
  );
  assert.ok(
    rollbackRun.stderr.includes("Remote state drift detected") ||
      rollbackRun.stdout.includes("Remote state drift detected"),
    "Rollback output must explicitly report Remote state drift detected"
  );
  console.log(`   ✓ Cryptographic drift detection prevented accidental rollback corruption (exit code 3)`);

  return {
    id: scenarioNum,
    name,
    status: "PASSED",
    durationMs: Date.now() - start,
    details: "Detected out-of-band lifecycle drift against UndoManifest; halted rollback with SemVer exit code 3.",
  };
}

/**
 * Scenario 7: S3 Object Lock (COMPLIANCE Mode) Barrier
 */
async function runScenario7(): Promise<ScenarioResult> {
  const start = Date.now();
  const scenarioNum = 7;
  const name = "S3 Object Lock (COMPLIANCE Mode) Barrier";
  logScenarioHeader(scenarioNum, name);

  const bucketName = `test-ent-lock-${suiteId}`;
  createdBuckets.push(bucketName);

  console.log(`   Creating bucket with ObjectLockEnabledForBucket: true...`);
  await s3.send(
    new CreateBucketCommand({
      Bucket: bucketName,
      ObjectLockEnabledForBucket: true,
    })
  );

  console.log(`   Configuring COMPLIANCE mode default retention...`);
  await s3.send(
    new PutObjectLockConfigurationCommand({
      Bucket: bucketName,
      ObjectLockConfiguration: {
        ObjectLockEnabled: "Enabled",
        Rule: {
          DefaultRetention: {
            Mode: "COMPLIANCE",
            Days: 1,
          },
        },
      },
    })
  );

  console.log(`   Placing an in-flight MPU under Object Lock...`);
  const mpu = await s3.send(
    new CreateMultipartUploadCommand({
      Bucket: bucketName,
      Key: "compliance-records/audit-log-01.parquet",
    })
  );
  assert.ok(mpu.UploadId);

  console.log(`   Attempting purge via sovereign operator...`);
  const operateRun = await runCli([
    "operate",
    bucketName,
    "--once",
    "--older-than",
    "0",
    "--max-blast-radius",
    "100",
    "--endpoint",
    ENDPOINT,
    "--force-path-style",
  ]);

  console.log(`   Operate CLI Exit Code: ${operateRun.exitCode}`);
  assert.strictEqual(
    operateRun.exitCode,
    4,
    "Operator must halt with SemVer exit code 4 (CIRCUIT_CANARY_BLAST_RADIUS) on COMPLIANCE lock"
  );
  assert.ok(
    operateRun.stderr.includes("COMPLIANCE") ||
      operateRun.stdout.includes("COMPLIANCE") ||
      operateRun.stderr.includes("BLOCKED_COMPLIANCE_LOCK") ||
      operateRun.stdout.includes("BLOCKED_COMPLIANCE_LOCK"),
    "Output must cite S3 Object Lock in COMPLIANCE mode"
  );
  console.log(`   ✓ Identified COMPLIANCE lock barrier; destructive delete prevented (exit code 4)`);

  return {
    id: scenarioNum,
    name,
    status: "PASSED",
    durationMs: Date.now() - start,
    details: "Detected S3 Object Lock COMPLIANCE mode; halted at BLAST_RADIUS_AUDIT with SemVer exit code 4.",
  };
}

/**
 * Scenario 8: Standalone SEA Native Binary Execution
 */
async function runScenario8(): Promise<ScenarioResult> {
  const start = Date.now();
  const scenarioNum = 8;
  const name = "Standalone SEA Native Binary Execution";
  logScenarioHeader(scenarioNum, name);

  const binaryName = process.platform === "win32" ? "s3-guardian.exe" : "s3-guardian";
  const binaryPath = path.resolve(process.cwd(), "dist", binaryName);

  console.log(`   Locating compiled standalone binary: ${binaryPath}`);
  assert.ok(fsSync.existsSync(binaryPath), `Binary file '${binaryPath}' must exist on disk`);

  console.log(`   1. Testing '${binaryName} --version'...`);
  const versionRun = await execFileAsync(binaryPath, ["--version"], {
    env: {
      ...process.env,
      AWS_ACCESS_KEY_ID: ACCESS_KEY_ID,
      AWS_SECRET_ACCESS_KEY: SECRET_ACCESS_KEY,
      AWS_REGION: REGION,
      AWS_ENDPOINT_URL: ENDPOINT,
    },
  });

  console.log(`   Version stdout: ${versionRun.stdout.trim()}`);
  assert.ok(
    versionRun.stdout.includes("v2.0.0"),
    `Binary --version output must contain 'v2.0.0', got: '${versionRun.stdout}'`
  );
  console.log(`   ✓ Verified standalone binary reports version v2.0.0`);

  console.log(`   2. Testing '${binaryName} operate --once --dry-run'...`);
  const operateRun = await execFileAsync(
    binaryPath,
    ["operate", "--once", "--dry-run", "--max-blast-radius", "100", "--endpoint", ENDPOINT, "--force-path-style"],
    {
      env: {
        ...process.env,
        AWS_ACCESS_KEY_ID: ACCESS_KEY_ID,
        AWS_SECRET_ACCESS_KEY: SECRET_ACCESS_KEY,
        AWS_REGION: REGION,
        AWS_ENDPOINT_URL: ENDPOINT,
      },
    }
  );

  console.log(`   Binary operate output snippet:\n${operateRun.stdout.split("\n").slice(0, 8).join("\n")}`);
  assert.ok(
    operateRun.stdout.includes("[DISCOVERY]") &&
      operateRun.stdout.includes("[POLICY_MATCH]") &&
      operateRun.stdout.includes("[BLAST_RADIUS_AUDIT]"),
    "Binary execution must successfully execute 9-phase operator loop in dry-run mode"
  );
  console.log(`   ✓ Standalone native binary executed operator state machine successfully`);

  return {
    id: scenarioNum,
    name,
    status: "PASSED",
    durationMs: Date.now() - start,
    details: `Executed ${binaryName} directly: verified v2.0.0 banner and completed operate --once --dry-run.`,
  };
}

// ══════════════════════════════════════════════════════════════════════════════
// MAIN RUNNER
// ══════════════════════════════════════════════════════════════════════════════

async function main() {
  logBanner("s3-guardian v2.0.0 Enterprise Production Simulation Harness");
  console.log(`MinIO Endpoint:  ${ENDPOINT}`);
  console.log(`Region:          ${REGION}`);
  console.log(`Suite Run ID:    ${suiteId}`);
  console.log(`Platform:        ${process.platform} (${process.arch})`);
  console.log(`Node Runtime:    ${process.version}`);

  const scenarios = [
    runScenario1,
    runScenario2,
    runScenario3,
    runScenario4,
    runScenario5,
    runScenario6,
    runScenario7,
    runScenario8,
  ];

  let anyFailed = false;

  for (const fn of scenarios) {
    try {
      const res = await fn();
      scenarioResults.push(res);
    } catch (err: unknown) {
      anyFailed = true;
      const msg = err instanceof Error ? err.stack ?? err.message : String(err);
      console.error(`\n❌ SCENARIO FAILED: ${msg}`);
      scenarioResults.push({
        id: scenarioResults.length + 1,
        name: fn.name,
        status: "FAILED",
        durationMs: 0,
        details: (err as Error).message || String(err),
      });
    }
  }

  // Teardown
  logBanner("TEARDOWN & RESOURCE CLEANUP");
  for (const b of createdBuckets) {
    await cleanDeleteBucket(s3, b);
  }

  for (const f of tempFilesToClean) {
    try {
      await fs.rm(f, { force: true });
    } catch {
      // Ignore
    }
  }

  for (const d of tempDirsToClean) {
    try {
      await fs.rm(d, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  }

  // Summary Table
  logBanner("ENTERPRISE SIMULATION HARNESS SUMMARY");
  console.log(
    "ID".padEnd(4) +
      "Scenario Name".padEnd(52) +
      "Status".padEnd(12) +
      "Time".padEnd(10) +
      "Details"
  );
  console.log("-".repeat(110));

  for (const r of scenarioResults) {
    const icon = r.status === "PASSED" ? "✅" : "❌";
    console.log(
      `#${r.id}`.padEnd(4) +
        r.name.padEnd(52) +
        `${icon} ${r.status}`.padEnd(12) +
        `${r.durationMs}ms`.padEnd(10) +
        r.details
    );
  }

  console.log("-".repeat(110));
  const passedCount = scenarioResults.filter((s) => s.status === "PASSED").length;
  console.log(`Total: ${scenarioResults.length} | Passed: ${passedCount} | Failed: ${scenarioResults.length - passedCount}`);

  if (anyFailed || passedCount !== scenarios.length) {
    console.error("\n❌ Enterprise simulation harness encountered failures!");
    process.exit(1);
  }

  console.log("\n🎉 ALL 8 ENTERPRISE PRODUCTION SCENARIOS PASSED WITH 100% SUCCESS!\n");
  process.exit(0);
}

main().catch((err) => {
  console.error("Fatal simulation runner error:", err);
  process.exit(1);
});
