import { spawn } from "node:child_process";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as assert from "node:assert";
import {
  S3Client,
  CreateBucketCommand,
  PutBucketVersioningCommand,
  CreateMultipartUploadCommand,
  UploadPartCommand,
  PutObjectCommand,
  DeleteObjectCommand,
  GetObjectCommand,
  PutBucketTaggingCommand,
  DeleteBucketTaggingCommand,
  ListObjectVersionsCommand,
  DeleteObjectsCommand,
  DeleteBucketCommand,
  ListMultipartUploadsCommand,
  AbortMultipartUploadCommand,
} from "@aws-sdk/client-s3";

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

const timestamp = Date.now();
const bucketName = `s3-guardian-live-test-${timestamp}`;
const planFilePath = path.resolve(`live-plan-${timestamp}.json`);

function logHeader(title: string) {
  console.log(`\n================================================================================`);
  console.log(`🔷 ${title}`);
  console.log(`================================================================================`);
}

function logStep(step: string, desc: string) {
  console.log(`\n▶ [${step}] ${desc}`);
}

function runCli(args: string[]): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, ["./dist/cli.js", ...args], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        AWS_ACCESS_KEY_ID: ACCESS_KEY_ID,
        AWS_SECRET_ACCESS_KEY: SECRET_ACCESS_KEY,
        AWS_REGION: REGION,
        AWS_ENDPOINT_URL: ENDPOINT,
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
    const listVersions = await client.send(
      new ListObjectVersionsCommand({ Bucket: bucket })
    );

    const objectsToDelete = [
      ...(listVersions.Versions ?? []).map((v) => ({
        Key: v.Key!,
        VersionId: v.VersionId,
      })),
      ...(listVersions.DeleteMarkers ?? []).map((d) => ({
        Key: d.Key!,
        VersionId: d.VersionId,
      })),
    ];

    if (objectsToDelete.length > 0) {
      await client.send(
        new DeleteObjectsCommand({
          Bucket: bucket,
          Delete: { Objects: objectsToDelete, Quiet: true },
        })
      );
    }

    // Abort any remaining MPUs if present
    try {
      const listMpus = await client.send(
        new ListMultipartUploadsCommand({ Bucket: bucket })
      );
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
      // ignore
    }

    await client.send(new DeleteBucketCommand({ Bucket: bucket }));
    console.log(`   ✓ Bucket '${bucket}' cleanly deleted.`);
  } catch (err: unknown) {
    console.warn(`   ⚠️  Teardown cleanup notice: ${(err as Error).message}`);
  }
}

async function main() {
  console.log(`🚀 Starting s3-guardian Live End-to-End MinIO Integration Test Suite`);
  console.log(`   Target Endpoint:  ${ENDPOINT}`);
  console.log(`   Target Bucket:    ${bucketName}`);
  console.log(`   Plan File:        ${planFilePath}`);

  try {
    // ── 1. Setup ─────────────────────────────────────────────────────────────
    logHeader("1. SETUP: Creating Test Bucket & Enabling Versioning");
    logStep("1.1", `Creating S3 bucket '${bucketName}'...`);
    await s3.send(new CreateBucketCommand({ Bucket: bucketName }));
    console.log(`   ✓ Bucket created.`);

    logStep("1.2", `Enabling versioning on bucket '${bucketName}'...`);
    await s3.send(
      new PutBucketVersioningCommand({
        Bucket: bucketName,
        VersioningConfiguration: { Status: "Enabled" },
      })
    );
    console.log(`   ✓ Versioning status: Enabled.`);

    // ── 2. Populate Test Data ────────────────────────────────────────────────
    logHeader("2. POPULATING TEST DATA");

    // Scenario A: Abandoned MPU
    logStep("2.1", "Scenario A: Initiating abandoned multipart upload ('uploads/stalled.bin')...");
    const mpuInit = await s3.send(
      new CreateMultipartUploadCommand({
        Bucket: bucketName,
        Key: "uploads/stalled.bin",
      })
    );
    const uploadId = mpuInit.UploadId!;
    console.log(`   ✓ Initiated uploadId: ${uploadId}`);

    const fiveMb = Buffer.alloc(5 * 1024 * 1024, "A");
    await s3.send(
      new UploadPartCommand({
        Bucket: bucketName,
        Key: "uploads/stalled.bin",
        UploadId: uploadId,
        PartNumber: 1,
        Body: fiveMb,
      })
    );
    console.log(`   ✓ Uploaded Part 1 (5MB buffer). Upload left incomplete.`);

    // Scenario B: Versioning Bleed & EODM
    logStep("2.2", "Scenario B: Creating 3 versions and a delete marker ('data/record.json')...");
    const oneMb = Buffer.alloc(1024 * 1024, "1");
    await s3.send(new PutObjectCommand({ Bucket: bucketName, Key: "data/record.json", Body: oneMb }));
    await s3.send(new PutObjectCommand({ Bucket: bucketName, Key: "data/record.json", Body: oneMb }));
    await s3.send(new PutObjectCommand({ Bucket: bucketName, Key: "data/record.json", Body: oneMb }));
    await s3.send(new DeleteObjectCommand({ Bucket: bucketName, Key: "data/record.json" }));
    console.log(`   ✓ Created 3 noncurrent versions + 1 Expired Object Delete Marker.`);

    // Scenario C: Safe Inactive Object
    logStep("2.3", "Scenario C: Putting safe active object ('data/active.txt', 500KB)...");
    const halfMb = Buffer.alloc(500 * 1024, "X");
    await s3.send(new PutObjectCommand({ Bucket: bucketName, Key: "data/active.txt", Body: halfMb }));
    console.log(`   ✓ Active object created (must remain untouched).`);

    // ── 3. Test Pipeline ─────────────────────────────────────────────────────
    logHeader("3. TEST PIPELINE EXECUTION");

    // Step 1: Run scan with --include-versions
    logStep("Step 1", "Running 'scan' with --include-versions and --json...");
    const scanResult = await runCli([
      "scan",
      bucketName,
      "--include-versions",
      "--older-than",
      "0",
      "--endpoint",
      ENDPOINT,
      "--force-path-style",
      "--region",
      REGION,
      "--json",
    ]);

    assert.strictEqual(scanResult.exitCode, 0, `scan failed with exit code ${scanResult.exitCode}: ${scanResult.stderr}`);
    const scanJson = JSON.parse(scanResult.stdout);
    const noncurrentCount =
      scanJson.versioning?.noncurrentVersionsCount ??
      scanJson.versioning?.noncurrentVersions?.length;
    const expiredCount =
      scanJson.versioning?.expiredDeleteMarkersCount ??
      scanJson.versioning?.expiredDeleteMarkers?.length;

    console.log(`   ✓ Scan output parsed successfully:`);
    console.log(`     - Zombie Uploads:          ${scanJson.totalZombieUploads}`);
    console.log(`     - Noncurrent Versions:     ${noncurrentCount}`);
    console.log(`     - Expired Delete Markers:  ${expiredCount}`);

    assert.strictEqual(scanJson.totalZombieUploads, 1, "Expected exactly 1 zombie multipart upload");
    assert.strictEqual(noncurrentCount, 3, "Expected 3 noncurrent versions");
    assert.strictEqual(expiredCount, 1, "Expected 1 expired delete marker");

    // Step 2: Run plan with --include-versions
    logStep("Step 2", "Running 'plan' with --include-versions --out live-plan.json...");
    const planResult = await runCli([
      "plan",
      bucketName,
      "--include-versions",
      "--older-than",
      "0",
      "--out",
      planFilePath,
      "--endpoint",
      ENDPOINT,
      "--force-path-style",
      "--region",
      REGION,
    ]);

    assert.strictEqual(planResult.exitCode, 0, `plan failed: ${planResult.stderr}`);
    console.log(planResult.stdout.trim());

    const planContent = await fs.readFile(planFilePath, "utf8");
    const planData = JSON.parse(planContent);

    assert.strictEqual(planData.schemaVersion, "1.3", "Plan schemaVersion must be 1.3");
    assert.ok(planData.planHash && planData.planHash.length === 64, "Plan must contain valid 64-char SHA-256 planHash");
    assert.strictEqual(planData.uploads.length, 1, "Plan must contain 1 MPU upload");
    assert.strictEqual(planData.versionDeletions.length, 4, "Plan must contain 4 version deletion targets (3 versions + 1 EDM)");
    console.log(`   ✓ Plan verified: Schema ${planData.schemaVersion}, planHash: ${planData.planHash}`);

    // Step 3 (Tamper Guard): Tamper with 1 byte in live-plan.json and run apply
    logStep("Step 3", "Tamper Guard: Modifying 1 target key in plan file and executing apply...");
    const tamperedData = JSON.parse(planContent);
    tamperedData.uploads[0].key = "uploads/tampered-hacked-target.bin";
    await fs.writeFile(planFilePath, JSON.stringify(tamperedData, null, 2), "utf8");

    const tamperApply = await runCli([
      "apply",
      "--plan",
      planFilePath,
      "--confirm",
      "--allow-active-churn",
      "--endpoint",
      ENDPOINT,
      "--force-path-style",
      "--region",
      REGION,
    ]);

    console.log(`   Tamper Run Exit Code: ${tamperApply.exitCode}`);
    console.log(`   Captured Stderr:\n${tamperApply.stderr.trim()}`);
    assert.strictEqual(tamperApply.exitCode, 1, "Tampered plan must be rejected with exit code 1");
    assert.ok(
      tamperApply.stderr.includes("Plan Integrity Violation") ||
        tamperApply.stderr.includes("Plan integrity verification failed"),
      "CLI must report cryptographic integrity violation"
    );
    console.log(`   ✓ Tamper guard successfully detected modification and aborted deletion!`);

    // Step 4 (Protected Tag Guard): Put tag s3-guardian:ignore=true on bucket
    logStep("Step 4", "Protected Tag Guard: Tagging bucket with 's3-guardian:ignore=true'...");
    // Restore clean plan
    await fs.writeFile(planFilePath, planContent, "utf8");

    await s3.send(
      new PutBucketTaggingCommand({
        Bucket: bucketName,
        Tagging: {
          TagSet: [{ Key: "s3-guardian:ignore", Value: "true" }],
        },
      })
    );
    console.log(`   ✓ Tag 's3-guardian:ignore=true' applied to bucket.`);

    const tagApply = await runCli([
      "apply",
      "--plan",
      planFilePath,
      "--confirm",
      "--allow-active-churn",
      "--endpoint",
      ENDPOINT,
      "--force-path-style",
      "--region",
      REGION,
    ]);

    console.log(`   Tag Run Exit Code: ${tagApply.exitCode}`);
    console.log(`   Captured Stderr:\n${tagApply.stderr.trim()}`);
    assert.strictEqual(tagApply.exitCode, 1, "Protected tag must cause apply to abort with exit code 1");
    assert.ok(
      tagApply.stderr.includes("PROTECTED_TAG_DETECTED") ||
        tagApply.stderr.includes("s3-guardian:ignore"),
      "CLI must report protected tag violation"
    );
    console.log(`   ✓ Protected tag guard successfully prevented destructive mutations!`);

    // Remove protected tag
    await s3.send(new DeleteBucketTaggingCommand({ Bucket: bucketName }));
    console.log(`   ✓ Removed 's3-guardian:ignore' tag.`);

    // Step 5 (Clean Mutation): Regenerate clean live-plan.json and run apply --confirm
    logStep("Step 5", "Clean Mutation: Regenerating clean plan and executing apply --confirm...");
    const regenPlan = await runCli([
      "plan",
      bucketName,
      "--include-versions",
      "--older-than",
      "0",
      "--out",
      planFilePath,
      "--endpoint",
      ENDPOINT,
      "--force-path-style",
      "--region",
      REGION,
    ]);
    assert.strictEqual(regenPlan.exitCode, 0, `Failed to regenerate plan: ${regenPlan.stderr}`);

    const cleanApply = await runCli([
      "apply",
      "--plan",
      planFilePath,
      "--confirm",
      "--allow-active-churn",
      "--endpoint",
      ENDPOINT,
      "--force-path-style",
      "--region",
      REGION,
    ]);

    console.log(`   Clean Apply Exit Code: ${cleanApply.exitCode}`);
    console.log(cleanApply.stdout.trim());
    assert.strictEqual(cleanApply.exitCode, 0, `Clean apply failed with exit code ${cleanApply.exitCode}: ${cleanApply.stderr}`);
    assert.ok(
      cleanApply.stdout.includes("Successfully aborted: 1"),
      "Must confirm 1 MPU upload successfully aborted"
    );
    assert.ok(
      cleanApply.stdout.includes("Successfully deleted: 4"),
      "Must confirm 4 version items successfully deleted"
    );
    assert.ok(
      cleanApply.stdout.includes("Cleanup completed successfully"),
      "Must confirm cleanup completed successfully"
    );
    console.log(`   ✓ Clean mutation executed and confirmed!`);

    // Step 6 (Zero-Waste Verification): Run scan again
    logStep("Step 6", "Zero-Waste Verification: Running post-apply scan...");
    const verifyScan = await runCli([
      "scan",
      bucketName,
      "--include-versions",
      "--older-than",
      "0",
      "--endpoint",
      ENDPOINT,
      "--force-path-style",
      "--region",
      REGION,
      "--json",
    ]);

    assert.strictEqual(verifyScan.exitCode, 0, `verify scan failed: ${verifyScan.stderr}`);
    const verifyJson = JSON.parse(verifyScan.stdout);
    const finalNoncurrent =
      verifyJson.versioning?.noncurrentVersionsCount ??
      verifyJson.versioning?.noncurrentVersions?.length ??
      0;
    const finalExpired =
      verifyJson.versioning?.expiredDeleteMarkersCount ??
      verifyJson.versioning?.expiredDeleteMarkers?.length ??
      0;

    assert.strictEqual(verifyJson.totalZombieUploads, 0, "Zombie uploads must be 0 after apply");
    assert.strictEqual(finalNoncurrent, 0, "Noncurrent versions must be 0 after apply");
    assert.strictEqual(finalExpired, 0, "Expired delete markers must be 0 after apply");
    console.log(`   ✓ Zero-waste confirmed: 0 MPUs, 0 noncurrent versions, 0 delete markers.`);

    // Verify data/active.txt is intact
    logStep("Step 6.1", "Verifying 'data/active.txt' object is completely untouched...");
    const activeObj = await s3.send(
      new GetObjectCommand({
        Bucket: bucketName,
        Key: "data/active.txt",
      })
    );
    assert.strictEqual(
      activeObj.ContentLength,
      500 * 1024,
      "data/active.txt ContentLength must be intact at exactly 500KB"
    );
    console.log(`   ✓ 'data/active.txt' verified: untouched with exact byte length (${activeObj.ContentLength} bytes).`);

    logHeader("🎉 ALL LIVE INTEGRATION SCENARIOS PASSED WITH 100% SUCCESS!");
  } finally {
    // ── 4. Teardown ──────────────────────────────────────────────────────────
    logHeader("4. TEARDOWN: Cleaning up test artifacts and bucket");
    await cleanDeleteBucket(s3, bucketName);
    await fs.unlink(planFilePath).catch(() => {});
    console.log(`   ✓ Plan file cleaned up.`);
  }
}

main().catch((err) => {
  console.error("\n❌ LIVE INTEGRATION TEST SUITE FAILED:");
  console.error(err);
  process.exit(1);
});
