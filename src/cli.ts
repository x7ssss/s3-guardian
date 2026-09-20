#!/usr/bin/env node
import { parseArgs } from "node:util";
import { createS3Client } from "./client.js";
import { scanMultipartUploads } from "./scanner/multipart.js";
import { createPlan, writePlanFile, readPlanFile, Plan } from "./planner/plan.js";
import { executeAbortPlan } from "./executor/abort.js";
import { formatBytes, formatMonthlyCost } from "./cost/estimator.js";

const VERSION = "0.1.0";

const HELP_TEXT = `
s3-guardian v${VERSION} — Clean up abandoned S3 multipart uploads

USAGE:
  s3-guardian scan <bucket> [options]
  s3-guardian plan <bucket> --out <file> [options]
  s3-guardian apply --plan <file> --confirm [options]

COMMANDS:
  scan <bucket>           Read-only scan of incomplete multipart uploads
  plan <bucket>           Generate an inspectable, deterministic JSON plan file
  apply                   Execute aborts defined in a plan file (requires --confirm)

OPTIONS:
  --older-than <days>     Age threshold in days (default: 7)
  --out <file>            Output path for plan file (default: plan.json)
  --plan <file>           Plan file to apply
  --confirm               Explicit confirmation required to execute apply deletions
  --endpoint <url>        Custom S3 endpoint URL (MinIO, Cloudflare R2, LocalStack)
  --force-path-style      Use S3 path-style addressing
  --region <region>       AWS Region (default: us-east-1 or AWS_REGION)
  --prefix <prefix>       Filter uploads by object key prefix
  --json                  Output results in JSON format
  -h, --help              Show this help message
  -v, --version           Show version

SAFETY GUARANTEES:
  • 'scan' and 'plan' are 100% read-only.
  • 'apply' strictly requires both a valid plan file and the '--confirm' flag.
  • ListParts fan-out concurrency is capped at 10 to prevent 503 Slow Down rate-limits.
`;

export interface CliOptions {
  stdout?: (msg: string) => void;
  stderr?: (msg: string) => void;
}

function getString(val: unknown): string | undefined {
  return typeof val === "string" ? val : undefined;
}

export async function main(
  argv: string[] = process.argv.slice(2),
  io: CliOptions = {}
): Promise<number> {
  const log = io.stdout ?? console.log;
  const error = io.stderr ?? console.error;

  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      options: {
        bucket: { type: "string" },
        "older-than": { type: "string", default: "7" },
        out: { type: "string" },
        plan: { type: "string" },
        confirm: { type: "boolean", default: false },
        endpoint: { type: "string" },
        "force-path-style": { type: "boolean", default: false },
        region: { type: "string" },
        prefix: { type: "string" },
        json: { type: "boolean", default: false },
        help: { type: "boolean", short: "h", default: false },
        version: { type: "boolean", short: "v", default: false },
      },
      allowPositionals: true,
      strict: false,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    error(`Argument error: ${msg}`);
    log(HELP_TEXT);
    return 1;
  }

  const { values, positionals } = parsed;

  if (values.version === true) {
    log(`s3-guardian v${VERSION}`);
    return 0;
  }

  if (values.help === true || positionals.length === 0) {
    log(HELP_TEXT);
    return 0;
  }

  const command = positionals[0]?.toLowerCase();
  const bucket =
    (typeof positionals[1] === "string" ? positionals[1] : undefined) ||
    getString(values.bucket);

  const olderThanStr = getString(values["older-than"]) ?? "7";
  const olderThanDays = parseInt(olderThanStr, 10);
  if (isNaN(olderThanDays) || olderThanDays < 0) {
    error("Error: --older-than must be a non-negative integer");
    return 1;
  }

  const region = getString(values.region);
  const endpoint = getString(values.endpoint);
  const prefix = getString(values.prefix);
  const forcePathStyle = values["force-path-style"] === true;
  const isJson = values.json === true;

  const clientConfig = {
    region,
    endpoint,
    forcePathStyle,
  };

  switch (command) {
    case "scan": {
      if (!bucket) {
        error("Error: Bucket name is required for 'scan'. Usage: s3-guardian scan <bucket>");
        return 1;
      }

      if (!isJson) {
        log(`🔍 Scanning bucket '${bucket}' for multipart uploads older than ${olderThanDays} days...`);
      }

      const client = createS3Client(clientConfig);
      const scanResult = await scanMultipartUploads(client, bucket, {
        olderThanDays,
        endpoint,
        prefix,
      });

      if (isJson) {
        log(JSON.stringify(scanResult, null, 2));
        return 0;
      }

      if (scanResult.uploads.length === 0) {
        log(`✅ Clean! No multipart uploads older than ${olderThanDays} days found in '${bucket}'.`);
        return 0;
      }

      log(`\nFound ${scanResult.totalZombieUploads} zombie multipart upload(s):\n`);

      // Print table header
      const padKey = 40;
      const padId = 24;
      const padInit = 22;
      const padParts = 8;
      const padBytes = 14;

      log(
        "Key".padEnd(padKey) +
        "Upload ID".padEnd(padId) +
        "Initiated".padEnd(padInit) +
        "Parts".padEnd(padParts) +
        "Stranded Bytes".padEnd(padBytes)
      );
      log("-".repeat(padKey + padId + padInit + padParts + padBytes));

      for (const u of scanResult.uploads) {
        const shortKey = u.key.length > padKey - 3 ? u.key.slice(0, padKey - 3) + "..." : u.key;
        const shortId = u.uploadId.length > padId - 3 ? u.uploadId.slice(0, padId - 3) + "..." : u.uploadId;
        const initStr = u.initiated.replace("T", " ").replace(/\.\d+Z$/, "");

        log(
          shortKey.padEnd(padKey) +
          shortId.padEnd(padId) +
          initStr.padEnd(padInit) +
          String(u.partsCount).padEnd(padParts) +
          formatBytes(u.bytes).padEnd(padBytes)
        );
      }

      log("\nSummary:");
      log(`  Zombie Uploads:           ${scanResult.totalZombieUploads}`);
      log(`  Total Stranded Storage:   ${formatBytes(scanResult.totalStrandedBytes)} (${scanResult.totalStrandedBytes.toLocaleString()} bytes)`);
      log(`  Estimated Monthly Waste:  ${formatMonthlyCost(scanResult.estimatedMonthlyWasteUSD)} (AWS S3 Standard baseline)`);
      log("\nNext steps:");
      log(`  Generate an execution plan to safely clean up:`);
      log(`  $ s3-guardian plan ${bucket} --out plan.json\n`);

      return 0;
    }

    case "plan": {
      if (!bucket) {
        error("Error: Bucket name is required for 'plan'. Usage: s3-guardian plan <bucket> --out <file>");
        return 1;
      }

      const outFile = getString(values.out) || "plan.json";

      log(`📝 Scanning '${bucket}' to generate deletion plan (older than ${olderThanDays} days)...`);
      const client = createS3Client(clientConfig);
      const scanResult = await scanMultipartUploads(client, bucket, {
        olderThanDays,
        endpoint,
        prefix,
      });

      const plan: Plan = createPlan({
        bucket,
        endpoint,
        olderThanDays,
        uploads: scanResult.uploads,
      });

      await writePlanFile(outFile, plan);

      log(`\nPlan generated successfully!`);
      log(`  Bucket:                   ${bucket}`);
      log(`  Zombie Uploads:           ${plan.totalZombieUploads}`);
      log(`  Total Stranded Storage:   ${formatBytes(plan.totalStrandedBytes)}`);
      log(`  Estimated Monthly Waste:  ${formatMonthlyCost(plan.estimatedMonthlyWasteUSD)}`);
      log(`  Plan File:                ${outFile}`);

      if (plan.totalZombieUploads > 0) {
        log("\nNext steps:");
        log(`  Inspect '${outFile}' to verify targeted uploads.`);
        log(`  To safely abort these uploads, run:`);
        log(`  $ s3-guardian apply --plan ${outFile} --confirm\n`);
      } else {
        log(`\nBucket is clean. No uploads scheduled for deletion.`);
      }

      return 0;
    }

    case "apply": {
      const planFile = getString(values.plan);
      if (!planFile) {
        error("Error: --plan <file> is required for 'apply'. Usage: s3-guardian apply --plan <file> --confirm");
        return 1;
      }

      if (values.confirm !== true) {
        error(
          "\n❌ Safety check failed: The '--confirm' flag is strictly required to execute aborts.\n" +
          "No changes were made to your bucket.\n\n" +
          `To proceed, review '${planFile}' and run:\n` +
          `  $ s3-guardian apply --plan ${planFile} --confirm\n`
        );
        return 1;
      }

      log(`🚀 Reading and validating plan file: ${planFile}...`);
      let plan: Plan;
      try {
        plan = await readPlanFile(planFile);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        error(`Failed to load plan: ${msg}`);
        return 1;
      }

      if (plan.uploads.length === 0) {
        log("Plan contains 0 uploads to abort. Nothing to do.");
        return 0;
      }

      log(`Executing abort operations for bucket '${plan.bucket}' (${plan.uploads.length} upload(s))...`);

      const effectiveClientConfig = {
        region,
        endpoint: endpoint ?? plan.endpoint ?? undefined,
        forcePathStyle,
      };

      const client = createS3Client(effectiveClientConfig);
      const result = await executeAbortPlan(client, plan, {
        confirm: true,
        onProgress: (completed, total, item, status) => {
          if (status === "SKIPPED_ALREADY_ABORTED") {
            log(`  [${completed}/${total}] Skipped '${item.key}' (UploadId: ${item.uploadId}) — already aborted or completed`);
          } else if (status === "FAILED") {
            log(`  [${completed}/${total}] Failed '${item.key}' (UploadId: ${item.uploadId})`);
          } else {
            log(`  [${completed}/${total}] Aborted '${item.key}' (UploadId: ${item.uploadId})`);
          }
        },
      });

      log("\nApply execution summary:");
      log(`  Total Targeted:       ${result.total}`);
      log(`  Successfully aborted: ${result.aborted}`);
      if (result.skipped > 0) {
        log(`  Skipped (already aborted): ${result.skipped}`);
      }
      log(`  Failed:               ${result.failed}`);
      log(`  Storage Freed:        ${formatBytes(result.bytesFreed)}`);

      if (result.errors.length > 0) {
        log("\nErrors encountered:");
        for (const e of result.errors) {
          log(`  - Key: ${e.key}, UploadId: ${e.uploadId}: ${e.error}`);
        }
        return 1;
      }

      log("\n✅ Done! Cleanup completed successfully.");
      return 0;
    }

    default: {
      error(`Error: Unknown command '${command}'`);
      log(HELP_TEXT);
      return 1;
    }
  }
}

// Auto-run when executed directly
if (
  process.argv[1] &&
  (process.argv[1].endsWith("cli.js") || process.argv[1].endsWith("cli.ts"))
) {
  main().then((exitCode) => {
    if (exitCode !== 0) {
      process.exit(exitCode);
    }
  }).catch((err) => {
    console.error("Fatal error:", err?.message || err);
    process.exit(1);
  });
}
