#!/usr/bin/env node
import { parseArgs } from "node:util";
import { createS3Client } from "./client.js";
import { scanMultipartUploads } from "./scanner/multipart.js";
import { createPlan, writePlanFile, readPlanFile, Plan } from "./planner/plan.js";
import { executeAbortPlan } from "./executor/abort.js";
import { formatBytes, formatMonthlyCost } from "./cost/estimator.js";
import { auditBucketLifecycle, evaluateUploadCoverage } from "./lifecycle/audit.js";
import { scanFleet, DiscoveryAuthError, FleetScanResult, BucketAuditResult } from "./fleet/scanner.js";
import { evaluatePolicy, EXIT_CODES, PolicyOptions } from "./policy/evaluator.js";
import { S3ClientPool } from "./discovery/client-pool.js";

const VERSION = "0.3.0";

const HELP_TEXT = `
s3-guardian v${VERSION} — Clean up abandoned S3 multipart uploads

USAGE:
  s3-guardian scan <bucket> [options]
  s3-guardian scan --all-buckets [options]
  s3-guardian plan <bucket> --out <file> [options]
  s3-guardian plan --all-buckets --out <file> [options]
  s3-guardian apply --plan <file> --confirm [options]

COMMANDS:
  scan <bucket>           Read-only scan of incomplete multipart uploads
  scan --all-buckets      Read-only fleet scan across all account buckets
  plan <bucket>           Generate an inspectable, deterministic JSON plan file
  plan --all-buckets      Generate a fleet-wide plan (summary JSON)
  apply                   Execute aborts defined in a plan file (requires --confirm)

OPTIONS:
  --older-than <days>          Age threshold in days (default: 7)
  --out <file>                 Output path for plan file (default: plan.json)
  --plan <file>                Plan file to apply
  --confirm                    Explicit confirmation required to execute apply deletions
  --endpoint <url>             Custom S3 endpoint URL (MinIO, Cloudflare R2, LocalStack)
  --force-path-style           Use S3 path-style addressing
  --region <region>            AWS Region (default: us-east-1 or AWS_REGION)
  --prefix <prefix>            Filter uploads by object key prefix
  --all-buckets                Scan all buckets in the account (fleet mode)
  --exclude-bucket <patterns>  Comma-separated bucket name substrings/globs to exclude
  --exclude-region <regions>   Comma-separated AWS regions to exclude
  --max-waste-usd <amount>     Exit code 1 if total monthly waste exceeds this USD amount
  --fail-on-unprotected        Exit code 1 if any bucket has no active MPU lifecycle rule
  --format <table|json|github> Output format (default: table)
  --json                       Shorthand for --format json
  -h, --help                   Show this help message
  -v, --version                Show version

EXIT CODES:
  0   Success, no policy violations
  1   Policy threshold breached (--max-waste-usd or --fail-on-unprotected)
  2   CLI argument / syntax error
  3   Account discovery / authentication failure

SAFETY GUARANTEES:
  • 'scan' and 'plan' are 100% read-only.
  • 'apply' strictly requires both a valid plan file and the '--confirm' flag.
  • Fleet mode: per-bucket failures (403, 404, RequesterPays) are isolated and never abort the full scan.
  • ListParts fan-out concurrency is capped at 10 to prevent 503 Slow Down rate-limits.
  • Fleet bucket concurrency is capped at 5.
`;

export interface CliOptions {
  stdout?: (msg: string) => void;
  stderr?: (msg: string) => void;
}

function getString(val: unknown): string | undefined {
  return typeof val === "string" ? val : undefined;
}

function splitCsv(val: string | undefined): string[] {
  if (!val) return [];
  return val
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

// ─── Formatters ───────────────────────────────────────────────────────────────

function renderFleetTable(
  result: FleetScanResult,
  log: (msg: string) => void
): void {
  const padBucket = 32;
  const padRegion = 16;
  const padStatus = 24;
  const padUploads = 10;
  const padBytes = 14;
  const padWaste = 12;

  log(
    "Bucket".padEnd(padBucket) +
    "Region".padEnd(padRegion) +
    "Status".padEnd(padStatus) +
    "Uploads".padEnd(padUploads) +
    "Stranded".padEnd(padBytes) +
    "Waste/mo".padEnd(padWaste)
  );
  log("-".repeat(padBucket + padRegion + padStatus + padUploads + padBytes + padWaste));

  for (const r of result.bucketResults) {
    const shortBucket =
      r.bucket.length > padBucket - 2
        ? r.bucket.slice(0, padBucket - 3) + "..."
        : r.bucket;
    const region = r.region ?? "—";
    const status = r.status === "AUDITED" ? "✓ AUDITED" : `⚠ ${r.status.replace("SKIPPED_", "")}`;
    const uploads =
      r.status === "AUDITED" ? String(r.totalZombieUploads ?? 0) : "—";
    const bytes =
      r.status === "AUDITED" ? formatBytes(r.totalStrandedBytes ?? 0) : "—";
    const waste =
      r.status === "AUDITED"
        ? formatMonthlyCost(r.estimatedMonthlyWasteUSD ?? 0)
        : "—";

    log(
      shortBucket.padEnd(padBucket) +
      region.padEnd(padRegion) +
      status.padEnd(padStatus) +
      uploads.padEnd(padUploads) +
      bytes.padEnd(padBytes) +
      waste.padEnd(padWaste)
    );
  }
}

function renderFleetGitHub(
  result: FleetScanResult,
  violations: string[],
  log: (msg: string) => void
): void {
  log(`## 🛡️ s3-guardian Fleet Scan — v${VERSION}`);
  log(``);
  log(`| Metric | Value |`);
  log(`|--------|-------|`);
  log(`| Buckets Discovered | ${result.bucketsDiscovered} |`);
  log(`| Buckets Audited | ${result.bucketsAudited} |`);
  log(`| Buckets Skipped | ${result.bucketsSkipped} |`);
  log(`| Total Zombie Uploads | ${result.totalZombieUploads} |`);
  log(`| Total Stranded Storage | ${formatBytes(result.totalStrandedBytes)} |`);
  log(`| Estimated Monthly Waste | ${formatMonthlyCost(result.totalEstimatedMonthlyWasteUSD)} |`);
  log(``);

  if (violations.length > 0) {
    log(`### ❌ Policy Violations`);
    log(``);
    for (const v of violations) {
      log(`- ${v}`);
    }
    log(``);
  }

  // Per-bucket detail
  const audited = result.bucketResults.filter((r) => r.status === "AUDITED");
  if (audited.length > 0) {
    log(`### Bucket Details`);
    log(``);
    log(`| Bucket | Region | Uploads | Stranded | Waste/mo | Lifecycle |`);
    log(`|--------|--------|---------|----------|----------|-----------|`);
    for (const r of audited) {
      const lifecycle = r.lifecycleAudit?.hasCoveringRule
        ? "✅ Covered"
        : r.lifecycleAudit?.ghostRulesDetected?.length
        ? "⚠️ Ghost Rule"
        : "❌ Unprotected";
      log(
        `| ${r.bucket} | ${r.region ?? "—"} | ${r.totalZombieUploads ?? 0} | ${formatBytes(r.totalStrandedBytes ?? 0)} | ${formatMonthlyCost(r.estimatedMonthlyWasteUSD ?? 0)} | ${lifecycle} |`
      );
    }
    log(``);
  }

  const skipped = result.bucketResults.filter((r) => r.status !== "AUDITED");
  if (skipped.length > 0) {
    log(`### Skipped Buckets`);
    log(``);
    log(`| Bucket | Reason |`);
    log(`|--------|--------|`);
    for (const r of skipped) {
      log(`| ${r.bucket} | ${r.status} |`);
    }
    log(``);
  }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

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
        "all-buckets": { type: "boolean", default: false },
        "exclude-bucket": { type: "string" },
        "exclude-region": { type: "string" },
        "max-waste-usd": { type: "string" },
        "fail-on-unprotected": { type: "boolean", default: false },
        format: { type: "string", default: "table" },
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
    return EXIT_CODES.ARG_ERROR;
  }

  const { values, positionals } = parsed;

  if (values.version === true) {
    log(`s3-guardian v${VERSION}`);
    return EXIT_CODES.SUCCESS;
  }

  if (values.help === true || positionals.length === 0) {
    log(HELP_TEXT);
    return EXIT_CODES.SUCCESS;
  }

  const command = positionals[0]?.toLowerCase();
  const bucketArg =
    (typeof positionals[1] === "string" ? positionals[1] : undefined) ||
    getString(values.bucket);

  const olderThanStr = getString(values["older-than"]) ?? "7";
  const olderThanDays = parseInt(olderThanStr, 10);
  if (isNaN(olderThanDays) || olderThanDays < 0) {
    error("Error: --older-than must be a non-negative integer");
    return EXIT_CODES.ARG_ERROR;
  }

  const region = getString(values.region);
  const endpoint = getString(values.endpoint);
  const prefix = getString(values.prefix);
  const forcePathStyle = values["force-path-style"] === true;
  const allBuckets = values["all-buckets"] === true;
  const excludeBuckets = splitCsv(getString(values["exclude-bucket"]));
  const excludeRegions = splitCsv(getString(values["exclude-region"]));
  const failOnUnprotected = values["fail-on-unprotected"] === true;
  const formatStr = getString(values.format) ?? "table";
  const isJson = values.json === true || formatStr === "json";
  const isGitHub = formatStr === "github";

  // Parse --max-waste-usd
  let maxWasteUSD: number | undefined;
  const maxWasteStr = getString(values["max-waste-usd"]);
  if (maxWasteStr !== undefined) {
    maxWasteUSD = parseFloat(maxWasteStr);
    if (isNaN(maxWasteUSD) || maxWasteUSD < 0) {
      error("Error: --max-waste-usd must be a non-negative number");
      return EXIT_CODES.ARG_ERROR;
    }
  }

  const policyOptions: PolicyOptions = { maxWasteUSD, failOnUnprotected };

  const clientConfig = { region, endpoint, forcePathStyle };

  // ════════════════════════════════════════════════════════════════════════════
  switch (command) {
    // ── SCAN ─────────────────────────────────────────────────────────────────
    case "scan": {
      // ── Fleet mode: --all-buckets ──────────────────────────────────────────
      if (allBuckets) {
        if (!isJson && !isGitHub) {
          log(`🔍 Fleet scan: discovering all account buckets (older than ${olderThanDays} days)...`);
        }

        const pool = new S3ClientPool();
        let fleetResult: FleetScanResult;

        try {
          const discoveryClient = createS3Client(clientConfig);
          fleetResult = await scanFleet({
            olderThanDays,
            prefix,
            excludeBuckets,
            excludeRegions,
            endpoint,
            discoveryClient,
            clientPool: pool,
          });
        } catch (err) {
          if (err instanceof DiscoveryAuthError) {
            error(`\n❌ Discovery failed: ${err.message}`);
            return EXIT_CODES.DISCOVERY_AUTH_ERROR;
          }
          throw err;
        } finally {
          await pool.destroy();
        }

        if (isJson) {
          log(JSON.stringify(fleetResult, null, 2));
          const policyResult = evaluatePolicy(fleetResult, policyOptions);
          return policyResult.exitCode;
        }

        const policyResult = evaluatePolicy(fleetResult, policyOptions);

        if (isGitHub) {
          renderFleetGitHub(
            fleetResult,
            policyResult.violations.map((v) => v.message),
            log
          );
          return policyResult.exitCode;
        }

        // Terminal table
        log(`\nFleet Scan Summary:`);
        log(`  Buckets Discovered:       ${fleetResult.bucketsDiscovered}`);
        log(`  Buckets Audited:          ${fleetResult.bucketsAudited}`);
        log(`  Buckets Skipped:          ${fleetResult.bucketsSkipped}`);
        log(`  Total Zombie Uploads:     ${fleetResult.totalZombieUploads}`);
        log(`  Total Stranded Storage:   ${formatBytes(fleetResult.totalStrandedBytes)}`);
        log(`  Estimated Monthly Waste:  ${formatMonthlyCost(fleetResult.totalEstimatedMonthlyWasteUSD)}`);
        log(``);
        renderFleetTable(fleetResult, log);

        if (policyResult.violations.length > 0) {
          log(`\n❌ Policy violations detected:`);
          for (const v of policyResult.violations) {
            log(`  [${v.rule}] ${v.message}`);
          }
        }

        return policyResult.exitCode;
      }

      // ── Single-bucket scan ─────────────────────────────────────────────────
      if (!bucketArg) {
        error("Error: Bucket name is required for 'scan'. Usage: s3-guardian scan <bucket>");
        return EXIT_CODES.ARG_ERROR;
      }

      if (!isJson) {
        log(`🔍 Scanning bucket '${bucketArg}' for multipart uploads older than ${olderThanDays} days...`);
      }

      const client = createS3Client(clientConfig);

      const [scanResult, lifecycleAudit] = await Promise.all([
        scanMultipartUploads(client, bucketArg, { olderThanDays, endpoint, prefix }),
        auditBucketLifecycle(client, bucketArg, endpoint),
      ]);

      const now = new Date();
      const enrichedUploads = scanResult.uploads.map((u) => {
        const coverage = evaluateUploadCoverage(
          u.key,
          new Date(u.initiated),
          lifecycleAudit.mpuRules ?? [],
          now
        );
        return { ...u, lifecycleStatus: coverage.status };
      });

      if (isJson) {
        log(JSON.stringify({ ...scanResult, uploads: enrichedUploads, lifecycleAudit }, null, 2));
        return EXIT_CODES.SUCCESS;
      }

      // Lifecycle banner
      if (lifecycleAudit.providerNotes) {
        log(`\nℹ️  ${lifecycleAudit.providerNotes}`);
      } else if (lifecycleAudit.ghostRulesDetected.length > 0) {
        for (const ghost of lifecycleAudit.ghostRulesDetected) {
          log(`\n[!] Ghost rule detected: ${ghost}`);
        }
        if (!lifecycleAudit.hasCoveringRule) {
          log(`    No valid (non-ghost) lifecycle rule covers multipart uploads.`);
        }
      } else if (!lifecycleAudit.hasCoveringRule) {
        log(`\n[!] Bucket has NO lifecycle rule covering multipart uploads.`);
        log(`    Zombie uploads will accumulate indefinitely without manual cleanup.`);
      }

      if (enrichedUploads.length === 0) {
        log(`\n✅ Clean! No multipart uploads older than ${olderThanDays} days found in '${bucketArg}'.`);
        return EXIT_CODES.SUCCESS;
      }

      log(`\nFound ${scanResult.totalZombieUploads} zombie multipart upload(s):\n`);

      const padKey = 36;
      const padId = 22;
      const padInit = 22;
      const padParts = 8;
      const padBytes = 14;
      const padClass = 14;
      const padCoverage = 16;

      log(
        "Key".padEnd(padKey) +
        "Upload ID".padEnd(padId) +
        "Initiated".padEnd(padInit) +
        "Parts".padEnd(padParts) +
        "Stranded Bytes".padEnd(padBytes) +
        "Storage Class".padEnd(padClass) +
        "Coverage".padEnd(padCoverage)
      );
      log("-".repeat(padKey + padId + padInit + padParts + padBytes + padClass + padCoverage));

      for (const u of enrichedUploads) {
        const shortKey = u.key.length > padKey - 3 ? u.key.slice(0, padKey - 3) + "..." : u.key;
        const shortId = u.uploadId.length > padId - 3 ? u.uploadId.slice(0, padId - 3) + "..." : u.uploadId;
        const initStr = u.initiated.replace("T", " ").replace(/\.\d+Z$/, "");
        const storageClassDisplay =
          u.storageClass !== "STANDARD" ? `⚠ ${u.storageClass}` : u.storageClass;

        log(
          shortKey.padEnd(padKey) +
          shortId.padEnd(padId) +
          initStr.padEnd(padInit) +
          String(u.partsCount).padEnd(padParts) +
          formatBytes(u.bytes).padEnd(padBytes) +
          storageClassDisplay.padEnd(padClass) +
          u.lifecycleStatus.padEnd(padCoverage)
        );
      }

      log("\nSummary:");
      log(`  Zombie Uploads:           ${scanResult.totalZombieUploads}`);
      log(`  Total Stranded Storage:   ${formatBytes(scanResult.totalStrandedBytes)} (${scanResult.totalStrandedBytes.toLocaleString()} bytes)`);
      log(`  Estimated Monthly Waste:  ${formatMonthlyCost(scanResult.estimatedMonthlyWasteUSD)} (AWS S3 Standard baseline)`);

      if (scanResult.totalZombieUploads > 10_000) {
        log(`\n⚠️  High Volume Warning: Executing apply on >10k uploads will generate substantial CloudTrail Data Events.`);
      }

      log("\nNext steps:");
      log(`  Generate an execution plan to safely clean up:`);
      log(`  $ s3-guardian plan ${bucketArg} --out plan.json\n`);

      return EXIT_CODES.SUCCESS;
    }

    // ── PLAN ─────────────────────────────────────────────────────────────────
    case "plan": {
      if (allBuckets) {
        const outFile = getString(values.out) || "fleet-plan.json";
        log(`📝 Fleet plan: scanning all buckets (older than ${olderThanDays} days)...`);

        const pool = new S3ClientPool();
        let fleetResult: FleetScanResult;

        try {
          const discoveryClient = createS3Client(clientConfig);
          fleetResult = await scanFleet({
            olderThanDays,
            prefix,
            excludeBuckets,
            excludeRegions,
            endpoint,
            discoveryClient,
            clientPool: pool,
          });
        } catch (err) {
          if (err instanceof DiscoveryAuthError) {
            error(`\n❌ Discovery failed: ${err.message}`);
            return EXIT_CODES.DISCOVERY_AUTH_ERROR;
          }
          throw err;
        } finally {
          await pool.destroy();
        }

        const policyResult = evaluatePolicy(fleetResult, policyOptions);

        // Write fleet summary plan to disk
        const { writeFile, mkdir } = await import("node:fs/promises");
        const { dirname, resolve: pathResolve } = await import("node:path");
        const resolvedOut = pathResolve(outFile);
        await mkdir(dirname(resolvedOut), { recursive: true });
        await writeFile(resolvedOut, JSON.stringify(fleetResult, null, 2), "utf8");

        log(`\nFleet plan generated: ${outFile}`);
        log(`  Buckets Audited:          ${fleetResult.bucketsAudited}`);
        log(`  Total Zombie Uploads:     ${fleetResult.totalZombieUploads}`);
        log(`  Total Stranded Storage:   ${formatBytes(fleetResult.totalStrandedBytes)}`);
        log(`  Estimated Monthly Waste:  ${formatMonthlyCost(fleetResult.totalEstimatedMonthlyWasteUSD)}`);

        if (policyResult.violations.length > 0) {
          log(`\n❌ Policy violations:`);
          for (const v of policyResult.violations) {
            log(`  [${v.rule}] ${v.message}`);
          }
        }

        return policyResult.exitCode;
      }

      // Single-bucket plan
      if (!bucketArg) {
        error("Error: Bucket name is required for 'plan'. Usage: s3-guardian plan <bucket> --out <file>");
        return EXIT_CODES.ARG_ERROR;
      }

      const outFile = getString(values.out) || "plan.json";
      log(`📝 Scanning '${bucketArg}' to generate deletion plan (older than ${olderThanDays} days)...`);
      const client = createS3Client(clientConfig);

      const [scanResult, lifecycleAudit] = await Promise.all([
        scanMultipartUploads(client, bucketArg, { olderThanDays, endpoint, prefix }),
        auditBucketLifecycle(client, bucketArg, endpoint),
      ]);

      const now = new Date();
      const enrichedUploads = scanResult.uploads.map((u) => {
        const coverage = evaluateUploadCoverage(
          u.key,
          new Date(u.initiated),
          lifecycleAudit.mpuRules ?? [],
          now
        );
        return { ...u, lifecycleStatus: coverage.status };
      });

      const plan: Plan = createPlan({
        bucket: bucketArg,
        endpoint,
        olderThanDays,
        uploads: enrichedUploads,
        lifecycleAudit,
      });

      await writePlanFile(outFile, plan);

      log(`\nPlan generated successfully!`);
      log(`  Bucket:                   ${bucketArg}`);
      log(`  Zombie Uploads:           ${plan.totalZombieUploads}`);
      log(`  Total Stranded Storage:   ${formatBytes(plan.totalStrandedBytes)}`);
      log(`  Estimated Monthly Waste:  ${formatMonthlyCost(plan.estimatedMonthlyWasteUSD)}`);
      log(`  Plan File:                ${outFile}`);

      if (lifecycleAudit.providerNotes) {
        log(`\nℹ️  Lifecycle Note: ${lifecycleAudit.providerNotes}`);
      } else if (!lifecycleAudit.hasCoveringRule) {
        log(`\n[!] Lifecycle Audit: Bucket has NO lifecycle rule covering multipart uploads.`);
      }
      for (const ghost of lifecycleAudit.ghostRulesDetected) {
        log(`[!] Ghost Rule: ${ghost}`);
      }

      if (plan.highVolumeWarning) {
        log(`\n⚠️  ${plan.highVolumeWarning}`);
      }

      if (plan.totalZombieUploads > 0) {
        log("\nNext steps:");
        log(`  Inspect '${outFile}' to verify targeted uploads.`);
        log(`  To safely abort these uploads, run:`);
        log(`  $ s3-guardian apply --plan ${outFile} --confirm\n`);
      } else {
        log(`\nBucket is clean. No uploads scheduled for deletion.`);
      }

      return EXIT_CODES.SUCCESS;
    }

    // ── APPLY ─────────────────────────────────────────────────────────────────
    case "apply": {
      const planFile = getString(values.plan);
      if (!planFile) {
        error("Error: --plan <file> is required for 'apply'. Usage: s3-guardian apply --plan <file> --confirm");
        return EXIT_CODES.ARG_ERROR;
      }

      if (values.confirm !== true) {
        error(
          "\n❌ Safety check failed: The '--confirm' flag is strictly required to execute aborts.\n" +
          "No changes were made to your bucket.\n\n" +
          `To proceed, review '${planFile}' and run:\n` +
          `  $ s3-guardian apply --plan ${planFile} --confirm\n`
        );
        return EXIT_CODES.ARG_ERROR;
      }

      log(`🚀 Reading and validating plan file: ${planFile}...`);
      let plan: Plan;
      try {
        plan = await readPlanFile(planFile);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        error(`Failed to load plan: ${msg}`);
        return EXIT_CODES.ARG_ERROR;
      }

      if (plan.uploads.length === 0) {
        log("Plan contains 0 uploads to abort. Nothing to do.");
        return EXIT_CODES.SUCCESS;
      }

      if (plan.highVolumeWarning) {
        log(`\n⚠️  ${plan.highVolumeWarning}`);
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
        return EXIT_CODES.POLICY_VIOLATION;
      }

      log("\n✅ Done! Cleanup completed successfully.");
      return EXIT_CODES.SUCCESS;
    }

    default: {
      error(`Error: Unknown command '${command}'`);
      log(HELP_TEXT);
      return EXIT_CODES.ARG_ERROR;
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
    process.exit(EXIT_CODES.ARG_ERROR);
  });
}
