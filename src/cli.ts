#!/usr/bin/env node
import { parseArgs } from "node:util";
import { createS3Client } from "./client.js";
import { scanMultipartUploads } from "./scanner/multipart.js";
import {
  createPlan,
  writePlanFile,
  readPlanFile,
  verifyPlanIntegrity,
  Plan,
  VersionDeletionEntry,
} from "./planner/plan.js";
import { assessBucketBlastRadius, BlastRadiusTargetItem } from "./safety/blast-radius.js";
import { executeAbortPlan } from "./executor/abort.js";
import { formatBytes, formatMonthlyCost } from "./cost/estimator.js";
import { auditBucketLifecycle, evaluateUploadCoverage } from "./lifecycle/audit.js";
import { scanFleet, DiscoveryAuthError, FleetScanResult, BucketAuditResult } from "./fleet/scanner.js";
import { evaluatePolicy, EXIT_CODES, PolicyOptions } from "./policy/evaluator.js";
import { S3ClientPool } from "./discovery/client-pool.js";
import { formatOrSaveIac, IacFormat } from "./remediation/iac.js";
import { applyLifecycleRuleDirectly } from "./remediation/api.js";
import { dispatchNotification, WebhookType } from "./notifications/dispatcher.js";
import { scanObjectVersions, VersionScanResult } from "./versioning/scanner.js";
import { executeVersionDeletion } from "./versioning/executor.js";
import {
  resolveTargetAccounts,
  OrganizationsDiscoveryError,
  OrganizationAccount,
} from "./discovery/organizations.js";
import {
  runMultiAccountSweep,
  MultiAccountSweepResult,
  AccountSweepResult,
} from "./multi-account/runner.js";
import { readStorageLensMetrics } from "./lens/reader.js";
import { StorageLensBucketMetrics } from "./lens/scorer.js";
import {
  auditBucketTransitions,
  BucketTransitionAuditResult,
  DangerousTransitionRule,
} from "./transitions/index.js";
import {
  startDaemon,
  parseHumanInterval,
  DaemonLockError,
} from "./daemon/index.js";
import {
  detectLifecycleDrift,
  LifecycleDriftResult,
} from "./drift/index.js";
import {
  generateTerraformTransitionRemediation,
  generateCloudFormationTransitionRemediation,
} from "./remediation/iac.js";
import { ListBucketsCommand, GetBucketLocationCommand } from "@aws-sdk/client-s3";
import { normalizeBucketRegion, US_EAST_1 } from "./discovery/regions.js";
import { matchesExcludePattern } from "./fleet/scanner.js";
import * as fsPromises from "node:fs/promises";
import * as fsSync from "node:fs";

const VERSION = "1.3.0";

const HELP_TEXT = `
s3-guardian v${VERSION} — Clean up abandoned S3 multipart uploads, versioning waste, and transition traps

USAGE:
  s3-guardian scan <bucket> [options]
  s3-guardian scan --all-buckets [options]
  s3-guardian scan <bucket> --daemon [options]
  s3-guardian scan --all-buckets --daemon [options]
  s3-guardian scan --org [options]
  s3-guardian scan --accounts <id,id,...> [options]
  s3-guardian scan-versions <bucket> [options]
  s3-guardian scan-versions --org [options]
  s3-guardian audit-transitions <bucket> [options]
  s3-guardian audit-transitions --all-buckets [options]
  s3-guardian audit-transitions <bucket> --daemon [options]
  s3-guardian audit-transitions --all-buckets --daemon [options]
  s3-guardian plan <bucket> --out <file> [options]
  s3-guardian plan --all-buckets --out <file> [options]
  s3-guardian plan --org --out <file> [options]
  s3-guardian apply --plan <file> --confirm [options]
  s3-guardian remediate <bucket> [options]
  s3-guardian remediate --all-buckets [options]
  s3-guardian lens <source> [options]
  s3-guardian drift <bucket> [options]

COMMANDS:
  scan <bucket>           Read-only scan of incomplete multipart uploads
  scan --all-buckets      Read-only fleet scan across all account buckets
  scan --org              Multi-account sweep across AWS Organizations accounts
  scan-versions <bucket>  Scan for noncurrent object versions and expired delete markers
  audit-transitions <bucket> Audit lifecycle rules for Glacier/IA small-object transition traps
  plan <bucket>           Generate an inspectable, deterministic JSON plan file (RFC 8785 verified)
  plan --all-buckets      Generate a fleet-wide plan (summary JSON)
  plan --org              Generate a multi-account organization plan (summary JSON)
  apply                   Execute aborts and version deletions defined in a plan file (requires --confirm)
  remediate <bucket>      Generate IaC fix (Terraform / CloudFormation) or apply direct rule
  lens <source>           Zero-overhead triage and ranking from AWS Storage Lens CSV export
  drift <bucket>          Detect lifecycle configuration drift between AWS S3 and Terraform IaC

OPTIONS:
  --tf-file <path>             Target Terraform .tf file to compare against
  --tfstate <path>             Target terraform.tfstate JSON file
  --patch                      Output unified diff patch directly to stdout
  --write                      Atomically update the target .tf file in-place with the patch applied
  --daemon                     Continuous in-process daemon mode
  --interval <duration>        Daemon execution interval (e.g. 1h, 30m, 12h, 24h, default: 1h)
  --once                       Execute exactly one iteration in daemon harness (validates lock & metrics)
  --older-than <days>          Age threshold in days (default: 7)
  --include-versions           Scan and plan for noncurrent versions and expired delete markers
  --audit-transitions          Audit lifecycle transitions for Glacier/IA small-object traps during scan
  --out <file>                 Output path for plan file (default: plan.json)
  --plan <file>                Plan file to apply
  --confirm                    Explicit confirmation required to execute apply deletions
  --bypass-governance          Bypass S3 Object Lock GOVERNANCE mode retention for version purges
  --acknowledge-replication-divergence Acknowledge replica divergence on buckets with active replication
  --allow-active-churn         Allow deletion of uploads or versions modified within 24 hours
  --endpoint <url>             Custom S3 endpoint URL (MinIO, Cloudflare R2, LocalStack)
  --force-path-style           Use S3 path-style addressing
  --region <region>            AWS Region (default: us-east-1 or AWS_REGION)
  --prefix <prefix>            Filter uploads by object key prefix
  --all-buckets                Scan / remediate all buckets in the account (fleet mode)
  --org                        Discover member accounts via AWS Organizations
  --role-name <name>           IAM role name to assume into member accounts (default: OrganizationAccountAccessRole)
  --external-id <id>           Optional external ID for STS AssumeRole
  --accounts <id,id,...>       Comma-separated AWS account IDs to scan
  --accounts-file <path>       File containing AWS account IDs (one per line or comma-separated)
  --exclude-account <id>       Comma-separated AWS account IDs to exclude
  --account-concurrency <n>    Max concurrent account sweeps (default: 5)
  --top <n>                    Limit top offending buckets shown in lens (default: 20)
  --min-waste-usd <amount>     Filter buckets below monthly waste threshold (USD)
  --exclude-bucket <patterns>  Comma-separated bucket name substrings/globs to exclude
  --exclude-region <regions>   Comma-separated AWS regions to exclude
  --max-waste-usd <amount>     Exit code 1 if total monthly waste exceeds this USD amount
  --fail-on-unprotected        Exit code 1 if any bucket has no active MPU lifecycle rule
  --format <fmt>               Output format: table|json|github for scan; terraform|cloudformation for remediate
  --json                       Shorthand for --format json
  --out-iac <path>             Write generated IaC code to a file instead of stdout
  --days <n>                   MPU age threshold in days for lifecycle rule (default: 7)
  --danger-direct-api-apply    Directly apply lifecycle rule to S3 via API (bypasses GitOps)
  --webhook-url <url>          Dispatch audit summary to Slack, Discord, PagerDuty, or Generic webhook
  --webhook-type <type>        Explicit webhook target: slack | discord | pagerduty | generic (autodetected if omitted)
  --notify-always              Dispatch webhook even if total waste is $0.00 (bypasses circuit breaker)
  --checkpoint <s3-uri>        S3 URI (s3://bucket/key.json) for resumable fleet scanning across execution limits
  -h, --help                   Show this help message
  -v, --version                Show version

EXIT CODES:
  0   Success, no policy violations
  1   Policy threshold breached (--max-waste-usd or --fail-on-unprotected)
  2   CLI argument / syntax error
  3   Account discovery / authentication failure

SAFETY GUARANTEES:
  • 'scan', 'scan-versions', and 'plan' are 100% read-only.
  • Pre-flight blast radius simulator prevents accidental deletion under Object Lock, replication, protected prefixes, tags, and churn.
  • Cryptographic RFC 8785 SHA-256 integrity verification guarantees plan immutability prior to apply.
  • 'remediate' defaults to generating deterministic IaC code (GitOps-first).
  • Direct API mutation requires explicit '--danger-direct-api-apply' and preserves 100% of existing rules.
  • 'apply' strictly requires both a valid plan file and the '--confirm' flag.
  • Fleet mode: per-bucket failures (403, 404, RequesterPays) are isolated and never abort the full scan.
  • Multi-account mode: member account failures (403, SCP, STS) never abort the multi-account audit.
  • 'lens' operates with zero data-plane overhead, reading only macroscopic export metrics without object-level APIs.
  • Bulk deletion uses Quiet mode while unconditionally inspecting response.Errors.
  • CloudTrail request ID correlation is captured for all batch mutations.
`;

export interface CliOptions {
  stdout?: (msg: string) => void;
  stderr?: (msg: string) => void;
  signal?: AbortSignal;
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

function renderVersioningTable(
  versionResult: VersionScanResult,
  log: (msg: string) => void
): void {
  log("\nVersioning Waste Analysis:");
  const padNV = 22;
  const padSS = 18;
  const padMC = 16;
  const padEDM = 24;

  log(
    "Noncurrent Versions".padEnd(padNV) +
    "Stranded Size".padEnd(padSS) +
    "Monthly Cost".padEnd(padMC) +
    "Expired Delete Markers".padEnd(padEDM)
  );
  log("-".repeat(padNV + padSS + padMC + padEDM));

  log(
    String(versionResult.noncurrentVersionsCount).padEnd(padNV) +
    formatBytes(versionResult.noncurrentBytes).padEnd(padSS) +
    formatMonthlyCost(versionResult.estimatedMonthlyWasteUSD).padEnd(padMC) +
    String(versionResult.expiredDeleteMarkersCount).padEnd(padEDM)
  );
}

function renderMultiAccountTable(
  result: MultiAccountSweepResult,
  includeVersions: boolean,
  log: (msg: string) => void
): void {
  const padAccount = 16;
  const padName = 22;
  const padStatus = 18;
  const padBuckets = 10;
  const padUploads = 10;
  const padStranded = 14;
  const padWaste = 12;
  const padVersions = includeVersions ? 10 : 0;
  const padVerWaste = includeVersions ? 12 : 0;

  let header =
    "Account ID".padEnd(padAccount) +
    "Account Name".padEnd(padName) +
    "Status".padEnd(padStatus) +
    "Buckets".padEnd(padBuckets) +
    "Uploads".padEnd(padUploads) +
    "Stranded".padEnd(padStranded) +
    "Waste/mo".padEnd(padWaste);

  if (includeVersions) {
    header += "Versions".padEnd(padVersions) + "Ver.Waste".padEnd(padVerWaste);
  }

  const totalWidth =
    padAccount + padName + padStatus + padBuckets + padUploads + padStranded + padWaste +
    padVersions + padVerWaste;

  log(header);
  log("-".repeat(totalWidth));

  for (const r of result.accountResults) {
    const shortName =
      r.accountName.length > padName - 2
        ? r.accountName.slice(0, padName - 3) + "..."
        : r.accountName;

    let statusDisplay = "✓ SUCCESS";
    if (r.status === "PARTIAL") statusDisplay = "⚠ PARTIAL";
    else if (r.status === "SKIPPED_ASSUME_ROLE_FAILED") statusDisplay = "⚠ STS_FAILED";
    else if (r.status === "SKIPPED_ACCESS_DENIED") statusDisplay = "⚠ ACCESS_DENIED";
    else if (r.status === "ERROR") statusDisplay = "❌ ERROR";

    const isAudited = r.status === "SUCCESS" || r.status === "PARTIAL";
    const buckets = isAudited ? `${r.bucketsAudited}/${r.bucketsDiscovered}` : "—";
    const uploads = isAudited ? String(r.totalZombieUploads) : "—";
    const stranded = isAudited ? formatBytes(r.totalStrandedBytes) : "—";
    const waste = isAudited ? formatMonthlyCost(r.totalEstimatedMonthlyWasteUSD) : "—";

    let row =
      r.accountId.padEnd(padAccount) +
      shortName.padEnd(padName) +
      statusDisplay.padEnd(padStatus) +
      buckets.padEnd(padBuckets) +
      uploads.padEnd(padUploads) +
      stranded.padEnd(padStranded) +
      waste.padEnd(padWaste);

    if (includeVersions) {
      const versions = isAudited ? String(r.totalNoncurrentVersions ?? 0) : "—";
      const vWaste = isAudited ? formatMonthlyCost(r.versioningMonthlyWasteUSD ?? 0) : "—";
      row += versions.padEnd(padVersions) + vWaste.padEnd(padVerWaste);
    }

    log(row);
  }

  log("-".repeat(totalWidth));
  log(`Total Accounts:        ${result.totalAccounts}`);
  log(`  Accounts Succeeded:  ${result.accountsSucceeded}`);
  log(`  Accounts Scanned:    ${result.accountsScanned}`);
  log(`  Accounts Skipped:    ${result.accountsSkipped}`);
  log(`Total Buckets:         ${result.totalBucketsAudited} audited (${result.totalBucketsDiscovered} discovered, ${result.totalBucketsSkipped} skipped)`);
  log(`Total Zombie Uploads:  ${result.totalZombieUploads}`);
  log(`Total Stranded:        ${formatBytes(result.totalStrandedBytes)}`);
  log(`Total Monthly Waste:   ${formatMonthlyCost(result.totalCombinedMonthlyWasteUSD)}`);
  if (includeVersions && (result.totalNoncurrentVersions ?? 0) > 0) {
    log(`Total Noncurrent Ver.: ${result.totalNoncurrentVersions}`);
    log(`Versioning Waste:      ${formatMonthlyCost(result.totalVersioningWasteUSD ?? 0)}`);
  }
}

function renderMultiAccountGitHub(
  result: MultiAccountSweepResult,
  violations: string[],
  log: (msg: string) => void
): void {
  log(`## 🛡️ s3-guardian Multi-Account Sweep — v${VERSION}`);
  log(``);
  log(`| Metric | Value |`);
  log(`|--------|-------|`);
  log(`| Total Accounts | ${result.totalAccounts} |`);
  log(`| Accounts Succeeded | ${result.accountsSucceeded} |`);
  log(`| Accounts Scanned | ${result.accountsScanned} |`);
  log(`| Accounts Skipped | ${result.accountsSkipped} |`);
  log(`| Buckets Discovered | ${result.totalBucketsDiscovered} |`);
  log(`| Buckets Audited | ${result.totalBucketsAudited} |`);
  log(`| Total Zombie Uploads | ${result.totalZombieUploads} |`);
  log(`| Total Stranded Storage | ${formatBytes(result.totalStrandedBytes)} |`);
  log(`| Total Monthly Waste | ${formatMonthlyCost(result.totalCombinedMonthlyWasteUSD)} |`);
  log(``);

  if (violations.length > 0) {
    log(`### ❌ Policy Violations`);
    log(``);
    for (const v of violations) {
      log(`- ${v}`);
    }
    log(``);
  }

  log(`### Account Details`);
  log(``);
  log(`| Account ID | Account Name | Status | Buckets | Uploads | Stranded | Waste/mo |`);
  log(`|------------|--------------|--------|---------|---------|----------|----------|`);
  for (const r of result.accountResults) {
    log(
      `| ${r.accountId} | ${r.accountName} | ${r.status} | ${r.bucketsAudited}/${r.bucketsDiscovered} | ${r.totalZombieUploads} | ${formatBytes(r.totalStrandedBytes)} | ${formatMonthlyCost(r.totalMonthlyWasteUSD)} |`
    );
  }
  log(``);
}

function renderLensTable(
  metrics: StorageLensBucketMetrics[],
  log: (msg: string) => void
): void {
  const padRank = 6;
  const padAccount = 16;
  const padBucket = 28;
  const padStorage = 15;
  const padWasteBytes = 15;
  const padWastePct = 10;
  const padWasteMo = 15;
  const padPriority = 10;

  log(
    "Rank".padEnd(padRank) +
    "Account".padEnd(padAccount) +
    "Bucket".padEnd(padBucket) +
    "Total Storage".padEnd(padStorage) +
    "Waste Bytes".padEnd(padWasteBytes) +
    "Waste %".padEnd(padWastePct) +
    "Est. Waste/Mo".padEnd(padWasteMo) +
    "Priority".padEnd(padPriority)
  );
  log(
    "-".repeat(
      padRank +
      padAccount +
      padBucket +
      padStorage +
      padWasteBytes +
      padWastePct +
      padWasteMo +
      padPriority
    )
  );

  let rank = 1;
  for (const m of metrics) {
    const shortBucket =
      m.bucketName.length > padBucket - 2
        ? m.bucketName.slice(0, padBucket - 3) + "..."
        : m.bucketName;

    log(
      `#${rank}`.padEnd(padRank) +
      m.accountId.padEnd(padAccount) +
      shortBucket.padEnd(padBucket) +
      formatBytes(m.storageBytes).padEnd(padStorage) +
      formatBytes(m.wasteBytes).padEnd(padWasteBytes) +
      `${m.wasteScore.toFixed(1)}%`.padEnd(padWastePct) +
      formatMonthlyCost(m.estimatedMonthlyWasteUSD).padEnd(padWasteMo) +
      m.priority.toFixed(1).padEnd(padPriority)
    );
    rank++;
  }
}

function renderTransitionTable(
  auditResult: BucketTransitionAuditResult,
  log: (msg: string) => void
): void {
  if (auditResult.dangerousRules.length === 0) {
    log(`✅ Clean! All transition rules in '${auditResult.bucketName}' have safe size filters (>= 128 KiB).`);
    return;
  }

  log(`\nFound ${auditResult.dangerousRules.length} unconstrained or dangerous transition rule(s) in '${auditResult.bucketName}':\n`);

  const padRuleId = 28;
  const padTier = 16;
  const padDays = 8;
  const padMinSize = 20;
  const padRisk = 20;
  const padPenalty = 18;
  const padStatus = 16;

  log(
    "Rule ID".padEnd(padRuleId) +
    "Target Tier".padEnd(padTier) +
    "Days".padEnd(padDays) +
    "Min Size Filter".padEnd(padMinSize) +
    "Small-Object Risk".padEnd(padRisk) +
    "Est. Penalty/Mo".padEnd(padPenalty) +
    "Status".padEnd(padStatus)
  );
  log(
    "-".repeat(
      padRuleId + padTier + padDays + padMinSize + padRisk + padPenalty + padStatus
    )
  );

  for (const r of auditResult.dangerousRules) {
    const shortId =
      r.ruleId.length > padRuleId - 3
        ? r.ruleId.slice(0, padRuleId - 3) + "..."
        : r.ruleId;
    const tier = r.targetStorageClass;
    const daysStr = String(r.days);
    const minSizeStr =
      r.currentFilterMinSize !== undefined
        ? formatBytes(r.currentFilterMinSize)
        : "None (0 B)";
    const riskStr =
      r.currentFilterMinSize === undefined || r.currentFilterMinSize < 131072
        ? "HIGH (< 128 KiB)"
        : "NONE (>= 128 KiB)";
    const penaltyStr = formatMonthlyCost(r.estimatedPenaltyUSD);
    const statusStr = r.estimatedPenaltyUSD > 0 ? "TRAP DETECTED" : "DANGEROUS";

    log(
      shortId.padEnd(padRuleId) +
      tier.padEnd(padTier) +
      daysStr.padEnd(padDays) +
      minSizeStr.padEnd(padMinSize) +
      riskStr.padEnd(padRisk) +
      penaltyStr.padEnd(padPenalty) +
      statusStr.padEnd(padStatus)
    );
  }

  if (auditResult.totalEstimatedPenaltyUSD > 0) {
    log(
      `\n⚠️  Total Projected Monthly Penalty: ${formatMonthlyCost(
        auditResult.totalEstimatedPenaltyUSD
      )}`
    );
  }

  log(`\n💡 Actionable Tip: Small-object transition traps detected!`);
  log(
    `   Transitioning objects < 128 KiB to ${
      auditResult.dangerousRules[0]?.targetStorageClass || "Glacier"
    } increases storage costs due to 128 KiB floor / 40 KiB metadata overhead.`
  );
  log(
    `   Inject \`object_size_greater_than = 131072\` (128 KiB) to protect small objects from transition traps.\n`
  );
  log(`   Recommended Terraform Fix:`);
  log(`   ---------------------------`);
  log(
    generateTerraformTransitionRemediation(
      auditResult.bucketName,
      auditResult.dangerousRules
    )
  );
}

function renderDriftTable(
  result: LifecycleDriftResult,
  log: (msg: string) => void
): void {
  const padBucket = 28;
  const padResType = 42;
  const padIac = 14;
  const padLive = 14;
  const padStatus = 20;

  log(
    "Bucket".padEnd(padBucket) +
    "Resource Type".padEnd(padResType) +
    "IaC State".padEnd(padIac) +
    "Live State".padEnd(padLive) +
    "Drift Status".padEnd(padStatus)
  );
  log("-".repeat(padBucket + padResType + padIac + padLive + padStatus));

  const statusDisplay =
    result.status === "IN_SYNC"
      ? "✅ IN_SYNC"
      : result.status === "GHOST_CONFIG"
      ? "⚠️ GHOST_CONFIG"
      : "❌ DRIFT_DETECTED";

  const shortBucket =
    result.bucketName.length > padBucket - 2
      ? result.bucketName.slice(0, padBucket - 3) + "..."
      : result.bucketName;

  const resTypeDisplay = result.resourceType ?? "(unmanaged in IaC)";
  const shortResType =
    resTypeDisplay.length > padResType - 2
      ? resTypeDisplay.slice(0, padResType - 3) + "..."
      : resTypeDisplay;

  log(
    shortBucket.padEnd(padBucket) +
    shortResType.padEnd(padResType) +
    `${result.iacRulesCount} Rule(s)`.padEnd(padIac) +
    `${result.liveRulesCount} Rule(s)`.padEnd(padLive) +
    statusDisplay.padEnd(padStatus)
  );
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
        "include-versions": { type: "boolean", default: false },
        "audit-transitions": { type: "boolean", default: false },
        out: { type: "string" },
        plan: { type: "string" },
        confirm: { type: "boolean", default: false },
        "bypass-governance": { type: "boolean", default: false },
        "acknowledge-replication-divergence": { type: "boolean", default: false },
        "allow-active-churn": { type: "boolean", default: false },
        endpoint: { type: "string" },
        "force-path-style": { type: "boolean", default: false },
        region: { type: "string" },
        prefix: { type: "string" },
        "all-buckets": { type: "boolean", default: false },
        org: { type: "boolean", default: false },
        "role-name": { type: "string" },
        "external-id": { type: "string" },
        accounts: { type: "string" },
        "accounts-file": { type: "string" },
        "exclude-account": { type: "string" },
        "account-concurrency": { type: "string", default: "5" },
        top: { type: "string", default: "20" },
        "min-waste-usd": { type: "string" },
        "exclude-bucket": { type: "string" },
        "exclude-region": { type: "string" },
        "max-waste-usd": { type: "string" },
        "fail-on-unprotected": { type: "boolean", default: false },
        format: { type: "string", default: "table" },
        json: { type: "boolean", default: false },
        "out-iac": { type: "string" },
        days: { type: "string", default: "7" },
        "danger-direct-api-apply": { type: "boolean", default: false },
        "webhook-url": { type: "string" },
        "webhook-type": { type: "string" },
        "notify-always": { type: "boolean", default: false },
        checkpoint: { type: "string" },
        daemon: { type: "boolean", default: false },
        interval: { type: "string", default: "1h" },
        once: { type: "boolean", default: false },
        "tf-file": { type: "string" },
        tfstate: { type: "string" },
        patch: { type: "boolean", default: false },
        write: { type: "boolean", default: false },
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

  const isDaemon = values.daemon === true || values.once === true;
  const isOnce = values.once === true;
  let daemonIntervalMs = 3600000;
  const intervalArg = getString(values.interval);
  if (intervalArg !== undefined) {
    try {
      daemonIntervalMs = parseHumanInterval(intervalArg);
    } catch (err: unknown) {
      error(`Error: ${err instanceof Error ? err.message : String(err)}`);
      return EXIT_CODES.ARG_ERROR;
    }
  }

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
  const isOrg = values.org === true;
  const accountsStr = getString(values.accounts);
  const accountsFile = getString(values["accounts-file"]);
  const excludeAccounts = splitCsv(getString(values["exclude-account"]));
  const roleName = getString(values["role-name"]) || "OrganizationAccountAccessRole";
  const externalId = getString(values["external-id"]);
  const accountConcurrencyStr = getString(values["account-concurrency"]) ?? "5";
  const accountConcurrency = parseInt(accountConcurrencyStr, 10) || 5;

  const isMultiAccount = isOrg || Boolean(accountsStr) || Boolean(accountsFile);

  const includeVersions =
    values["include-versions"] === true || command === "scan-versions";
  const auditTransitions =
    values["audit-transitions"] === true || command === "audit-transitions";
  const excludeBuckets = splitCsv(getString(values["exclude-bucket"]));
  const excludeRegions = splitCsv(getString(values["exclude-region"]));
  const failOnUnprotected = values["fail-on-unprotected"] === true;
  const formatStr = getString(values.format) ?? "table";
  const isJson = values.json === true || formatStr === "json";
  const isGitHub = formatStr === "github";
  const webhookUrl = getString(values["webhook-url"]);
  const webhookType = getString(values["webhook-type"]) as WebhookType | undefined;
  const notifyAlways = values["notify-always"] === true;
  const checkpoint = getString(values.checkpoint);

  let maxWasteUSD: number | undefined;
  const maxWasteStr = getString(values["max-waste-usd"]);
  if (maxWasteStr !== undefined) {
    maxWasteUSD = parseFloat(maxWasteStr);
    if (isNaN(maxWasteUSD) || maxWasteUSD < 0) {
      error("Error: --max-waste-usd must be a non-negative number");
      return EXIT_CODES.ARG_ERROR;
    }
  }

  const topStr = getString(values.top) ?? "20";
  const top = parseInt(topStr, 10) || 20;

  let minWasteUSD: number | undefined;
  const minWasteStr = getString(values["min-waste-usd"]);
  if (minWasteStr !== undefined) {
    minWasteUSD = parseFloat(minWasteStr);
    if (isNaN(minWasteUSD) || minWasteUSD < 0) {
      error("Error: --min-waste-usd must be a non-negative number");
      return EXIT_CODES.ARG_ERROR;
    }
  }

  const policyOptions: PolicyOptions = { maxWasteUSD, failOnUnprotected };
  const clientConfig = { region, endpoint, forcePathStyle };

  // ════════════════════════════════════════════════════════════════════════════
  switch (command) {
    // ── SCAN & SCAN-VERSIONS ─────────────────────────────────────────────────
    case "scan":
    case "scan-versions": {
      // ── Multi-Account mode: --org or --accounts or --accounts-file ──────────
      if (isMultiAccount) {
        if (!isJson && !isGitHub) {
          log(`🌐 Multi-account sweep: resolving target accounts...`);
        }

        let targetAccounts: OrganizationAccount[];
        try {
          targetAccounts = await resolveTargetAccounts({
            useOrg: isOrg,
            accounts: splitCsv(accountsStr),
            accountsFile,
            excludeAccounts,
          });
        } catch (err: unknown) {
          if (err instanceof OrganizationsDiscoveryError) {
            error(`\n❌ Discovery failed: ${err.message}`);
            return EXIT_CODES.DISCOVERY_AUTH_ERROR;
          }
          throw err;
        }

        if (targetAccounts.length === 0) {
          error("Error: No accounts found to scan (check --accounts, --accounts-file, or --org filters)");
          return EXIT_CODES.ARG_ERROR;
        }

        if (!isJson && !isGitHub) {
          log(`🌐 Multi-account sweep: scanning ${targetAccounts.length} account(s) using role '${roleName}'...`);
        }

        const sweepResult = await runMultiAccountSweep({
          accounts: targetAccounts,
          roleName,
          externalId,
          accountConcurrency,
          olderThanDays,
          prefix,
          includeVersions,
          excludeBuckets,
          excludeRegions,
          endpoint,
        });

        const aggregateFleetResult: FleetScanResult = {
          bucketsDiscovered: sweepResult.totalBucketsDiscovered,
          bucketsAudited: sweepResult.totalBucketsAudited,
          bucketsSkipped: sweepResult.totalBucketsSkipped,
          totalZombieUploads: sweepResult.totalZombieUploads,
          totalStrandedBytes: sweepResult.totalStrandedBytes,
          totalEstimatedMonthlyWasteUSD: sweepResult.totalCombinedMonthlyWasteUSD,
          bucketResults: sweepResult.accountResults.flatMap((a) => a.fleetResult?.bucketResults ?? []),
        };
        const policyResult = evaluatePolicy(aggregateFleetResult, policyOptions);

        if (webhookUrl) {
          await dispatchNotification(
            {
              scope: "fleet",
              target: `multi-account (${sweepResult.accountsScanned}/${sweepResult.totalAccounts} accounts)`,
              totalZombieUploads: sweepResult.totalZombieUploads,
              totalStrandedBytes: sweepResult.totalStrandedBytes,
              totalEstimatedMonthlyWasteUSD: sweepResult.totalCombinedMonthlyWasteUSD,
              bucketsDiscovered: sweepResult.totalBucketsDiscovered,
              bucketsAudited: sweepResult.totalBucketsAudited,
              bucketsSkipped: sweepResult.totalBucketsSkipped,
              policyViolations: policyResult.violations.map((v) => v.message),
            },
            {
              webhookUrl,
              webhookType,
              notifyAlways,
            }
          );
        }

        if (isJson) {
          log(JSON.stringify(sweepResult, null, 2));
          return policyResult.exitCode;
        }

        if (isGitHub) {
          renderMultiAccountGitHub(
            sweepResult,
            policyResult.violations.map((v) => v.message),
            log
          );
          return policyResult.exitCode;
        }

        log(`\nMulti-Account Sweep Summary:`);
        renderMultiAccountTable(sweepResult, includeVersions, log);

        const hasUnprotected = aggregateFleetResult.bucketResults.some(
          (b) =>
            b.status === "AUDITED" &&
            (!b.lifecycleAudit?.hasCoveringRule ||
              (b.lifecycleAudit?.ghostRulesDetected && b.lifecycleAudit.ghostRulesDetected.length > 0))
        );
        if (hasUnprotected) {
          log(`\n💡 Tip: Run \`s3-guardian remediate --all-buckets\` to generate Terraform/CloudFormation fix.`);
        }

        if (policyResult.violations.length > 0) {
          log(`\n❌ Policy violations detected:`);
          for (const v of policyResult.violations) {
            log(`  [${v.rule}] ${v.message}`);
          }
        }

        return policyResult.exitCode;
      }

      // ── Fleet mode: --all-buckets ──────────────────────────────────────────
      if (allBuckets) {
        if (isDaemon) {
          try {
            let lastExitCode: number = EXIT_CODES.SUCCESS;
            await startDaemon({
              lockName: "scan-fleet",
              intervalMs: daemonIntervalMs,
              maxRuns: isOnce ? 1 : undefined,
              log,
              error,
              signal: io.signal,
              exitOnSignal: process.env.NODE_ENV !== "test",
              targetDescription: "Fleet scan (--all-buckets)",
              task: async (runIndex) => {
                if (!isJson && !isGitHub) {
                  log(`\n🔍 Fleet scan (Run #${runIndex}): discovering all account buckets (older than ${olderThanDays} days)...`);
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
                    checkpointUri: checkpoint,
                    auditTransitions,
                  });
                } catch (err) {
                  if (err instanceof DiscoveryAuthError) {
                    error(`\n❌ Discovery failed: ${err.message}`);
                    lastExitCode = EXIT_CODES.DISCOVERY_AUTH_ERROR;
                    return;
                  }
                  throw err;
                } finally {
                  await pool.destroy();
                }

                const policyResult = evaluatePolicy(fleetResult, policyOptions);
                lastExitCode = policyResult.exitCode;

                if (webhookUrl) {
                  await dispatchNotification(
                    {
                      scope: "fleet",
                      target: "all-buckets",
                      totalZombieUploads: fleetResult.totalZombieUploads,
                      totalStrandedBytes: fleetResult.totalStrandedBytes,
                      totalEstimatedMonthlyWasteUSD: fleetResult.totalEstimatedMonthlyWasteUSD,
                      bucketsDiscovered: fleetResult.bucketsDiscovered,
                      bucketsAudited: fleetResult.bucketsAudited,
                      bucketsSkipped: fleetResult.bucketsSkipped,
                      policyViolations: policyResult.violations.map((v) => v.message),
                    },
                    {
                      webhookUrl,
                      webhookType,
                      notifyAlways,
                    }
                  );
                }

                if (isJson) {
                  log(JSON.stringify(fleetResult, null, 2));
                  return { wasteDetectedUSD: fleetResult.totalEstimatedMonthlyWasteUSD };
                }

                if (isGitHub) {
                  renderFleetGitHub(
                    fleetResult,
                    policyResult.violations.map((v) => v.message),
                    log
                  );
                  return { wasteDetectedUSD: fleetResult.totalEstimatedMonthlyWasteUSD };
                }

                log(`\nFleet Scan Summary (Run #${runIndex}):`);
                log(`  Buckets Discovered:       ${fleetResult.bucketsDiscovered}`);
                log(`  Buckets Audited:          ${fleetResult.bucketsAudited}`);
                log(`  Buckets Skipped:          ${fleetResult.bucketsSkipped}`);
                log(`  Total Zombie Uploads:     ${fleetResult.totalZombieUploads}`);
                log(`  Total Stranded Storage:   ${formatBytes(fleetResult.totalStrandedBytes)}`);
                log(`  Estimated Monthly Waste:  ${formatMonthlyCost(fleetResult.totalEstimatedMonthlyWasteUSD)}`);
                if (auditTransitions && fleetResult.totalTransitionPenaltyUSD !== undefined) {
                  log(`  Transition Trap Penalty:  ${formatMonthlyCost(fleetResult.totalTransitionPenaltyUSD)}`);
                }
                log(``);
                renderFleetTable(fleetResult, log);

                if (auditTransitions) {
                  const bucketsWithTraps = fleetResult.bucketResults.filter(
                    (b) => b.transitionAudit && b.transitionAudit.dangerousRules.length > 0
                  );
                  if (bucketsWithTraps.length > 0) {
                    log(`\n⚠️  Transition Traps detected in ${bucketsWithTraps.length} bucket(s):`);
                    for (const b of bucketsWithTraps) {
                      renderTransitionTable(b.transitionAudit!, log);
                    }
                  }
                }

                const hasUnprotectedFleet = fleetResult.bucketResults.some(
                  (b) => b.status === "AUDITED" && (!b.lifecycleAudit?.hasCoveringRule || (b.lifecycleAudit?.ghostRulesDetected && b.lifecycleAudit.ghostRulesDetected.length > 0))
                );
                if (hasUnprotectedFleet) {
                  log(`\n💡 Tip: Run \`s3-guardian remediate --all-buckets\` to generate Terraform/CloudFormation fix.`);
                }

                if (policyResult.violations.length > 0) {
                  log(`\n❌ Policy violations detected:`);
                  for (const v of policyResult.violations) {
                    log(`  [${v.rule}] ${v.message}`);
                  }
                }

                return { wasteDetectedUSD: fleetResult.totalEstimatedMonthlyWasteUSD };
              },
            });
            return lastExitCode;
          } catch (err: unknown) {
            if (err instanceof DaemonLockError) {
              error(`\n❌ Daemon lock conflict: ${err.message}`);
              return EXIT_CODES.ARG_ERROR;
            }
            throw err;
          }
        }

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
            checkpointUri: checkpoint,
            auditTransitions,
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

        if (webhookUrl) {
          await dispatchNotification(
            {
              scope: "fleet",
              target: "all-buckets",
              totalZombieUploads: fleetResult.totalZombieUploads,
              totalStrandedBytes: fleetResult.totalStrandedBytes,
              totalEstimatedMonthlyWasteUSD: fleetResult.totalEstimatedMonthlyWasteUSD,
              bucketsDiscovered: fleetResult.bucketsDiscovered,
              bucketsAudited: fleetResult.bucketsAudited,
              bucketsSkipped: fleetResult.bucketsSkipped,
              policyViolations: policyResult.violations.map((v) => v.message),
            },
            {
              webhookUrl,
              webhookType,
              notifyAlways,
            }
          );
        }

        if (isJson) {
          log(JSON.stringify(fleetResult, null, 2));
          return policyResult.exitCode;
        }

        if (isGitHub) {
          renderFleetGitHub(
            fleetResult,
            policyResult.violations.map((v) => v.message),
            log
          );
          return policyResult.exitCode;
        }

        log(`\nFleet Scan Summary:`);
        log(`  Buckets Discovered:       ${fleetResult.bucketsDiscovered}`);
        log(`  Buckets Audited:          ${fleetResult.bucketsAudited}`);
        log(`  Buckets Skipped:          ${fleetResult.bucketsSkipped}`);
        log(`  Total Zombie Uploads:     ${fleetResult.totalZombieUploads}`);
        log(`  Total Stranded Storage:   ${formatBytes(fleetResult.totalStrandedBytes)}`);
        log(`  Estimated Monthly Waste:  ${formatMonthlyCost(fleetResult.totalEstimatedMonthlyWasteUSD)}`);
        if (auditTransitions && fleetResult.totalTransitionPenaltyUSD !== undefined) {
          log(`  Transition Trap Penalty:  ${formatMonthlyCost(fleetResult.totalTransitionPenaltyUSD)}`);
        }
        log(``);
        renderFleetTable(fleetResult, log);

        if (auditTransitions) {
          const bucketsWithTraps = fleetResult.bucketResults.filter(
            (b) => b.transitionAudit && b.transitionAudit.dangerousRules.length > 0
          );
          if (bucketsWithTraps.length > 0) {
            log(`\n⚠️  Transition Traps detected in ${bucketsWithTraps.length} bucket(s):`);
            for (const b of bucketsWithTraps) {
              renderTransitionTable(b.transitionAudit!, log);
            }
          }
        }

        const hasUnprotectedFleet = fleetResult.bucketResults.some(
          (b) => b.status === "AUDITED" && (!b.lifecycleAudit?.hasCoveringRule || (b.lifecycleAudit?.ghostRulesDetected && b.lifecycleAudit.ghostRulesDetected.length > 0))
        );
        if (hasUnprotectedFleet) {
          log(`\n💡 Tip: Run \`s3-guardian remediate --all-buckets\` to generate Terraform/CloudFormation fix.`);
        }

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

      if (isDaemon) {
        try {
          let lastExitCode: number = EXIT_CODES.SUCCESS;
          await startDaemon({
            lockName: `scan-${bucketArg}`,
            intervalMs: daemonIntervalMs,
            maxRuns: isOnce ? 1 : undefined,
            log,
            error,
            signal: io.signal,
            exitOnSignal: process.env.NODE_ENV !== "test",
            targetDescription: `Bucket scan (${bucketArg})`,
            task: async (runIndex) => {
              if (!isJson) {
                log(`\n🔍 Scanning bucket '${bucketArg}' (Run #${runIndex}) for multipart uploads older than ${olderThanDays} days...`);
              }

              const client = createS3Client(clientConfig);

              const shouldAuditTransitions = values["audit-transitions"] === true;
              const [scanResult, lifecycleAudit, versionResult, transitionResult] = await Promise.all([
                scanMultipartUploads(client, bucketArg, { olderThanDays, endpoint, prefix }),
                auditBucketLifecycle(client, bucketArg, endpoint),
                includeVersions
                  ? scanObjectVersions(client, bucketArg, { olderThanDays, prefix })
                  : Promise.resolve(null),
                shouldAuditTransitions
                  ? auditBucketTransitions(client, bucketArg, { prefix })
                  : Promise.resolve(null),
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

              const totalMonthlyWaste =
                scanResult.estimatedMonthlyWasteUSD +
                (versionResult ? versionResult.estimatedMonthlyWasteUSD : 0);

              if (webhookUrl) {
                await dispatchNotification(
                  {
                    scope: "bucket",
                    target: bucketArg,
                    totalZombieUploads: scanResult.totalZombieUploads,
                    totalStrandedBytes: scanResult.totalStrandedBytes,
                    totalEstimatedMonthlyWasteUSD: totalMonthlyWaste,
                    policyViolations: [],
                  },
                  {
                    webhookUrl,
                    webhookType,
                    notifyAlways,
                  }
                );
              }

              if (isJson) {
                log(
                  JSON.stringify(
                    {
                      ...scanResult,
                      uploads: enrichedUploads,
                      lifecycleAudit,
                      versioning: versionResult ?? undefined,
                      transitionAudit: transitionResult ?? undefined,
                    },
                    null,
                    2
                  )
                );
                return { wasteDetectedUSD: totalMonthlyWaste };
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
                log(`\n💡 Tip: Run \`s3-guardian remediate ${bucketArg}\` to generate Terraform/CloudFormation fix.`);
              } else if (!lifecycleAudit.hasCoveringRule) {
                log(`\n[!] Bucket has NO lifecycle rule covering multipart uploads.`);
                log(`    Zombie uploads will accumulate indefinitely without manual cleanup.`);
                log(`\n💡 Tip: Run \`s3-guardian remediate ${bucketArg}\` to generate Terraform/CloudFormation fix.`);
              }

              if (enrichedUploads.length === 0) {
                log(`\n✅ Clean! No multipart uploads older than ${olderThanDays} days found in '${bucketArg}'.`);
              } else {
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
              }

              // Display versioning table if requested
              if (versionResult) {
                renderVersioningTable(versionResult, log);
              }

              // Display transition audit table if requested
              if (transitionResult) {
                renderTransitionTable(transitionResult, log);
              }

              return { wasteDetectedUSD: totalMonthlyWaste };
            },
          });
          return lastExitCode;
        } catch (err: unknown) {
          if (err instanceof DaemonLockError) {
            error(`\n❌ Daemon lock conflict: ${err.message}`);
            return EXIT_CODES.ARG_ERROR;
          }
          throw err;
        }
      }

      if (!isJson) {
        log(`🔍 Scanning bucket '${bucketArg}' for multipart uploads older than ${olderThanDays} days...`);
      }

      const client = createS3Client(clientConfig);

      const shouldAuditTransitions = values["audit-transitions"] === true;
      const [scanResult, lifecycleAudit, versionResult, transitionResult] = await Promise.all([
        scanMultipartUploads(client, bucketArg, { olderThanDays, endpoint, prefix }),
        auditBucketLifecycle(client, bucketArg, endpoint),
        includeVersions
          ? scanObjectVersions(client, bucketArg, { olderThanDays, prefix })
          : Promise.resolve(null),
        shouldAuditTransitions
          ? auditBucketTransitions(client, bucketArg, { prefix })
          : Promise.resolve(null),
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

      const totalMonthlyWaste =
        scanResult.estimatedMonthlyWasteUSD +
        (versionResult ? versionResult.estimatedMonthlyWasteUSD : 0);

      if (webhookUrl) {
        await dispatchNotification(
          {
            scope: "bucket",
            target: bucketArg,
            totalZombieUploads: scanResult.totalZombieUploads,
            totalStrandedBytes: scanResult.totalStrandedBytes,
            totalEstimatedMonthlyWasteUSD: totalMonthlyWaste,
            policyViolations: [],
          },
          {
            webhookUrl,
            webhookType,
            notifyAlways,
          }
        );
      }

      if (isJson) {
        log(
          JSON.stringify(
            {
              ...scanResult,
              uploads: enrichedUploads,
              lifecycleAudit,
              versioning: versionResult ?? undefined,
              transitionAudit: transitionResult ?? undefined,
            },
            null,
            2
          )
        );
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
        log(`\n💡 Tip: Run \`s3-guardian remediate ${bucketArg}\` to generate Terraform/CloudFormation fix.`);
      } else if (!lifecycleAudit.hasCoveringRule) {
        log(`\n[!] Bucket has NO lifecycle rule covering multipart uploads.`);
        log(`    Zombie uploads will accumulate indefinitely without manual cleanup.`);
        log(`\n💡 Tip: Run \`s3-guardian remediate ${bucketArg}\` to generate Terraform/CloudFormation fix.`);
      }

      if (enrichedUploads.length === 0) {
        log(`\n✅ Clean! No multipart uploads older than ${olderThanDays} days found in '${bucketArg}'.`);
      } else {
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
      }

      // Display versioning table if requested
      if (versionResult) {
        renderVersioningTable(versionResult, log);
      }

      // Display transition audit table if requested
      if (transitionResult) {
        renderTransitionTable(transitionResult, log);
      }

      log("\nNext steps:");
      log(`  Generate an execution plan to safely clean up:`);
      log(`  $ s3-guardian plan ${bucketArg}${includeVersions ? " --include-versions" : ""} --out plan.json\n`);

      return EXIT_CODES.SUCCESS;
    }

    // ── AUDIT-TRANSITIONS ────────────────────────────────────────────────────
    case "audit-transitions": {
      // ── Fleet mode: --all-buckets ──────────────────────────────────────────
      if (allBuckets) {
        if (isDaemon) {
          try {
            let lastExitCode: number = EXIT_CODES.SUCCESS;
            await startDaemon({
              lockName: "audit-transitions-fleet",
              intervalMs: daemonIntervalMs,
              maxRuns: isOnce ? 1 : undefined,
              log,
              error,
              signal: io.signal,
              exitOnSignal: process.env.NODE_ENV !== "test",
              targetDescription: "Fleet transition audit (--all-buckets)",
              task: async (runIndex) => {
                if (!isJson) {
                  log(`\n🔍 Fleet transition audit (Run #${runIndex}): discovering all account buckets...`);
                }

                const pool = new S3ClientPool();
                const discoveryClient = createS3Client(clientConfig);

                let allBucketsList: Array<{ Name?: string }>;
                try {
                  const listRes = await discoveryClient.send(new ListBucketsCommand({}));
                  allBucketsList = listRes.Buckets ?? [];
                } catch (err) {
                  error(`\n❌ Bucket discovery failed: ${err instanceof Error ? err.message : String(err)}`);
                  lastExitCode = EXIT_CODES.DISCOVERY_AUTH_ERROR;
                  return;
                }

                const filteredBuckets = allBucketsList.filter((b) => {
                  if (!b.Name) return false;
                  if (excludeBuckets.length > 0 && matchesExcludePattern(b.Name, excludeBuckets)) {
                    return false;
                  }
                  return true;
                });

                const auditResults: BucketTransitionAuditResult[] = [];
                for (const b of filteredBuckets) {
                  const bucketName = b.Name!;
                  try {
                    let bucketRegion = clientConfig.region;
                    if (!bucketRegion) {
                      try {
                        const locRes = await discoveryClient.send(
                          new GetBucketLocationCommand({ Bucket: bucketName })
                        );
                        bucketRegion = normalizeBucketRegion(locRes.LocationConstraint);
                      } catch {
                        bucketRegion = US_EAST_1;
                      }
                    }
                    if (
                      excludeRegions.length > 0 &&
                      excludeRegions.some((r) => r.toLowerCase() === (bucketRegion || "").toLowerCase())
                    ) {
                      continue;
                    }
                    const bucketClient = pool.getClient(bucketRegion || US_EAST_1);
                    const res = await auditBucketTransitions(bucketClient, bucketName, { prefix });
                    auditResults.push(res);
                  } catch {
                    // gracefully continue fleet scan
                  }
                }

                await pool.destroy();

                const totalPenaltyUSD =
                  Math.round(
                    auditResults.reduce((sum, r) => sum + r.totalEstimatedPenaltyUSD, 0) * 100
                  ) / 100;

                const dangerousBuckets = auditResults.filter(
                  (r) => r.dangerousRules.length > 0
                );

                if (isJson) {
                  log(
                    JSON.stringify(
                      {
                        buckets: auditResults,
                        totalEstimatedPenaltyUSD: totalPenaltyUSD,
                        bucketsAudited: auditResults.length,
                        dangerousBucketsCount: dangerousBuckets.length,
                      },
                      null,
                      2
                    )
                  );
                  return { wasteDetectedUSD: totalPenaltyUSD };
                }

                log(`\nFleet Transition Audit Summary (Run #${runIndex}):`);
                log(`  Buckets Audited:           ${auditResults.length}`);
                log(`  Buckets with Traps:        ${dangerousBuckets.length}`);
                log(`  Total Projected Penalty:   ${formatMonthlyCost(totalPenaltyUSD)}`);

                if (dangerousBuckets.length === 0) {
                  log(`\n✅ Clean! No transition traps detected across all audited buckets.`);
                } else {
                  for (const d of dangerousBuckets) {
                    renderTransitionTable(d, log);
                  }
                }

                return { wasteDetectedUSD: totalPenaltyUSD };
              },
            });
            return lastExitCode;
          } catch (err: unknown) {
            if (err instanceof DaemonLockError) {
              error(`\n❌ Daemon lock conflict: ${err.message}`);
              return EXIT_CODES.ARG_ERROR;
            }
            throw err;
          }
        }

        if (!isJson) {
          log(`🔍 Fleet transition audit: discovering all account buckets...`);
        }

        const pool = new S3ClientPool();
        const discoveryClient = createS3Client(clientConfig);

        let allBucketsList: Array<{ Name?: string }>;
        try {
          const listRes = await discoveryClient.send(new ListBucketsCommand({}));
          allBucketsList = listRes.Buckets ?? [];
        } catch (err) {
          error(`\n❌ Bucket discovery failed: ${err instanceof Error ? err.message : String(err)}`);
          return EXIT_CODES.DISCOVERY_AUTH_ERROR;
        }

        const filteredBuckets = allBucketsList.filter((b) => {
          if (!b.Name) return false;
          if (excludeBuckets.length > 0 && matchesExcludePattern(b.Name, excludeBuckets)) {
            return false;
          }
          return true;
        });

        const auditResults: BucketTransitionAuditResult[] = [];
        for (const b of filteredBuckets) {
          const bucketName = b.Name!;
          try {
            let bucketRegion = clientConfig.region;
            if (!bucketRegion) {
              try {
                const locRes = await discoveryClient.send(
                  new GetBucketLocationCommand({ Bucket: bucketName })
                );
                bucketRegion = normalizeBucketRegion(locRes.LocationConstraint);
              } catch {
                bucketRegion = US_EAST_1;
              }
            }
            if (
              excludeRegions.length > 0 &&
              excludeRegions.some((r) => r.toLowerCase() === (bucketRegion || "").toLowerCase())
            ) {
              continue;
            }
            const bucketClient = pool.getClient(bucketRegion || US_EAST_1);
            const res = await auditBucketTransitions(bucketClient, bucketName, { prefix });
            auditResults.push(res);
          } catch {
            // gracefully continue fleet scan
          }
        }

        await pool.destroy();

        const totalPenaltyUSD =
          Math.round(
            auditResults.reduce((sum, r) => sum + r.totalEstimatedPenaltyUSD, 0) * 100
          ) / 100;

        const dangerousBuckets = auditResults.filter(
          (r) => r.dangerousRules.length > 0
        );

        if (isJson) {
          log(
            JSON.stringify(
              {
                buckets: auditResults,
                totalEstimatedPenaltyUSD: totalPenaltyUSD,
                bucketsAudited: auditResults.length,
                dangerousBucketsCount: dangerousBuckets.length,
              },
              null,
              2
            )
          );
          return EXIT_CODES.SUCCESS;
        }

        log(`\nFleet Transition Audit Summary:`);
        log(`  Buckets Audited:           ${auditResults.length}`);
        log(`  Buckets with Traps:        ${dangerousBuckets.length}`);
        log(`  Total Projected Penalty:   ${formatMonthlyCost(totalPenaltyUSD)}`);

        if (dangerousBuckets.length === 0) {
          log(`\n✅ Clean! No transition traps detected across all audited buckets.`);
        } else {
          for (const d of dangerousBuckets) {
            renderTransitionTable(d, log);
          }
        }

        return EXIT_CODES.SUCCESS;
      }

      // ── Single-bucket mode ─────────────────────────────────────────────────
      if (!bucketArg) {
        error(
          "Error: Bucket name is required for 'audit-transitions'. Usage: s3-guardian audit-transitions <bucket>"
        );
        return EXIT_CODES.ARG_ERROR;
      }

      if (isDaemon) {
        try {
          let lastExitCode: number = EXIT_CODES.SUCCESS;
          await startDaemon({
            lockName: `audit-transitions-${bucketArg}`,
            intervalMs: daemonIntervalMs,
            maxRuns: isOnce ? 1 : undefined,
            log,
            error,
            signal: io.signal,
            exitOnSignal: process.env.NODE_ENV !== "test",
            targetDescription: `Bucket transition audit (${bucketArg})`,
            task: async (runIndex) => {
              if (!isJson) {
                log(`\n🔍 Auditing lifecycle transitions in bucket '${bucketArg}' (Run #${runIndex})...`);
              }

              const client = createS3Client(clientConfig);
              const auditResult = await auditBucketTransitions(client, bucketArg, { prefix });

              if (isJson) {
                log(JSON.stringify(auditResult, null, 2));
                return { wasteDetectedUSD: auditResult.totalEstimatedPenaltyUSD };
              }

              if (!auditResult.hasLifecyclePolicy) {
                log(`\nℹ️  Bucket '${bucketArg}' has no lifecycle configuration.`);
                return { wasteDetectedUSD: 0 };
              }

              renderTransitionTable(auditResult, log);
              return { wasteDetectedUSD: auditResult.totalEstimatedPenaltyUSD };
            },
          });
          return lastExitCode;
        } catch (err: unknown) {
          if (err instanceof DaemonLockError) {
            error(`\n❌ Daemon lock conflict: ${err.message}`);
            return EXIT_CODES.ARG_ERROR;
          }
          throw err;
        }
      }

      if (!isJson) {
        log(`🔍 Auditing lifecycle transitions in bucket '${bucketArg}'...`);
      }

      const client = createS3Client(clientConfig);
      const auditResult = await auditBucketTransitions(client, bucketArg, { prefix });

      if (isJson) {
        log(JSON.stringify(auditResult, null, 2));
        return EXIT_CODES.SUCCESS;
      }

      if (!auditResult.hasLifecyclePolicy) {
        log(`\nℹ️  Bucket '${bucketArg}' has no lifecycle configuration.`);
        return EXIT_CODES.SUCCESS;
      }

      renderTransitionTable(auditResult, log);
      return EXIT_CODES.SUCCESS;
    }

    // ── PLAN ─────────────────────────────────────────────────────────────────
    case "plan": {
      if (isMultiAccount) {
        const outFile = getString(values.out) || "multi-account-plan.json";
        log(`📝 Multi-account plan: resolving target accounts...`);

        let targetAccounts: OrganizationAccount[];
        try {
          targetAccounts = await resolveTargetAccounts({
            useOrg: isOrg,
            accounts: splitCsv(accountsStr),
            accountsFile,
            excludeAccounts,
          });
        } catch (err: unknown) {
          if (err instanceof OrganizationsDiscoveryError) {
            error(`\n❌ Discovery failed: ${err.message}`);
            return EXIT_CODES.DISCOVERY_AUTH_ERROR;
          }
          throw err;
        }

        if (targetAccounts.length === 0) {
          error("Error: No accounts found to plan (check --accounts, --accounts-file, or --org filters)");
          return EXIT_CODES.ARG_ERROR;
        }

        log(`📝 Multi-account plan: scanning ${targetAccounts.length} account(s) using role '${roleName}'...`);

        const sweepResult = await runMultiAccountSweep({
          accounts: targetAccounts,
          roleName,
          externalId,
          accountConcurrency,
          olderThanDays,
          prefix,
          includeVersions,
          excludeBuckets,
          excludeRegions,
          endpoint,
        });

        const aggregateFleetResult: FleetScanResult = {
          bucketsDiscovered: sweepResult.totalBucketsDiscovered,
          bucketsAudited: sweepResult.totalBucketsAudited,
          bucketsSkipped: sweepResult.totalBucketsSkipped,
          totalZombieUploads: sweepResult.totalZombieUploads,
          totalStrandedBytes: sweepResult.totalStrandedBytes,
          totalEstimatedMonthlyWasteUSD: sweepResult.totalCombinedMonthlyWasteUSD,
          bucketResults: sweepResult.accountResults.flatMap((a) => a.fleetResult?.bucketResults ?? []),
        };
        const policyResult = evaluatePolicy(aggregateFleetResult, policyOptions);

        const { writeFile, mkdir } = await import("node:fs/promises");
        const { dirname, resolve: pathResolve } = await import("node:path");
        const resolvedOut = pathResolve(outFile);
        await mkdir(dirname(resolvedOut), { recursive: true });
        await writeFile(resolvedOut, JSON.stringify(sweepResult, null, 2), "utf8");

        log(`\nMulti-account plan generated: ${outFile}`);
        log(`  Total Accounts:           ${sweepResult.totalAccounts}`);
        log(`  Accounts Succeeded:       ${sweepResult.accountsSucceeded}`);
        log(`  Accounts Skipped:         ${sweepResult.accountsSkipped}`);
        log(`  Buckets Audited:          ${sweepResult.totalBucketsAudited}`);
        log(`  Total Zombie Uploads:     ${sweepResult.totalZombieUploads}`);
        log(`  Total Stranded Storage:   ${formatBytes(sweepResult.totalStrandedBytes)}`);
        log(`  Estimated Monthly Waste:  ${formatMonthlyCost(sweepResult.totalCombinedMonthlyWasteUSD)}`);

        if (policyResult.violations.length > 0) {
          log(`\n❌ Policy violations:`);
          for (const v of policyResult.violations) {
            log(`  [${v.rule}] ${v.message}`);
          }
        }

        return policyResult.exitCode;
      }

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
            checkpointUri: checkpoint,
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

        const hasUnprotectedFleet = fleetResult.bucketResults.some(
          (b) => b.status === "AUDITED" && (!b.lifecycleAudit?.hasCoveringRule || (b.lifecycleAudit?.ghostRulesDetected && b.lifecycleAudit.ghostRulesDetected.length > 0))
        );
        if (hasUnprotectedFleet) {
          log(`\n💡 Tip: Run \`s3-guardian remediate --all-buckets\` to generate Terraform/CloudFormation fix.`);
        }

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

      const [scanResult, lifecycleAudit, versionResult] = await Promise.all([
        scanMultipartUploads(client, bucketArg, { olderThanDays, endpoint, prefix }),
        auditBucketLifecycle(client, bucketArg, endpoint),
        includeVersions
          ? scanObjectVersions(client, bucketArg, { olderThanDays, prefix })
          : Promise.resolve(null),
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

      let versionDeletions: VersionDeletionEntry[] | undefined;
      if (versionResult) {
        versionDeletions = [
          ...versionResult.noncurrentVersions.map((v) => ({
            key: v.key,
            versionId: v.versionId,
            type: "NONCURRENT_VERSION" as const,
            size: v.size,
            lastModified: v.lastModified,
          })),
          ...versionResult.expiredDeleteMarkers.map((dm) => ({
            key: dm.key,
            versionId: dm.versionId,
            type: "EXPIRED_DELETE_MARKER" as const,
            size: 0,
            lastModified: dm.lastModified,
          })),
        ];
      }

      const blastRadiusTargets: BlastRadiusTargetItem[] = [
        ...enrichedUploads.map((u) => ({ key: u.key, timestamp: u.initiated })),
        ...(versionDeletions ?? []).map((v) => ({ key: v.key, timestamp: v.lastModified })),
      ];

      const blastRadiusAudit = await assessBucketBlastRadius(client, bucketArg, {
        targets: blastRadiusTargets,
        bypassGovernance: values["bypass-governance"] === true,
        acknowledgeReplicationDivergence: values["acknowledge-replication-divergence"] === true,
        allowActiveChurn: values["allow-active-churn"] === true,
        now,
      });

      const plan: Plan = createPlan({
        bucket: bucketArg,
        endpoint,
        olderThanDays,
        uploads: enrichedUploads,
        versionDeletions,
        lifecycleAudit,
        blastRadiusAudit,
      });

      await writePlanFile(outFile, plan);

      log(`\nPlan generated successfully!`);
      log(`  Schema Version:           ${plan.schemaVersion}`);
      log(`  Bucket:                   ${bucketArg}`);
      log(`  Zombie Uploads:           ${plan.totalZombieUploads}`);
      log(`  Total Stranded Storage:   ${formatBytes(plan.totalStrandedBytes)}`);
      log(`  Estimated Monthly Waste:  ${formatMonthlyCost(plan.estimatedMonthlyWasteUSD)}`);

      if (plan.versionDeletions && plan.versionDeletions.length > 0) {
        log(`  Noncurrent Versions:      ${plan.totalNoncurrentVersions ?? 0}`);
        log(`  Expired Delete Markers:   ${plan.totalExpiredDeleteMarkers ?? 0}`);
        log(`  Versioning Monthly Waste: ${formatMonthlyCost(plan.versioningMonthlyWasteUSD ?? 0)}`);
      }

      log(`  Blast Radius Risk:        ${blastRadiusAudit.riskLevel}`);
      if (plan.planHash) {
        log(`  Plan SHA-256 (RFC 8785):  ${plan.planHash}`);
      }

      log(`  Plan File:                ${outFile}`);

      if (blastRadiusAudit.findings.length > 0) {
        log(`\n🛡️  Blast Radius Assessment:`);
        for (const f of blastRadiusAudit.findings) {
          const icon = f.risk === "CRITICAL_BLOCKED" ? "⛔" : f.risk === "HIGH" ? "⚠️ " : "ℹ️ ";
          log(`  ${icon} [${f.code}] ${f.message}`);
        }
      }

      if (lifecycleAudit.providerNotes) {
        log(`\nℹ️  Lifecycle Note: ${lifecycleAudit.providerNotes}`);
      } else if (!lifecycleAudit.hasCoveringRule) {
        log(`\n[!] Lifecycle Audit: Bucket has NO lifecycle rule covering multipart uploads.`);
        log(`💡 Tip: Run \`s3-guardian remediate ${bucketArg}\` to generate Terraform/CloudFormation fix.`);
      }
      for (const ghost of lifecycleAudit.ghostRulesDetected) {
        log(`[!] Ghost Rule: ${ghost}`);
      }
      if (lifecycleAudit.ghostRulesDetected.length > 0 && lifecycleAudit.hasCoveringRule) {
        log(`💡 Tip: Run \`s3-guardian remediate ${bucketArg}\` to generate Terraform/CloudFormation fix.`);
      }

      if (plan.highVolumeWarning) {
        log(`\n⚠️  ${plan.highVolumeWarning}`);
      }

      const totalItemsToClean =
        plan.totalZombieUploads + (plan.versionDeletions?.length ?? 0);

      if (totalItemsToClean > 0) {
        log("\nNext steps:");
        log(`  Inspect '${outFile}' to verify targeted deletions.`);
        log(`  To safely execute these deletions, run:`);
        log(`  $ s3-guardian apply --plan ${outFile} --confirm\n`);
      } else {
        log(`\nBucket is clean. No items scheduled for deletion.`);
      }

      return EXIT_CODES.SUCCESS;
    }

    // ── REMEDIATE ─────────────────────────────────────────────────────────────
    case "remediate": {
      const daysStr = getString(values.days) ?? getString(values["older-than"]) ?? "7";
      const days = parseInt(daysStr, 10);
      if (isNaN(days) || days < 1) {
        error("Error: --days must be a positive integer");
        return EXIT_CODES.ARG_ERROR;
      }

      const formatVal = getString(values.format)?.toLowerCase();
      const iacFormat: IacFormat =
        formatVal === "cloudformation" || formatVal === "cfn"
          ? "cloudformation"
          : "terraform";

      const outIac = getString(values["out-iac"]);
      const dangerDirect = values["danger-direct-api-apply"] === true;

      // Fleet remediation
      if (allBuckets) {
        if (dangerDirect) {
          log(`⚠️  Direct API Remediation: applying lifecycle rule across all account buckets...`);
          const pool = new S3ClientPool();
          try {
            const discoveryClient = createS3Client(clientConfig);
            const fleetResult = await scanFleet({
              olderThanDays: days,
              prefix,
              excludeBuckets,
              excludeRegions,
              endpoint,
              discoveryClient,
              clientPool: pool,
              checkpointUri: checkpoint,
            });

            const eligibleBuckets = fleetResult.bucketResults.filter(
              (b) =>
                b.status === "AUDITED" &&
                (!b.lifecycleAudit?.hasCoveringRule ||
                  (b.lifecycleAudit?.ghostRulesDetected && b.lifecycleAudit.ghostRulesDetected.length > 0))
            );

            if (eligibleBuckets.length === 0) {
              log(`✅ All audited buckets already have active, valid lifecycle rules.`);
              return EXIT_CODES.SUCCESS;
            }

            log(`Found ${eligibleBuckets.length} bucket(s) requiring remediation.`);
            let appliedCount = 0;
            for (const b of eligibleBuckets) {
              const bClient = pool.getClient(b.region ?? "us-east-1");
              const res = await applyLifecycleRuleDirectly(bClient, b.bucket, days, {
                dangerDirectApiApply: true,
              });
              appliedCount++;
              log(`  [${appliedCount}/${eligibleBuckets.length}] Applied rule to '${b.bucket}' (${res.action}, total rules: ${res.totalRules})`);
              if (res.ghostRuleWarning) {
                log(`    ⚠️  ${res.ghostRuleWarning}`);
              }
            }
            log(`\n✅ Direct API remediation applied to ${appliedCount} bucket(s).`);
            return EXIT_CODES.SUCCESS;
          } catch (err) {
            if (err instanceof DiscoveryAuthError) {
              error(`\n❌ Discovery failed: ${err.message}`);
              return EXIT_CODES.DISCOVERY_AUTH_ERROR;
            }
            throw err;
          } finally {
            await pool.destroy();
          }
        } else {
          log(`📝 Fleet Remediation: generating ${iacFormat.toUpperCase()} code for all account buckets...`);
          const discoveryClient = createS3Client(clientConfig);
          let allBucketsList: { Name?: string }[];
          try {
            const { ListBucketsCommand } = await import("@aws-sdk/client-s3");
            const listResponse = await discoveryClient.send(new ListBucketsCommand({}));
            allBucketsList = listResponse.Buckets ?? [];
          } catch (err: unknown) {
            error(`\n❌ Discovery failed: ${err instanceof Error ? err.message : String(err)}`);
            return EXIT_CODES.DISCOVERY_AUTH_ERROR;
          }

          let bucketNames = allBucketsList
            .map((b) => b.Name)
            .filter((n): n is string => Boolean(n));

          if (excludeBuckets.length > 0) {
            const { matchesExcludePattern } = await import("./fleet/scanner.js");
            bucketNames = bucketNames.filter(
              (name) => !matchesExcludePattern(name, excludeBuckets)
            );
          }

          if (bucketNames.length === 0) {
            log(`No matching buckets found to remediate.`);
            return EXIT_CODES.SUCCESS;
          }

          const output = await formatOrSaveIac(bucketNames, {
            format: iacFormat,
            daysAfterInitiation: days,
            includeVersioning: includeVersions,
            outIac,
          });

          if (outIac) {
            log(`\n✅ Generated ${iacFormat.toUpperCase()} configuration for ${bucketNames.length} bucket(s) saved to: ${outIac}`);
          } else {
            log(output);
          }
          return EXIT_CODES.SUCCESS;
        }
      }

      // Single-bucket remediation
      if (!bucketArg) {
        error("Error: Bucket name is required for 'remediate'. Usage: s3-guardian remediate <bucket> [options]");
        return EXIT_CODES.ARG_ERROR;
      }

      if (dangerDirect) {
        log(`⚠️  Executing direct API lifecycle policy update for bucket '${bucketArg}'...`);
        const client = createS3Client(clientConfig);
        const result = await applyLifecycleRuleDirectly(client, bucketArg, days, {
          dangerDirectApiApply: true,
        });

        log(`\n✅ Direct API remediation complete for '${bucketArg}'.`);
        log(`   Applied rule 's3-guardian-abort-mpu' (Status: Enabled, DaysAfterInitiation: ${days}).`);
        log(`   Action: ${result.action} rule. Total active rules: ${result.totalRules} (preserved ${result.preservedRuleIds.length} existing rule(s)).`);
        if (result.ghostRuleWarning) {
          log(`   ⚠️  Warning: ${result.ghostRuleWarning}`);
        }
        return EXIT_CODES.SUCCESS;
      }

      const output = await formatOrSaveIac(bucketArg, {
        format: iacFormat,
        daysAfterInitiation: days,
        includeVersioning: includeVersions,
        outIac,
      });

      if (outIac) {
        log(`✅ Generated ${iacFormat.toUpperCase()} snippet saved to: ${outIac}`);
      } else {
        log(output);
      }
      return EXIT_CODES.SUCCESS;
    }

    // ── APPLY ─────────────────────────────────────────────────────────────────
    case "apply": {
      const planFile =
        getString(values.plan) ||
        (typeof positionals[1] === "string" ? positionals[1] : undefined);
      if (!planFile) {
        error("Error: --plan <file> is required for 'apply'. Usage: s3-guardian apply --plan <file> --confirm");
        return EXIT_CODES.ARG_ERROR;
      }

      if (values.confirm !== true) {
        error(
          "\n❌ Safety check failed: The '--confirm' flag is strictly required to execute aborts or version deletions.\n" +
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

      const integrity = verifyPlanIntegrity(plan);
      if (!integrity.valid) {
        error(`\n❌ Cryptographic Plan Integrity Violation: ${integrity.error}`);
        return EXIT_CODES.POLICY_VIOLATION;
      }

      const hasUploads = plan.uploads && plan.uploads.length > 0;
      const hasVersions = plan.versionDeletions && plan.versionDeletions.length > 0;

      if (!hasUploads && !hasVersions) {
        log("Plan contains 0 items to delete. Nothing to do.");
        return EXIT_CODES.SUCCESS;
      }

      if (plan.highVolumeWarning) {
        log(`\n⚠️  ${plan.highVolumeWarning}`);
      }

      const effectiveClientConfig = {
        region,
        endpoint: endpoint ?? plan.endpoint ?? undefined,
        forcePathStyle,
      };
      const client = createS3Client(effectiveClientConfig);

      // Pre-flight Blast Radius Simulation
      log(`🛡️  Running pre-flight blast radius assessment on '${plan.bucket}'...`);
      const blastRadiusTargets: BlastRadiusTargetItem[] = [
        ...(plan.uploads ?? []).map((u) => ({ key: u.key, timestamp: u.initiated })),
        ...(plan.versionDeletions ?? []).map((v) => ({ key: v.key, timestamp: v.lastModified })),
      ];

      const bypassGov = values["bypass-governance"] === true;
      const ackRepl = values["acknowledge-replication-divergence"] === true;
      const allowChurn = values["allow-active-churn"] === true;

      const blastRadius = await assessBucketBlastRadius(client, plan.bucket, {
        targets: blastRadiusTargets,
        bypassGovernance: bypassGov,
        acknowledgeReplicationDivergence: ackRepl,
        allowActiveChurn: allowChurn,
      });

      if (blastRadius.isBlocked) {
        error(`\n❌ Pre-flight blast radius check BLOCKED execution on bucket '${plan.bucket}':`);
        for (const f of blastRadius.findings.filter((f) => f.risk === "CRITICAL_BLOCKED")) {
          error(`   ⛔ [${f.code}] ${f.message}`);
        }
        return EXIT_CODES.POLICY_VIOLATION;
      }

      if (blastRadius.requiresGovernanceBypass) {
        error(`\n❌ S3 Object Lock GOVERNANCE mode is active on bucket '${plan.bucket}'.`);
        error(`   Permanent version deletions require the '--bypass-governance' flag.`);
        return EXIT_CODES.POLICY_VIOLATION;
      }

      if (blastRadius.requiresReplicationAck) {
        error(`\n❌ Active replication (CRR/SRR) detected on bucket '${plan.bucket}'.`);
        error(`   Permanent version purges do NOT replicate across buckets, which will cause replica divergence.`);
        error(`   Pass '--acknowledge-replication-divergence' to proceed.`);
        return EXIT_CODES.POLICY_VIOLATION;
      }

      const unacknowledgedHigh = blastRadius.findings.filter((f) => f.risk === "HIGH");
      if (unacknowledgedHigh.length > 0) {
        error(`\n❌ Pre-flight safety check failed (HIGH risk detected):`);
        for (const f of unacknowledgedHigh) {
          error(`   ⚠️  [${f.code}] ${f.message}`);
        }
        return EXIT_CODES.POLICY_VIOLATION;
      }

      let hadErrors = false;

      // 1. Execute multipart upload aborts
      if (hasUploads) {
        log(`Executing abort operations for bucket '${plan.bucket}' (${plan.uploads.length} upload(s))...`);
        const abortResult = await executeAbortPlan(client, plan, {
          confirm: true,
          onProgress: (completed, total, item, status, correlation) => {
            const trace = correlation?.requestId
              ? ` [x-amz-request-id: ${correlation.requestId}]`
              : "";
            if (status === "SKIPPED_ALREADY_ABORTED") {
              log(`  [${completed}/${total}] Skipped '${item.key}' (UploadId: ${item.uploadId}) — already aborted or completed${trace}`);
            } else if (status === "FAILED") {
              log(`  [${completed}/${total}] Failed '${item.key}' (UploadId: ${item.uploadId})${trace}`);
            } else {
              log(`  [${completed}/${total}] Aborted '${item.key}' (UploadId: ${item.uploadId})${trace}`);
            }
          },
        });

        log("\nMultipart Upload cleanup summary:");
        log(`  Total Targeted:       ${abortResult.total}`);
        log(`  Successfully aborted: ${abortResult.aborted}`);
        if (abortResult.skipped > 0) {
          log(`  Skipped (already aborted): ${abortResult.skipped}`);
        }
        log(`  Failed:               ${abortResult.failed}`);
        log(`  Storage Freed:        ${formatBytes(abortResult.bytesFreed)}`);

        if (abortResult.errors.length > 0) {
          hadErrors = true;
          log("\nErrors encountered during abort:");
          for (const e of abortResult.errors) {
            log(`  - Key: ${e.key}, UploadId: ${e.uploadId}: ${e.error}`);
          }
        }
      }

      // 2. Execute version deletions
      if (hasVersions) {
        log(`\nExecuting version deletions for bucket '${plan.bucket}' (${plan.versionDeletions!.length} item(s))...`);
        const entries = plan.versionDeletions!.map((v) => ({
          Key: v.key,
          VersionId: v.versionId,
        }));

        const passBypassGov = Boolean(
          blastRadius.objectLock?.mode === "GOVERNANCE" && bypassGov
        );

        const versionResult = await executeVersionDeletion(
          client,
          plan.bucket,
          entries,
          {
            confirm: true,
            bypassGovernance: passBypassGov,
            onProgress: (deleted, total, correlation) => {
              const trace = correlation?.requestId
                ? ` [x-amz-request-id: ${correlation.requestId}]`
                : "";
              log(`  [${deleted}/${total}] Deleted object versions...${trace}`);
            },
          }
        );

        log("\nVersion Deletion summary:");
        log(`  Total Targeted:       ${versionResult.total}`);
        log(`  Successfully deleted: ${versionResult.deleted}`);
        log(`  Failed:               ${versionResult.failed}`);

        if (versionResult.errors.length > 0) {
          hadErrors = true;
          log("\nErrors encountered during version deletion:");
          for (const e of versionResult.errors) {
            log(`  - Key: ${e.Key}, VersionId: ${e.VersionId}: ${e.Message ?? e.Code}`);
          }
        }
      }

      if (hadErrors) {
        return EXIT_CODES.POLICY_VIOLATION;
      }

      log("\n✅ Done! Cleanup completed successfully.");
      return EXIT_CODES.SUCCESS;
    }

    // ── LENS ─────────────────────────────────────────────────────────────────
    case "lens": {
      const sourceArg =
        (typeof positionals[1] === "string" ? positionals[1] : undefined) ||
        getString(values.source);

      if (!sourceArg) {
        error("Error: <source> is required for 'lens'. Usage: s3-guardian lens <path-or-s3-uri>");
        return EXIT_CODES.ARG_ERROR;
      }

      if (!isJson) {
        log(`🔍 Reading Storage Lens export from '${sourceArg}'...`);
      }

      const client = createS3Client(clientConfig);
      let metrics: StorageLensBucketMetrics[];

      try {
        metrics = await readStorageLensMetrics(client, sourceArg, {
          top,
          minWasteUSD,
        });
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        error(`\n❌ Failed to read Storage Lens metrics: ${msg}`);
        return EXIT_CODES.ARG_ERROR;
      }

      if (isJson) {
        log(JSON.stringify(metrics, null, 2));
        return EXIT_CODES.SUCCESS;
      }

      if (metrics.length === 0) {
        log("\nNo bucket metrics found matching criteria.");
        return EXIT_CODES.SUCCESS;
      }

      log(`\nStorage Lens Triage & Ranking (Top ${metrics.length}):\n`);
      renderLensTable(metrics, log);

      const topOffender = metrics[0]?.bucketName;
      log(
        `\n💡 Tip: Run 's3-guardian scan ${topOffender} --include-versions' to inspect and generate a plan for the top offenders.\n`
      );

      return EXIT_CODES.SUCCESS;
    }

    // ── DRIFT ────────────────────────────────────────────────────────────────
    case "drift": {
      const bucketName = bucketArg;
      if (!bucketName) {
        error("Error: Bucket name is required for 'drift'. Usage: s3-guardian drift <bucket> [options]");
        return EXIT_CODES.ARG_ERROR;
      }

      const tfFile = getString(values["tf-file"]);
      const tfStateFile = getString(values.tfstate);
      const isPatch = values.patch === true;
      const isWrite = values.write === true;

      if (!tfFile && !tfStateFile) {
        error("Error: Either --tf-file <path> or --tfstate <path> must be provided for 'drift'");
        return EXIT_CODES.ARG_ERROR;
      }

      if (tfFile && !fsSync.existsSync(tfFile)) {
        error(`Error: Target Terraform file not found: '${tfFile}'`);
        return EXIT_CODES.ARG_ERROR;
      }

      if (tfStateFile && !fsSync.existsSync(tfStateFile)) {
        error(`Error: Target Terraform state file not found: '${tfStateFile}'`);
        return EXIT_CODES.ARG_ERROR;
      }

      if (isWrite && !tfFile) {
        error("Error: --write requires --tf-file <path> to apply the patch");
        return EXIT_CODES.ARG_ERROR;
      }

      const client = createS3Client(clientConfig);
      let driftResult: LifecycleDriftResult;

      try {
        driftResult = await detectLifecycleDrift(client, bucketName, {
          tfFile,
          tfStateFile,
          generatePatch: true,
          prefix,
        });
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        error(`\n❌ Drift detection failed: ${msg}`);
        return EXIT_CODES.ARG_ERROR;
      }

      if (isWrite) {
        if (driftResult.patchedTfContent && tfFile && driftResult.patch) {
          try {
            await fsPromises.writeFile(tfFile, driftResult.patchedTfContent, "utf8");
            log(`\n✅ Successfully applied drift remediation patch to '${tfFile}'`);
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            error(`\n❌ Failed to write patched file '${tfFile}': ${msg}`);
            return EXIT_CODES.ARG_ERROR;
          }
        } else {
          log(`\nℹ️  No changes needed for '${tfFile}'. File is already up to date.`);
        }
      }

      if (isPatch) {
        if (driftResult.patch) {
          log(driftResult.patch.trimEnd());
        } else {
          log("# No drift detected; files are in sync.");
        }
        return EXIT_CODES.SUCCESS;
      }

      if (isJson) {
        log(JSON.stringify(driftResult, null, 2));
        return driftResult.isDrifted ? EXIT_CODES.POLICY_VIOLATION : EXIT_CODES.SUCCESS;
      }

      log(`\n🔍 S3 Lifecycle Drift Assessment: '${bucketName}'\n`);
      renderDriftTable(driftResult, log);

      if (driftResult.differences.length > 0) {
        log(`\nDrift Details & Safety Gaps (${driftResult.differences.length}):`);
        for (const diff of driftResult.differences) {
          log(`  - ${diff}`);
        }
      }

      if (driftResult.patch && tfFile) {
        if (!isWrite) {
          log(
            `\n💡 Tip: Run \`s3-guardian drift ${bucketName} --tf-file ${tfFile} --patch\` to view unified diff patch, or \`--write\` to apply automatically.\n`
          );
        }
      }

      return driftResult.isDrifted ? EXIT_CODES.POLICY_VIOLATION : EXIT_CODES.SUCCESS;
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
