import { STSSessionPool } from "../auth/sts-pool.js";
import { OrganizationAccount } from "../discovery/organizations.js";
import { S3ClientPool } from "../discovery/client-pool.js";
import { scanFleet, FleetScanResult, DiscoveryAuthError } from "../fleet/scanner.js";
import { createS3Client } from "../client.js";
import { scanObjectVersions, VersionScanResult } from "../versioning/scanner.js";
import { createConcurrencyLimiter } from "../utils/concurrency.js";
import { RetryOptions } from "../utils/retry.js";

export type AccountStatus =
  | "SUCCESS"
  | "PARTIAL"
  | "SKIPPED_ASSUME_ROLE_FAILED"
  | "SKIPPED_ACCESS_DENIED"
  | "ERROR";

export interface AccountSweepResult {
  accountId: string;
  accountName: string;
  status: AccountStatus;
  bucketsDiscovered: number;
  bucketsAudited: number;
  bucketsSkipped: number;
  totalZombieUploads: number;
  totalStrandedBytes: number;
  totalEstimatedMonthlyWasteUSD: number;
  totalNoncurrentVersions?: number;
  totalNoncurrentBytes?: number;
  totalExpiredDeleteMarkers?: number;
  versioningMonthlyWasteUSD?: number;
  totalMonthlyWasteUSD: number;
  fleetResult?: FleetScanResult;
  versionResults?: Record<string, VersionScanResult>;
  errorMessage?: string;
}

export interface MultiAccountSweepResult {
  totalAccounts: number;
  accountsScanned: number;
  accountsSucceeded: number;
  accountsSkipped: number;
  totalBucketsDiscovered: number;
  totalBucketsAudited: number;
  totalBucketsSkipped: number;
  totalZombieUploads: number;
  totalStrandedBytes: number;
  totalEstimatedMonthlyWasteUSD: number;
  totalNoncurrentVersions?: number;
  totalNoncurrentBytes?: number;
  totalExpiredDeleteMarkers?: number;
  totalVersioningWasteUSD?: number;
  totalCombinedMonthlyWasteUSD: number;
  accountResults: AccountSweepResult[];
}

export interface MultiAccountSweepOptions {
  accounts: Array<OrganizationAccount | string>;
  roleName: string;
  externalId?: string;
  sessionDurationSeconds?: number;
  accountConcurrency?: number;
  bucketConcurrency?: number;
  olderThanDays?: number;
  prefix?: string;
  includeVersions?: boolean;
  excludeBuckets?: string[];
  excludeRegions?: string[];
  endpoint?: string | null;
  now?: Date;
  retryOptions?: RetryOptions;
  stsPool?: STSSessionPool;
  onAccountStart?: (account: OrganizationAccount) => void;
  onAccountComplete?: (result: AccountSweepResult) => void;
}

function normalizeAccount(account: OrganizationAccount | string): OrganizationAccount {
  if (typeof account === "string") {
    return {
      id: account,
      name: account,
      status: "ACTIVE",
    };
  }
  return account;
}

/**
 * Sweeps an individual account using dedicated assumed-role credentials and isolated client pools.
 * Invariants:
 *  - Fault isolation: Failures on this account never affect other accounts.
 *  - Credential isolation: Regional clients use explicit assumed-role credentials and are destroyed cleanly.
 */
async function sweepOneAccount(
  account: OrganizationAccount,
  options: MultiAccountSweepOptions,
  stsPool: STSSessionPool
): Promise<AccountSweepResult> {
  const { id: accountId, name: accountName } = account;
  let accountPool: S3ClientPool | undefined;

  try {
    // ── Step 1: Assume role via STS pool ──────────────────────────────────────
    let creds;
    try {
      creds = await stsPool.assumeRole({
        accountId,
        roleName: options.roleName,
        externalId: options.externalId,
        durationSeconds: options.sessionDurationSeconds,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        accountId,
        accountName,
        status: "SKIPPED_ASSUME_ROLE_FAILED",
        bucketsDiscovered: 0,
        bucketsAudited: 0,
        bucketsSkipped: 0,
        totalZombieUploads: 0,
        totalStrandedBytes: 0,
        totalEstimatedMonthlyWasteUSD: 0,
        totalMonthlyWasteUSD: 0,
        errorMessage: `Failed to assume role ${options.roleName} in account ${accountId}: ${msg}`,
      };
    }

    // ── Step 2: Build isolated static credentials and client pool ─────────────
    const staticCredentials = {
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
      sessionToken: creds.sessionToken,
      expiration: creds.expiration,
    };

    accountPool = new S3ClientPool({ credentials: staticCredentials });
    const discoveryClient = createS3Client({
      credentials: staticCredentials,
      endpoint: options.endpoint ?? undefined,
      region: "us-east-1",
    });

    // ── Step 3: Run fleet audit on the account ────────────────────────────────
    let fleetResult: FleetScanResult;
    try {
      fleetResult = await scanFleet({
        olderThanDays: options.olderThanDays,
        prefix: options.prefix,
        bucketConcurrency: options.bucketConcurrency ?? 5,
        excludeBuckets: options.excludeBuckets,
        excludeRegions: options.excludeRegions,
        now: options.now,
        endpoint: options.endpoint,
        retryOptions: options.retryOptions,
        discoveryClient,
        clientPool: accountPool,
      });
    } catch (err: unknown) {
      if (err instanceof DiscoveryAuthError) {
        return {
          accountId,
          accountName,
          status: "SKIPPED_ACCESS_DENIED",
          bucketsDiscovered: 0,
          bucketsAudited: 0,
          bucketsSkipped: 0,
          totalZombieUploads: 0,
          totalStrandedBytes: 0,
          totalEstimatedMonthlyWasteUSD: 0,
          totalMonthlyWasteUSD: 0,
          errorMessage: err.message,
        };
      }
      throw err;
    }

    // ── Step 4: Optional Versioning Scan ──────────────────────────────────────
    let totalNoncurrentVersions = 0;
    let totalNoncurrentBytes = 0;
    let totalExpiredDeleteMarkers = 0;
    let versioningMonthlyWasteUSD = 0;
    const versionResults: Record<string, VersionScanResult> = {};

    if (options.includeVersions) {
      const auditedBuckets = fleetResult.bucketResults.filter(
        (b) => b.status === "AUDITED"
      );

      for (const b of auditedBuckets) {
        try {
          const client = accountPool.getClient(b.region || "us-east-1");
          const vResult = await scanObjectVersions(client, b.bucket, {
            olderThanDays: options.olderThanDays,
            prefix: options.prefix,
            now: options.now,
            retryOptions: options.retryOptions,
          });

          versionResults[b.bucket] = vResult;
          totalNoncurrentVersions += vResult.noncurrentVersionsCount;
          totalNoncurrentBytes += vResult.noncurrentBytes;
          totalExpiredDeleteMarkers += vResult.expiredDeleteMarkersCount;
          versioningMonthlyWasteUSD += vResult.estimatedMonthlyWasteUSD;
        } catch {
          // Individual bucket version scan failure is isolated
        }
      }
    }

    // ── Step 5: Derive status and aggregate ───────────────────────────────────
    const totalMonthlyWasteUSD =
      fleetResult.totalEstimatedMonthlyWasteUSD +
      (options.includeVersions ? versioningMonthlyWasteUSD : 0);

    let status: AccountStatus = "SUCCESS";
    if (fleetResult.bucketsDiscovered > 0 && fleetResult.bucketsAudited < fleetResult.bucketsDiscovered) {
      status = "PARTIAL";
    }

    return {
      accountId,
      accountName,
      status,
      bucketsDiscovered: fleetResult.bucketsDiscovered,
      bucketsAudited: fleetResult.bucketsAudited,
      bucketsSkipped: fleetResult.bucketsSkipped,
      totalZombieUploads: fleetResult.totalZombieUploads,
      totalStrandedBytes: fleetResult.totalStrandedBytes,
      totalEstimatedMonthlyWasteUSD: fleetResult.totalEstimatedMonthlyWasteUSD,
      totalNoncurrentVersions: options.includeVersions ? totalNoncurrentVersions : undefined,
      totalNoncurrentBytes: options.includeVersions ? totalNoncurrentBytes : undefined,
      totalExpiredDeleteMarkers: options.includeVersions ? totalExpiredDeleteMarkers : undefined,
      versioningMonthlyWasteUSD: options.includeVersions ? versioningMonthlyWasteUSD : undefined,
      totalMonthlyWasteUSD,
      fleetResult,
      versionResults: options.includeVersions ? versionResults : undefined,
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      accountId,
      accountName,
      status: "ERROR",
      bucketsDiscovered: 0,
      bucketsAudited: 0,
      bucketsSkipped: 0,
      totalZombieUploads: 0,
      totalStrandedBytes: 0,
      totalEstimatedMonthlyWasteUSD: 0,
      totalMonthlyWasteUSD: 0,
      errorMessage: `Unexpected error during sweep of account ${accountId}: ${msg}`,
    };
  } finally {
    if (accountPool) {
      await accountPool.destroy();
    }
  }
}

/**
 * Orchestrates multi-account sweeps across member accounts with bounded concurrency
 * and complete credential/fault isolation.
 */
export async function runMultiAccountSweep(
  options: MultiAccountSweepOptions
): Promise<MultiAccountSweepResult> {
  const normalizedAccounts = options.accounts.map(normalizeAccount);
  const concurrency = Math.max(1, Math.min(10, options.accountConcurrency ?? 5));
  const limiter = createConcurrencyLimiter(concurrency);
  const stsPool = options.stsPool ?? new STSSessionPool();
  const ownsStsPool = !options.stsPool;

  try {
    const sweepPromises = normalizedAccounts.map((account) =>
      limiter(async () => {
        options.onAccountStart?.(account);
        const result = await sweepOneAccount(account, options, stsPool);
        options.onAccountComplete?.(result);
        return result;
      })
    );

    const accountResults = await Promise.all(sweepPromises);

    // Roll up multi-account totals
    let accountsScanned = 0;
    let accountsSucceeded = 0;
    let accountsSkipped = 0;
    let totalBucketsDiscovered = 0;
    let totalBucketsAudited = 0;
    let totalBucketsSkipped = 0;
    let totalZombieUploads = 0;
    let totalStrandedBytes = 0;
    let totalEstimatedMonthlyWasteUSD = 0;
    let totalNoncurrentVersions: number | undefined = options.includeVersions ? 0 : undefined;
    let totalNoncurrentBytes: number | undefined = options.includeVersions ? 0 : undefined;
    let totalExpiredDeleteMarkers: number | undefined = options.includeVersions ? 0 : undefined;
    let totalVersioningWasteUSD: number | undefined = options.includeVersions ? 0 : undefined;

    for (const r of accountResults) {
      if (r.status === "SUCCESS" || r.status === "PARTIAL") {
        accountsScanned++;
        if (r.status === "SUCCESS") accountsSucceeded++;
      } else {
        accountsSkipped++;
      }

      totalBucketsDiscovered += r.bucketsDiscovered;
      totalBucketsAudited += r.bucketsAudited;
      totalBucketsSkipped += r.bucketsSkipped;
      totalZombieUploads += r.totalZombieUploads;
      totalStrandedBytes += r.totalStrandedBytes;
      totalEstimatedMonthlyWasteUSD += r.totalEstimatedMonthlyWasteUSD;

      if (options.includeVersions) {
        totalNoncurrentVersions! += r.totalNoncurrentVersions ?? 0;
        totalNoncurrentBytes! += r.totalNoncurrentBytes ?? 0;
        totalExpiredDeleteMarkers! += r.totalExpiredDeleteMarkers ?? 0;
        totalVersioningWasteUSD! += r.versioningMonthlyWasteUSD ?? 0;
      }
    }

    const totalCombinedMonthlyWasteUSD =
      totalEstimatedMonthlyWasteUSD + (totalVersioningWasteUSD ?? 0);

    return {
      totalAccounts: normalizedAccounts.length,
      accountsScanned,
      accountsSucceeded,
      accountsSkipped,
      totalBucketsDiscovered,
      totalBucketsAudited,
      totalBucketsSkipped,
      totalZombieUploads,
      totalStrandedBytes,
      totalEstimatedMonthlyWasteUSD,
      totalNoncurrentVersions,
      totalNoncurrentBytes,
      totalExpiredDeleteMarkers,
      totalVersioningWasteUSD,
      totalCombinedMonthlyWasteUSD,
      accountResults,
    };
  } finally {
    if (ownsStsPool) {
      await stsPool.destroy();
    }
  }
}
