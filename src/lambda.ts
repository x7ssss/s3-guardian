import { createS3Client } from "./client.js";
import { scanMultipartUploads } from "./scanner/multipart.js";
import { auditBucketLifecycle, evaluateUploadCoverage } from "./lifecycle/audit.js";
import { scanFleet, FleetScanResult } from "./fleet/scanner.js";
import { evaluatePolicy } from "./policy/evaluator.js";
import { S3ClientPool } from "./discovery/client-pool.js";
import {
  dispatchNotification,
  AuditNotificationData,
  WebhookType,
} from "./notifications/dispatcher.js";

export interface LambdaEvent {
  allBuckets?: boolean;
  bucket?: string;
  olderThan?: number;
  maxWasteUsd?: number;
  failOnUnprotected?: boolean;
  webhookUrl?: string;
  webhookType?: WebhookType | string;
  checkpointUri?: string;
  notifyAlways?: boolean;
  prefix?: string;
}

export interface LambdaResult {
  statusCode: number;
  body: Record<string, unknown>;
}

/**
 * Idiomatic AWS Lambda handler for automated serverless sweeps and Cron schedules.
 * Accepts parameters via event payload or environment variables.
 */
export const handler = async (
  event: LambdaEvent = {},
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  _context?: any
): Promise<LambdaResult> => {
  try {
    // 1. Resolve configuration from event or ambient environment variables
    const allBuckets =
      event.allBuckets === true ||
      process.env.S3_GUARDIAN_ALL_BUCKETS === "true";

    const bucket = event.bucket || process.env.S3_GUARDIAN_BUCKET;

    const olderThan =
      event.olderThan ??
      (process.env.S3_GUARDIAN_OLDER_THAN
        ? parseInt(process.env.S3_GUARDIAN_OLDER_THAN, 10)
        : 7);

    const maxWasteUsd =
      event.maxWasteUsd ??
      (process.env.S3_GUARDIAN_MAX_WASTE_USD
        ? parseFloat(process.env.S3_GUARDIAN_MAX_WASTE_USD)
        : undefined);

    const failOnUnprotected =
      event.failOnUnprotected === true ||
      process.env.S3_GUARDIAN_FAIL_ON_UNPROTECTED === "true";

    const webhookUrl =
      event.webhookUrl || process.env.S3_GUARDIAN_WEBHOOK_URL;

    const webhookType =
      event.webhookType || process.env.S3_GUARDIAN_WEBHOOK_TYPE;

    const checkpointUri =
      event.checkpointUri || process.env.S3_GUARDIAN_CHECKPOINT_URI;

    const notifyAlways =
      event.notifyAlways === true ||
      process.env.S3_GUARDIAN_NOTIFY_ALWAYS === "true";

    const prefix = event.prefix;

    if (!allBuckets && !bucket) {
      return {
        statusCode: 400,
        body: {
          error:
            "Invalid configuration: either 'allBuckets: true' or a target 'bucket' must be provided via event or environment variables.",
        },
      };
    }

    // 2. Fleet Mode: scan all account buckets
    if (allBuckets) {
      const pool = new S3ClientPool();
      let fleetResult: FleetScanResult;

      try {
        const discoveryClient = createS3Client({});
        fleetResult = await scanFleet({
          olderThanDays: olderThan,
          prefix,
          checkpointUri,
          discoveryClient,
          clientPool: pool,
        });
      } finally {
        await pool.destroy();
      }

      const policyResult = evaluatePolicy(fleetResult, {
        maxWasteUSD: maxWasteUsd,
        failOnUnprotected,
      });

      if (webhookUrl) {
        const notifData: AuditNotificationData = {
          scope: "fleet",
          target: "all-buckets",
          totalZombieUploads: fleetResult.totalZombieUploads,
          totalStrandedBytes: fleetResult.totalStrandedBytes,
          totalEstimatedMonthlyWasteUSD: fleetResult.totalEstimatedMonthlyWasteUSD,
          bucketsDiscovered: fleetResult.bucketsDiscovered,
          bucketsAudited: fleetResult.bucketsAudited,
          bucketsSkipped: fleetResult.bucketsSkipped,
          policyViolations: policyResult.violations.map((v) => v.message),
        };

        await dispatchNotification(notifData, {
          webhookUrl,
          webhookType,
          notifyAlways,
        });
      }

      return {
        statusCode: 200,
        body: {
          ...fleetResult,
          policyViolations: policyResult.violations,
        },
      };
    }

    // 3. Single Bucket Mode
    const client = createS3Client({});
    const [scanResult, lifecycleAudit] = await Promise.all([
      scanMultipartUploads(client, bucket!, { olderThanDays: olderThan, prefix }),
      auditBucketLifecycle(client, bucket!),
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

    const violations: string[] = [];
    if (maxWasteUsd !== undefined && scanResult.estimatedMonthlyWasteUSD > maxWasteUsd) {
      violations.push(
        `Estimated waste $${scanResult.estimatedMonthlyWasteUSD.toFixed(2)} exceeds threshold $${maxWasteUsd.toFixed(2)}`
      );
    }
    if (failOnUnprotected && !lifecycleAudit.hasCoveringRule && !lifecycleAudit.providerNotes) {
      violations.push(`Bucket '${bucket}' has no active MPU lifecycle rule`);
    }

    if (webhookUrl) {
      const notifData: AuditNotificationData = {
        scope: "bucket",
        target: bucket!,
        totalZombieUploads: scanResult.totalZombieUploads,
        totalStrandedBytes: scanResult.totalStrandedBytes,
        totalEstimatedMonthlyWasteUSD: scanResult.estimatedMonthlyWasteUSD,
        policyViolations: violations,
      };

      await dispatchNotification(notifData, {
        webhookUrl,
        webhookType,
        notifyAlways,
      });
    }

    return {
      statusCode: 200,
      body: {
        ...scanResult,
        uploads: enrichedUploads,
        lifecycleAudit,
        policyViolations: violations,
      },
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      statusCode: 500,
      body: { error: message },
    };
  }
};
