import {
  S3Client,
  GetObjectLockConfigurationCommand,
  GetBucketReplicationCommand,
  GetBucketTaggingCommand,
} from "@aws-sdk/client-s3";

export type BlastRadiusRisk = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL_BLOCKED";

export interface BlastRadiusFinding {
  code: string;
  message: string;
  risk: BlastRadiusRisk;
  details?: Record<string, unknown>;
}

export interface BlastRadiusTargetItem {
  key: string;
  timestamp?: string | Date | number;
}

export interface BlastRadiusOptions {
  targets?: BlastRadiusTargetItem[];
  targetKeys?: string[];
  bypassGovernance?: boolean;
  acknowledgeReplicationDivergence?: boolean;
  allowActiveChurn?: boolean;
  now?: Date;
}

export interface BlastRadiusAssessment {
  bucket: string;
  riskLevel: BlastRadiusRisk;
  isBlocked: boolean;
  requiresGovernanceBypass: boolean;
  requiresReplicationAck: boolean;
  findings: BlastRadiusFinding[];
  objectLock?: {
    enabled: boolean;
    mode?: "COMPLIANCE" | "GOVERNANCE";
  };
  replication?: {
    enabled: boolean;
    ruleCount: number;
    hasDeleteMarkerReplication: boolean;
  };
  tags?: Record<string, string>;
  evaluatedAt: string;
}

export const PROTECTED_PREFIXES: readonly string[] = [
  "checkpoints/",
  "savepoints/",
  "_wal/",
  "manifests/",
  "iceberg/",
  "glue-shuffle-data/",
  "terraform/",
  "state/",
];

const TWENTY_FOUR_HOURS_MS = 24 * 60 * 60 * 1000;

function isNotFoundError(err: unknown): boolean {
  if (!err || typeof err !== "object") return false;
  const e = err as Record<string, unknown>;
  const name = String(e.name || e.Code || "");
  const status =
    (e.$metadata as Record<string, unknown> | undefined)?.httpStatusCode ??
    e.statusCode ??
    e.status;

  return (
    status === 404 ||
    name === "NoSuchObjectLockConfiguration" ||
    name === "ObjectLockConfigurationNotFoundError" ||
    name === "ReplicationConfigurationNotFoundError" ||
    name === "NoSuchReplicationConfiguration" ||
    name === "NoSuchTagSet" ||
    name === "TagSetNotFoundError"
  );
}

/**
 * Pre-flight blast radius simulation and safety assessment for S3 buckets.
 *
 * Enforces Core Invariants:
 *  1. Object Lock Compliance: COMPLIANCE mode hard-blocks deletions; GOVERNANCE mode requires --bypass-governance.
 *  2. Replication Divergence Guard: Warns that version purges do not replicate across CRR/SRR and requires explicit acknowledgment.
 *  3. Streaming/Pipeline Prefix Guard: Hard-blocks deletions in protected state prefixes (checkpoints, WAL, iceberg, terraform state).
 *  4. Active Churn Protection: Refuses deletion of uploads or versions modified within 24 hours without explicit override.
 *  5. Tag Protection: Respects 's3-guardian:ignore=true', 'Backup=true', and 'Protection=locked'.
 */
export async function assessBucketBlastRadius(
  s3Client: S3Client,
  bucket: string,
  options: BlastRadiusOptions = {}
): Promise<BlastRadiusAssessment> {
  const findings: BlastRadiusFinding[] = [];
  const now = options.now ?? new Date();

  let objectLockInfo: BlastRadiusAssessment["objectLock"] = undefined;
  let replicationInfo: BlastRadiusAssessment["replication"] = undefined;
  let tagsRecord: Record<string, string> | undefined = undefined;

  let requiresGovernanceBypass = false;
  let requiresReplicationAck = false;

  // ── Step 1: Check Object Lock Configuration ───────────────────────────────
  try {
    const lockRes = await s3Client.send(
      new GetObjectLockConfigurationCommand({ Bucket: bucket })
    );

    const config = lockRes.ObjectLockConfiguration;
    if (config && config.ObjectLockEnabled === "Enabled") {
      const mode = config.Rule?.DefaultRetention?.Mode as "COMPLIANCE" | "GOVERNANCE" | undefined;
      objectLockInfo = { enabled: true, mode };

      if (mode === "COMPLIANCE") {
        findings.push({
          code: "BLOCKED_COMPLIANCE_LOCK",
          message: `Bucket "${bucket}" has S3 Object Lock in COMPLIANCE mode. Deletions are strictly prohibited.`,
          risk: "CRITICAL_BLOCKED",
          details: { mode },
        });
      } else if (mode === "GOVERNANCE") {
        if (!options.bypassGovernance) {
          requiresGovernanceBypass = true;
          findings.push({
            code: "GOVERNANCE_LOCK_ACTIVE",
            message: `Bucket "${bucket}" has S3 Object Lock in GOVERNANCE mode. Deletions require the --bypass-governance flag.`,
            risk: "HIGH",
            details: { mode },
          });
        } else {
          findings.push({
            code: "GOVERNANCE_LOCK_BYPASSED",
            message: `Bucket "${bucket}" has S3 Object Lock in GOVERNANCE mode (explicitly bypassed via --bypass-governance).`,
            risk: "MEDIUM",
            details: { mode },
          });
        }
      } else {
        findings.push({
          code: "OBJECT_LOCK_ENABLED",
          message: `Bucket "${bucket}" has S3 Object Lock enabled without default retention rule. Individual objects may be locked.`,
          risk: "MEDIUM",
        });
      }
    }
  } catch (err: unknown) {
    if (!isNotFoundError(err)) {
      // Non-404 error (e.g. AccessDenied on lock configuration)
      findings.push({
        code: "OBJECT_LOCK_CHECK_FAILED",
        message: `Could not verify Object Lock configuration for "${bucket}": ${err instanceof Error ? err.message : String(err)}`,
        risk: "MEDIUM",
      });
    }
  }

  // ── Step 2: Check Bucket Replication (CRR / SRR) ──────────────────────────
  try {
    const replRes = await s3Client.send(
      new GetBucketReplicationCommand({ Bucket: bucket })
    );

    const rules = replRes.ReplicationConfiguration?.Rules ?? [];
    const activeRules = rules.filter((r) => r.Status === "Enabled");

    if (activeRules.length > 0) {
      const hasDeleteMarkerReplication = activeRules.some(
        (r) => r.DeleteMarkerReplication?.Status === "Enabled"
      );

      replicationInfo = {
        enabled: true,
        ruleCount: activeRules.length,
        hasDeleteMarkerReplication,
      };

      if (!options.acknowledgeReplicationDivergence) {
        requiresReplicationAck = true;
        findings.push({
          code: "REPLICATION_DETECTED",
          message:
            `Bucket "${bucket}" has active replication (${activeRules.length} rule(s)). ` +
            `Permanent version purges do NOT replicate to destination replicas, causing replica divergence. ` +
            `You must pass --acknowledge-replication-divergence to proceed.`,
          risk: "HIGH",
          details: { ruleCount: activeRules.length, hasDeleteMarkerReplication },
        });
      } else {
        findings.push({
          code: "REPLICATION_ACKNOWLEDGED",
          message:
            `Bucket "${bucket}" replication divergence acknowledged by operator via --acknowledge-replication-divergence.`,
          risk: "MEDIUM",
          details: { ruleCount: activeRules.length },
        });
      }
    }
  } catch (err: unknown) {
    if (!isNotFoundError(err)) {
      findings.push({
        code: "REPLICATION_CHECK_FAILED",
        message: `Could not verify replication configuration for "${bucket}": ${err instanceof Error ? err.message : String(err)}`,
        risk: "MEDIUM",
      });
    }
  }

  // ── Step 3: Check Bucket Tagging ──────────────────────────────────────────
  try {
    const tagRes = await s3Client.send(
      new GetBucketTaggingCommand({ Bucket: bucket })
    );

    const tagSet = tagRes.TagSet ?? [];
    tagsRecord = {};
    for (const t of tagSet) {
      if (t.Key) tagsRecord[t.Key] = t.Value ?? "";
    }

    for (const [k, v] of Object.entries(tagsRecord)) {
      const lowerKey = k.toLowerCase();
      const lowerVal = v.toLowerCase();

      if (lowerKey === "s3-guardian:ignore" && lowerVal === "true") {
        findings.push({
          code: "PROTECTED_TAG_DETECTED",
          message: `Bucket "${bucket}" has tag "${k}=${v}". Excluded by guardian tag policy.`,
          risk: "CRITICAL_BLOCKED",
          details: { tag: `${k}=${v}` },
        });
      } else if (lowerKey === "backup" && lowerVal === "true") {
        findings.push({
          code: "PROTECTED_TAG_DETECTED",
          message: `Bucket "${bucket}" is tagged as a Backup bucket ("${k}=${v}"). Mutating backup buckets is forbidden.`,
          risk: "CRITICAL_BLOCKED",
          details: { tag: `${k}=${v}` },
        });
      } else if (lowerKey === "protection" && lowerVal === "locked") {
        findings.push({
          code: "PROTECTED_TAG_DETECTED",
          message: `Bucket "${bucket}" has explicit protection lock tag ("${k}=${v}").`,
          risk: "CRITICAL_BLOCKED",
          details: { tag: `${k}=${v}` },
        });
      }
    }
  } catch (err: unknown) {
    if (!isNotFoundError(err)) {
      // Tags not found or access denied
    }
  }

  // ── Step 4: Protected Ingestion/Pipeline Prefix Guard ─────────────────────
  const allTargetKeys: string[] = [];
  if (options.targetKeys) {
    allTargetKeys.push(...options.targetKeys);
  }
  if (options.targets) {
    allTargetKeys.push(...options.targets.map((t) => t.key));
  }

  const violatingKeys: string[] = [];
  for (const key of allTargetKeys) {
    for (const prefix of PROTECTED_PREFIXES) {
      if (key.startsWith(prefix) || key.includes("/" + prefix)) {
        violatingKeys.push(key);
        break;
      }
    }
  }

  if (violatingKeys.length > 0) {
    const sample = violatingKeys.slice(0, 3).join(", ");
    const remaining = violatingKeys.length > 3 ? ` (+${violatingKeys.length - 3} more)` : "";
    findings.push({
      code: "PROTECTED_PREFIX_DETECTED",
      message:
        `Target deletion list contains ${violatingKeys.length} key(s) in protected pipeline/state prefixes: ${sample}${remaining}. ` +
        `Deletions of state/checkpoint data are hard-blocked to prevent stream or pipeline corruption.`,
      risk: "CRITICAL_BLOCKED",
      details: { violatingKeyCount: violatingKeys.length, sampleKeys: violatingKeys.slice(0, 5) },
    });
  }

  // ── Step 5: Active Churn Guard (< 24 Hours) ───────────────────────────────
  if (options.targets && options.targets.length > 0) {
    let recentCount = 0;
    const nowTime = now.getTime();

    for (const target of options.targets) {
      if (!target.timestamp) continue;
      const ts = target.timestamp instanceof Date
        ? target.timestamp.getTime()
        : new Date(target.timestamp).getTime();

      if (!isNaN(ts) && nowTime - ts < TWENTY_FOUR_HOURS_MS) {
        recentCount++;
      }
    }

    if (recentCount > 0) {
      if (!options.allowActiveChurn) {
        findings.push({
          code: "ACTIVE_CHURN_DETECTED",
          message:
            `Detected ${recentCount} item(s) initiated or modified within the last 24 hours. ` +
            `In-flight data pipelines may still be writing these uploads or versions. ` +
            `Pass --allow-active-churn to override.`,
          risk: "HIGH",
          details: { recentCount },
        });
      } else {
        findings.push({
          code: "ACTIVE_CHURN_OVERRIDDEN",
          message:
            `Active churn detected (${recentCount} item(s) < 24h old), overridden via --allow-active-churn.`,
          risk: "MEDIUM",
          details: { recentCount },
        });
      }
    }
  }

  // ── Step 6: Derive Overall Risk Level ─────────────────────────────────────
  let riskLevel: BlastRadiusRisk = "LOW";
  if (findings.some((f) => f.risk === "CRITICAL_BLOCKED")) {
    riskLevel = "CRITICAL_BLOCKED";
  } else if (findings.some((f) => f.risk === "HIGH")) {
    riskLevel = "HIGH";
  } else if (findings.some((f) => f.risk === "MEDIUM")) {
    riskLevel = "MEDIUM";
  }

  return {
    bucket,
    riskLevel,
    isBlocked: riskLevel === "CRITICAL_BLOCKED",
    requiresGovernanceBypass,
    requiresReplicationAck,
    findings,
    objectLock: objectLockInfo,
    replication: replicationInfo,
    tags: tagsRecord,
    evaluatedAt: now.toISOString(),
  };
}
