import * as fs from "node:fs";
import * as fsPromises from "node:fs/promises";
import * as path from "node:path";
import {
  S3Client,
  ListBucketsCommand,
  AbortMultipartUploadCommand,
  DeleteObjectsCommand,
  PutObjectCommand,
  GetBucketTaggingCommand,
  GetBucketLocationCommand,
} from "@aws-sdk/client-s3";
import { CircuitBreaker } from "../circuit/breaker.js";
import { executeCanaryGate, CanaryVerificationError } from "../safety/canary.js";
import { assessBucketBlastRadius } from "../safety/blast-radius.js";
import { evaluateMutationCeiling } from "../safety/mutation-budget.js";
import { scanMultipartUploads } from "../scanner/multipart.js";
import { scanObjectVersions } from "../versioning/scanner.js";
import {
  createUndoManifest,
  createDeletionCertificate,
  computeCanonicalStateHash,
} from "../rollback/manifest-generator.js";
import { AuditLogWriter } from "../state/audit-writer.js";
import { createAuditEvent, AuditEvent } from "../state/types.js";
import { createConcurrencyLimiter } from "../utils/concurrency.js";
import { withRetry } from "../utils/retry.js";
import { parsePolicyDocument } from "../policy/parser.js";
import { resolveBucketPolicy } from "../policy/resolver.js";
import { normalizeBucketRegion, US_EAST_1 } from "../discovery/regions.js";
import { acquireDaemonLock, DaemonLock } from "../daemon/lockfile.js";
import { createS3Client } from "../client.js";
import { loadCustomCaCertificates } from "./ca-loader.js";
import type {
  OperatorState,
  OperatorConfig,
  OperatorContext,
  CandidateMutationTarget,
} from "./types.js";
import type { GuardianPolicy, BucketMetadata } from "../policy/types.js";

/**
 * The Autonomous Sovereign Operator executes the 9-phase governance state machine
 * inside a drift-free monotonic async loop.
 *
 * State Transition Cycle:
 * DISCOVERY -> POLICY_MATCH -> BLAST_RADIUS_AUDIT -> CANARY_TEST -> CIRCUIT_VERIFY
 * -> BULK_EXECUTE -> AUDIT_LOG -> UNDO_EXPORT -> SLEEP
 */
export class SovereignOperator {
  public readonly config: Required<
    Pick<
      OperatorConfig,
      | "intervalMs"
      | "maxBlastRadiusPercent"
      | "canaryCount"
      | "maxConcurrency"
      | "stateDir"
    >
  > &
    OperatorConfig;

  private state: OperatorState = "SLEEP";
  private context: OperatorContext;
  private client: S3Client;
  private auditWriter: AuditLogWriter;
  private lock: DaemonLock | null = null;
  private isShuttingDown: boolean = false;
  private isRunning: boolean = false;
  private epochStartNano: bigint = 0n;
  private abortController: AbortController = new AbortController();
  private signalHandlersInstalled: boolean = false;
  private currentPhasePromise: Promise<void> | null = null;

  constructor(config: OperatorConfig) {
    this.config = {
      intervalMs: config.intervalMs ?? 3600000,
      maxBlastRadiusPercent: config.maxBlastRadiusPercent ?? 0.05,
      canaryCount: config.canaryCount ?? 5,
      maxConcurrency: config.maxConcurrency ?? 10,
      stateDir: config.stateDir ?? path.resolve(process.cwd(), ".s3-guardian"),
      policyPath: config.policyPath,
      s3MirrorBucket: config.s3MirrorBucket,
      dryRun: config.dryRun ?? false,
      maxRuns: config.maxRuns,
      targetBucket: config.targetBucket,
      client: config.client,
      logger: config.logger,
      json: config.json ?? false,
      once: config.once ?? false,
      signal: config.signal,
      bypassGovernance: config.bypassGovernance ?? false,
      olderThanDays: config.olderThanDays,
    };

    // Load any enterprise custom CA certificates into Node TLS context
    loadCustomCaCertificates();

    this.client = this.config.client ?? createS3Client();
    this.auditWriter = new AuditLogWriter({ stateDir: this.config.stateDir });

    const primaryTargetBucket = this.config.targetBucket ?? "fleet";
    const breaker = new CircuitBreaker(primaryTargetBucket, "AbortMultipartUpload", {
      initialConcurrency: this.config.maxConcurrency,
      minConcurrency: 1,
    });

    this.context = {
      discoveredBuckets: [],
      discoveredTargets: [],
      policies: [],
      resolvedPolicies: new Map(),
      matchedViolations: [],
      circuitBreaker: breaker,
      blastRadiusAssessments: new Map(),
      undoManifests: [],
      deletionCertificates: [],
      auditEvents: [],
      epoch: 0,
      totalMutations: 0,
      totalBytesFreed: 0,
      lastRunDurationMs: 0,
      isHalted: false,
    };
  }

  public getState(): OperatorState {
    return this.state;
  }

  public getContext(): OperatorContext {
    return this.context;
  }

  private log(message: string): void {
    if (this.config.json) {
      return;
    }
    if (this.config.logger) {
      this.config.logger(message);
    } else {
      console.log(message);
    }
  }

  private logJson(data: Record<string, unknown>): void {
    const payload = JSON.stringify(data);
    if (this.config.logger) {
      this.config.logger(payload);
    } else {
      console.log(payload);
    }
  }

  /**
   * Phase 1: DISCOVERY
   * Paginates targets across accounts/buckets with cursor resumption.
   */
  public async stepDiscovery(): Promise<void> {
    this.state = "DISCOVERY";
    this.log(`[OPERATOR] [${this.state}] Discovering storage targets (epoch ${this.context.epoch})...`);

    this.context.discoveredBuckets = [];
    this.context.discoveredTargets = [];

    let targetBucketNames: string[] = [];

    if (this.config.targetBucket) {
      targetBucketNames = [this.config.targetBucket];
    } else {
      try {
        const listRes = await withRetry(() =>
          this.client.send(new ListBucketsCommand({}))
        );
        targetBucketNames = (listRes.Buckets ?? [])
          .map((b) => b.Name)
          .filter((name): name is string => typeof name === "string" && name.length > 0);
      } catch (err: unknown) {
        this.context.isHalted = true;
        this.context.lastError = err;
        this.context.haltReason = `Discovery failed on ListBuckets: ${err instanceof Error ? err.message : String(err)}`;
        this.state = "HALTED";
        return;
      }
    }

    // Cursor resumption: resume from cursor bucket if set
    if (this.context.cursor) {
      const cursorIdx = targetBucketNames.indexOf(this.context.cursor);
      if (cursorIdx >= 0) {
        targetBucketNames = targetBucketNames.slice(cursorIdx);
      }
    }

    for (const bucketName of targetBucketNames) {
      if (this.isShuttingDown) break;

      try {
        // Resolve region
        let region = US_EAST_1;
        try {
          const locRes = await this.client.send(new GetBucketLocationCommand({ Bucket: bucketName }));
          region = normalizeBucketRegion(locRes.LocationConstraint);
        } catch {
          // Default to us-east-1 if location cannot be resolved
        }

        // Scan incomplete multipart uploads
        const mpuResult = await scanMultipartUploads(this.client, bucketName, { olderThanDays: 0 });
        for (const item of mpuResult.uploads) {
          this.context.discoveredTargets.push({
            bucket: bucketName,
            key: item.key,
            uploadId: item.uploadId,
            initiated: item.initiated,
            bytes: item.bytes,
            reason: "ZOMBIE_MULTIPART_UPLOAD",
          });
        }

        // Scan object versions (noncurrent versions and expired delete markers)
        try {
          const versionResult = await scanObjectVersions(this.client, bucketName, { olderThanDays: 0 });
          for (const item of versionResult.noncurrentVersions) {
            this.context.discoveredTargets.push({
              bucket: bucketName,
              key: item.key,
              versionId: item.versionId,
              size: item.size,
              bytes: item.size,
              lastModified: item.lastModified,
              reason: "NONCURRENT_VERSION",
            });
          }
          for (const item of versionResult.expiredDeleteMarkers) {
            this.context.discoveredTargets.push({
              bucket: bucketName,
              key: item.key,
              versionId: item.versionId,
              size: 0,
              bytes: 0,
              lastModified: item.lastModified,
              reason: "EXPIRED_DELETE_MARKER",
            });
          }
        } catch {
          // Ignore if bucket does not have versioning or lacks permissions
        }

        this.context.discoveredBuckets.push({
          bucket: bucketName,
          region,
          status: "AUDITED",
          zombieUploads: mpuResult.uploads,
          totalZombieUploads: mpuResult.totalZombieUploads,
          totalStrandedBytes: mpuResult.totalStrandedBytes,
          estimatedMonthlyWasteUSD: mpuResult.estimatedMonthlyWasteUSD,
        });

        this.context.cursor = bucketName;
      } catch (err: unknown) {
        this.context.discoveredBuckets.push({
          bucket: bucketName,
          region: null,
          status: "ERROR",
          errorMessage: err instanceof Error ? err.message : String(err),
        });
      }
    }

    this.log(
      `[OPERATOR] [${this.state}] Discovered ${this.context.discoveredBuckets.length} bucket(s), ` +
        `${this.context.discoveredTargets.length} candidate target(s).`
    );
  }

  /**
   * Phase 2: POLICY_MATCH
   * Evaluates discovered inventory against declarative policy (v1.9.0).
   */
  public async stepPolicyMatch(): Promise<void> {
    this.state = "POLICY_MATCH";
    this.log(`[OPERATOR] [${this.state}] Evaluating discovered targets against declarative policy...`);

    this.context.matchedViolations = [];
    this.context.resolvedPolicies.clear();

    // Load policy from file if specified
    if (this.config.policyPath) {
      try {
        const policyContent = await fsPromises.readFile(this.config.policyPath, "utf8");
        const policy = parsePolicyDocument(policyContent);
        this.context.policies = [policy];
      } catch (err: unknown) {
        this.context.isHalted = true;
        this.context.lastError = err;
        this.context.haltReason = `Failed to load policy from ${this.config.policyPath}: ${
          err instanceof Error ? err.message : String(err)
        }`;
        this.state = "HALTED";
        return;
      }
    }

    const now = Date.now();

    for (const b of this.context.discoveredBuckets) {
      if (b.status !== "AUDITED") continue;

      let tags: Record<string, string> = {};
      try {
        const tagRes = await this.client.send(new GetBucketTaggingCommand({ Bucket: b.bucket }));
        for (const t of tagRes.TagSet ?? []) {
          if (t.Key && t.Value) tags[t.Key] = t.Value;
        }
      } catch {
        // TagSet not found or forbidden
      }

      const metadata: BucketMetadata = {
        name: b.bucket,
        region: b.region ?? US_EAST_1,
        tags,
      };

      let mpuAbortDays = this.config.olderThanDays ?? 7;
      let noncurrentExpirationDays = this.config.olderThanDays ?? 30;
      let actionMode: "MONITOR_ONLY" | "PLAN_ONLY" | "AUTO_REMEDIATE" = "AUTO_REMEDIATE";

      if (this.context.policies.length > 0) {
        const resolved = resolveBucketPolicy(metadata, this.context.policies);
        this.context.resolvedPolicies.set(b.bucket, resolved);
        actionMode = resolved.action;

        for (const rule of resolved.effectiveRules) {
          if (rule.mpuAbortDays !== undefined) {
            mpuAbortDays = rule.mpuAbortDays;
          }
          if (rule.noncurrentExpirationDays !== undefined) {
            noncurrentExpirationDays = rule.noncurrentExpirationDays;
          }
        }
      }

      // If policy action is MONITOR_ONLY, violations are reported without mutation queueing
      if (actionMode === "MONITOR_ONLY") {
        continue;
      }

      // Match discovered targets for this bucket
      const bucketTargets = this.context.discoveredTargets.filter((t) => t.bucket === b.bucket);
      for (const target of bucketTargets) {
        if (target.uploadId && target.initiated) {
          const initiatedTime = new Date(target.initiated).getTime();
          const ageDays = (now - initiatedTime) / (1000 * 60 * 60 * 24);
          if (ageDays >= mpuAbortDays) {
            this.context.matchedViolations.push(target);
          }
        } else if (target.reason === "EXPIRED_DELETE_MARKER") {
          this.context.matchedViolations.push(target);
        } else if (target.versionId && target.lastModified) {
          const modifiedTime = new Date(target.lastModified).getTime();
          const ageDays = (now - modifiedTime) / (1000 * 60 * 60 * 24);
          if (ageDays >= noncurrentExpirationDays) {
            this.context.matchedViolations.push(target);
          }
        } else {
          // Default fallback matching
          this.context.matchedViolations.push(target);
        }
      }
    }

    this.log(
      `[OPERATOR] [${this.state}] Policy evaluation matched ${this.context.matchedViolations.length} violation(s).`
    );
  }

  /**
   * Phase 3: BLAST_RADIUS_AUDIT
   * Checks relative mutation ceiling; halts to SLEEP/HALTED if exceeded.
   */
  public async stepBlastRadiusAudit(): Promise<void> {
    this.state = "BLAST_RADIUS_AUDIT";
    this.log(`[OPERATOR] [${this.state}] Performing safety and blast radius assessment...`);

    const plannedCount = this.context.matchedViolations.length;
    const totalInventory = Math.max(plannedCount, this.context.discoveredTargets.length);

    // 1. Evaluate relative mutation ceiling
    const ceilingResult = evaluateMutationCeiling(plannedCount, totalInventory, {
      maxPercent: this.config.maxBlastRadiusPercent,
      bypass: false,
    });

    if (!ceilingResult.allowed) {
      this.context.isHalted = true;
      this.context.haltReason = ceilingResult.reason;
      this.log(`[OPERATOR] [${this.state}] [HALTED] ${ceilingResult.reason}`);

      const event = createAuditEvent({
        eventType: "BLAST_RADIUS_ASSESSMENT",
        accountId: "self",
        bucketName: this.config.targetBucket ?? "fleet",
        targetCount: plannedCount,
        details: { ceilingResult, risk: "CRITICAL_BLOCKED" },
      });
      this.context.auditEvents.push(event);

      this.state = "HALTED";
      return;
    }

    // 2. Perform pre-flight bucket blast radius check (Object Lock, protected prefixes, churn)
    const affectedBuckets = Array.from(new Set(this.context.matchedViolations.map((v) => v.bucket)));
    for (const bucket of affectedBuckets) {
      const bucketTargets = this.context.matchedViolations.filter((v) => v.bucket === bucket);
      try {
        const assessment = await assessBucketBlastRadius(this.client, bucket, {
          targets: bucketTargets.map((t) => ({ key: t.key, timestamp: t.initiated ?? t.lastModified })),
          bypassGovernance: this.config.bypassGovernance,
        });

        this.context.blastRadiusAssessments.set(bucket, assessment);

        if (assessment.isBlocked) {
          const reason = assessment.findings.map((f) => f.message).join("; ");
          this.context.isHalted = true;
          this.context.haltReason = `Blast radius blocked bucket '${bucket}': ${reason}`;
          this.log(`[OPERATOR] [${this.state}] [HALTED] ${this.context.haltReason}`);

          const event = createAuditEvent({
            eventType: "BLAST_RADIUS_ASSESSMENT",
            accountId: "self",
            bucketName: bucket,
            targetCount: bucketTargets.length,
            details: { assessment, risk: assessment.riskLevel },
          });
          this.context.auditEvents.push(event);

          this.state = "HALTED";
          return;
        }
      } catch (err: unknown) {
        // If blast radius assessment fails on client error, halt safely
        this.context.isHalted = true;
        this.context.lastError = err;
        this.context.haltReason = `Blast radius check error on '${bucket}': ${
          err instanceof Error ? err.message : String(err)
        }`;
        this.state = "HALTED";
        return;
      }
    }

    this.log(`[OPERATOR] [${this.state}] Safety checks passed for ${affectedBuckets.length} bucket(s).`);
  }

  /**
   * Phase 4: CANARY_TEST
   * Dispatches 1-5 oldest items via executeCanaryGate.
   */
  public async stepCanaryTest(): Promise<void> {
    this.state = "CANARY_TEST";
    this.log(`[OPERATOR] [${this.state}] Dispatching canary verification gate...`);

    if (this.context.matchedViolations.length === 0) {
      this.log(`[OPERATOR] [${this.state}] No targets to mutate. Canary check skipped.`);
      return;
    }

    const canaryCount = Math.min(this.config.canaryCount, this.context.matchedViolations.length);
    const affectedBuckets = Array.from(new Set(this.context.matchedViolations.map((v) => v.bucket)));

    for (const bucket of affectedBuckets) {
      const bucketTargets = this.context.matchedViolations.filter((v) => v.bucket === bucket);
      if (bucketTargets.length === 0) continue;

      if (this.config.dryRun) {
        this.log(`[OPERATOR] [${this.state}] [DRY-RUN] Simulated canary pass for bucket '${bucket}'.`);
        continue;
      }

      try {
        const canaryResult = await executeCanaryGate(
          this.client,
          bucket,
          bucketTargets,
          this.context.circuitBreaker,
          {
            maxCanaryCount: canaryCount,
            bypassGovernance: this.config.bypassGovernance,
          }
        );

        this.context.canaryResult = canaryResult;

        if (!canaryResult.success) {
          throw new CanaryVerificationError(`Canary gate reported failure on bucket '${bucket}'`);
        }

        const canaryMutations = canaryResult.abortedCount + canaryResult.deletedCount;
        this.context.totalMutations += canaryMutations;
        this.context.totalBytesFreed += canaryResult.bytesFreed;

        const event = createAuditEvent({
          eventType: "CANARY_VERIFIED",
          accountId: "self",
          bucketName: bucket,
          targetCount: canaryResult.canaryTargetCount,
          bytesFreed: canaryResult.bytesFreed,
          xAmzRequestIds: canaryResult.requestIds,
        });
        this.context.auditEvents.push(event);

        this.log(
          `[OPERATOR] [${this.state}] Canary passed on '${bucket}' (${canaryResult.canaryTargetCount} item(s) verified).`
        );
      } catch (err: unknown) {
        this.context.circuitBreaker.recordError(err);
        this.context.circuitBreaker.trip(
          `Canary gate verification failed on bucket '${bucket}': ${
            err instanceof Error ? err.message : String(err)
          }`
        );
        this.context.isHalted = true;
        this.context.lastError = err;
        this.context.haltReason = `Canary verification failure on '${bucket}': ${
          err instanceof Error ? err.message : String(err)
        }`;
        this.log(`[OPERATOR] [${this.state}] [HALTED] ${this.context.haltReason}`);
        this.state = "HALTED";
        return;
      }
    }
  }

  /**
   * Phase 5: CIRCUIT_VERIFY
   * Checks circuit breaker state; halts if error rates spiked.
   */
  public async stepCircuitVerify(): Promise<void> {
    this.state = "CIRCUIT_VERIFY";
    this.log(`[OPERATOR] [${this.state}] Verifying circuit breaker health...`);

    const breakerState = this.context.circuitBreaker.getState();
    if (breakerState === "OPEN") {
      this.context.isHalted = true;
      this.context.haltReason = `Circuit breaker is OPEN on bucket '${this.context.circuitBreaker.bucket}'. Error thresholds exceeded.`;
      this.log(`[OPERATOR] [${this.state}] [HALTED] ${this.context.haltReason}`);

      const event = createAuditEvent({
        eventType: "CIRCUIT_BREAKER_TRIPPED",
        accountId: "self",
        bucketName: this.context.circuitBreaker.bucket,
        details: { state: breakerState },
      });
      this.context.auditEvents.push(event);

      this.state = "HALTED";
      return;
    }

    this.log(`[OPERATOR] [${this.state}] Circuit breaker state is healthy (${breakerState}).`);
  }

  /**
   * Phase 6: BULK_EXECUTE
   * Bounded concurrency pool draining mutation queue.
   */
  public async stepBulkExecute(): Promise<void> {
    this.state = "BULK_EXECUTE";
    this.log(`[OPERATOR] [${this.state}] Draining mutation queue with bounded concurrency pool...`);

    // Exclude items already handled during Canary phase
    const canaryKeys = new Set(
      (this.context.canaryResult?.outcomes ?? []).map((o) => `${o.key}::${o.uploadId ?? ""}`)
    );

    const remainingTargets = this.context.matchedViolations.filter(
      (t) => !canaryKeys.has(`${t.key}::${t.uploadId ?? ""}`)
    );

    if (remainingTargets.length === 0) {
      this.log(`[OPERATOR] [${this.state}] No remaining items to mutate in bulk.`);
      return;
    }

    if (this.config.dryRun) {
      this.log(`[OPERATOR] [${this.state}] [DRY-RUN] Simulated bulk execution of ${remainingTargets.length} item(s).`);
      this.context.totalMutations += remainingTargets.length;
      return;
    }

    const limiter = createConcurrencyLimiter(this.config.maxConcurrency);
    const requestIds: string[] = [];
    let executedCount = 0;
    let freedBytes = 0;

    const tasks = remainingTargets.map((target) =>
      limiter(async () => {
        if (this.isShuttingDown) return;

        try {
          if (target.uploadId) {
            const res = await withRetry(() =>
              this.client.send(
                new AbortMultipartUploadCommand({
                  Bucket: target.bucket,
                  Key: target.key,
                  UploadId: target.uploadId,
                })
              )
            );
            executedCount++;
            freedBytes += target.bytes ?? 0;
            if (res?.$metadata?.requestId) {
              requestIds.push(res.$metadata.requestId);
            }
          } else if (target.versionId) {
            const res = await withRetry(() =>
              this.client.send(
                new DeleteObjectsCommand({
                  Bucket: target.bucket,
                  Delete: {
                    Objects: [{ Key: target.key, VersionId: target.versionId }],
                    Quiet: true,
                  },
                  ...(this.config.bypassGovernance ? { BypassGovernanceRetention: true } : {}),
                })
              )
            );
            executedCount++;
            freedBytes += target.bytes ?? target.size ?? 0;
            if (res?.$metadata?.requestId) {
              requestIds.push(res.$metadata.requestId);
            }
          }
          this.context.circuitBreaker.recordSuccess();
        } catch (err: unknown) {
          this.context.circuitBreaker.recordError(err);
        }
      })
    );

    await Promise.all(tasks);

    this.context.totalMutations += executedCount;
    this.context.totalBytesFreed += freedBytes;

    const affectedBuckets = Array.from(new Set(remainingTargets.map((t) => t.bucket)));
    for (const b of affectedBuckets) {
      const event = createAuditEvent({
        eventType: "REMEDIATION_EXECUTED",
        accountId: "self",
        bucketName: b,
        targetCount: executedCount,
        bytesFreed: freedBytes,
        xAmzRequestIds: requestIds,
      });
      this.context.auditEvents.push(event);
    }

    this.log(
      `[OPERATOR] [${this.state}] Bulk execution completed: ${executedCount} mutation(s), ${freedBytes} byte(s) freed.`
    );
  }

  /**
   * Phase 7: AUDIT_LOG
   * Appends JSONL events to audit.jsonl and streams structured stdout logs.
   */
  public async stepAuditLog(): Promise<void> {
    this.state = "AUDIT_LOG";
    this.log(`[OPERATOR] [${this.state}] Appending ${this.context.auditEvents.length} event(s) to JSONL ledger...`);

    for (const event of this.context.auditEvents) {
      await this.auditWriter.append(event);
      if (this.config.json) {
        this.logJson(event as unknown as Record<string, unknown>);
      }
    }

    // Central administrative S3 mirror
    if (this.config.s3MirrorBucket && !this.config.dryRun && this.context.auditEvents.length > 0) {
      try {
        const mirrorKey = `audit-logs/epoch-${this.context.epoch}-${Date.now()}.jsonl`;
        const bodyContent = this.context.auditEvents.map((e) => JSON.stringify(e)).join("\n") + "\n";
        await this.client.send(
          new PutObjectCommand({
            Bucket: this.config.s3MirrorBucket,
            Key: mirrorKey,
            Body: bodyContent,
          })
        );
        this.log(`[OPERATOR] [${this.state}] Mirrored audit events to s3://${this.config.s3MirrorBucket}/${mirrorKey}`);
      } catch (err: unknown) {
        this.log(`[OPERATOR] [${this.state}] [WARN] S3 audit mirroring failed: ${err}`);
      }
    }

    this.context.auditEvents = [];
  }

  /**
   * Phase 8: UNDO_EXPORT
   * Generates and persists UndoManifest and DeletionCertificate.
   */
  public async stepUndoExport(): Promise<void> {
    this.state = "UNDO_EXPORT";
    this.log(`[OPERATOR] [${this.state}] Generating cryptographic UndoManifest and DeletionCertificate...`);

    if (this.context.matchedViolations.length === 0) {
      this.log(`[OPERATOR] [${this.state}] No mutations performed. Manifest generation skipped.`);
      return;
    }

    const affectedBuckets = Array.from(new Set(this.context.matchedViolations.map((v) => v.bucket)));

    for (const bucket of affectedBuckets) {
      const bucketTargets = this.context.matchedViolations.filter((v) => v.bucket === bucket);
      const totalBytes = bucketTargets.reduce((sum, t) => sum + (t.bytes ?? t.size ?? 0), 0);

      try {
        // Generate UndoManifest
        const planHash = computeCanonicalStateHash(bucketTargets);
        const undoRes = await createUndoManifest({
          bucketName: bucket,
          mutationType: "OBJECT_DELETION",
          preState: bucketTargets,
          postState: [],
          appliedPlanHash: planHash,
          stateDir: this.config.stateDir,
        });
        this.context.undoManifests.push(undoRes.manifest);

        // Generate DeletionCertificate
        const certOperation = bucketTargets.some((t) => t.uploadId)
          ? "ABORT_MULTIPART_UPLOAD"
          : "PERMANENT_VERSION_DELETE";

        const certRes = await createDeletionCertificate({
          bucketName: bucket,
          operation: certOperation,
          totalBytesReclaimed: totalBytes,
          planHash: undoRes.manifest.canonicalPreStateHash,
          itemLedger: bucketTargets.map((t) => ({
            key: t.key,
            versionId: t.versionId,
            uploadId: t.uploadId,
            sizeBytes: t.bytes ?? t.size ?? 0,
          })),
          stateDir: this.config.stateDir,
        });
        this.context.deletionCertificates.push(certRes.certificate);

        this.log(`[OPERATOR] [${this.state}] Exported UndoManifest: ${undoRes.manifestPath}`);
        this.log(`[OPERATOR] [${this.state}] Exported DeletionCertificate: ${certRes.certificatePath}`);
      } catch (err: unknown) {
        this.log(`[OPERATOR] [${this.state}] [WARN] Manifest generation failed on '${bucket}': ${err}`);
      }
    }
  }

  /**
   * Phase 9: SLEEP
   * Monotonic sleep subtracting run duration, resets half-open probes.
   */
  public async stepSleep(): Promise<void> {
    this.state = "SLEEP";

    const elapsedMs = Number((process.hrtime.bigint() - this.epochStartNano) / 1000000n);
    this.context.lastRunDurationMs = elapsedMs;

    const remainingSleepMs = Math.max(0, this.config.intervalMs - elapsedMs);

    this.log(
      `[OPERATOR] [${this.state}] Epoch ${this.context.epoch} complete in ${elapsedMs}ms. Sleeping for ${remainingSleepMs}ms...`
    );

    if (this.config.json) {
      this.logJson({
        operator: "s3-guardian",
        epoch: this.context.epoch,
        state: this.state,
        discoveredBuckets: this.context.discoveredBuckets.length,
        matchedViolations: this.context.matchedViolations.length,
        totalMutations: this.context.totalMutations,
        totalBytesFreed: this.context.totalBytesFreed,
        durationMs: elapsedMs,
        isHalted: this.context.isHalted,
        haltReason: this.context.haltReason,
      });
    }

    // Reset circuit breaker half-open probes if safe
    if (this.context.circuitBreaker.getState() === "HALF_OPEN") {
      this.context.circuitBreaker.reset();
    }

    if (this.isShuttingDown || this.config.once) {
      return;
    }

    if (typeof this.config.maxRuns === "number" && this.context.epoch >= this.config.maxRuns) {
      return;
    }

    // Interruptible sleep
    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        cleanup();
        resolve();
      }, remainingSleepMs);

      const onAbort = () => {
        cleanup();
        resolve();
      };

      const cleanup = () => {
        clearTimeout(timer);
        this.abortController.signal.removeEventListener("abort", onAbort);
        this.config.signal?.removeEventListener("abort", onAbort);
      };

      this.abortController.signal.addEventListener("abort", onAbort, { once: true });
      this.config.signal?.addEventListener("abort", onAbort, { once: true });
    });
  }

  /**
   * Executes a single complete 9-phase epoch.
   */
  public async runOnce(): Promise<OperatorContext> {
    this.epochStartNano = process.hrtime.bigint();
    this.context.epoch++;
    this.context.isHalted = false;
    this.context.haltReason = undefined;

    const runPhase = async (phaseFn: () => Promise<void>) => {
      if (this.context.isHalted || this.isShuttingDown) return;
      this.currentPhasePromise = phaseFn();
      await this.currentPhasePromise;
      this.currentPhasePromise = null;
    };

    // 1. DISCOVERY
    await runPhase(() => this.stepDiscovery());

    // 2. POLICY_MATCH
    await runPhase(() => this.stepPolicyMatch());

    // 3. BLAST_RADIUS_AUDIT
    await runPhase(() => this.stepBlastRadiusAudit());

    // 4. CANARY_TEST
    await runPhase(() => this.stepCanaryTest());

    // 5. CIRCUIT_VERIFY
    await runPhase(() => this.stepCircuitVerify());

    // 6. BULK_EXECUTE
    await runPhase(() => this.stepBulkExecute());

    // 7. AUDIT_LOG
    await runPhase(() => this.stepAuditLog());

    // 8. UNDO_EXPORT
    await runPhase(() => this.stepUndoExport());

    // 9. SLEEP
    if (!this.context.isHalted) {
      await this.stepSleep();
    } else {
      const elapsedMs = Number((process.hrtime.bigint() - this.epochStartNano) / 1000000n);
      this.context.lastRunDurationMs = elapsedMs;
      if (this.config.json) {
        this.logJson({
          operator: "s3-guardian",
          epoch: this.context.epoch,
          state: this.state,
          discoveredBuckets: this.context.discoveredBuckets.length,
          matchedViolations: this.context.matchedViolations.length,
          totalMutations: this.context.totalMutations,
          totalBytesFreed: this.context.totalBytesFreed,
          durationMs: elapsedMs,
          isHalted: this.context.isHalted,
          haltReason: this.context.haltReason,
        });
      }
    }

    return this.context;
  }

  /**
   * Starts continuous sovereign governance daemon loop.
   */
  public async start(): Promise<void> {
    if (this.isRunning) return;
    this.isRunning = true;

    // Acquire lockfile
    const lockName = `sovereign-operator-${this.config.targetBucket ?? "fleet"}`;
    this.lock = acquireDaemonLock(lockName);

    this.installSignalHandlers();

    this.log(`[OPERATOR] Sovereign Operator started. Interval: ${this.config.intervalMs}ms.`);

    try {
      while (
        !this.isShuttingDown &&
        !this.abortController.signal.aborted &&
        (!this.config.signal || !this.config.signal.aborted)
      ) {
        await this.runOnce();

        if (this.context.isHalted) {
          this.log(`[OPERATOR] Operator execution halted: ${this.context.haltReason}`);
          break;
        }

        if (this.config.once) {
          break;
        }

        if (
          typeof this.config.maxRuns === "number" &&
          this.context.epoch >= this.config.maxRuns
        ) {
          break;
        }
      }
    } finally {
      await this.stop();
    }
  }

  /**
   * Graceful stop: completes in-flight batch, writes checkpoint, releases lockfile.
   */
  public async stop(): Promise<void> {
    if (!this.isRunning && !this.lock) return;

    this.isShuttingDown = true;
    this.abortController.abort();

    if (this.currentPhasePromise) {
      try {
        await this.currentPhasePromise;
      } catch {
        // Handled
      }
    }

    try {
      await this.auditWriter.close();
    } catch {
      // Ignore
    }

    // Persist checkpoint state
    try {
      const checkpointPath = path.join(this.config.stateDir, "operator-checkpoint.json");
      const checkpointData = {
        epoch: this.context.epoch,
        cursor: this.context.cursor,
        totalMutations: this.context.totalMutations,
        totalBytesFreed: this.context.totalBytesFreed,
        timestamp: new Date().toISOString(),
      };
      await fsPromises.mkdir(this.config.stateDir, { recursive: true });
      await fsPromises.writeFile(checkpointPath, JSON.stringify(checkpointData, null, 2), "utf8");
    } catch {
      // Best-effort checkpoint
    }

    if (this.lock) {
      this.lock.release();
      this.lock = null;
    }

    this.isRunning = false;
    this.log(`[OPERATOR] Sovereign Operator stopped cleanly.`);
  }

  private installSignalHandlers(): void {
    if (this.signalHandlersInstalled) return;
    this.signalHandlersInstalled = true;

    const handleSignal = async (sig: string) => {
      this.log(`\n[OPERATOR] [SHUTDOWN] Signal ${sig} received. Gracefully terminating...`);
      await this.stop();
      process.exit(0);
    };

    process.once("SIGINT", () => handleSignal("SIGINT"));
    process.once("SIGTERM", () => handleSignal("SIGTERM"));
  }
}
