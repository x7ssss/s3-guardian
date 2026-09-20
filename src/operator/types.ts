import type { S3Client } from "@aws-sdk/client-s3";
import type { CircuitBreaker } from "../circuit/breaker.js";
import type { CanaryGateResult } from "../safety/canary.js";
import type { BlastRadiusAssessment } from "../safety/blast-radius.js";
import type { UndoManifest, DeletionCertificate } from "../rollback/types.js";
import type { AuditEvent } from "../state/types.js";
import type { BucketAuditResult } from "../fleet/scanner.js";
import type { GuardianPolicy, ResolvedPolicy } from "../policy/types.js";

/**
 * 9-phase Sovereign Governance State Machine states plus terminal HALTED state.
 */
export type OperatorState =
  | "DISCOVERY"
  | "POLICY_MATCH"
  | "BLAST_RADIUS_AUDIT"
  | "CANARY_TEST"
  | "CIRCUIT_VERIFY"
  | "BULK_EXECUTE"
  | "AUDIT_LOG"
  | "UNDO_EXPORT"
  | "SLEEP"
  | "HALTED";

/**
 * Configuration for the Autonomous Sovereign Operator.
 */
export interface OperatorConfig {
  /** Execution interval in milliseconds (default: 3,600,000 = 1 hour). */
  intervalMs?: number;
  /** File path to declarative policy document (JSON / YAML subset). */
  policyPath?: string;
  /** Maximum relative mutation ceiling fraction (default: 0.05 = 5%). */
  maxBlastRadiusPercent?: number;
  /** Number of canary candidate items dispatched during canary phase (default: 5). */
  canaryCount?: number;
  /** Maximum concurrent delete/abort requests (default: 10). */
  maxConcurrency?: number;
  /** Local state directory for JSONL ledger, snapshots, manifests (default: ./.s3-guardian). */
  stateDir: string;
  /** Central administrative S3 bucket to mirror state and compaction snapshots. */
  s3MirrorBucket?: string;
  /** Simulation mode without applying cloud mutations. */
  dryRun?: boolean;
  /** Maximum run iterations (for finite testing and CI). */
  maxRuns?: number;
  /** Optional target bucket name to scope execution to a single bucket. */
  targetBucket?: string;
  /** Optional preconfigured S3Client instance. */
  client?: S3Client;
  /** Optional custom logger callback. */
  logger?: (msg: string) => void;
  /** Emit strict JSONL machine logs. */
  json?: boolean;
  /** Run a single epoch and exit. */
  once?: boolean;
  /** Optional abort signal for cooperative cancellation. */
  signal?: AbortSignal;
  /** Bypass S3 Object Lock governance retention mode. */
  bypassGovernance?: boolean;
}

/**
 * Discovered candidate mutation target (MPU upload or noncurrent object version).
 */
export interface CandidateMutationTarget {
  bucket: string;
  key: string;
  uploadId?: string;
  versionId?: string;
  isDeleteMarker?: boolean;
  initiated?: Date | string;
  lastModified?: Date | string;
  bytes?: number;
  size?: number;
  ruleId?: string;
  reason?: string;
}

/**
 * Execution context carrying state through the 9-phase operator pipeline.
 */
export interface OperatorContext {
  /** Discovered bucket audit summaries. */
  discoveredBuckets: BucketAuditResult[];
  /** Candidate items discovered across buckets. */
  discoveredTargets: CandidateMutationTarget[];
  /** Loaded and resolved declarative policies. */
  policies: GuardianPolicy[];
  /** Policy evaluation results per bucket. */
  resolvedPolicies: Map<string, ResolvedPolicy>;
  /** Discovered candidate items matching policy violations. */
  matchedViolations: CandidateMutationTarget[];
  /** Canary execution result from CANARY_TEST phase. */
  canaryResult?: CanaryGateResult<CandidateMutationTarget>;
  /** Active circuit breaker tracking error rates. */
  circuitBreaker: CircuitBreaker;
  /** Blast radius assessments per bucket. */
  blastRadiusAssessments: Map<string, BlastRadiusAssessment>;
  /** Generated UndoManifest entries awaiting persistence. */
  undoManifests: UndoManifest[];
  /** Generated DeletionCertificate entries awaiting persistence. */
  deletionCertificates: DeletionCertificate[];
  /** Audit log events generated in current epoch. */
  auditEvents: AuditEvent[];
  /** Pagination cursor for target resumption. */
  cursor?: string;
  /** Current epoch execution counter. */
  epoch: number;
  /** Total number of mutations executed across epochs. */
  totalMutations: number;
  /** Total bytes freed across epochs. */
  totalBytesFreed: number;
  /** Duration in milliseconds of last run epoch. */
  lastRunDurationMs: number;
  /** Indicates whether the operator was halted due to safety or circuit breaker trip. */
  isHalted: boolean;
  /** Descriptive reason if operator is halted or skipped to sleep. */
  haltReason?: string;
  /** Last error caught during state execution. */
  lastError?: unknown;
}
