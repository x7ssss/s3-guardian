import { randomUUID } from "node:crypto";
import * as path from "node:path";
import {
  S3Client,
  GetBucketLifecycleConfigurationCommand,
  GetBucketTaggingCommand,
} from "@aws-sdk/client-s3";
import { canonicalizeJson, computeSha256Hex } from "../planner/jcs.js";
import { writeAtomic } from "../state/atomic-file.js";
import {
  UndoManifest,
  DeletionCertificate,
  StateCaptureResult,
  MutationType,
  InverseCommandType,
  IrreversibleOperation,
  DeletionCertificateLedgerItem,
} from "./types.js";

export function computeCanonicalStateHash(state: unknown): string {
  return computeSha256Hex(canonicalizeJson(state));
}

/**
 * Captures live lifecycle configuration pre-state for a bucket.
 * Traps NoSuchLifecycleConfiguration (404) and returns null state.
 * Computes RFC 8785 canonical hash.
 */
export async function captureLifecyclePreState(
  s3Client: S3Client,
  bucketName: string
): Promise<StateCaptureResult> {
  try {
    const response = await s3Client.send(
      new GetBucketLifecycleConfigurationCommand({ Bucket: bucketName })
    );
    const rules = response.Rules ?? [];
    const state = { Rules: rules };
    const canonicalHash = computeCanonicalStateHash(state);
    return {
      preState: state,
      state,
      canonicalHash,
      hash: canonicalHash,
    };
  } catch (err: unknown) {
    const errorObj = err as Record<string, unknown>;
    const name = String(errorObj?.name || errorObj?.Code || "");
    const status =
      (errorObj?.$metadata as Record<string, unknown> | undefined)?.httpStatusCode ??
      errorObj?.statusCode ??
      errorObj?.status;

    if (name === "NoSuchLifecycleConfiguration" || status === 404) {
      const canonicalHash = computeCanonicalStateHash(null);
      return {
        preState: null,
        state: null,
        canonicalHash,
        hash: canonicalHash,
      };
    }
    throw err;
  }
}

/**
 * Captures live tagging pre-state for a bucket.
 * Traps NoSuchTagSet (404) and returns null state.
 * Computes RFC 8785 canonical hash.
 */
export async function captureTaggingPreState(
  s3Client: S3Client,
  bucketName: string
): Promise<StateCaptureResult> {
  try {
    const response = await s3Client.send(
      new GetBucketTaggingCommand({ Bucket: bucketName })
    );
    const tagSet = response.TagSet ?? [];
    const state = { TagSet: tagSet };
    const canonicalHash = computeCanonicalStateHash(state);
    return {
      preState: state,
      state,
      canonicalHash,
      hash: canonicalHash,
    };
  } catch (err: unknown) {
    const errorObj = err as Record<string, unknown>;
    const name = String(errorObj?.name || errorObj?.Code || "");
    const status =
      (errorObj?.$metadata as Record<string, unknown> | undefined)?.httpStatusCode ??
      errorObj?.statusCode ??
      errorObj?.status;

    if (name === "NoSuchTagSet" || status === 404) {
      const canonicalHash = computeCanonicalStateHash(null);
      return {
        preState: null,
        state: null,
        canonicalHash,
        hash: canonicalHash,
      };
    }
    throw err;
  }
}

export interface CreateUndoManifestParams {
  stateDir?: string;
  bucketName: string;
  mutationType: MutationType;
  preState: any;
  postState: any;
  inverseCommandType?: InverseCommandType;
  inversePayload?: any;
  appliedPlanHash: string;
  requestIds?: string[];
  manifestId?: string;
  createdAt?: string;
  timestamp?: string;
}

export interface CreateUndoManifestResult extends UndoManifest {
  manifest: UndoManifest;
  manifestPath: string;
}

/**
 * Generates an UndoManifest and writes undo-<bucket>-<timestamp>.json atomically to ${stateDir}/undo/
 */
export async function createUndoManifest(
  params: CreateUndoManifestParams
): Promise<CreateUndoManifestResult> {
  const manifestId = params.manifestId ?? randomUUID();
  const createdAt = params.createdAt ?? new Date().toISOString();
  const canonicalPreStateHash = computeCanonicalStateHash(params.preState);
  const canonicalPostStateHash = computeCanonicalStateHash(params.postState);

  let inverseCommandType = params.inverseCommandType;
  if (!inverseCommandType) {
    if (params.mutationType === "LIFECYCLE_CONFIGURATION") {
      inverseCommandType =
        params.preState === null
          ? "DeleteBucketLifecycleConfiguration"
          : "PutBucketLifecycleConfiguration";
    } else if (params.mutationType === "BUCKET_TAGGING") {
      inverseCommandType =
        params.preState === null ? "DeleteBucketTagging" : "PutBucketTagging";
    } else {
      inverseCommandType = "DeleteObjects";
    }
  }

  let inversePayload = params.inversePayload;
  if (inversePayload === undefined) {
    if (params.mutationType === "LIFECYCLE_CONFIGURATION") {
      inversePayload =
        params.preState === null
          ? null
          : params.preState.Rules
          ? { LifecycleConfiguration: params.preState }
          : { LifecycleConfiguration: { Rules: params.preState } };
    } else if (params.mutationType === "BUCKET_TAGGING") {
      inversePayload =
        params.preState === null
          ? null
          : params.preState.TagSet
          ? { Tagging: params.preState }
          : { Tagging: { TagSet: params.preState } };
    } else {
      inversePayload = params.preState;
    }
  }

  const manifest: UndoManifest = {
    manifestId,
    manifestVersion: "1.8.0",
    createdAt,
    bucketName: params.bucketName,
    mutationType: params.mutationType,
    canonicalPreStateHash,
    canonicalPostStateHash,
    preState: params.preState,
    postState: params.postState,
    inverseCommandType,
    inversePayload,
    appliedPlanHash: params.appliedPlanHash,
    requestIds: params.requestIds ?? [],
  };

  const timeStr =
    params.timestamp ?? createdAt.replace(/[:.]/g, "-");
  const stateDir =
    params.stateDir ?? path.resolve(process.cwd(), ".s3-guardian");
  const undoDir = path.join(stateDir, "undo");
  const manifestPath = path.join(
    undoDir,
    `undo-${params.bucketName}-${timeStr}.json`
  );

  await writeAtomic(manifestPath, JSON.stringify(manifest, null, 2));

  return {
    ...manifest,
    manifest,
    manifestPath,
  };
}

export interface CreateDeletionCertificateParams {
  stateDir?: string;
  bucketName: string;
  operation: IrreversibleOperation;
  targetCount?: number;
  totalBytesReclaimed: number;
  planHash: string;
  requestIds?: string[];
  itemLedger: DeletionCertificateLedgerItem[];
  certificateId?: string;
  timestamp?: string;
  timeStr?: string;
}

export interface CreateDeletionCertificateResult extends DeletionCertificate {
  certificate: DeletionCertificate;
  certificatePath: string;
}

/**
 * Generates an immutable DeletionCertificate and writes deletion-certificate-<bucket>-<timestamp>.json atomically to ${stateDir}/certificates/
 */
export async function createDeletionCertificate(
  params: CreateDeletionCertificateParams
): Promise<CreateDeletionCertificateResult> {
  const certificateId = params.certificateId ?? randomUUID();
  const timestamp = params.timestamp ?? new Date().toISOString();
  const targetCount = params.targetCount ?? params.itemLedger.length;
  const requestIds = params.requestIds ?? [];

  const certificate: DeletionCertificate = {
    certificateId,
    timestamp,
    bucketName: params.bucketName,
    operation: params.operation,
    targetCount,
    totalBytesReclaimed: params.totalBytesReclaimed,
    planHash: params.planHash,
    requestIds,
    itemLedger: params.itemLedger,
  };

  const timeStr =
    params.timeStr ?? timestamp.replace(/[:.]/g, "-");
  const stateDir =
    params.stateDir ?? path.resolve(process.cwd(), ".s3-guardian");
  const certsDir = path.join(stateDir, "certificates");
  const certificatePath = path.join(
    certsDir,
    `deletion-certificate-${params.bucketName}-${timeStr}.json`
  );

  await writeAtomic(certificatePath, JSON.stringify(certificate, null, 2));

  return {
    ...certificate,
    certificate,
    certificatePath,
  };
}
