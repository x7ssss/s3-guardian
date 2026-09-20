import * as fs from "node:fs/promises";
import * as path from "node:path";
import {
  S3Client,
  PutBucketLifecycleConfigurationCommand,
  DeleteBucketLifecycleCommand,
  PutBucketTaggingCommand,
  DeleteBucketTaggingCommand,
  DeleteObjectsCommand,
} from "@aws-sdk/client-s3";
import { AuditLogWriter, createAuditEvent } from "../state/index.js";
import {
  captureLifecyclePreState,
  captureTaggingPreState,
  computeCanonicalStateHash,
} from "./manifest-generator.js";
import { paginateListObjectVersions } from "./rehydrator.js";
import {
  UndoManifest,
  RemoteStateDriftError,
  RollbackResult,
} from "./types.js";

export interface ExecuteRollbackOptions {
  force?: boolean;
  stateDir?: string;
}

/**
 * Loads an UndoManifest, checks for remote state drift against S3 live state,
 * inverts the recorded mutation, and appends a REMEDIATION_ROLLED_BACK event to audit.jsonl.
 */
export async function executeRollback(
  s3Client: S3Client,
  manifestPath: string,
  options: ExecuteRollbackOptions = {}
): Promise<RollbackResult> {
  const content = await fs.readFile(manifestPath, "utf8");
  const manifest = JSON.parse(content) as UndoManifest;

  if (
    !manifest.manifestId ||
    !manifest.bucketName ||
    !manifest.mutationType ||
    !manifest.canonicalPostStateHash
  ) {
    throw new Error(
      `Invalid UndoManifest at '${manifestPath}': missing required manifest fields.`
    );
  }

  // 1. Evaluate remote state drift
  let liveCanonicalHash: string;

  if (manifest.mutationType === "LIFECYCLE_CONFIGURATION") {
    const capture = await captureLifecyclePreState(
      s3Client,
      manifest.bucketName
    );
    liveCanonicalHash = capture.canonicalHash;
  } else if (manifest.mutationType === "BUCKET_TAGGING") {
    const capture = await captureTaggingPreState(
      s3Client,
      manifest.bucketName
    );
    liveCanonicalHash = capture.canonicalHash;
  } else if (manifest.mutationType === "SOFT_DELETE_MARKER") {
    const keys: string[] = Array.isArray(manifest.postState)
      ? manifest.postState.map((i: any) => i.Key ?? i.key)
      : Array.isArray(manifest.postState?.markers)
      ? manifest.postState.markers.map((i: any) => i.Key ?? i.key)
      : Array.isArray(manifest.postState?.Objects)
      ? manifest.postState.Objects.map((i: any) => i.Key ?? i.key)
      : [];

    const keySet = new Set(keys.filter(Boolean));
    if (keySet.size === 0) {
      liveCanonicalHash = computeCanonicalStateHash(manifest.postState);
    } else {
      const liveMarkers: Array<{ Key: string; VersionId: string }> = [];
      for await (const page of paginateListObjectVersions(
        s3Client,
        manifest.bucketName
      )) {
        for (const dm of page.deleteMarkers) {
          if (
            dm.Key &&
            keySet.has(dm.Key) &&
            dm.IsLatest === true &&
            dm.VersionId
          ) {
            liveMarkers.push({ Key: dm.Key, VersionId: dm.VersionId });
          }
        }
      }
      liveMarkers.sort(
        (a, b) =>
          a.Key.localeCompare(b.Key) || a.VersionId.localeCompare(b.VersionId)
      );
      const state = Array.isArray(manifest.postState)
        ? liveMarkers
        : { ...manifest.postState, markers: liveMarkers };
      liveCanonicalHash = computeCanonicalStateHash(state);
    }
  } else {
    liveCanonicalHash = manifest.canonicalPostStateHash;
  }

  if (liveCanonicalHash !== manifest.canonicalPostStateHash && !options.force) {
    throw new RemoteStateDriftError(
      manifest.bucketName,
      manifest.canonicalPostStateHash,
      liveCanonicalHash
    );
  }

  // 2. Invert mutation
  if (
    manifest.inverseCommandType === "PutBucketLifecycleConfiguration" ||
    (manifest.mutationType === "LIFECYCLE_CONFIGURATION" &&
      manifest.preState !== null)
  ) {
    const rawRules =
      manifest.inversePayload?.LifecycleConfiguration?.Rules ??
      manifest.inversePayload?.Rules ??
      manifest.preState?.Rules ??
      manifest.preState;
    const rules = Array.isArray(rawRules) ? rawRules : [];

    await s3Client.send(
      new PutBucketLifecycleConfigurationCommand({
        Bucket: manifest.bucketName,
        LifecycleConfiguration: { Rules: rules },
      })
    );
  } else if (
    manifest.inverseCommandType === "DeleteBucketLifecycleConfiguration" ||
    (manifest.mutationType === "LIFECYCLE_CONFIGURATION" &&
      manifest.preState === null)
  ) {
    await s3Client.send(
      new DeleteBucketLifecycleCommand({
        Bucket: manifest.bucketName,
      })
    );
  } else if (
    manifest.inverseCommandType === "PutBucketTagging" ||
    (manifest.mutationType === "BUCKET_TAGGING" && manifest.preState !== null)
  ) {
    const rawTags =
      manifest.inversePayload?.Tagging?.TagSet ??
      manifest.inversePayload?.TagSet ??
      manifest.preState?.TagSet ??
      manifest.preState;
    const tagSet = Array.isArray(rawTags) ? rawTags : [];

    await s3Client.send(
      new PutBucketTaggingCommand({
        Bucket: manifest.bucketName,
        Tagging: { TagSet: tagSet },
      })
    );
  } else if (
    manifest.inverseCommandType === "DeleteBucketTagging" ||
    (manifest.mutationType === "BUCKET_TAGGING" && manifest.preState === null)
  ) {
    await s3Client.send(
      new DeleteBucketTaggingCommand({
        Bucket: manifest.bucketName,
      })
    );
  } else if (
    manifest.inverseCommandType === "DeleteObjects" ||
    manifest.mutationType === "SOFT_DELETE_MARKER"
  ) {
    const rawObjects =
      manifest.inversePayload?.Delete?.Objects ??
      manifest.inversePayload?.Objects ??
      (Array.isArray(manifest.inversePayload) ? manifest.inversePayload : null) ??
      manifest.preState?.Objects ??
      (Array.isArray(manifest.preState) ? manifest.preState : []);

    const objects = (Array.isArray(rawObjects) ? rawObjects : []).map(
      (item: any) => ({
        Key: item.Key ?? item.key,
        VersionId: item.VersionId ?? item.versionId,
      })
    );

    if (objects.length > 0) {
      await s3Client.send(
        new DeleteObjectsCommand({
          Bucket: manifest.bucketName,
          Delete: {
            Objects: objects,
            Quiet: true,
          },
        })
      );
    }
  }

  // 3. Emit REMEDIATION_ROLLED_BACK event to audit.jsonl
  const resolvedStateDir =
    options.stateDir ??
    (manifestPath.includes("undo")
      ? path.dirname(path.dirname(path.resolve(manifestPath)))
      : path.resolve(process.cwd(), ".s3-guardian"));

  const auditWriter = new AuditLogWriter({ stateDir: resolvedStateDir });
  await auditWriter
    .append(
      createAuditEvent({
        eventType: "REMEDIATION_ROLLED_BACK",
        accountId: "ambient",
        bucketName: manifest.bucketName,
        planHash: manifest.appliedPlanHash,
        details: {
          manifestId: manifest.manifestId,
          mutationType: manifest.mutationType,
          inverseCommandType: manifest.inverseCommandType,
          forced: Boolean(options.force),
        },
      })
    )
    .catch(() => {});
  await auditWriter.close().catch(() => {});

  return {
    manifestId: manifest.manifestId,
    bucketName: manifest.bucketName,
    status: "RESTORED",
    restoredAt: new Date().toISOString(),
  };
}
