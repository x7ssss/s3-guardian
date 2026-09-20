import {
  S3Client,
  GetObjectCommand,
  PutObjectCommand,
} from "@aws-sdk/client-s3";
import type { BucketAuditResult } from "../fleet/scanner.js";

export interface CheckpointState {
  completedBuckets: BucketAuditResult[];
  lastUpdatedAt: string;
}

export interface ParsedS3Uri {
  bucket: string;
  key: string;
}

/**
 * Parses an S3 URI of the form `s3://<bucket>/<key>`.
 * Throws an Error if the URI is not a valid S3 URI.
 */
export function parseS3Uri(uri: string): ParsedS3Uri {
  if (!uri.startsWith("s3://")) {
    throw new Error(`Invalid S3 URI "${uri}": must start with "s3://"`);
  }

  const path = uri.slice(5); // remove 's3://'
  const slashIdx = path.indexOf("/");

  if (slashIdx === -1 || slashIdx === 0 || slashIdx === path.length - 1) {
    throw new Error(
      `Invalid S3 URI "${uri}": must specify both bucket and object key (e.g. s3://my-bucket/checkpoint.json)`
    );
  }

  const bucket = path.slice(0, slashIdx);
  const key = path.slice(slashIdx + 1);

  return { bucket, key };
}

/**
 * Loads an existing checkpoint from S3.
 * Gracefully returns an empty state if the object does not exist (404 / NoSuchKey).
 */
export async function loadCheckpoint(
  client: S3Client,
  uri: string
): Promise<CheckpointState> {
  const { bucket, key } = parseS3Uri(uri);

  try {
    const response = await client.send(
      new GetObjectCommand({
        Bucket: bucket,
        Key: key,
      })
    );

    let bodyText: string | undefined;
    try {
      bodyText = await response.Body?.transformToString();
    } catch (err) {
      if (
        response.Body &&
        typeof (response.Body as unknown as { destroy?: () => void }).destroy ===
          "function"
      ) {
        (response.Body as unknown as { destroy: () => void }).destroy();
      }
      throw err;
    }
    if (!bodyText) {
      return {
        completedBuckets: [],
        lastUpdatedAt: new Date().toISOString(),
      };
    }

    const parsed = JSON.parse(bodyText);
    return {
      completedBuckets: Array.isArray(parsed.completedBuckets)
        ? parsed.completedBuckets
        : [],
      lastUpdatedAt:
        typeof parsed.lastUpdatedAt === "string"
          ? parsed.lastUpdatedAt
          : new Date().toISOString(),
    };
  } catch (err: unknown) {
    const errorObj = err as Record<string, unknown>;
    const name = String(errorObj?.name || errorObj?.Code || "");
    const status =
      (errorObj?.$metadata as Record<string, unknown> | undefined)
        ?.httpStatusCode ?? errorObj?.statusCode;

    // Object doesn't exist yet: initialize a fresh checkpoint
    if (name === "NoSuchKey" || name === "NotFound" || status === 404) {
      return {
        completedBuckets: [],
        lastUpdatedAt: new Date().toISOString(),
      };
    }

    throw err;
  }
}

/**
 * Persists updated checkpoint state to S3.
 */
export async function saveCheckpoint(
  client: S3Client,
  uri: string,
  state: CheckpointState
): Promise<void> {
  const { bucket, key } = parseS3Uri(uri);

  const payload: CheckpointState = {
    completedBuckets: state.completedBuckets,
    lastUpdatedAt: new Date().toISOString(),
  };

  await client.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: key,
      Body: JSON.stringify(payload, null, 2),
      ContentType: "application/json",
    })
  );
}
